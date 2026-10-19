import { createHash, createPublicKey, verify as verifySignature, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const CONTRACT_ID = "agentic-v4-trust-anchor-provider";
const SIGNED_EVIDENCE_DOMAIN = "agentic-v4-signed-anchor-continuity-evidence";
const RUNBOOK_DOMAIN = "agentic-v4-finalization-anchor-recovery-runbook";
const SUPPORTED_CONTRACTS = new Map([
  ["1.0.0", ["read", "compareAndSet"]],
  ["1.1.0", ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"]]
]);
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const MAX_RUNBOOK_BYTES = 1024 * 1024;

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clone = value => value == null ? value : structuredClone(value);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
  }
}
function parsePublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Public key harus Ed25519");
  return key;
}
function verifyEd25519(key, payload, signature) {
  try {
    if (typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
    const bytes = Buffer.from(signature, "base64url");
    return bytes.length === 64 && bytes.toString("base64url") === signature
      && verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes);
  } catch { return false; }
}
function digestWithout(value, field) {
  const unsigned = clone(value);
  delete unsigned[field];
  return sha256(canonical(unsigned));
}
function summarizeFindings(items) {
  return items.slice(0, 30).map(item => ({ code: String(item?.code || "UNKNOWN").replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 100),
    severity: ["error", "warning", "info"].includes(item?.severity) ? item.severity : "warning" }));
}

export function createRecoverySloFinalizationAnchorEvidenceService({
  keyPolicy, anchorOperations, externalAnchorProvider = null, clock = () => new Date().toISOString(),
  contractVersion = "1.0.0", contractVersionResolver = null, continuitySigner = null, continuityKeyId = null, continuityPublicKeys = null,
  requireSignedContinuityEvidence = false
} = {}) {
  if (!keyPolicy || typeof keyPolicy.getRecoverySloFinalizationKeyPolicyAnchorStatus !== "function"
    || typeof keyPolicy.auditRecoverySloFinalizationKeyPolicy !== "function"
    || typeof keyPolicy.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof !== "function"
    || typeof keyPolicy.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof !== "function"
    || !anchorOperations || typeof anchorOperations.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof !== "function"
    || typeof anchorOperations.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence !== "function"
    || typeof clock !== "function") throw new TypeError("Anchor evidence service memerlukan key policy, anchor operations, dan clock");
  if (externalAnchorProvider != null && (typeof externalAnchorProvider.read !== "function" || typeof externalAnchorProvider.compareAndSet !== "function")) {
    throw new TypeError("Provider harus menyediakan read() dan compareAndSet()");
  }
  if (!SUPPORTED_CONTRACTS.has(contractVersion)) throw new TypeError(`Contract version tidak didukung: ${String(contractVersion)}`);
  if (contractVersionResolver != null && typeof contractVersionResolver !== "function") throw new TypeError("contractVersionResolver harus berupa function");
  const keys = new Map();
  const source = continuityPublicKeys instanceof Map ? [...continuityPublicKeys.entries()]
    : continuityPublicKeys && typeof continuityPublicKeys === "object" && !Array.isArray(continuityPublicKeys) ? Object.entries(continuityPublicKeys) : [];
  for (const [id, value] of source.slice(0, 50)) {
    if (typeof id !== "string" || !KEY_ID.test(id)) continue;
    try { keys.set(id, parsePublicKey(value)); } catch { /* invalid keys are never trusted */ }
  }
  const signingConfigured = continuitySigner != null || continuityKeyId != null || requireSignedContinuityEvidence;
  if (signingConfigured && (typeof continuitySigner !== "function" || typeof continuityKeyId !== "string"
    || !KEY_ID.test(continuityKeyId) || !keys.has(continuityKeyId))) {
    throw new TypeError("Signed continuity evidence memerlukan signer, key ID, dan public key Ed25519 tepercaya yang cocok");
  }
  if (requireSignedContinuityEvidence && !signingConfigured) throw new TypeError("Signed continuity evidence diwajibkan tetapi belum dikonfigurasi");

  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_CLOCK_INVALID", "Clock anchor evidence tidak valid", 500);
    return new Date(value).toISOString();
  }
  async function readProviderContractInfo() {
    if (!externalAnchorProvider) return { info: null, declared: false, error: "PROVIDER_NOT_CONFIGURED" };
    try {
      let info = externalAnchorProvider.contractInfo ?? null;
      if (typeof externalAnchorProvider.getContractInfo === "function") info = await externalAnchorProvider.getContractInfo();
      if (info == null) return { info: null, declared: false, error: null };
      if (!info || typeof info !== "object" || Array.isArray(info)) return { info: null, declared: true, error: "PROVIDER_CONTRACT_METADATA_INVALID" };
      return { info: clone(info), declared: true, error: null };
    } catch { return { info: null, declared: true, error: "PROVIDER_CONTRACT_METADATA_UNAVAILABLE" }; }
  }
  async function resolveExpectedContractVersion(ownerId) {
    if (typeof contractVersionResolver === "function") {
      const resolved = await contractVersionResolver(ownerId);
      if (resolved != null) {
        if (!SUPPORTED_CONTRACTS.has(resolved)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_POLICY_INVALID", "Contract migration policy berisi versi yang tidak didukung", 409);
        return resolved;
      }
    }
    return contractVersion;
  }
  async function getContractStatus(ownerId, requestedVersion = null) {
    assertOwner(ownerId);
    const activeVersion = requestedVersion ?? await resolveExpectedContractVersion(ownerId);
    if (!SUPPORTED_CONTRACTS.has(activeVersion)) throw new AgenticError("RECOVERY_SLO_CONTRACT_VERSION_UNSUPPORTED", "Versi kontrak tidak didukung", 400);
    const expectedCapabilities = SUPPORTED_CONTRACTS.get(activeVersion);
    if (!externalAnchorProvider) return { ownerId, contractId: CONTRACT_ID, status: "not_configured", expectedVersion: activeVersion,
      actualVersion: null, declared: false, requiredCapabilities: expectedCapabilities, availableCapabilities: [],
      findings: [{ code: "PROVIDER_NOT_CONFIGURED", severity: "error" }], readOnly: true, mutationAllowed: false };
    const metadata = await readProviderContractInfo();
    const actualVersion = metadata.info?.version ?? (metadata.declared ? null : "1.0.0");
    const available = new Set();
    if (typeof externalAnchorProvider.read === "function") available.add("read");
    if (typeof externalAnchorProvider.compareAndSet === "function") available.add("compareAndSet");
    if (Array.isArray(metadata.info?.capabilities)) for (const capability of metadata.info.capabilities) {
      if (typeof capability === "string" && /^[A-Za-z][A-Za-z0-9]*$/.test(capability)) available.add(capability);
    }
    const findings = [];
    if (metadata.error) findings.push({ code: metadata.error, severity: "error" });
    if (metadata.declared && metadata.info?.contractId !== CONTRACT_ID) findings.push({ code: "PROVIDER_CONTRACT_ID_MISMATCH", severity: "error" });
    if (actualVersion !== activeVersion) findings.push({ code: "PROVIDER_CONTRACT_VERSION_MISMATCH", severity: "error" });
    for (const capability of expectedCapabilities) if (!available.has(capability)) findings.push({ code: `PROVIDER_CAPABILITY_MISSING_${capability.toUpperCase()}`, severity: "error" });
    if (activeVersion !== "1.0.0" && !metadata.declared) findings.push({ code: "PROVIDER_CONTRACT_DECLARATION_REQUIRED", severity: "error" });
    if (activeVersion === "1.1.0" && (metadata.info?.ownerScope !== "ownerId" || metadata.info?.casSemantics !== "digest-compare-and-set"
      || metadata.info?.schemaVersion !== 1)) findings.push({ code: "PROVIDER_CONTRACT_SEMANTICS_MISMATCH", severity: "error" });
    const legacy = !metadata.declared && activeVersion === "1.0.0" && findings.length === 0;
    return { ownerId, contractId: CONTRACT_ID, status: findings.length ? "incompatible" : legacy ? "compatible_legacy" : "compatible_declared",
      expectedVersion: activeVersion, actualVersion, declared: metadata.declared, legacyImplicitContract: legacy,
      declarationSource: metadata.declared ? "provider_metadata" : "legacy_method_inference", providerMetadataAuthenticated: false,
      behavioralConformanceRequired: true,
      schemaVersion: metadata.info?.schemaVersion ?? null, ownerScope: metadata.info?.ownerScope ?? (legacy ? "method-boundary-only" : null),
      casSemantics: metadata.info?.casSemantics ?? (legacy ? "provider-implementation-assumed" : null),
      requiredCapabilities: expectedCapabilities, availableCapabilities: [...available].sort(),
      findings: legacy ? [{ code: "PROVIDER_CONTRACT_DECLARATION_MISSING", severity: "warning" }] : findings,
      readOnly: true, mutationAllowed: false };
  }
  async function buildSignedEvidenceFromProof(ownerId, proof, contractStatus = null) {
    if (!continuitySigner || !continuityKeyId || !keys.has(continuityKeyId)) {
      if (requireSignedContinuityEvidence) throw new AgenticError("RECOVERY_SLO_SIGNED_CONTINUITY_REQUIRED", "Signed continuity evidence diwajibkan tetapi signer tidak tersedia", 503);
      return null;
    }
    const contract = contractStatus ?? await getContractStatus(ownerId);
    const unsigned = { domain: SIGNED_EVIDENCE_DOMAIN, schemaVersion: 1, evidenceId: `recovery-slo-signed-continuity-${sha256(`${ownerId}:${proof.proofId}:${now()}`).slice(0, 32)}`,
      ownerId, issuedAt: now(), contract: { contractId: contract.contractId, status: contract.status,
        expectedVersion: contract.expectedVersion, actualVersion: contract.actualVersion, declared: contract.declared,
        declarationSource: contract.declarationSource ?? null, providerMetadataAuthenticated: false,
        behavioralConformanceRequired: true, schemaVersion: contract.schemaVersion ?? null,
        ownerScope: contract.ownerScope ?? null, casSemantics: contract.casSemantics ?? null,
        requiredCapabilities: contract.requiredCapabilities, availableCapabilities: contract.availableCapabilities,
        findings: contract.findings },
      continuityProof: clone(proof), continuityProofDigest: proof.proofDigest,
      signing: { algorithm: "Ed25519", keyId: continuityKeyId },
      claims: { proofDigestBound: true, contractVersionEvaluated: contract.expectedVersion,
        providerObservationAuthenticated: false, currentAnchorClaim: proof.claims?.anchorCurrent === true },
      readOnly: true, mutationAllowed: false };
    unsigned.evidenceDigest = sha256(canonical(unsigned));
    let result;
    try { result = await continuitySigner(clone(unsigned)); }
    catch { throw new AgenticError("RECOVERY_SLO_CONTINUITY_SIGNER_FAILED", "External signer continuity evidence gagal", 502); }
    const signature = typeof result === "string" ? result : result?.signature;
    const returnedKeyId = typeof result === "object" && result ? result.keyId : null;
    if (returnedKeyId != null && returnedKeyId !== continuityKeyId) throw new AgenticError("RECOVERY_SLO_CONTINUITY_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID yang tidak sesuai", 502);
    if (!verifyEd25519(keys.get(continuityKeyId), unsigned, signature)) throw new AgenticError("RECOVERY_SLO_CONTINUITY_SIGNATURE_INVALID", "Signature continuity evidence tidak cocok dengan trusted public key", 502);
    return { ...unsigned, signature };
  }
  async function createSignedContinuityEvidence(ownerId) {
    assertOwner(ownerId);
    const contract = await getContractStatus(ownerId);
    const { proof } = await anchorOperations.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof(ownerId);
    const evidence = await buildSignedEvidenceFromProof(ownerId, proof, contract);
    if (!evidence) return { status: "integrity_only", signed: false, proof, contractStatus: contract, readOnly: true, mutationAllowed: false };
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "continuity_evidence_signed", {
      evidenceId: evidence.evidenceId, evidenceDigest: evidence.evidenceDigest, contractVersion: contract.expectedVersion, contractStatus: contract.status,
      signatureKeyId: continuityKeyId, outcome: "signed" });
    return { status: "signed", signed: true, evidence, contractStatus: contract, readOnly: true, mutationAllowed: false };
  }
  async function verifySignedContinuityEvidence(ownerId, evidence) {
    assertOwner(ownerId);
    const fail = code => ({ valid: false, signatureValid: false, proofValid: false, status: "invalid", ownerId,
      findings: [code], readOnly: true, mutationAllowed: false });
    if (!evidence || typeof evidence !== "object" || evidence.domain !== SIGNED_EVIDENCE_DOMAIN || evidence.schemaVersion !== 1
      || evidence.ownerId !== ownerId || typeof evidence.evidenceId !== "string" || !Number.isFinite(Date.parse(evidence.issuedAt))
      || evidence.signing?.algorithm !== "Ed25519" || typeof evidence.signing?.keyId !== "string" || !DIGEST.test(evidence.evidenceDigest || "")
      || evidence.continuityProofDigest !== evidence.continuityProof?.proofDigest
      || evidence.contract?.contractId !== CONTRACT_ID || !SUPPORTED_CONTRACTS.has(evidence.contract?.expectedVersion)
      || !["compatible_declared", "compatible_legacy", "incompatible", "not_configured"].includes(evidence.contract?.status)
      || evidence.claims?.contractVersionEvaluated !== evidence.contract.expectedVersion
      || evidence.claims?.providerObservationAuthenticated !== false) return fail("SIGNED_CONTINUITY_EVIDENCE_SHAPE_INVALID");
    const unsigned = clone(evidence); delete unsigned.signature;
    const digestPayload = clone(unsigned); delete digestPayload.evidenceDigest;
    if (sha256(canonical(digestPayload)) !== evidence.evidenceDigest) return fail("SIGNED_CONTINUITY_EVIDENCE_DIGEST_MISMATCH");
    const key = keys.get(evidence.signing.keyId);
    if (!key) return fail("SIGNED_CONTINUITY_EVIDENCE_KEY_UNTRUSTED");
    if (!verifyEd25519(key, unsigned, evidence.signature)) return fail("SIGNED_CONTINUITY_EVIDENCE_SIGNATURE_INVALID");
    const proofResult = keyPolicy.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof(ownerId, evidence.continuityProof);
    if (!proofResult.valid || proofResult.proofDigest !== evidence.continuityProofDigest) return fail("SIGNED_CONTINUITY_EVIDENCE_PROOF_INVALID");
    if (evidence.signing.keyId !== continuityKeyId && !keys.has(evidence.signing.keyId)) return fail("SIGNED_CONTINUITY_EVIDENCE_KEY_UNTRUSTED");
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "continuity_evidence_verified", {
      evidenceId: evidence.evidenceId, evidenceDigest: evidence.evidenceDigest, contractVersion: evidence.contract?.expectedVersion,
      contractStatus: evidence.contract?.status, signatureKeyId: evidence.signing.keyId, outcome: "verified" }).catch(() => {});
    return { valid: true, signatureValid: true, proofValid: true, evidenceDigest: evidence.evidenceDigest,
      evidenceId: evidence.evidenceId, keyId: evidence.signing.keyId, status: proofResult.status,
      continuityEstablished: proofResult.continuityEstablished, current: proofResult.current,
      providerObservationAuthenticated: false, readOnly: true, mutationAllowed: false, findings: [] };
  }
  function runbookActions(contract, anchor, policyAudit, operatorAudit) {
    const actions = [];
    if (["not_configured", "incompatible"].includes(contract.status)) actions.push({ priority: "critical", code: "STOP_TRUST_SENSITIVE_OPERATIONS",
      instruction: "Jangan lakukan rotasi kunci atau rekonsiliasi sampai kontrak provider diverifikasi dan kompatibel." });
    else if (contract.status === "compatible_legacy") actions.push({ priority: "medium", code: "DECLARE_PROVIDER_CONTRACT_VERSION",
      instruction: "Tambahkan deklarasi kontrak provider eksplisit dan rencanakan migrasi teruji sebelum menaikkan versi kontrak." });
    else if (contract.status === "compatible_declared") actions.push({ priority: "high", code: "VERIFY_PROVIDER_BEHAVIORAL_CONFORMANCE",
      instruction: "Jalankan conformance probe pada namespace disposable; metadata versi tidak membuktikan perilaku CAS atau isolasi owner." });
    if (["rollback_detected", "mismatch", "invalid", "local_policy_unhealthy"].includes(anchor.status) || policyAudit.status === "unhealthy") {
      actions.push({ priority: "critical", code: "PRESERVE_AND_ESCALATE_TRUST_EVIDENCE",
        instruction: "Pertahankan snapshot dan log yang ada; jangan enroll ulang atau menimpa anchor; eskalasi ke administrator trust." });
    } else if (["behind_registry", "anchor_pending"].includes(anchor.status)) {
      actions.push({ priority: "high", code: "RECONCILE_VERIFIED_ANCESTOR_ONLY",
        instruction: "Periksa continuity evidence, lalu jalankan rekonsiliasi terkontrol hanya jika anchor terbukti ancestor yang valid." });
    } else if (["missing", "local_policy_missing", "not_configured"].includes(anchor.status)) {
      actions.push({ priority: "high", code: "REVIEW_GENESIS_ENROLLMENT",
        instruction: "Jangan enroll ulang secara otomatis; verifikasi provenance dan otorisasi genesis sebelum membuat anchor baru." });
    }
    if (operatorAudit.status === "unhealthy") actions.push({ priority: "critical", code: "FREEZE_OPERATOR_EVIDENCE_WRITES",
      instruction: "Hentikan penambahan operator evidence dan simpan salinan storage untuk investigasi integritas." });
    else if (operatorAudit.status === "degraded") actions.push({ priority: "high", code: "RESOLVE_PENDING_RECONCILIATION",
      instruction: "Periksa operasi rekonsiliasi yang masih pending dan catat hasilnya tanpa menghapus event lama." });
    if (!actions.length) actions.push({ priority: "normal", code: "CONTINUE_MONITORING",
      instruction: "Lanjutkan monitoring; verifikasi ulang status provider dan anchor sebelum perubahan trust berikutnya." });
    return actions;
  }
  async function exportRecoveryRunbook(ownerId, options = {}) {
    assertOwner(ownerId);
    const contract = await getContractStatus(ownerId);
    const [anchor, policyAudit, operatorAudit] = await Promise.all([
      keyPolicy.getRecoverySloFinalizationKeyPolicyAnchorStatus(ownerId),
      keyPolicy.auditRecoverySloFinalizationKeyPolicy(ownerId),
      anchorOperations.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(ownerId)
    ]);
    let proof = null;
    let signedEvidence = null;
    let continuityEvidence;
    let proofUnavailableCode = null;
    try {
      const proofResult = await anchorOperations.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof(ownerId);
      proof = proofResult.proof;
    } catch (error) {
      proofUnavailableCode = String(error?.code || "CONTINUITY_PROOF_UNAVAILABLE").replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 100);
      if (requireSignedContinuityEvidence) throw new AgenticError("RECOVERY_SLO_SIGNED_CONTINUITY_REQUIRED", "Runbook tidak dapat diekspor tanpa signed continuity evidence", 503);
      continuityEvidence = { mode: "unavailable", status: "evidence_unavailable", findings: [proofUnavailableCode] };
    }
    if (proof) {
      // A configured signer failure must not be downgraded to an unsigned runbook.
      signedEvidence = await buildSignedEvidenceFromProof(ownerId, proof, contract);
      continuityEvidence = signedEvidence ? { mode: "signed", evidence: signedEvidence } : { mode: "integrity_only", proof };
    }
    if (requireSignedContinuityEvidence && !signedEvidence) throw new AgenticError("RECOVERY_SLO_SIGNED_CONTINUITY_REQUIRED", "Runbook tidak dapat diekspor tanpa signed continuity evidence", 503);
    const unsigned = { domain: RUNBOOK_DOMAIN, schemaVersion: 1, runbookId: `recovery-runbook-${randomUUID()}`,
      ownerId, exportedAt: now(), contractStatus: contract, anchorStatus: anchor,
      keyPolicyAudit: { status: policyAudit.status, localStatus: policyAudit.localStatus, revision: policyAudit.revision,
        findings: summarizeFindings(policyAudit.findings || []) },
      operatorEvidenceAudit: { status: operatorAudit.status, eventCount: operatorAudit.eventCount ?? 0,
        revision: operatorAudit.revision ?? null, pendingReconciliations: (operatorAudit.pendingReconciliations || []).slice(0, 50),
        findings: summarizeFindings(operatorAudit.findings || []) },
      continuityEvidence,
      recommendedActions: runbookActions(contract, anchor, policyAudit, operatorAudit),
      safety: { automaticMutationAuthorized: false, privateKeysIncluded: false, accessTokensIncluded: false,
        remoteObservationAuthenticated: false, requiresOperatorReview: true }, readOnly: true, mutationAllowed: false };
    const runbook = { ...unsigned, runbookDigest: sha256(canonical(unsigned)) };
    const maxBytes = Number.isSafeInteger(options.maxBytes) ? Math.max(1024, Math.min(MAX_RUNBOOK_BYTES, options.maxBytes)) : MAX_RUNBOOK_BYTES;
    if (Buffer.byteLength(canonical(runbook), "utf8") > maxBytes) throw new AgenticError("RECOVERY_SLO_RUNBOOK_SIZE_LIMIT", "Recovery runbook melebihi batas ekspor", 413);
    if (signedEvidence) await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "continuity_evidence_signed", {
      evidenceId: signedEvidence.evidenceId, evidenceDigest: signedEvidence.evidenceDigest, contractVersion: contract.expectedVersion,
      contractStatus: contract.status, signatureKeyId: signedEvidence.signing.keyId, outcome: "signed_in_runbook" });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "recovery_runbook_exported", {
      runbookDigest: runbook.runbookDigest, contractVersion: contract.expectedVersion, contractStatus: contract.status,
      evidenceId: signedEvidence?.evidenceId, evidenceDigest: signedEvidence?.evidenceDigest,
      signatureKeyId: signedEvidence?.signing?.keyId, outcome: signedEvidence ? "signed_continuity_included" : continuityEvidence.mode });
    return { status: "exported", runbook, runbookDigest: runbook.runbookDigest, byteLength: Buffer.byteLength(canonical(runbook), "utf8"),
      signedContinuityEvidence: Boolean(signedEvidence), readOnly: true, mutationAllowed: false };
  }
  async function verifyRecoveryRunbook(ownerId, runbook) {
    assertOwner(ownerId);
    const fail = code => ({ valid: false, runbookIntegrityValid: false, continuityEvidenceValid: false,
      ownerId, findings: [code], readOnly: true, mutationAllowed: false });
    if (!runbook || typeof runbook !== "object" || runbook.domain !== RUNBOOK_DOMAIN || runbook.schemaVersion !== 1
      || runbook.ownerId !== ownerId || typeof runbook.runbookId !== "string" || !Number.isFinite(Date.parse(runbook.exportedAt))
      || !DIGEST.test(runbook.runbookDigest || "")) return fail("RECOVERY_RUNBOOK_SHAPE_INVALID");
    const digestInput = clone(runbook); delete digestInput.runbookDigest; delete digestInput.attestation;
    if (sha256(canonical(digestInput)) !== runbook.runbookDigest) return fail("RECOVERY_RUNBOOK_DIGEST_MISMATCH");
    let continuity;
    if (runbook.continuityEvidence?.mode === "signed") {
      continuity = await verifySignedContinuityEvidence(ownerId, runbook.continuityEvidence.evidence);
    } else if (runbook.continuityEvidence?.mode === "integrity_only") {
      const proof = runbook.continuityEvidence.proof;
      const result = keyPolicy.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof(ownerId, proof);
      continuity = { valid: result.valid, status: result.status, continuityEstablished: result.continuityEstablished,
        findings: result.findings || [] };
    } else if (runbook.continuityEvidence?.mode === "unavailable") {
      continuity = { valid: false, status: "evidence_unavailable", continuityEstablished: false,
        findings: Array.isArray(runbook.continuityEvidence.findings) ? runbook.continuityEvidence.findings.slice(0, 10) : [] };
    } else return fail("RECOVERY_RUNBOOK_CONTINUITY_EVIDENCE_MISSING");
    if (!continuity.valid && continuity.status !== "evidence_unavailable") return { ...fail("RECOVERY_RUNBOOK_CONTINUITY_EVIDENCE_INVALID"), continuityEvidence: continuity };
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "recovery_runbook_verified", {
      runbookDigest: runbook.runbookDigest, contractVersion: runbook.contractStatus?.expectedVersion,
      contractStatus: runbook.contractStatus?.status, outcome: continuity.valid ? "verified" : "evidence_unavailable" }).catch(() => {});
    return { valid: true, runbookIntegrityValid: true, continuityEvidenceValid: continuity.valid, runbookDigest: runbook.runbookDigest,
      contractVersion: runbook.contractStatus?.expectedVersion ?? null, providerContractStatus: runbook.contractStatus?.status ?? "unknown",
      anchorStatus: runbook.anchorStatus?.status ?? "unknown", continuityStatus: continuity.status,
      continuityEstablished: continuity.continuityEstablished === true, signedContinuityEvidence: runbook.continuityEvidence.mode === "signed",
      readOnly: true, mutationAllowed: false, findings: continuity.valid ? [] : [{ code: "CONTINUITY_EVIDENCE_UNAVAILABLE", severity: "warning" }] };
  }
  return Object.freeze({ getRecoverySloFinalizationKeyPolicyAnchorContractStatus: getContractStatus,
    getRecoverySloFinalizationKeyPolicyAnchorContractStatusForVersion: (ownerId, version) => getContractStatus(ownerId, version),
    getConfiguredRecoverySloFinalizationKeyPolicyAnchorContractVersion: () => contractVersion,
    exportRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence: createSignedContinuityEvidence,
    verifyRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence: verifySignedContinuityEvidence,
    exportRecoverySloFinalizationAnchorRecoveryRunbook: exportRecoveryRunbook,
    verifyRecoverySloFinalizationAnchorRecoveryRunbook: verifyRecoveryRunbook });
}
