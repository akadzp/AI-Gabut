import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const DOMAIN = "agentic-v4-root-trust-conformance-baseline-attestation";
const REPORT_KIND = "recovery-slo-root-recovery-trust-anchor-conformance-challenge";
const ARTIFACT = "root_trust_conformance_baseline_attestation";
const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item);
  return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
const currentPointerId = ownerId => `recovery-slo-root-trust-baseline-current-${sha256(ownerId).slice(0, 40)}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_ATTESTATION_OWNER_REQUIRED", "Owner baseline attestation wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function toPublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Root-trust baseline public key harus Ed25519");
  return key;
}
function makeKeyMap(input) {
  const entries = input instanceof Map ? [...input] : input && typeof input === "object" ? Object.entries(input) : [];
  const map = new Map();
  for (const [id, value] of entries) {
    if (!KEY_ID.test(String(id))) throw new TypeError("Root-trust baseline key ID tidak valid");
    map.set(String(id), toPublicKey(value));
  }
  return map;
}
function liveProviderSnapshot(provider) {
  const identity = typeof provider?.providerIdentity === "string" && provider.providerIdentity.trim()
    ? sha256(provider.providerIdentity.trim()) : null;
  const raw = provider?.contractInfo;
  const contract = raw && typeof raw === "object" ? { contractId: String(raw.contractId || "").slice(0, 100),
    version: String(raw.version || "").slice(0, 40), schemaVersion: Number.isSafeInteger(raw.schemaVersion) ? raw.schemaVersion : null,
    ownerScope: String(raw.ownerScope || "").slice(0, 80), casSemantics: String(raw.casSemantics || "").slice(0, 100),
    capabilities: Array.isArray(raw.capabilities) ? raw.capabilities.slice(0, 30).map(item => String(item).slice(0, 80)) : [] } : null;
  return { providerIdentityFingerprint: identity, providerContractDigest: contract ? sha256(canonical(contract)) : null, contract };
}

export function createRecoverySloRootTrustConformanceBaselineAttestationService({ store, provider = null, retainedEvidenceService,
  signer = null, keyId = null, publicKeys = null, required = false, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.listEvidence || !retainedEvidenceService?.retainRecoverySloAnchorEvidence
    || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence || typeof clock !== "function") {
    throw new TypeError("Root-trust baseline attestation membutuhkan store, retained-evidence service, dan clock");
  }
  const keys = makeKeyMap(publicKeys);
  if (keyId != null && !KEY_ID.test(keyId)) throw new TypeError("Root-trust baseline signing key ID tidak valid");
  if (required && (!signer || !keyId || !keys.has(keyId))) throw new TypeError("Root-trust baseline attestation wajib memiliki signer dan trusted public key");
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_ATTESTATION_CLOCK_INVALID", "Clock baseline attestation tidak valid", 500);
    return new Date(time).toISOString();
  }
  function validateEnvelope(ownerId, value) {
    const findings = [];
    if (!value || value.domain !== DOMAIN || value.schemaVersion !== 1 || value.ownerId !== ownerId
      || typeof value.attestationId !== "string" || !Number.isFinite(Date.parse(value.issuedAt)) || !validReason(value.reason)
      || !value.baseline || value.baseline.ownerId !== ownerId || value.baseline.providerDomain !== "root_recovery_trust"
      || value.baseline.conformanceStatus !== "conformant" || !DIGEST.test(value.baseline.challengeDigest || "")
      || !DIGEST.test(value.baseline.reportDigest || "") || !DIGEST.test(value.baseline.providerIdentityFingerprint || "")
      || !DIGEST.test(value.baseline.providerContractDigest || "") || !value.signing || value.signing.algorithm !== "Ed25519"
      || !KEY_ID.test(value.signing.keyId || "") || !DIGEST.test(value.attestationDigest || "") || !SIGNATURE.test(value.signature || "")) {
      findings.push({ code: "ROOT_TRUST_BASELINE_ATTESTATION_SHAPE_INVALID" });
    }
    const unsigned = clean(value || {}); delete unsigned.attestationDigest; delete unsigned.signature;
    const digestValid = Boolean(value?.attestationDigest && sha256(canonical(unsigned)) === value.attestationDigest);
    if (!digestValid) findings.push({ code: "ROOT_TRUST_BASELINE_ATTESTATION_DIGEST_INVALID" });
    const key = keys.get(value?.signing?.keyId);
    let signatureValid = false;
    if (!key) findings.push({ code: "ROOT_TRUST_BASELINE_ATTESTATION_KEY_UNTRUSTED" });
    else {
      try { signatureValid = verifySignature(null, Buffer.from(canonical({ ...unsigned, attestationDigest: value.attestationDigest }), "utf8"), key, Buffer.from(value.signature || "", "base64url")); }
      catch { signatureValid = false; }
      if (!signatureValid) findings.push({ code: "ROOT_TRUST_BASELINE_ATTESTATION_SIGNATURE_INVALID" });
    }
    return { valid: findings.length === 0 && digestValid && signatureValid, signatureValid, findings };
  }
  async function loadReport(ownerId, challengeId) {
    const challenge = await store.getEvidence(ownerId, challengeId);
    const unsigned = clean(challenge?.report || {}); delete unsigned.reportDigest;
    const reportDigestValid = Boolean(challenge?.report && challenge.report.reportDigest === challenge.reportDigest
      && sha256(canonical(unsigned)) === challenge.reportDigest);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== REPORT_KIND || challenge.status !== "completed"
      || challenge.digest !== digestRecord(challenge) || !reportDigestValid || challenge.report?.ownerId !== ownerId
      || challenge.report?.providerDomain !== "root_recovery_trust" || challenge.report?.conformant !== true
      || challenge.report?.status !== "conformant") {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_SOURCE_REPORT_INVALID", "Baseline hanya dapat ditandatangani dari laporan root-trust conformance valid dan conformant", 409);
    }
    return challenge;
  }
  async function attest(ownerId, { challengeId, reason } = {}) {
    assertOwner(ownerId);
    if (!signer || !keyId || !keys.has(keyId)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_SIGNER_NOT_CONFIGURED", "Signer dan trusted public key baseline belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_REASON_INVALID", "Alasan baseline wajib 12–240 karakter", 400);
    const challenge = await loadReport(ownerId, challengeId);
    const live = liveProviderSnapshot(provider);
    const contractDigest = challenge.report.providerContract ? sha256(canonical(challenge.report.providerContract)) : null;
    if (!live.providerIdentityFingerprint || live.providerIdentityFingerprint !== challenge.report.providerIdentityFingerprint
      || !contractDigest || live.providerContractDigest !== contractDigest) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_PROVIDER_CHANGED", "Identitas atau kontrak provider berubah sejak conformance; jalankan pengujian baru", 409);
    }
    const issuedAt = now();
    const unsigned = { domain: DOMAIN, schemaVersion: 1, attestationId: `root-trust-conformance-baseline-${ownerHash(ownerId)}-${randomUUID()}`,
      ownerId, issuedAt, reason: reason.trim(), baseline: { ownerId, providerDomain: "root_recovery_trust", conformanceStatus: "conformant",
        challengeId: challenge.id, challengeDigest: challenge.digest, reportDigest: challenge.reportDigest,
        providerIdentityFingerprint: live.providerIdentityFingerprint, providerContractDigest: live.providerContractDigest,
        acceptedAt: challenge.completedAt, historyNotProven: true }, signing: { algorithm: "Ed25519", keyId } };
    const payload = { ...unsigned, attestationDigest: sha256(canonical(unsigned)) };
    let signed;
    try { signed = await signer(structuredClone(payload)); }
    catch { throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_SIGNER_FAILED", "External signer baseline gagal", 502); }
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== keyId) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_SIGNER_KEY_MISMATCH", "Signer baseline mengembalikan key ID berbeda", 502);
    }
    const signature = typeof signed === "string" ? signed : signed?.signature;
    const attestation = { ...payload, signature };
    const checked = validateEnvelope(ownerId, attestation);
    if (!checked.valid) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BASELINE_SIGNATURE_INVALID", "Signature baseline tidak valid", 502, { findings: checked.findings });
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: ARTIFACT,
      sourceId: attestation.attestationDigest, payload: attestation });
    return { status: "signed", attestation, retention, historyNotProven: true, readOnly: false, mutationAllowed: false };
  }
  async function verify(ownerId, attestation) {
    assertOwner(ownerId);
    const envelope = validateEnvelope(ownerId, attestation);
    const records = (await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true })).items;
    const retained = records.some(item => item.artifactType === ARTIFACT && item.sourceId === attestation?.attestationDigest
      && item.status === "retained" && item.payload?.attestationId === attestation?.attestationId
      && item.payload?.attestationDigest === attestation?.attestationDigest
      && item.payloadDigest === sha256(canonical(item.payload)));
    if (!retained) envelope.findings.push({ code: "ROOT_TRUST_BASELINE_ATTESTATION_NOT_RETAINED" });
    const live = liveProviderSnapshot(provider);
    const providerMatchesCurrent = Boolean(live.providerIdentityFingerprint && live.providerIdentityFingerprint === attestation?.baseline?.providerIdentityFingerprint
      && live.providerContractDigest && live.providerContractDigest === attestation?.baseline?.providerContractDigest);
    if (!providerMatchesCurrent) envelope.findings.push({ code: "ROOT_TRUST_BASELINE_PROVIDER_DRIFT" });
    const pointer = await store.getEvidence(ownerId, currentPointerId(ownerId));
    let currentPointerValid = true, selectedAsCurrentBaseline = true;
    if (pointer) {
      currentPointerValid = pointer.ownerId === ownerId && pointer.id === currentPointerId(ownerId)
        && pointer.kind === "recovery-slo-root-trust-conformance-baseline-current" && Number.isSafeInteger(pointer.revision) && pointer.revision >= 1
        && DIGEST.test(pointer.activeAttestationDigest || "") && DIGEST.test(pointer.digest || "") && pointer.digest === digestRecord(pointer);
      selectedAsCurrentBaseline = currentPointerValid && pointer.activeAttestationDigest === attestation?.attestationDigest;
      if (!currentPointerValid) envelope.findings.push({ code: "ROOT_TRUST_BASELINE_CURRENT_POINTER_INVALID" });
      else if (!selectedAsCurrentBaseline) envelope.findings.push({ code: "ROOT_TRUST_BASELINE_ATTESTATION_SUPERSEDED" });
    }
    const historicallyValid = envelope.valid && retained;
    const usableAsCurrentBaseline = historicallyValid && providerMatchesCurrent && currentPointerValid && selectedAsCurrentBaseline;
    return { valid: usableAsCurrentBaseline, historicallyValid, signatureValid: envelope.signatureValid, retained,
      providerMatchesCurrent, currentPointerValid, selectedAsCurrentBaseline, usableAsCurrentBaseline, historyNotProven: true,
      findings: envelope.findings, readOnly: true, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [listed, overall] = await Promise.all([
      retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true }),
      retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId)
    ]);
    const records = listed.items.filter(item => item.artifactType === ARTIFACT);
    const findings = [];
    let retained = 0, tombstones = 0;
    for (const record of records) {
      if (record.status === "tombstone") { tombstones++; continue; }
      retained++;
      const envelope = validateEnvelope(ownerId, record.payload);
      if (record.status !== "retained" || !envelope.valid || record.sourceId !== record.payload?.attestationDigest
        || record.payloadDigest !== sha256(canonical(record.payload))) findings.push({ code: "ROOT_TRUST_BASELINE_ATTESTATION_RECORD_INVALID", evidenceId: record.id });
    }
    if (overall.status !== "healthy") findings.push({ code: "ROOT_TRUST_BASELINE_RETAINED_EVIDENCE_UNHEALTHY" });
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, retained, tombstones, findings,
      signingConfigured: Boolean(signer && keyId && keys.has(keyId)), readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ attestRecoverySloRootTrustConformanceBaseline: attest,
    verifyRecoverySloRootTrustConformanceBaselineAttestation: verify,
    auditRecoverySloRootTrustConformanceBaselineAttestations: audit,
    configured: Boolean(signer && keyId && keys.has(keyId)), required });
}
