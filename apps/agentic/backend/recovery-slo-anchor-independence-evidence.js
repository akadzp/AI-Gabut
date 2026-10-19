import { createHash, createPublicKey, verify as verifySignature, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const RECEIPT_DOMAIN = "agentic-v4-retention-checkpoint-continuity-receipt";
const RETENTION_KIND = "recovery-slo-anchor-evidence-retention-record";
const CONFORMANCE_CHALLENGE_KIND = "recovery-slo-recovery-journal-anchor-conformance-challenge";
const RETENTION_PREFIX = "recovery-slo-anchor-evidence-retention-";
const RECEIPT_PREFIX = "recovery-slo-retention-checkpoint-continuity-receipt-";
const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const MAX_ACTIVE = 500;
const MAX_TOTAL = 2000;
const MAX_PRUNE = 100;
const MAX_LIST = 200;
const MAX_RETRIES = 4;

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clone = value => value == null ? value : structuredClone(value);
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = clean(item);
  return result;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const digestWithout = (value, field) => { const copy = clone(value); delete copy[field]; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
const retainedId = (ownerId, sourceId) => `${RETENTION_PREFIX}${ownerHash(ownerId)}-${sha256(`${ownerId}:${sourceId}`).slice(0, 40)}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
  }
}
function parsePublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Public key continuity receipt harus Ed25519");
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
function normalizeIdentity(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const raw = value.trim();
  try {
    const url = new URL(raw);
    url.username = ""; url.password = ""; url.search = ""; url.hash = "";
    return url.toString().replace(/\/+$/, "").toLowerCase();
  } catch { return raw.replace(/\s+/g, " ").toLowerCase(); }
}
function providerIdentities(provider, endpoint) {
  const fields = [
    ["configured_endpoint", endpoint],
    ["provider_identity", provider?.providerIdentity],
    ["backend_identity", provider?.backendIdentity],
    ["backend_id", provider?.backendId],
    ["store_id", provider?.storeId],
    ["storage_id", provider?.storageId],
    ["resource_id", provider?.resourceId],
    ["namespace_id", provider?.namespaceId],
    ["namespace", provider?.namespace],
    ["base_url", provider?.baseUrl],
    ["contract_backend_id", provider?.contractInfo?.backendId],
    ["contract_store_id", provider?.contractInfo?.storeId],
    ["contract_namespace_id", provider?.contractInfo?.namespaceId]
  ];
  const seen = new Set();
  const identities = [];
  for (const [source, value] of fields) {
    const normalized = normalizeIdentity(value);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    identities.push({ source, normalized, fingerprint: sha256(normalized) });
  }
  return identities;
}

export function createRecoverySloAnchorIndependenceEvidenceService({
  store, clock = () => new Date().toISOString(), retentionDays = 90,
  continuitySigner = null, continuityKeyId = null, continuityPublicKeys = null,
  requireSignedContinuityReceipt = false, getRetentionCheckpointStatus = null, anchorDomains = [],
  retainedEvidenceChainService = null, independenceSigner = null, independenceKeyId = null,
  independencePublicKeys = null, requireSignedIndependenceAttestation = false
} = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function") {
    throw new TypeError("Anchor evidence service membutuhkan store dan clock yang valid");
  }
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    throw new TypeError("Retensi conformance evidence harus 1–3650 hari");
  }
  if (requireSignedContinuityReceipt && (!continuitySigner || !continuityKeyId || !continuityPublicKeys)) {
    throw new TypeError("Signed retention continuity receipt diwajibkan tetapi signer dan trusted public key belum lengkap");
  }
  if ((continuitySigner || continuityKeyId || continuityPublicKeys) && (!continuitySigner || !continuityKeyId || !continuityPublicKeys)) {
    throw new TypeError("Konfigurasi retention continuity signer harus mencakup signer, key ID, dan trusted public keys");
  }
  if (continuityKeyId && !KEY_ID.test(continuityKeyId)) throw new TypeError("Retention continuity key ID tidak valid");
  const keys = new Map();
  if (continuityPublicKeys instanceof Map) {
    for (const [id, value] of continuityPublicKeys) {
      if (!KEY_ID.test(String(id))) throw new TypeError("Retention continuity public key ID tidak valid");
      keys.set(String(id), parsePublicKey(value));
    }
  } else if (continuityPublicKeys && typeof continuityPublicKeys === "object") {
    for (const [id, value] of Object.entries(continuityPublicKeys)) {
      if (!KEY_ID.test(id)) throw new TypeError("Retention continuity public key ID tidak valid");
      keys.set(id, parsePublicKey(value));
    }
  }
  if (continuitySigner && (!keys.has(continuityKeyId))) throw new TypeError("Retention continuity signing key harus ada di trusted public key registry");
  if (requireSignedIndependenceAttestation && (!independenceSigner || !independenceKeyId || !independencePublicKeys)) {
    throw new TypeError("Signed trust-domain independence attestation diwajibkan tetapi signer dan trusted public key belum lengkap");
  }
  if ((independenceSigner || independenceKeyId || independencePublicKeys) && (!independenceSigner || !independenceKeyId || !independencePublicKeys)) {
    throw new TypeError("Konfigurasi independence attestation harus mencakup signer, key ID, dan trusted public keys");
  }
  if (independenceKeyId && !KEY_ID.test(independenceKeyId)) throw new TypeError("Independence attestation key ID tidak valid");
  const independenceKeys = new Map();
  if (independencePublicKeys instanceof Map) {
    for (const [id, value] of independencePublicKeys) {
      if (!KEY_ID.test(String(id))) throw new TypeError("Independence attestation public key ID tidak valid");
      independenceKeys.set(String(id), parsePublicKey(value));
    }
  } else if (independencePublicKeys && typeof independencePublicKeys === "object") {
    for (const [id, value] of Object.entries(independencePublicKeys)) {
      if (!KEY_ID.test(id)) throw new TypeError("Independence attestation public key ID tidak valid");
      independenceKeys.set(id, parsePublicKey(value));
    }
  }
  if (independenceSigner && !independenceKeys.has(independenceKeyId)) throw new TypeError("Independence attestation signing key harus ada di trusted public key registry");
  const inFlight = new Map();
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_CLOCK_INVALID", "Clock anchor evidence tidak valid", 500);
    return new Date(time).toISOString();
  }
  function withOwnerLock(ownerId, operation) {
    const previous = inFlight.get(ownerId) || Promise.resolve();
    const next = previous.catch(() => {}).then(operation);
    inFlight.set(ownerId, next);
    return next.finally(() => { if (inFlight.get(ownerId) === next) inFlight.delete(ownerId); });
  }
  function validateConformanceChallenge(ownerId, challenge) {
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CONFORMANCE_CHALLENGE_KIND
      || challenge.status !== "completed" || !challenge.report || !DIGEST.test(challenge.digest || "")
      || !DIGEST.test(challenge.reportDigest || "") || digestRecord(challenge) !== challenge.digest) return false;
    const report = clone(challenge.report);
    const declared = report.reportDigest;
    delete report.reportDigest;
    return declared === challenge.reportDigest && sha256(canonical(report)) === challenge.reportDigest
      && challenge.report.conformant === (challenge.report.checksFailed === 0)
      && challenge.report.reportDigest === challenge.reportDigest;
  }
  async function activeRecords(ownerId) {
    return (await store.listEvidence(ownerId)).filter(record => record?.kind === RETENTION_KIND);
  }
  function validateRetainedRecord(ownerId, record) {
    if (!record || record.ownerId !== ownerId || record.kind !== RETENTION_KIND || record.schemaVersion !== 1
      || !["provider_conformance", "root_recovery_trust_anchor_conformance", "retention_continuity_receipt", "trust_domain_independence_attestation", "provider_identity_drift_event", "retained_evidence_chain_recovery_attestation", "retention_reconciliation_attestation", "provider_conformance_drift_event", "root_trust_conformance_baseline_attestation",
        "retention_reconciliation_decision_gate_audit", "provider_conformance_drift_chain_checkpoint_receipt", "root_trust_conformance_baseline_lifecycle", "retention_decision_gate_anchor_conformance", "retention_decision_gate_anchor_recovery_attestation", "root_trust_baseline_checkpoint_continuity_proof", "root_trust_baseline_continuity_proof_revocation", "retention_freshness_policy_approval_anchor_conformance"].includes(record.artifactType)
      || !Number.isFinite(Date.parse(record.capturedAt)) || !Number.isFinite(Date.parse(record.expiresAt))
      || !Number.isSafeInteger(record.retentionDays) || record.retentionDays < 1 || record.retentionDays > 3650
      || !DIGEST.test(record.payloadDigest || "") || !DIGEST.test(record.digest || "")
      || !["retained", "tombstone"].includes(record.status) || digestRecord(record) !== record.digest) return false;
    if (record.status === "retained") return record.payload != null && sha256(canonical(record.payload)) === record.payloadDigest && record.tombstone == null;
    return record.payload == null && record.tombstone?.payloadDigest === record.payloadDigest
      && record.tombstone?.reason === "RETENTION_PERIOD_ELAPSED" && Number.isFinite(Date.parse(record.tombstone.expiredAt));
  }
  async function retain(ownerId, { artifactType, sourceId, payload, payloadDigest, retentionDays: days = retentionDays } = {}) {
    assertOwner(ownerId);
    if (!new Set(["provider_conformance", "root_recovery_trust_anchor_conformance", "retention_continuity_receipt", "trust_domain_independence_attestation", "provider_identity_drift_event", "retained_evidence_chain_recovery_attestation", "retention_reconciliation_attestation", "provider_conformance_drift_event", "root_trust_conformance_baseline_attestation",
      "retention_reconciliation_decision_gate_audit", "provider_conformance_drift_chain_checkpoint_receipt", "root_trust_conformance_baseline_lifecycle", "retention_decision_gate_anchor_conformance", "retention_decision_gate_anchor_recovery_attestation", "root_trust_baseline_checkpoint_continuity_proof", "root_trust_baseline_continuity_proof_revocation", "retention_freshness_policy_approval_anchor_conformance"]).has(artifactType)
      || typeof sourceId !== "string" || !sourceId || sourceId.length > 240 || payload == null
      || !Number.isSafeInteger(days) || days < 1 || days > 3650) {
      throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_INPUT_INVALID", "Input retention evidence tidak valid", 400);
    }
    const canonicalPayload = clone(payload);
    const computedPayloadDigest = sha256(canonical(canonicalPayload));
    if (payloadDigest && payloadDigest !== computedPayloadDigest) throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_PAYLOAD_DIGEST_MISMATCH", "Digest payload retention evidence tidak cocok", 409);
    const id = retainedId(ownerId, `${artifactType}:${sourceId}`);
    return withOwnerLock(ownerId, async () => {
      const existing = await store.getEvidence(ownerId, id);
      if (existing) {
        if (existing.payloadDigest === computedPayloadDigest && existing.sourceId === sourceId && existing.artifactType === artifactType) {
          if (!validateRetainedRecord(ownerId, existing)) throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_CORRUPT", "Retained evidence yang sudah ada tidak valid", 409);
          if (retainedEvidenceChainService) {
            if (existing.status === "retained") await retainedEvidenceChainService.recordRetainedEvidence(ownerId, existing);
            else await retainedEvidenceChainService.recordPrunedEvidence(ownerId, existing);
          }
          return { id, status: existing.status, payloadDigest: existing.payloadDigest, expiresAt: existing.expiresAt, idempotent: true };
        }
        throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_ID_CONFLICT", "ID retained evidence sudah terikat pada payload berbeda", 409);
      }
      const all = await activeRecords(ownerId);
      if (all.length >= MAX_TOTAL) throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_CAPACITY", "Kapasitas total retained anchor evidence tercapai", 409);
      if (all.filter(item => item.status === "retained").length >= MAX_ACTIVE) throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_ACTIVE_CAPACITY", "Kapasitas retained anchor evidence aktif tercapai", 409);
      const capturedAt = now();
      const unsigned = { id, ownerId, kind: RETENTION_KIND, schemaVersion: 1, artifactType, sourceId,
        capturedAt, expiresAt: new Date(Date.parse(capturedAt) + days * 86400_000).toISOString(),
        retentionDays: days, status: "retained", payloadDigest: computedPayloadDigest, payload: canonicalPayload, tombstone: null };
      const record = { ...unsigned, digest: digestRecord(unsigned) };
      try { await store.putEvidence(ownerId, record, { overwrite: false }); }
      catch (error) {
        const winner = await store.getEvidence(ownerId, id);
        if (winner && winner.payloadDigest === computedPayloadDigest && winner.sourceId === sourceId
          && winner.artifactType === artifactType && validateRetainedRecord(ownerId, winner)) {
          if (retainedEvidenceChainService) await retainedEvidenceChainService.recordRetainedEvidence(ownerId, winner);
          return { id, status: winner.status, payloadDigest: winner.payloadDigest, expiresAt: winner.expiresAt, idempotent: true };
        }
        throw error;
      }
      const saved = await store.getEvidence(ownerId, id);
      if (!validateRetainedRecord(ownerId, saved) || saved.digest !== record.digest) {
        throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_WRITE_FAILED", "Retained anchor evidence gagal diverifikasi setelah penyimpanan", 409);
      }
      if (retainedEvidenceChainService) await retainedEvidenceChainService.recordRetainedEvidence(ownerId, saved);
      return { id, status: saved.status, payloadDigest: saved.payloadDigest, expiresAt: saved.expiresAt, idempotent: false };
    });
  }
  async function retainRecoverySloRecoveryJournalAnchorConformanceEvidence(ownerId, challenge) {
    assertOwner(ownerId);
    if (!validateConformanceChallenge(ownerId, challenge)) {
      throw new AgenticError("RECOVERY_SLO_CONFORMANCE_EVIDENCE_INVALID", "Conformance report tidak lengkap atau digest-nya tidak valid", 409);
    }
    return retain(ownerId, { artifactType: "provider_conformance", sourceId: challenge.id,
      payload: { schemaVersion: 1, ownerId, challengeId: challenge.id, challengeDigest: challenge.digest,
        reportDigest: challenge.reportDigest, conformanceStatus: challenge.report.conformant ? "conformant" : "nonconformant",
        providerDomain: "recovery_journal", completedAt: challenge.completedAt, report: challenge.report },
      retentionDays });
  }
  async function retainRecoverySloProviderIdentityBaselineConformanceEvidence(ownerId, challenge) {
    assertOwner(ownerId);
    const report = challenge?.report;
    const reportCopy = report && clone(report);
    if (reportCopy) delete reportCopy.reportDigest;
    const valid = challenge?.ownerId === ownerId
      && challenge?.kind === "recovery-slo-provider-identity-baseline-anchor-conformance-challenge"
      && challenge?.status === "completed" && DIGEST.test(challenge.digest || "")
      && challenge.digest === digestRecord(challenge) && DIGEST.test(challenge.reportDigest || "")
      && report?.reportDigest === challenge.reportDigest && sha256(canonical(reportCopy)) === challenge.reportDigest
      && report?.ownerId === ownerId && report?.challengeId === challenge.id
      && report?.conformant === (Array.isArray(report?.findings) && report.findings.length === 0
        && Array.isArray(report?.checks) && report.checks.every(item => item?.passed === true));
    if (!valid) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_EVIDENCE_INVALID", "Provider-identity conformance report tidak valid", 409);
    return retain(ownerId, { artifactType: "provider_conformance", sourceId: challenge.id,
      payload: { schemaVersion: 1, ownerId, challengeId: challenge.id, challengeDigest: challenge.digest,
        reportDigest: challenge.reportDigest, conformanceStatus: challenge.report.conformant ? "conformant" : "nonconformant",
        providerDomain: "provider_identity_baseline", completedAt: challenge.completedAt, report: challenge.report }, retentionDays });
  }
  async function createRetentionCheckpointContinuityReceipt(ownerId) {
    assertOwner(ownerId);
    if (!continuitySigner || !continuityKeyId || !keys.has(continuityKeyId)) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_CONTINUITY_SIGNER_NOT_CONFIGURED", "External signer dan trusted key untuk retention continuity receipt belum dikonfigurasi", 503);
    }
    if (typeof getRetentionCheckpointStatus !== "function") throw new AgenticError("RECOVERY_SLO_RETENTION_CONTINUITY_STATUS_UNAVAILABLE", "Pemeriksaan retention checkpoint tidak tersedia", 503);
    const status = await getRetentionCheckpointStatus(ownerId);
    if (status?.status !== "anchored" || !DIGEST.test(status.checkpointDigest || "") || !DIGEST.test(status.anchorDigest || "")
      || !Number.isSafeInteger(status.anchorSequence) || status.anchorSequence < 1 || !Number.isSafeInteger(status.revision) || status.revision < 1) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_CONTINUITY_NOT_ESTABLISHED", "Receipt hanya dapat dibuat ketika retention checkpoint berstatus anchored dan digest valid", 409,
        { status: status?.status || "unknown", finding: status?.finding || null });
    }
    const issuedAt = now();
    const unsigned = { domain: RECEIPT_DOMAIN, schemaVersion: 1,
      receiptId: `${RECEIPT_PREFIX}${randomUUID()}`, ownerId, issuedAt,
      checkpoint: { revision: status.revision, checkpointDigest: status.checkpointDigest,
        anchorDigest: status.anchorDigest, anchorSequence: status.anchorSequence,
        retentionDays: Number.isSafeInteger(status.retentionDays) ? status.retentionDays : null,
        statusAtIssuance: status.status, historyNotProven: status.historyNotProven === true },
      signing: { algorithm: "Ed25519", keyId: continuityKeyId },
      claims: { digestBound: true, externalAnchorObserved: true, anchorCurrentAtIssuance: true,
        historicalCompletenessProven: status.historyNotProven !== true },
      retention: { retentionDays, expiresAt: new Date(Date.parse(issuedAt) + retentionDays * 86400_000).toISOString() } };
    unsigned.receiptDigest = sha256(canonical(unsigned));
    let signed;
    try { signed = await continuitySigner(clone(unsigned)); }
    catch { throw new AgenticError("RECOVERY_SLO_RETENTION_CONTINUITY_SIGNER_FAILED", "External signer retention continuity receipt gagal", 502); }
    const signature = typeof signed === "string" ? signed : signed?.signature;
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== continuityKeyId) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_CONTINUITY_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID yang berbeda", 502);
    }
    if (!verifyEd25519(keys.get(continuityKeyId), unsigned, signature)) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_CONTINUITY_SIGNATURE_INVALID", "Signature receipt tidak cocok dengan trusted public key", 502);
    }
    const receipt = { ...unsigned, signature };
    const retained = await retain(ownerId, { artifactType: "retention_continuity_receipt", sourceId: receipt.receiptId,
      payload: receipt, payloadDigest: sha256(canonical(receipt)) });
    return { status: "signed", signed: true, receipt, retention: retained, readOnly: true, mutationAllowed: false };
  }
  async function verifyRetentionCheckpointContinuityReceipt(ownerId, receipt) {
    assertOwner(ownerId);
    const fail = code => ({ valid: false, signatureValid: false, digestValid: false, current: false, status: "invalid",
      ownerId, findings: [code], readOnly: true, mutationAllowed: false });
    if (!receipt || typeof receipt !== "object" || receipt.domain !== RECEIPT_DOMAIN || receipt.schemaVersion !== 1
      || receipt.ownerId !== ownerId || typeof receipt.receiptId !== "string" || !Number.isFinite(Date.parse(receipt.issuedAt))
      || receipt.signing?.algorithm !== "Ed25519" || !KEY_ID.test(receipt.signing?.keyId || "")
      || !DIGEST.test(receipt.receiptDigest || "") || !DIGEST.test(receipt.checkpoint?.checkpointDigest || "")
      || !DIGEST.test(receipt.checkpoint?.anchorDigest || "") || !Number.isSafeInteger(receipt.checkpoint?.revision)
      || !Number.isSafeInteger(receipt.checkpoint?.anchorSequence) || receipt.checkpoint.anchorSequence < 1
      || !Number.isSafeInteger(receipt.checkpoint?.retentionDays) || receipt.checkpoint.retentionDays < 1 || receipt.checkpoint.retentionDays > 3650
      || receipt.checkpoint?.statusAtIssuance !== "anchored" || typeof receipt.checkpoint?.historyNotProven !== "boolean"
      || receipt.claims?.historicalCompletenessProven !== (receipt.checkpoint.historyNotProven !== true)
      || receipt.claims?.anchorCurrentAtIssuance !== true || receipt.claims?.digestBound !== true || receipt.claims?.externalAnchorObserved !== true
      || !Number.isFinite(Date.parse(receipt.retention?.expiresAt)) || !Number.isSafeInteger(receipt.retention?.retentionDays)) {
      return fail("RETENTION_CONTINUITY_RECEIPT_SHAPE_INVALID");
    }
    const payload = clone(receipt); delete payload.signature;
    if (digestWithout(payload, "receiptDigest") !== receipt.receiptDigest) return fail("RETENTION_CONTINUITY_RECEIPT_DIGEST_MISMATCH");
    const key = keys.get(receipt.signing.keyId);
    if (!key) return fail("RETENTION_CONTINUITY_RECEIPT_KEY_UNTRUSTED");
    if (!verifyEd25519(key, payload, receipt.signature)) return fail("RETENTION_CONTINUITY_RECEIPT_SIGNATURE_INVALID");
    let current = false;
    let currentStatus = "unavailable";
    if (typeof getRetentionCheckpointStatus === "function") {
      try {
        const status = await getRetentionCheckpointStatus(ownerId);
        currentStatus = status?.status || "unknown";
        current = status?.status === "anchored" && status.checkpointDigest === receipt.checkpoint.checkpointDigest
          && status.anchorDigest === receipt.checkpoint.anchorDigest && status.anchorSequence === receipt.checkpoint.anchorSequence;
      } catch { currentStatus = "unavailable"; }
    }
    return { valid: true, signatureValid: true, digestValid: true, current, currentStatus,
      receiptId: receipt.receiptId, receiptDigest: receipt.receiptDigest, keyId: receipt.signing.keyId,
      historicalCompletenessProven: receipt.claims.historicalCompletenessProven === true,
      status: current ? "current" : "historical_or_stale", readOnly: true, mutationAllowed: false, findings: [] };
  }
  function verifyAnchorTrustDomainIndependenceAttestation(ownerId, attestation) {
    assertOwner(ownerId);
    const fail = code => ({ valid: false, signatureValid: false, digestValid: false, ownerId, findings: [code], readOnly: true, mutationAllowed: false });
    if (!attestation || typeof attestation !== "object" || attestation.domain !== "agentic-v4-anchor-trust-domain-independence-attestation"
      || attestation.schemaVersion !== 1 || attestation.ownerId !== ownerId || typeof attestation.attestationId !== "string"
      || !Number.isFinite(Date.parse(attestation.issuedAt)) || attestation.signing?.algorithm !== "Ed25519"
      || !KEY_ID.test(attestation.signing?.keyId || "") || !DIGEST.test(attestation.attestationDigest || "")
      || !attestation.report || attestation.report.ownerId !== ownerId || !DIGEST.test(attestation.reportDigest || "")
      || attestation.report.reportDigest !== attestation.reportDigest
      || digestWithout(attestation.report, "reportDigest") !== attestation.reportDigest
      || !Number.isFinite(Date.parse(attestation.retention?.expiresAt))
      || !Number.isSafeInteger(attestation.retention?.retentionDays) || attestation.retention.retentionDays < 1 || attestation.retention.retentionDays > 3650
      || attestation.claims?.reportDigestBound !== true || attestation.claims?.identityAuditSigned !== true
      || attestation.claims?.independenceIsNotCryptographicallyProven !== true || attestation.claims?.approvalGranted !== false) {
      return fail("ANCHOR_INDEPENDENCE_ATTESTATION_SHAPE_INVALID");
    }
    const payload = clone(attestation); delete payload.signature;
    if (digestWithout(payload, "attestationDigest") !== attestation.attestationDigest) return fail("ANCHOR_INDEPENDENCE_ATTESTATION_DIGEST_MISMATCH");
    const key = independenceKeys.get(attestation.signing.keyId);
    if (!key) return fail("ANCHOR_INDEPENDENCE_ATTESTATION_KEY_UNTRUSTED");
    if (!verifyEd25519(key, payload, attestation.signature)) return fail("ANCHOR_INDEPENDENCE_ATTESTATION_SIGNATURE_INVALID");
    return { valid: true, signatureValid: true, digestValid: true, ownerId, attestationId: attestation.attestationId,
      attestationDigest: attestation.attestationDigest, reportDigest: attestation.reportDigest,
      reportStatus: attestation.report.status, keyId: attestation.signing.keyId,
      signedReportIsApproval: false, readOnly: true, mutationAllowed: false, findings: [] };
  }
  async function attestAnchorTrustDomainIndependence(ownerId) {
    assertOwner(ownerId);
    if (!independenceSigner || !independenceKeyId || !independenceKeys.has(independenceKeyId)) {
      throw new AgenticError("RECOVERY_SLO_INDEPENDENCE_ATTESTATION_SIGNER_NOT_CONFIGURED", "External signer dan trusted key untuk independence attestation belum dikonfigurasi", 503);
    }
    const report = await auditCrossDomainAnchorIndependence(ownerId);
    if (!DIGEST.test(report.reportDigest || "") || digestWithout(report, "reportDigest") !== report.reportDigest) {
      throw new AgenticError("RECOVERY_SLO_INDEPENDENCE_REPORT_INVALID", "Laporan independensi gagal validasi digest", 409);
    }
    const issuedAt = now();
    const unsignedBase = { domain: "agentic-v4-anchor-trust-domain-independence-attestation", schemaVersion: 1,
      attestationId: `recovery-slo-anchor-independence-attestation-${randomUUID()}`, ownerId, issuedAt,
      reportDigest: report.reportDigest, report, signing: { algorithm: "Ed25519", keyId: independenceKeyId },
      retention: { retentionDays, expiresAt: new Date(Date.parse(issuedAt) + retentionDays * 86400_000).toISOString() },
      claims: { reportDigestBound: true, identityAuditSigned: true, independenceIsNotCryptographicallyProven: true, approvalGranted: false } };
    const payload = { ...unsignedBase, attestationDigest: sha256(canonical(unsignedBase)) };
    let signed;
    try { signed = await independenceSigner(clone(payload)); }
    catch { throw new AgenticError("RECOVERY_SLO_INDEPENDENCE_ATTESTATION_SIGNER_FAILED", "External signer independence attestation gagal", 502); }
    const signature = typeof signed === "string" ? signed : signed?.signature;
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== independenceKeyId) {
      throw new AgenticError("RECOVERY_SLO_INDEPENDENCE_ATTESTATION_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID yang berbeda", 502);
    }
    if (!verifyEd25519(independenceKeys.get(independenceKeyId), payload, signature)) {
      throw new AgenticError("RECOVERY_SLO_INDEPENDENCE_ATTESTATION_SIGNATURE_INVALID", "Signature independence attestation tidak cocok dengan trusted public key", 502);
    }
    const attestation = { ...payload, signature };
    const retention = await retain(ownerId, { artifactType: "trust_domain_independence_attestation", sourceId: attestation.attestationId,
      payload: attestation });
    return { status: "signed", signed: true, attestation, retention, readOnly: true, mutationAllowed: false };
  }
  async function listRetainedAnchorEvidence(ownerId, { limit = 50, includePayload = false } = {}) {
    assertOwner(ownerId);
    const count = Number(limit);
    const bounded = Number.isFinite(count) ? Math.max(1, Math.min(MAX_LIST, Math.floor(count))) : 50;
    const records = (await activeRecords(ownerId)).sort((a, b) => String(b.capturedAt).localeCompare(String(a.capturedAt))).slice(0, bounded);
    return { items: records.map(record => {
      const { _storage, payload, ...summary } = record;
      return includePayload ? { ...summary, payload: clone(payload) } : summary;
    }), count: records.length, readOnly: true, mutationAllowed: false };
  }
  async function auditRetainedAnchorEvidence(ownerId) {
    assertOwner(ownerId);
    const records = await activeRecords(ownerId);
    const findings = [];
    const seenSources = new Set();
    for (const record of records) {
      if (!validateRetainedRecord(ownerId, record)) findings.push({ code: "RETAINED_ANCHOR_EVIDENCE_INTEGRITY_INVALID", id: record.id });
      const sourceKey = `${record.artifactType}:${record.sourceId}`;
      if (seenSources.has(sourceKey)) findings.push({ code: "RETAINED_ANCHOR_EVIDENCE_DUPLICATE_SOURCE", id: record.id });
      seenSources.add(sourceKey);
      if (record.status === "retained" && record.artifactType === "provider_conformance") {
        const payload = record.payload;
        const domainValid = payload?.providerDomain === "recovery_journal" || payload?.providerDomain === "provider_identity_baseline"
          || payload?.providerDomain === "provider_identity_trust_policy";
        const report = payload?.report;
        const reportCopy = report && clone(report);
        if (reportCopy) delete reportCopy.reportDigest;
        const reportDigestValid = Boolean(report && payload?.reportDigest === report.reportDigest
          && sha256(canonical(reportCopy)) === payload.reportDigest);
        const conformanceValid = payload?.providerDomain === "recovery_journal"
          ? report?.conformant === (report?.checksFailed === 0)
          : report?.conformant === (Array.isArray(report?.findings) && report.findings.length === 0
            && Array.isArray(report?.checks) && report.checks.every(item => item?.passed === true));
        if (payload?.ownerId !== ownerId || !domainValid || !DIGEST.test(payload?.reportDigest || "")
          || !reportDigestValid || !conformanceValid) {
          findings.push({ code: "RETAINED_CONFORMANCE_REPORT_BINDING_INVALID", id: record.id });
        }
      }
      if (record.status === "retained" && record.artifactType === "retention_freshness_policy_approval_anchor_conformance") {
        const payload = record.payload, report = payload?.report, reportCopy = report && clone(report);
        if (reportCopy) delete reportCopy.reportDigest;
        const reportDigestValid = Boolean(report && payload?.reportDigest === report.reportDigest
          && sha256(canonical(reportCopy)) === payload.reportDigest);
        const sourceChallenge = payload?.challengeId ? await store.getEvidence(ownerId, payload.challengeId) : null;
        const challengeValid = Boolean(sourceChallenge && sourceChallenge.ownerId === ownerId
          && sourceChallenge.digest === payload?.challengeDigest && digestRecord(sourceChallenge) === sourceChallenge.digest
          && sourceChallenge.status === "completed" && sourceChallenge.reportDigest === payload?.reportDigest
          && sourceChallenge.report?.reportDigest === payload?.reportDigest);
        const conformant = report?.conformant === (Array.isArray(report?.findings) && report.findings.length === 0
          && Array.isArray(report?.checks) && report.checks.every(item => item?.passed === true));
        if (payload?.ownerId !== ownerId || payload?.providerDomain !== "retention_freshness_policy_approval" || !reportDigestValid
          || !challengeValid || !conformant || payload?.status !== (report?.conformant ? "conformant" : "nonconformant")) {
          findings.push({ code: "RETAINED_FRESHNESS_POLICY_APPROVAL_CONFORMANCE_REPORT_INVALID", id: record.id });
        }
      }
      if (record.status === "retained" && record.artifactType === "root_recovery_trust_anchor_conformance") {
        const payload = record.payload;
        const report = payload?.report;
        const reportCopy = report && clone(report);
        if (reportCopy) delete reportCopy.reportDigest;
        const reportDigestValid = Boolean(report && payload?.reportDigest === report.reportDigest
          && sha256(canonical(reportCopy)) === payload.reportDigest);
        const conformant = report?.conformant === (Array.isArray(report?.findings) && report.findings.length === 0
          && Array.isArray(report?.checks) && report.checks.every(item => item?.passed === true));
        const sourceChallenge = payload?.challengeId ? await store.getEvidence(ownerId, payload.challengeId) : null;
        const sourceChallengeValid = Boolean(sourceChallenge && sourceChallenge.ownerId === ownerId
          && sourceChallenge.digest === payload?.challengeDigest && digestRecord(sourceChallenge) === sourceChallenge.digest
          && sourceChallenge.status === "completed" && sourceChallenge.reportDigest === payload?.reportDigest
          && sourceChallenge.report?.reportDigest === payload?.reportDigest
          && sourceChallenge.report?.challengeDigest === report?.challengeDigest);
        const sourceReportChallengeValid = payload?.sourceReportChallengeDigest != null
          ? payload.sourceReportChallengeDigest === report?.challengeDigest : sourceChallengeValid;
        if (payload?.ownerId !== ownerId || payload?.providerDomain !== "root_recovery_trust" || !reportDigestValid
          || !sourceReportChallengeValid || payload?.conformanceStatus !== (report?.conformant ? "conformant" : "nonconformant")
          || report?.ownerId !== ownerId || !conformant) {
          findings.push({ code: "RETAINED_ROOT_TRUST_CONFORMANCE_REPORT_BINDING_INVALID", id: record.id });
        }
      }
      if (record.status === "retained" && record.artifactType === "retention_continuity_receipt") {
        const receiptResult = await verifyRetentionCheckpointContinuityReceipt(ownerId, record.payload);
        if (!receiptResult.valid) findings.push({ code: "RETAINED_CONTINUITY_RECEIPT_INVALID", id: record.id,
          detail: receiptResult.findings[0] });
      }
      if (record.status === "retained" && record.artifactType === "trust_domain_independence_attestation") {
        const attestationResult = verifyAnchorTrustDomainIndependenceAttestation(ownerId, record.payload);
        if (!attestationResult.valid) findings.push({ code: "RETAINED_INDEPENDENCE_ATTESTATION_INVALID", id: record.id,
          detail: attestationResult.findings[0] });
      }
      if (record.status === "retained" && record.artifactType === "provider_identity_drift_event") {
        const event = record.payload;
        if (event?.ownerId !== ownerId || event?.domain !== "agentic-v4-provider-identity-drift-event"
          || event?.eventType !== "provider_identity_drift_detected" || event?.report?.ownerId !== ownerId
          || event?.reportDigest !== event?.report?.reportDigest || !DIGEST.test(event?.attestationDigest || "")) {
          findings.push({ code: "RETAINED_PROVIDER_IDENTITY_DRIFT_EVENT_BINDING_INVALID", id: record.id });
        }
      }
      if (record.status === "retained" && record.artifactType === "provider_conformance_drift_event") {
        const event = record.payload;
        const eventCopy = event && clone(event);
        if (eventCopy) delete eventCopy.digest;
        if (event?.ownerId !== ownerId || event?.domain !== "agentic-v4-provider-conformance-drift-event"
          || event?.eventType !== "provider_conformance_drift_detected" || !DIGEST.test(event?.auditDigest || "")
          || event?.audit?.ownerId !== ownerId || event?.audit?.status !== "drift_detected"
          || event?.auditDigest !== sha256(canonical(event?.audit)) || !Number.isFinite(Date.parse(event?.capturedAt))
          || !Number.isSafeInteger(event?.retentionDays) || event.retentionDays < 1 || event.retentionDays > 3650
          || !DIGEST.test(event?.digest || "") || event.digest !== sha256(canonical(eventCopy))
          || record.sourceId !== event.eventId) {
          findings.push({ code: "RETAINED_PROVIDER_CONFORMANCE_DRIFT_EVENT_BINDING_INVALID", id: record.id });
        }
      }
      if (record.status === "retained" && record.artifactType === "retained_evidence_chain_recovery_attestation") {
        const attestation = record.payload;
        if (attestation?.ownerId !== ownerId || attestation?.domain !== "agentic-v4-retained-evidence-chain-recovery-attestation"
          || !DIGEST.test(attestation?.attestationDigest || "") || !Number.isSafeInteger(attestation?.snapshot?.sequence)
          || !DIGEST.test(attestation?.snapshot?.headDigest || "")) {
          findings.push({ code: "RETAINED_EVIDENCE_CHAIN_RECOVERY_ATTESTATION_BINDING_INVALID", id: record.id });
        }
      }
    }
    const chainAudit = retainedEvidenceChainService
      ? await retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId, records) : null;
    if (chainAudit && ["unhealthy", "rollback_suspected", "rollback_detected", "mismatch", "enrollment_required", "behind_local", "anchor_pending"].includes(chainAudit.status)) {
      findings.push({ code: "RETAINED_EVIDENCE_CHAIN_UNHEALTHY", status: chainAudit.status,
        detail: chainAudit.findings?.[0]?.code || chainAudit.anchor?.finding || null });
    }
    const active = records.filter(record => record.status === "retained").length;
    const tombstones = records.length - active;
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, active, tombstones,
      expiredRetained: records.filter(record => record.status === "retained" && Date.parse(record.expiresAt) <= Date.parse(now())).length,
      chain: chainAudit, findings, readOnly: true, mutationAllowed: false };
  }
  async function pruneExpiredRetainedAnchorEvidence(ownerId, { limit = MAX_PRUNE, artifactTypes = null } = {}) {
    assertOwner(ownerId);
    const count = Number(limit);
    const bounded = Number.isFinite(count) ? Math.max(1, Math.min(MAX_PRUNE, Math.floor(count))) : MAX_PRUNE;
    if (artifactTypes != null && (!Array.isArray(artifactTypes) || artifactTypes.length > 20
      || artifactTypes.some(type => !["provider_conformance", "root_recovery_trust_anchor_conformance", "retention_continuity_receipt", "trust_domain_independence_attestation", "provider_identity_drift_event", "retained_evidence_chain_recovery_attestation", "retention_reconciliation_attestation", "provider_conformance_drift_event", "root_trust_conformance_baseline_attestation", "retention_reconciliation_decision_gate_audit", "provider_conformance_drift_chain_checkpoint_receipt", "root_trust_conformance_baseline_lifecycle", "retention_decision_gate_anchor_conformance", "retention_freshness_policy_approval_anchor_conformance"].includes(type)))) {
      throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_FILTER_INVALID", "Filter artifact type retention tidak valid", 400);
    }
    const audit = await auditRetainedAnchorEvidence(ownerId);
    if (audit.status !== "healthy") throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_UNHEALTHY", "Retained anchor evidence tidak sehat; pruning ditolak", 409, { findings: audit.findings });
    const current = Date.parse(now());
    const expired = (await activeRecords(ownerId)).filter(record => record.status === "retained" && Date.parse(record.expiresAt) <= current
      && (!artifactTypes || artifactTypes.includes(record.artifactType)))
      .sort((a, b) => String(a.expiresAt).localeCompare(String(b.expiresAt))).slice(0, bounded);
    const pruned = [];
    for (const record of expired) {
      const unsigned = { ...clean(record), status: "tombstone", payload: null,
        tombstone: { payloadDigest: record.payloadDigest, expiredAt: record.expiresAt, reason: "RETENTION_PERIOD_ELAPSED" }, prunedAt: now() };
      delete unsigned.digest;
      const replacement = { ...unsigned, digest: digestRecord(unsigned) };
      await store.putEvidence(ownerId, replacement, { expectedVersion: record._storage?.version });
      const after = await store.getEvidence(ownerId, record.id);
      if (!validateRetainedRecord(ownerId, after) || after.status !== "tombstone") {
        throw new AgenticError("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_PRUNE_VERIFY_FAILED", "Tombstone gagal diverifikasi setelah pruning", 409, { id: record.id });
      }
      if (retainedEvidenceChainService) await retainedEvidenceChainService.recordPrunedEvidence(ownerId, after);
      pruned.push({ id: after.id, payloadDigest: after.payloadDigest, status: after.status });
    }
    return { status: "completed", pruned, count: pruned.length, remainingExpired: Math.max(0, audit.expiredRetained - pruned.length), readOnly: false, mutationAllowed: false };
  }
  async function auditCrossDomainAnchorIndependence(ownerId) {
    assertOwner(ownerId);
    const domains = anchorDomains.filter(domain => domain?.provider || domain?.required).map(domain => {
      const provider = domain?.provider || null;
      const configured = Boolean(provider);
      const identities = configured ? providerIdentities(provider, domain.endpoint) : [];
      return { domain: String(domain?.domain || "unknown"), configured, required: domain?.required === true,
        identityKnown: identities.length > 0, identitySources: identities.map(item => item.source),
        identityFingerprints: identities.map(item => item.fingerprint),
        providerObjectToken: provider ? objectToken(provider) : null };
    });
    const findings = [];
    const collisions = [];
    for (let i = 0; i < domains.length; i++) for (let j = i + 1; j < domains.length; j++) {
      const left = domains[i]; const right = domains[j];
      if (!left.configured || !right.configured) continue;
      const sameObject = left.providerObjectToken === right.providerObjectToken;
      const sharedIdentities = (left.identityFingerprints || []).filter(fingerprint => (right.identityFingerprints || []).includes(fingerprint));
      const sameIdentity = sharedIdentities.length > 0;
      if (sameObject || sameIdentity) {
        const collision = { domains: [left.domain, right.domain], reason: sameObject ? "SAME_PROVIDER_INSTANCE" : "SAME_BACKEND_OR_ENDPOINT_IDENTITY",
          sharedIdentityFingerprints: sharedIdentities };
        collisions.push(collision); findings.push({ code: "CROSS_DOMAIN_ANCHOR_INDEPENDENCE_VIOLATION", ...collision });
      }
    }
    const unconfigured = domains.filter(domain => !domain.configured).map(domain => domain.domain);
    const unknown = domains.filter(domain => domain.configured && !domain.identityKnown).map(domain => domain.domain);
    for (const domain of unconfigured) findings.push({ code: "ANCHOR_DOMAIN_NOT_CONFIGURED", domain });
    for (const domain of unknown) findings.push({ code: "ANCHOR_DOMAIN_IDENTITY_UNVERIFIABLE", domain });
    const status = collisions.length ? "unhealthy" : (unconfigured.length || unknown.length) ? "degraded" : "healthy";
    const report = { schemaVersion: 1, ownerId, checkedAt: now(), status, domains: domains.map(({ providerObjectToken, ...item }) => ({
        ...item, identityFingerprints: item.identityFingerprints || [] })),
      collisions, unconfiguredDomains: unconfigured, unverifiableDomains: unknown, findings,
      claims: { sameProviderInstanceChecked: true, stableBackendIdentityChecked: true, independentBackingStoresCryptographicallyProven: false },
      readOnly: true, mutationAllowed: false };
    report.reportDigest = sha256(canonical(report));
    return report;
  }
  const objectTokens = new WeakMap();
  let objectSequence = 0;
  function objectToken(value) {
    if (!objectTokens.has(value)) objectTokens.set(value, `object-${++objectSequence}`);
    return objectTokens.get(value);
  }
  return Object.freeze({
    createRecoverySloRetentionCheckpointContinuityReceipt: createRetentionCheckpointContinuityReceipt,
    verifyRecoverySloRetentionCheckpointContinuityReceipt: verifyRetentionCheckpointContinuityReceipt,
    retainRecoverySloRecoveryJournalAnchorConformanceEvidence,
    retainRecoverySloProviderIdentityBaselineConformanceEvidence,
    retainRecoverySloAnchorEvidence: retain,
    listRecoverySloRetainedAnchorEvidence: listRetainedAnchorEvidence,
    auditRecoverySloRetainedAnchorEvidence: auditRetainedAnchorEvidence,
    pruneExpiredRecoverySloRetainedAnchorEvidence: pruneExpiredRetainedAnchorEvidence,
    auditRecoverySloAnchorTrustDomainIndependence: auditCrossDomainAnchorIndependence,
    attestRecoverySloAnchorTrustDomainIndependence: attestAnchorTrustDomainIndependence,
    verifyRecoverySloAnchorTrustDomainIndependenceAttestation: verifyAnchorTrustDomainIndependenceAttestation,
    requiredSignedContinuityReceipt: requireSignedContinuityReceipt,
    requiredSignedIndependenceAttestation: requireSignedIndependenceAttestation,
    configuredContinuitySigner: Boolean(continuitySigner), configuredIndependenceSigner: Boolean(independenceSigner)
  });
}
