import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const DOMAIN = "agentic-v4-retention-reconciliation-attestation";
const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const KIND = "recovery-slo-retention-reconciliation-attestation";
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = clean(item);
  return result;
};
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_ATTESTATION_OWNER_REQUIRED", "Owner attestation wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function publicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Retention reconciliation public key harus Ed25519");
  return key;
}
function makeKeyMap(input) {
  const map = new Map();
  if (input instanceof Map) for (const [id, value] of input) {
    if (!KEY_ID.test(String(id))) throw new TypeError("Retention reconciliation key ID tidak valid");
    map.set(String(id), publicKey(value));
  } else if (input && typeof input === "object") for (const [id, value] of Object.entries(input)) {
    if (!KEY_ID.test(id)) throw new TypeError("Retention reconciliation key ID tidak valid");
    map.set(id, publicKey(value));
  }
  return map;
}
function verify(key, payload, signature) {
  try {
    if (!key || typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
    const bytes = Buffer.from(signature, "base64url");
    return bytes.length === 64 && bytes.toString("base64url") === signature
      && verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes);
  } catch { return false; }
}

export function createRecoverySloRetentionReconciliationAttestationService({ store, reconciliationService, retainedEvidenceService,
  signer = null, keyId = null, publicKeys = null, required = false, maxAgeMs = 24 * 60 * 60 * 1000,
  futureSkewMs = 60 * 1000, clock = () => new Date().toISOString() } = {}) {
  if (!store?.listEvidence || !reconciliationService?.auditRecoverySloRetentionEvidenceReconciliation
    || !retainedEvidenceService?.retainRecoverySloAnchorEvidence || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence
    || typeof clock !== "function") throw new TypeError("Retention reconciliation attestation membutuhkan store, audit service, retention service, dan clock");
  if (required && (!signer || !keyId || !publicKeys)) throw new TypeError("Signed retention reconciliation attestation diwajibkan tetapi signer dan trusted public keys belum lengkap");
  if ((signer || keyId || publicKeys) && (!signer || !keyId || !publicKeys)) throw new TypeError("Konfigurasi retention reconciliation signer harus lengkap");
  if (keyId && !KEY_ID.test(keyId)) throw new TypeError("Retention reconciliation key ID tidak valid");
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 60_000 || maxAgeMs > 30 * 86400_000) throw new TypeError("Retention reconciliation attestation maxAgeMs harus 1 menit–30 hari");
  if (!Number.isSafeInteger(futureSkewMs) || futureSkewMs < 0 || futureSkewMs > 10 * 60_000) throw new TypeError("Retention reconciliation futureSkewMs harus 0–10 menit");
  const keys = makeKeyMap(publicKeys);
  if (signer && !keys.has(keyId)) throw new TypeError("Retention reconciliation signing key harus ada di trusted registry");
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_ATTESTATION_CLOCK_INVALID", "Clock attestation tidak valid", 500);
    return new Date(value).toISOString();
  }
  function validateEnvelope(ownerId, value) {
    const findings = [];
    if (!value || value.domain !== DOMAIN || value.schemaVersion !== 1 || value.ownerId !== ownerId
      || !Number.isFinite(Date.parse(value.issuedAt)) || !validReason(value.reason)
      || !Number.isSafeInteger(value.freshnessPolicy?.maxAgeMs) || value.freshnessPolicy.maxAgeMs < 60_000 || value.freshnessPolicy.maxAgeMs > 30 * 86400_000
      || !Number.isSafeInteger(value.freshnessPolicy?.futureSkewMs) || value.freshnessPolicy.futureSkewMs < 0 || value.freshnessPolicy.futureSkewMs > 10 * 60_000
      || !Number.isFinite(Date.parse(value.freshUntil)) || Date.parse(value.freshUntil) !== Date.parse(value.issuedAt) + value.freshnessPolicy.maxAgeMs
      || !value.snapshot || value.snapshot.audit?.ownerId !== ownerId || !["healthy", "degraded"].includes(value.snapshot.audit?.status)
      || !DIGEST.test(value.snapshot.auditDigest || "") || value.snapshot.auditDigest !== sha256(canonical(value.snapshot.audit))
      || !value.signing || value.signing.algorithm !== "Ed25519" || !KEY_ID.test(value.signing.keyId || "")
      || !DIGEST.test(value.attestationDigest || "")) findings.push({ code: "RETENTION_RECONCILIATION_ATTESTATION_SHAPE_INVALID" });
    const unsigned = clean(value || {}); delete unsigned.attestationDigest; delete unsigned.signature;
    if (!value?.attestationDigest || sha256(canonical(unsigned)) !== value.attestationDigest) findings.push({ code: "RETENTION_RECONCILIATION_ATTESTATION_DIGEST_INVALID" });
    const key = keys.get(value?.signing?.keyId);
    const signatureValid = Boolean(key && verify(key, { ...unsigned, attestationDigest: value.attestationDigest }, value?.signature));
    if (!key) findings.push({ code: "RETENTION_RECONCILIATION_ATTESTATION_KEY_UNTRUSTED" });
    else if (!signatureValid) findings.push({ code: "RETENTION_RECONCILIATION_ATTESTATION_SIGNATURE_INVALID" });
    return { valid: findings.length === 0 && signatureValid, signatureValid, findings };
  }
  async function attest(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!signer || !keyId || !keys.has(keyId)) throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_SIGNER_NOT_CONFIGURED", "External signer dan trusted key belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_REASON_INVALID", "Alasan attestation wajib 12–240 karakter", 400);
    const audit = clean(await reconciliationService.auditRecoverySloRetentionEvidenceReconciliation(ownerId));
    if (!["healthy", "degraded"].includes(audit.status)) throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_UNHEALTHY", "Rekonsiliasi tidak sehat; attestation ditolak", 409, { status: audit.status });
    const issuedAt = now();
    const snapshot = { auditDigest: sha256(canonical(audit)), audit };
    const unsigned = { domain: DOMAIN, schemaVersion: 1, attestationId: `retention-reconciliation-${ownerHash(ownerId)}-${randomUUID()}`,
      ownerId, issuedAt, freshUntil: new Date(Date.parse(issuedAt) + maxAgeMs).toISOString(),
      freshnessPolicy: { maxAgeMs, futureSkewMs }, reason: reason.trim(), snapshot, signing: { algorithm: "Ed25519", keyId } };
    const payload = { ...unsigned, attestationDigest: sha256(canonical(unsigned)) };
    let signed;
    try { signed = await signer(structuredClone(payload)); }
    catch { throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_SIGNER_FAILED", "External signer gagal", 502); }
    const signature = typeof signed === "string" ? signed : signed?.signature;
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== keyId) throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID berbeda", 502);
    const attestation = { ...payload, signature };
    const verified = validateEnvelope(ownerId, attestation);
    if (!verified.valid) throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_SIGNATURE_INVALID", "Signature attestation tidak valid", 502, { findings: verified.findings });
    const retained = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: "retention_reconciliation_attestation",
      sourceId: attestation.attestationDigest, payload: attestation });
    return { status: "signed", attestation, retention: retained, snapshotStatus: audit.status, readOnly: false, mutationAllowed: false };
  }
  async function verifyAttestation(ownerId, attestation, { expectedAuditDigest = null } = {}) {
    assertOwner(ownerId);
    const envelope = validateEnvelope(ownerId, attestation);
    const records = (await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true })).items;
    const retained = records.some(item => item.artifactType === "retention_reconciliation_attestation" && item.sourceId === attestation?.attestationDigest
      && item.status === "retained" && item.payload?.attestationId === attestation?.attestationId
      && item.payload?.attestationDigest === attestation?.attestationDigest);
    const findings = [...envelope.findings];
    if (!retained) findings.push({ code: "RETENTION_RECONCILIATION_ATTESTATION_NOT_RETAINED" });
    const expectedProvided = expectedAuditDigest != null;
    const expectedValid = !expectedProvided || (DIGEST.test(expectedAuditDigest) && expectedAuditDigest === attestation?.snapshot?.auditDigest);
    if (!expectedValid) findings.push({ code: "RETENTION_RECONCILIATION_ATTESTATION_SNAPSHOT_MISMATCH" });
    const nowMs = Date.parse(now()), issuedAtMs = Date.parse(attestation?.issuedAt), signedMaxAge = attestation?.freshnessPolicy?.maxAgeMs;
    const effectiveMaxAge = Number.isSafeInteger(signedMaxAge) ? Math.min(signedMaxAge, maxAgeMs) : 0;
    const ageMs = nowMs - issuedAtMs;
    const fresh = envelope.valid && Number.isFinite(ageMs) && ageMs >= -Math.min(attestation?.freshnessPolicy?.futureSkewMs ?? 0, futureSkewMs)
      && ageMs < effectiveMaxAge && nowMs < Date.parse(attestation?.freshUntil || 0);
    const freshnessFinding = fresh ? null : !Number.isFinite(ageMs) ? "RETENTION_RECONCILIATION_ATTESTATION_TIME_INVALID"
      : ageMs < -Math.min(attestation?.freshnessPolicy?.futureSkewMs ?? 0, futureSkewMs) ? "RETENTION_RECONCILIATION_ATTESTATION_FROM_FUTURE"
        : "RETENTION_RECONCILIATION_ATTESTATION_STALE";
    if (!fresh) findings.push({ code: freshnessFinding });
    const historicallyValid = envelope.valid && retained && expectedValid;
    return { valid: historicallyValid && fresh, historicallyValid, signatureValid: envelope.signatureValid, retained, fresh,
      usableForCurrentDecision: historicallyValid && fresh, ageMs: Number.isFinite(ageMs) ? ageMs : null,
      freshUntil: attestation?.freshUntil || null, effectiveMaxAgeMs: effectiveMaxAge,
      matchesExpectedSnapshot: expectedProvided ? expectedValid : null, auditDigest: attestation?.snapshot?.auditDigest || null,
      findings, readOnly: true, mutationAllowed: false };
  }
  async function requireForDecision(ownerId, attestation, { expectedAuditDigest = null, decision = "unspecified" } = {}) {
    assertOwner(ownerId);
    if (typeof decision !== "string" || !decision.trim() || decision.trim().length > 120) {
      throw new AgenticError("RETENTION_RECONCILIATION_DECISION_LABEL_INVALID", "Label keputusan wajib 1–120 karakter", 400);
    }
    const verification = await verifyAttestation(ownerId, attestation, { expectedAuditDigest });
    if (!verification.usableForCurrentDecision) {
      throw new AgenticError("RETENTION_RECONCILIATION_ATTESTATION_NOT_USABLE_FOR_DECISION",
        "Attestation rekonsiliasi tidak memenuhi syarat freshness, signature, retensi, atau snapshot untuk keputusan saat ini", 409,
        { decision: decision.trim(), signatureValid: verification.signatureValid, historicallyValid: verification.historicallyValid,
          fresh: verification.fresh, usableForCurrentDecision: false, findings: verification.findings });
    }
    return { allowed: true, decision: decision.trim(), attestationDigest: attestation.attestationDigest,
      issuedAt: attestation.issuedAt, freshUntil: attestation.freshUntil, verification,
      readOnly: true, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const records = (await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true })).items
      .filter(item => item.artifactType === "retention_reconciliation_attestation");
    const findings = [];
    let staleCount = 0, freshCount = 0;
    for (const item of records) {
      if (item.status === "tombstone") continue;
      const result = validateEnvelope(ownerId, item.payload);
      if (!result.valid || item.sourceId !== item.payload?.attestationDigest) {
        findings.push({ code: "RETENTION_RECONCILIATION_ATTESTATION_RECORD_INVALID", evidenceId: item.id });
        continue;
      }
      const issuedAtMs = Date.parse(item.payload.issuedAt), ageMs = Date.parse(now()) - issuedAtMs;
      const effectiveMaxAge = Math.min(item.payload.freshnessPolicy.maxAgeMs, maxAgeMs);
      const fresh = Number.isFinite(ageMs) && ageMs >= -Math.min(item.payload.freshnessPolicy.futureSkewMs, futureSkewMs)
        && ageMs < effectiveMaxAge && Date.parse(now()) < Date.parse(item.payload.freshUntil);
      if (fresh) freshCount++; else staleCount++;
    }
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, freshCount, staleCount, findings,
      freshnessPolicy: { maxAgeMs, futureSkewMs }, signedAttestationConfigured: Boolean(signer && keyId && keys.has(keyId)), readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ attestRecoverySloRetentionEvidenceReconciliation: attest,
    verifyRecoverySloRetentionEvidenceReconciliationAttestation: verifyAttestation,
    requireRecoverySloRetentionReconciliationAttestationForDecision: requireForDecision,
    auditRecoverySloRetentionEvidenceReconciliationAttestations: audit,
    configured: Boolean(signer && keyId && keys.has(keyId)), required, freshnessPolicy: Object.freeze({ maxAgeMs, futureSkewMs }) });
}
