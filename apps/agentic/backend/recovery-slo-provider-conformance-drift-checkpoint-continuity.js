import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const ARTIFACT = "provider_conformance_drift_chain_checkpoint_receipt";
const DOMAIN = "agentic-v4-provider-conformance-drift-chain-checkpoint-continuity";
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
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_OWNER_REQUIRED", "Owner checkpoint continuity wajib ditentukan", 400);
  }
}
function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }
function toPublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Drift checkpoint public key harus Ed25519");
  return key;
}
function makeKeyMap(input) {
  const entries = input instanceof Map ? [...input] : input && typeof input === "object" ? Object.entries(input) : [];
  const map = new Map();
  for (const [id, value] of entries) { if (!KEY_ID.test(String(id))) throw new TypeError("Drift checkpoint key ID tidak valid"); map.set(String(id), toPublicKey(value)); }
  return map;
}

export function createRecoverySloProviderConformanceDriftCheckpointContinuityService({ store, driftChainService, retainedEvidenceChainService,
  retainedEvidenceService, signer = null, keyId = null, publicKeys = null, required = false, clock = () => new Date().toISOString(), maxAgeMs = 86400000, futureSkewMs = 60000 } = {}) {
  if (!store?.getEvidence || !store?.listEvidence || !driftChainService?.auditRecoverySloProviderConformanceDriftRetentionChain
    || !retainedEvidenceChainService?.verifyRecoverySloRetainedEvidenceChainCheckpoint || !retainedEvidenceChainService?.auditRecoverySloRetainedEvidenceChain
    || !retainedEvidenceService?.retainRecoverySloAnchorEvidence || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence || typeof clock !== "function") {
    throw new TypeError("Drift checkpoint continuity membutuhkan store, drift-chain audit, chain checkpoint verifier, retained evidence, dan clock");
  }
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 60000 || maxAgeMs > 30 * 86400000) throw new TypeError("Drift checkpoint maxAgeMs harus 1 menit–30 hari");
  if (!Number.isSafeInteger(futureSkewMs) || futureSkewMs < 0 || futureSkewMs > 600000) throw new TypeError("Drift checkpoint futureSkewMs harus 0–10 menit");
  const keys = makeKeyMap(publicKeys);
  if (keyId != null && !KEY_ID.test(keyId)) throw new TypeError("Drift checkpoint signing key ID tidak valid");
  if (required && (!signer || !keyId || !keys.has(keyId))) throw new TypeError("Drift checkpoint continuity wajib memiliki signer dan trusted public key");
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_CLOCK_INVALID", "Clock checkpoint continuity tidak valid", 500);
    return new Date(time).toISOString();
  }
  function validateEnvelope(ownerId, value) {
    const findings = [];
    if (!value || value.domain !== DOMAIN || value.schemaVersion !== 1 || value.ownerId !== ownerId
      || !Number.isFinite(Date.parse(value.issuedAt)) || !validReason(value.reason) || !value.checkpoint
      || !Number.isSafeInteger(value.checkpoint.sequence) || value.checkpoint.sequence < 1 || !DIGEST.test(value.checkpoint.headDigest || "")
      || !["healthy", "local_only"].includes(value.checkpoint.chainStatus) || !value.signing || value.signing.algorithm !== "Ed25519"
      || !KEY_ID.test(value.signing.keyId || "") || !DIGEST.test(value.receiptDigest || "") || !SIGNATURE.test(value.signature || "")) {
      findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_SHAPE_INVALID" });
    }
    if (value?.freshnessPolicy != null) {
      const policy = value.freshnessPolicy;
      if (!Number.isSafeInteger(policy.maxAgeMs) || policy.maxAgeMs < 60000 || policy.maxAgeMs > 30 * 86400000
        || !Number.isFinite(Date.parse(policy.freshUntil))
        || Date.parse(policy.freshUntil) !== Date.parse(value.issuedAt) + policy.maxAgeMs) {
        findings.push({ code: "DRIFT_CHECKPOINT_FRESHNESS_POLICY_INVALID" });
      }
    }
    if (value?.previousReceiptDigest !== null && !DIGEST.test(value?.previousReceiptDigest || "")) findings.push({ code: "DRIFT_CHECKPOINT_PREVIOUS_RECEIPT_DIGEST_INVALID" });
    const unsigned = clean(value || {}); delete unsigned.receiptDigest; delete unsigned.signature;
    const digestValid = Boolean(value?.receiptDigest && sha256(canonical(unsigned)) === value.receiptDigest);
    if (!digestValid) findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_DIGEST_INVALID" });
    const key = keys.get(value?.signing?.keyId);
    let signatureValid = false;
    if (!key) findings.push({ code: "DRIFT_CHECKPOINT_SIGNING_KEY_UNTRUSTED" });
    else {
      try { signatureValid = verifySignature(null, Buffer.from(canonical({ ...unsigned, receiptDigest: value.receiptDigest }), "utf8"), key, Buffer.from(value.signature || "", "base64url")); }
      catch { signatureValid = false; }
      if (!signatureValid) findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_SIGNATURE_INVALID" });
    }
    return { valid: findings.length === 0 && digestValid && signatureValid, signatureValid, findings };
  }
  function freshness(receipt) {
    const current = Date.parse(now()), issued = Date.parse(receipt?.issuedAt);
    if (!Number.isFinite(issued)) return { fresh: false, status: "unproven", ageMs: null, freshUntil: null };
    if (!receipt?.freshnessPolicy || !Number.isFinite(Date.parse(receipt.freshnessPolicy.freshUntil))) {
      return { fresh: false, status: "legacy_unbounded", ageMs: Math.max(0, current - issued), freshUntil: null };
    }
    const ageMs = current - issued;
    const allowedAge = Math.min(maxAgeMs, receipt.freshnessPolicy.maxAgeMs);
    if (issued > current + futureSkewMs) return { fresh: false, status: "future", ageMs, freshUntil: receipt.freshnessPolicy.freshUntil };
    if (ageMs > allowedAge || current >= Date.parse(receipt.freshnessPolicy.freshUntil)) {
      return { fresh: false, status: "stale", ageMs, freshUntil: receipt.freshnessPolicy.freshUntil };
    }
    return { fresh: true, status: "fresh", ageMs, freshUntil: receipt.freshnessPolicy.freshUntil };
  }
  async function receipts(ownerId) {
    const result = await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true });
    return result.items.filter(item => item.artifactType === ARTIFACT);
  }
  async function orderReceipts(ownerId, records) {
    const findings = [], active = [], tombstones = [];
    for (const record of records) {
      if (record.status === "tombstone") { tombstones.push(record); findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_HISTORY_PRUNED", evidenceId: record.id }); continue; }
      const receipt = record.payload, envelope = validateEnvelope(ownerId, receipt);
      if (!envelope.valid || record.sourceId !== receipt?.receiptDigest || record.payloadDigest !== sha256(canonical(receipt))) {
        findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_RECORD_INVALID", evidenceId: record.id }); continue;
      }
      active.push({ record, receipt });
    }
    const byDigest = new Map(active.map(item => [item.receipt.receiptDigest, item]));
    if (byDigest.size !== active.length) findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_DUPLICATE_DIGEST" });
    const roots = active.filter(item => item.receipt.previousReceiptDigest === null);
    if (active.length && roots.length !== 1) findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_ROOT_COUNT_INVALID", count: roots.length });
    const ordered = [];
    let current = roots[0] || null;
    while (current && ordered.length < active.length) {
      if (ordered.some(item => item.receipt.receiptDigest === current.receipt.receiptDigest)) {
        findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_CYCLE_DETECTED" }); break;
      }
      ordered.push(current);
      const children = active.filter(item => item.receipt.previousReceiptDigest === current.receipt.receiptDigest);
      if (children.length > 1) { findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_BRANCH_DETECTED" }); break; }
      current = children[0] || null;
    }
    if (ordered.length !== active.length) findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_SEQUENCE_DISCONTINUITY", ordered: ordered.length, total: active.length });
    for (const item of ordered) {
      const checkpoint = await retainedEvidenceChainService.verifyRecoverySloRetainedEvidenceChainCheckpoint(ownerId, item.receipt.checkpoint);
      if (!checkpoint.valid) findings.push({ code: "DRIFT_CHECKPOINT_NOT_IN_CHAIN_HISTORY", evidenceId: item.record.id, finding: checkpoint.finding });
    }
    return { ordered, findings, tombstones };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [chainAudit, driftAudit, records] = await Promise.all([
      retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId),
      driftChainService.auditRecoverySloProviderConformanceDriftRetentionChain(ownerId), receipts(ownerId)
    ]);
    const ordered = await orderReceipts(ownerId, records);
    const findings = [...ordered.findings];
    if (!["healthy", "local_only"].includes(chainAudit.status)) findings.push({ code: "DRIFT_CHECKPOINT_CURRENT_CHAIN_UNTRUSTED", status: chainAudit.status });
    if (!(["healthy", "local_only"].includes(driftAudit.status))) findings.push({ code: "DRIFT_CHECKPOINT_DRIFT_AUDIT_UNHEALTHY", status: driftAudit.status });
    const freshnessResults = ordered.ordered.map(item => ({ receiptDigest: item.receipt.receiptDigest, ...freshness(item.receipt) }));
    const latestFreshness = freshnessResults.at(-1) || { fresh: false, status: "not_initialized", ageMs: null, freshUntil: null };
    return { status: findings.length ? "unhealthy" : chainAudit.status === "local_only" ? "local_only" : "healthy", ownerId,
      total: records.length, verified: ordered.ordered.length, tombstones: ordered.tombstones.length,
      latestReceiptDigest: ordered.ordered.at(-1)?.receipt.receiptDigest || null,
      currentCheckpoint: { sequence: chainAudit.sequence || 0, headDigest: chainAudit.headDigest || null, chainStatus: chainAudit.status },
      freshness: { status: latestFreshness.status, latestFresh: latestFreshness.fresh, latestAgeMs: latestFreshness.ageMs,
        latestFreshUntil: latestFreshness.freshUntil, stale: freshnessResults.filter(item => item.status === "stale").length,
        future: freshnessResults.filter(item => item.status === "future").length,
        legacyUnbounded: freshnessResults.filter(item => item.status === "legacy_unbounded").length,
        usableForCurrentDecision: latestFreshness.fresh && !findings.length },
      findings, readOnly: true, mutationAllowed: false };
  }
  async function create(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!signer || !keyId || !keys.has(keyId)) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_SIGNER_NOT_CONFIGURED", "Signer dan trusted public key checkpoint belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_REASON_INVALID", "Alasan checkpoint wajib 12–240 karakter", 400);
    const before = await audit(ownerId);
    if (!["healthy", "local_only"].includes(before.status)) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_CHAIN_UNHEALTHY", "Chain drift tidak sehat; continuity receipt ditolak", 409, { findings: before.findings });
    const sequence = before.currentCheckpoint.sequence, headDigest = before.currentCheckpoint.headDigest;
    if (!Number.isSafeInteger(sequence) || sequence < 1 || !DIGEST.test(headDigest || "")) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_NOT_INITIALIZED", "Belum ada checkpoint chain yang dapat dibuktikan", 409);
    const verifiedCheckpoint = await retainedEvidenceChainService.verifyRecoverySloRetainedEvidenceChainCheckpoint(ownerId, { sequence, headDigest });
    if (!verifiedCheckpoint.valid) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_NOT_IN_HISTORY", "Checkpoint terkini tidak ditemukan dalam histori chain", 409);
    const existing = await receipts(ownerId);
    const ordered = await orderReceipts(ownerId, existing);
    if (ordered.findings.length) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_HISTORY_UNHEALTHY", "Histori receipt checkpoint tidak sehat", 409, { findings: ordered.findings });
    const previous = ordered.ordered.at(-1)?.receipt || null;
    if (previous) {
      if (sequence < previous.checkpoint.sequence) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_ROLLBACK_DETECTED", "Checkpoint terkini lebih lama daripada receipt sebelumnya", 409);
      const continuity = await retainedEvidenceChainService.verifyRecoverySloRetainedEvidenceChainCheckpoint(ownerId, previous.checkpoint);
      if (!continuity.valid) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_CONTINUITY_UNPROVEN", "Checkpoint sebelumnya tidak lagi dapat dibuktikan", 409);
      if (sequence === previous.checkpoint.sequence && headDigest !== previous.checkpoint.headDigest) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_MISMATCH", "Digest berubah pada sequence yang sama", 409);
    }
    const issuedAt = now();
    const unsigned = { domain: DOMAIN, schemaVersion: 1, receiptId: `drift-chain-checkpoint-${randomUUID()}`, ownerId, issuedAt, reason: reason.trim(),
      freshnessPolicy: { maxAgeMs, freshUntil: new Date(Date.parse(issuedAt) + maxAgeMs).toISOString() },
      previousReceiptDigest: previous?.receiptDigest || null, checkpoint: { sequence, headDigest, chainStatus: before.currentCheckpoint.chainStatus,
        driftAuditStatus: before.status, externalContinuityProven: before.status === "healthy" },
      signing: { algorithm: "Ed25519", keyId } };
    const payload = { ...unsigned, receiptDigest: sha256(canonical(unsigned)) };
    let signed;
    try { signed = await signer(structuredClone(payload)); }
    catch { throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_SIGNER_FAILED", "External signer checkpoint gagal", 502); }
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== keyId) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID berbeda", 502);
    const signature = typeof signed === "string" ? signed : signed?.signature;
    const receipt = { ...payload, signature };
    const envelope = validateEnvelope(ownerId, receipt);
    if (!envelope.valid) throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_SIGNATURE_INVALID", "Signature checkpoint tidak valid", 502, { findings: envelope.findings });
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: ARTIFACT,
      sourceId: receipt.receiptDigest, payload: receipt, retentionDays: 3650 });
    const after = await audit(ownerId);
    if (after.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_DRIFT_CHECKPOINT_POSTCHECK_FAILED", "Audit pascapenyimpanan continuity receipt gagal", 409, { findings: after.findings });
    return { status: "issued", receipt, retention, audit: after, readOnly: false, mutationAllowed: false };
  }
  async function verify(ownerId, receipt) {
    assertOwner(ownerId);
    const envelope = validateEnvelope(ownerId, receipt);
    const retained = (await receipts(ownerId)).some(item => item.status === "retained" && item.sourceId === receipt?.receiptDigest
      && item.payload?.receiptId === receipt?.receiptId && item.payload?.receiptDigest === receipt?.receiptDigest);
    if (!retained) envelope.findings.push({ code: "DRIFT_CHECKPOINT_RECEIPT_NOT_RETAINED" });
    const checkpoint = receipt?.checkpoint ? await retainedEvidenceChainService.verifyRecoverySloRetainedEvidenceChainCheckpoint(ownerId, receipt.checkpoint) : { valid: false };
    if (!checkpoint.valid) envelope.findings.push({ code: "DRIFT_CHECKPOINT_NOT_IN_CHAIN_HISTORY" });
    const chainAudit = await audit(ownerId);
    const historicallyValid = envelope.valid && retained && checkpoint.valid;
    const currentFreshness = freshness(receipt);
    const usableForCurrentDecision = historicallyValid && chainAudit.status !== "unhealthy" && currentFreshness.fresh;
    return { valid: usableForCurrentDecision, historicallyValid, signatureValid: envelope.signatureValid, retained,
      checkpointValid: checkpoint.valid, continuityStatus: chainAudit.status, freshnessStatus: currentFreshness.status,
      fresh: currentFreshness.fresh, ageMs: currentFreshness.ageMs, freshUntil: currentFreshness.freshUntil, usableForCurrentDecision,
      externalContinuityProven: receipt?.checkpoint?.externalContinuityProven === true && chainAudit.status === "healthy",
      findings: [...envelope.findings, ...(chainAudit.status === "unhealthy" ? [{ code: "DRIFT_CHECKPOINT_CHAIN_AUDIT_UNHEALTHY" }] : []),
        ...(!currentFreshness.fresh ? [{ code: "DRIFT_CHECKPOINT_RECEIPT_NOT_FRESH", status: currentFreshness.status }] : [])],
      readOnly: true, mutationAllowed: false };
  }
  async function requireFresh(ownerId, receipt) {
    const result = await verify(ownerId, receipt);
    if (!result.usableForCurrentDecision) throw new AgenticError("DRIFT_CHECKPOINT_RECEIPT_NOT_USABLE_FOR_CURRENT_DECISION",
      "Drift-chain checkpoint receipt tidak memenuhi persyaratan freshness untuk keputusan terkini", 409,
      { freshnessStatus: result.freshnessStatus, historicallyValid: result.historicallyValid, findings: result.findings });
    return { ...result, allowed: true, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ createRecoverySloProviderConformanceDriftChainCheckpointReceipt: create,
    verifyRecoverySloProviderConformanceDriftChainCheckpointReceipt: verify,
    requireFreshRecoverySloProviderConformanceDriftChainCheckpointReceipt: requireFresh,
    auditRecoverySloProviderConformanceDriftChainCheckpointContinuity: audit,
    configured: Boolean(signer && keyId && keys.has(keyId)), required, maxAgeMs, futureSkewMs });
}
