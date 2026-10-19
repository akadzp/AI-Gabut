import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";

const DIGEST = /^[a-f0-9]{64}$/;
const ARTIFACT = "retention_reconciliation_attestation";
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const out = {}; for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item); return out;
};
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RETENTION_FRESHNESS_POLICY_DRIFT_OWNER_REQUIRED", "Owner freshness-policy audit wajib ditentukan", 400);
  }
}
export function createRecoverySloRetentionFreshnessPolicyDriftService({ retainedEvidenceService, maxAgeMs = 86400000,
  futureSkewMs = 60000, clock = () => new Date().toISOString() } = {}) {
  if (typeof retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence !== "function"
    || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 60000 || maxAgeMs > 30 * 86400000
    || !Number.isSafeInteger(futureSkewMs) || futureSkewMs < 0 || futureSkewMs > 10 * 60000 || typeof clock !== "function") {
    throw new TypeError("Freshness policy drift membutuhkan retained evidence, kebijakan freshness valid, dan clock");
  }
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RETENTION_FRESHNESS_POLICY_DRIFT_CLOCK_INVALID", "Clock freshness-policy audit tidak valid", 500);
    return ms;
  }
  const currentPolicy = () => ({ schemaVersion: 1, maxAgeMs, futureSkewMs, digest: sha256(canonical({ schemaVersion: 1, maxAgeMs, futureSkewMs })) });
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [listed, nowMs] = await Promise.all([
      retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true }), Promise.resolve(now())
    ]);
    const policy = currentPolicy(), findings = [], mismatches = [], records = listed.items.filter(item => item?.artifactType === ARTIFACT);
    let compared = 0, stale = 0, future = 0, tombstones = 0;
    for (const record of records) {
      if (record.status === "tombstone") { tombstones++; continue; }
      const attestation = record.payload;
      const unsigned = clean(attestation || {}); delete unsigned.attestationDigest; delete unsigned.signature;
      if (record.status !== "retained" || !attestation || attestation.ownerId !== ownerId || record.sourceId !== attestation.attestationDigest
        || record.payloadDigest !== sha256(canonical(attestation)) || !DIGEST.test(attestation.attestationDigest || "")
        || sha256(canonical(unsigned)) !== attestation.attestationDigest || !Number.isSafeInteger(attestation.freshnessPolicy?.maxAgeMs)
        || !Number.isSafeInteger(attestation.freshnessPolicy?.futureSkewMs) || !Number.isFinite(Date.parse(attestation.issuedAt))
        || Date.parse(attestation.freshUntil) !== Date.parse(attestation.issuedAt) + attestation.freshnessPolicy.maxAgeMs) {
        findings.push({ code: "RETENTION_FRESHNESS_POLICY_ATTESTATION_INVALID", evidenceId: record.id });
        continue;
      }
      compared++;
      const signed = attestation.freshnessPolicy;
      if (signed.maxAgeMs !== maxAgeMs || signed.futureSkewMs !== futureSkewMs) {
        const item = { evidenceId: record.id, attestationDigest: attestation.attestationDigest,
          issuedAt: attestation.issuedAt, signedPolicy: { maxAgeMs: signed.maxAgeMs, futureSkewMs: signed.futureSkewMs },
          currentPolicy: { maxAgeMs, futureSkewMs }, policyDigest: policy.digest };
        mismatches.push(item);
      }
      const ageMs = nowMs - Date.parse(attestation.issuedAt);
      if (ageMs >= Math.min(signed.maxAgeMs, maxAgeMs) || nowMs >= Date.parse(attestation.freshUntil)) stale++;
      if (ageMs < -Math.min(signed.futureSkewMs, futureSkewMs)) future++;
    }
    if (mismatches.length) findings.push({ code: "RETENTION_FRESHNESS_POLICY_DRIFT_DETECTED", count: mismatches.length });
    const status = findings.some(item => item.code === "RETENTION_FRESHNESS_POLICY_ATTESTATION_INVALID") ? "unhealthy"
      : mismatches.length ? "drift_detected" : "healthy";
    return { status, ownerId, currentPolicy: policy, total: records.length, compared, policyDriftCount: mismatches.length,
      staleCount: stale, futureCount: future, tombstones, mismatches, findings, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ auditRecoverySloRetentionFreshnessPolicyDrift: audit, getCurrentRecoverySloRetentionFreshnessPolicy: currentPolicy,
    currentPolicy: Object.freeze({ maxAgeMs, futureSkewMs }), readOnly: true, mutationAllowed: false });
}
