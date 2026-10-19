import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const BASELINE_KIND = "recovery-slo-anchor-provider-identity-baseline";
const CHALLENGE_KIND = "recovery-slo-anchor-provider-identity-baseline-challenge";
const DIGEST = /^[a-f0-9]{64}$/;
const CHALLENGE_TTL_MS = 10 * 60 * 1000;
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
const baselineId = ownerId => `recovery-slo-provider-identity-baseline-${ownerHash(ownerId)}`;
const challengeId = id => `recovery-slo-provider-identity-baseline-challenge-${id}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_OWNER_REQUIRED", "Owner provider identity baseline wajib ditentukan", 400);
  }
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
function identitySnapshot(anchorDomains) {
  return anchorDomains.map(domain => {
    const provider = domain?.provider || null;
    const values = [domain?.endpoint, provider?.providerIdentity, provider?.backendIdentity, provider?.backendId,
      provider?.storeId, provider?.storageId, provider?.resourceId, provider?.namespaceId, provider?.namespace,
      provider?.baseUrl, provider?.contractInfo?.backendId, provider?.contractInfo?.storeId, provider?.contractInfo?.namespaceId]
      .map(normalizeIdentity).filter(Boolean);
    const fingerprints = [...new Set(values.map(value => sha256(value)))].sort();
    return { domain: String(domain?.domain || "unknown"), configured: Boolean(provider), required: domain?.required === true,
      identityKnown: fingerprints.length > 0, identityFingerprints: fingerprints };
  }).sort((a, b) => a.domain.localeCompare(b.domain));
}
function validateBaseline(ownerId, baseline) {
  if (!baseline || baseline.ownerId !== ownerId || baseline.id !== baselineId(ownerId) || baseline.kind !== BASELINE_KIND
    || baseline.schemaVersion !== 1 || !Number.isSafeInteger(baseline.revision) || baseline.revision < 1
    || !Array.isArray(baseline.snapshot) || !DIGEST.test(baseline.snapshotDigest || "")
    || sha256(canonical(baseline.snapshot)) !== baseline.snapshotDigest || !Number.isFinite(Date.parse(baseline.createdAt))
    || typeof baseline.reason !== "string" || baseline.reason.length < 12 || !DIGEST.test(baseline.digest || "")
    || baseline.digest !== digestRecord(baseline)) return { valid: false, code: "PROVIDER_IDENTITY_BASELINE_INVALID" };
  return { valid: true };
}
function validateChallenge(ownerId, challenge) {
  if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.schemaVersion !== 1
    || !["prepared", "used"].includes(challenge.status) || !["enroll", "rotate"].includes(challenge.intent)
    || !Array.isArray(challenge.snapshot) || !DIGEST.test(challenge.snapshotDigest || "")
    || sha256(canonical(challenge.snapshot)) !== challenge.snapshotDigest || !Number.isFinite(Date.parse(challenge.expiresAt))
    || !Number.isFinite(Date.parse(challenge.createdAt)) || !DIGEST.test(challenge.digest || "")
    || challenge.digest !== digestRecord(challenge)) return { valid: false, code: "PROVIDER_IDENTITY_BASELINE_CHALLENGE_INVALID" };
  return { valid: true };
}
export function createRecoverySloProviderIdentityDriftService({ store, anchorDomains = [], clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || typeof clock !== "function") throw new TypeError("Provider identity drift service membutuhkan store dan clock");
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_CLOCK_INVALID", "Clock provider drift tidak valid", 500);
    return new Date(ms).toISOString();
  }
  async function getBaseline(ownerId) {
    const baseline = await store.getEvidence(ownerId, baselineId(ownerId));
    if (!baseline) return { status: "missing", baseline: null };
    const check = validateBaseline(ownerId, baseline);
    return check.valid ? { status: "present", baseline } : { status: "invalid", baseline: null, finding: check.code };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const currentSnapshot = identitySnapshot(anchorDomains);
    const currentDigest = sha256(canonical(currentSnapshot));
    const state = await getBaseline(ownerId);
    if (state.status === "missing") return { status: "baseline_missing", ownerId, currentDigest,
      configuredDomains: currentSnapshot.filter(item => item.configured).length, domains: currentSnapshot,
      findings: [{ code: "PROVIDER_IDENTITY_BASELINE_NOT_ENROLLED" }], readOnly: true, mutationAllowed: false };
    if (state.status === "invalid") return { status: "unhealthy", ownerId, currentDigest,
      findings: [{ code: state.finding }], readOnly: true, mutationAllowed: false };
    const baseline = state.baseline;
    const baselineByDomain = new Map(baseline.snapshot.map(item => [item.domain, item]));
    const currentByDomain = new Map(currentSnapshot.map(item => [item.domain, item]));
    const changedDomains = [];
    const findings = [];
    for (const domain of new Set([...baselineByDomain.keys(), ...currentByDomain.keys()])) {
      const before = baselineByDomain.get(domain) || null;
      const after = currentByDomain.get(domain) || null;
      if (!before || !after || canonical(before) !== canonical(after)) {
        changedDomains.push({ domain, baseline: before, current: after });
        findings.push({ code: "ANCHOR_PROVIDER_IDENTITY_DRIFT", domain });
      }
    }
    const unverifiable = currentSnapshot.filter(item => item.configured && !item.identityKnown).map(item => item.domain);
    const requiredUnconfigured = currentSnapshot.filter(item => item.required && !item.configured).map(item => item.domain);
    for (const domain of unverifiable) findings.push({ code: "ANCHOR_PROVIDER_IDENTITY_UNVERIFIABLE", domain });
    for (const domain of requiredUnconfigured) findings.push({ code: "ANCHOR_PROVIDER_REQUIRED_BUT_UNCONFIGURED", domain });
    const status = changedDomains.length ? "drift_detected" : (unverifiable.length || requiredUnconfigured.length) ? "degraded" : "healthy";
    const report = { schemaVersion: 1, ownerId, checkedAt: now(), status, baselineRevision: baseline.revision,
      baselineDigest: baseline.digest, baselineSnapshotDigest: baseline.snapshotDigest, currentDigest,
      changedDomains, unverifiableDomains: unverifiable, requiredUnconfiguredDomains: requiredUnconfigured, findings,
      claims: { identityFingerprintsCompared: true, providerBehaviorRevalidated: false, backingInfrastructureIndependenceProven: false },
      readOnly: true, mutationAllowed: false };
    report.reportDigest = sha256(canonical(report));
    return report;
  }
  async function prepare(ownerId, { reason, rotate = false, expectedBaselineDigest = null } = {}) {
    assertOwner(ownerId);
    if (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_REASON_INVALID", "Alasan baseline wajib 12–240 karakter", 400);
    }
    const current = await getBaseline(ownerId);
    if (current.status === "invalid") throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_BASELINE_INVALID", "Baseline provider identity rusak", 409);
    const intent = rotate ? "rotate" : "enroll";
    if (!rotate && current.status !== "missing") throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_BASELINE_EXISTS", "Baseline sudah ada; rotasi memerlukan digest baseline terkini", 409);
    if (rotate && (current.status !== "present" || expectedBaselineDigest !== current.baseline.digest)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_BASELINE_DIGEST_REQUIRED", "Rotasi baseline memerlukan digest baseline terkini", 409);
    }
    const snapshot = identitySnapshot(anchorDomains);
    const createdAt = now();
    const id = challengeId(randomUUID());
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "prepared", intent,
      expectedBaselineDigest: current.baseline?.digest || null, snapshot, snapshotDigest: sha256(canonical(snapshot)),
      reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + CHALLENGE_TTL_MS).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, intent, snapshotDigest: challenge.snapshotDigest, baselineDigest: challenge.expectedBaselineDigest,
      expiresAt: challenge.expiresAt, confirmation: `${rotate ? "ROTATE" : "ENROLL"} PROVIDER IDENTITY BASELINE ${challenge.digest.slice(0, 12)}`,
      challengeDigest: challenge.digest, readOnly: true, mutationAllowed: false };
  }
  async function apply(ownerId, id, { confirmation, reason = null } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    const check = validateChallenge(ownerId, challenge);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_CHALLENGE_INVALID", "Challenge baseline provider tidak valid", 409, { finding: check.code });
    if (challenge.status !== "prepared") throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_CHALLENGE_REPLAY", "Challenge baseline sudah digunakan", 409);
    if (Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_CHALLENGE_EXPIRED", "Challenge baseline kedaluwarsa", 409);
    const expected = `${challenge.intent === "rotate" ? "ROTATE" : "ENROLL"} PROVIDER IDENTITY BASELINE ${challenge.digest.slice(0, 12)}`;
    if (confirmation !== expected) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_CONFIRMATION_INVALID", "Konfirmasi baseline tidak cocok", 409);
    if (reason != null && (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_REASON_INVALID", "Alasan baseline wajib 12–240 karakter", 400);
    }
    const current = await getBaseline(ownerId);
    if (current.status === "invalid" || (current.baseline?.digest || null) !== challenge.expectedBaselineDigest
      || (challenge.intent === "enroll" && current.status !== "missing") || (challenge.intent === "rotate" && current.status !== "present")) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_BASELINE_STALE", "Baseline berubah sejak challenge dibuat", 409);
    }
    const snapshot = identitySnapshot(anchorDomains);
    const snapshotDigest = sha256(canonical(snapshot));
    if (snapshotDigest !== challenge.snapshotDigest) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_SNAPSHOT_CHANGED", "Identitas provider berubah sejak challenge dibuat", 409);
    const createdAt = now();
    const unsigned = { id: baselineId(ownerId), ownerId, kind: BASELINE_KIND, schemaVersion: 1,
      revision: (current.baseline?.revision || 0) + 1, snapshot, snapshotDigest, reason: (reason || challenge.reason).trim(),
      createdAt, previousBaselineDigest: current.baseline?.digest || null, sourceChallengeDigest: challenge.digest };
    const baseline = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, baseline, current.baseline ? { expectedVersion: current.baseline._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, baseline.id);
    if (!validateBaseline(ownerId, saved).valid || saved.digest !== baseline.digest) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_BASELINE_WRITE_FAILED", "Baseline provider identity gagal diverifikasi", 409);
    const usedUnsigned = { ...clean(challenge), status: "used", usedAt: now(), appliedBaselineDigest: saved.digest };
    delete usedUnsigned.digest;
    const used = { ...usedUnsigned, digest: digestRecord(usedUnsigned) };
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { status: "enrolled", intent: challenge.intent, baseline: { revision: saved.revision, digest: saved.digest,
      snapshotDigest: saved.snapshotDigest, createdAt: saved.createdAt }, readOnly: false, mutationAllowed: false };
  }
  return Object.freeze({
    auditRecoverySloAnchorProviderIdentityDrift: audit,
    prepareRecoverySloAnchorProviderIdentityBaseline: prepare,
    applyRecoverySloAnchorProviderIdentityBaseline: apply,
    getRecoverySloAnchorProviderIdentityBaseline: async ownerId => {
      assertOwner(ownerId);
      const state = await getBaseline(ownerId);
      if (state.status !== "present") return { status: state.status, finding: state.finding || null, readOnly: true, mutationAllowed: false };
      const { snapshot, ...summary } = state.baseline;
      return { status: "present", baseline: summary, snapshot, readOnly: true, mutationAllowed: false };
    }
  });
}
