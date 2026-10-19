import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const STATE_KIND = "recovery-slo-retention-freshness-policy-approval-state";
const CHALLENGE_KIND = "recovery-slo-retention-freshness-policy-approval-challenge";
const DIGEST = /^[a-f0-9]{64}$/;
const TTL_MS = 10 * 60_000;
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
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const policyDigest = policy => sha256(canonical({ schemaVersion: 1, maxAgeMs: policy.maxAgeMs, futureSkewMs: policy.futureSkewMs }));
const stateId = ownerId => `retention-freshness-policy-approval-${sha256(ownerId).slice(0, 40)}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_OWNER_REQUIRED", "Owner freshness policy wajib ditentukan", 400);
}
function normalizePolicy(policy) {
  if (!policy || !Number.isSafeInteger(policy.maxAgeMs) || policy.maxAgeMs < 60000 || policy.maxAgeMs > 30 * 86400000
    || !Number.isSafeInteger(policy.futureSkewMs) || policy.futureSkewMs < 0 || policy.futureSkewMs > 10 * 60000)
    throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_POLICY_INVALID", "Kebijakan freshness berada di luar batas yang diizinkan", 400);
  return { schemaVersion: 1, maxAgeMs: policy.maxAgeMs, futureSkewMs: policy.futureSkewMs, digest: policyDigest(policy) };
}
function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }

export function createRecoverySloRetentionFreshnessPolicyApprovalService({ store, currentPolicyProvider, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || typeof currentPolicyProvider !== "function" || typeof clock !== "function")
    throw new TypeError("Freshness-policy approval membutuhkan store, current-policy provider, dan clock");
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_CLOCK_INVALID", "Clock policy approval tidak valid", 500);
    return new Date(ms).toISOString();
  }
  function validateState(ownerId, state) {
    if (!state || state.id !== stateId(ownerId) || state.ownerId !== ownerId || state.kind !== STATE_KIND || state.schemaVersion !== 1
      || !Number.isSafeInteger(state.revision) || state.revision < 1 || !Array.isArray(state.events) || state.digest !== digestRecord(state)) return false;
    let previous = null;
    for (let i = 0; i < state.events.length; i++) {
      const event = state.events[i], unsigned = clean(event || {}); delete unsigned.eventDigest;
      if (!event || event.sequence !== i + 1 || event.previousEventDigest !== previous || !DIGEST.test(event.eventDigest || "")
        || sha256(canonical(unsigned)) !== event.eventDigest || !DIGEST.test(event.fromPolicyDigest || "") || !DIGEST.test(event.toPolicyDigest || "")
        || policyDigest(event.toPolicy || {}) !== event.toPolicyDigest) return false;
      previous = event.eventDigest;
    }
    return state.revision === state.events.length && (!state.events.length || state.approvedPolicy?.digest === state.events.at(-1).toPolicyDigest);
  }
  async function currentPolicy() { return normalizePolicy(await currentPolicyProvider()); }
  async function readState(ownerId) {
    const state = await store.getEvidence(ownerId, stateId(ownerId));
    if (!state) return { status: "not_initialized", state: null };
    return validateState(ownerId, state) ? { status: "present", state } : { status: "unhealthy", state: null };
  }
  async function status(ownerId) {
    assertOwner(ownerId);
    const [runtime, saved] = await Promise.all([currentPolicy(), readState(ownerId)]);
    if (saved.status === "unhealthy") return { status: "unhealthy", ownerId, runtimePolicy: runtime, approvedPolicy: null,
      revision: null, findings: [{ code: "RETENTION_FRESHNESS_POLICY_APPROVAL_STATE_INVALID" }], readOnly: true, mutationAllowed: false };
    if (!saved.state) return { status: "not_initialized", ownerId, runtimePolicy: runtime, approvedPolicy: null, revision: 0,
      readOnly: true, mutationAllowed: false };
    const approvedPolicy = saved.state.approvedPolicy;
    return { status: approvedPolicy.digest === runtime.digest ? "aligned" : "deployment_pending", ownerId, runtimePolicy: runtime,
      approvedPolicy, revision: saved.state.revision, lastEventDigest: saved.state.events.at(-1)?.eventDigest || null,
      findings: approvedPolicy.digest === runtime.digest ? [] : [{ code: "RETENTION_FRESHNESS_POLICY_APPROVED_BUT_NOT_DEPLOYED" }],
      readOnly: true, mutationAllowed: false };
  }
  async function prepare(ownerId, { targetPolicy, reason } = {}) {
    assertOwner(ownerId);
    if (!validReason(reason)) throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_REASON_INVALID", "Alasan perubahan wajib 12–240 karakter", 400);
    const [runtime, saved] = await Promise.all([currentPolicy(), readState(ownerId)]);
    if (saved.status === "unhealthy") throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_STATE_UNHEALTHY", "Histori approval freshness tidak sehat", 409);
    if (saved.state && saved.state.approvedPolicy.digest !== runtime.digest) throw new AgenticError("RETENTION_FRESHNESS_POLICY_DEPLOYMENT_PENDING", "Perubahan freshness sebelumnya belum diterapkan pada konfigurasi runtime", 409,
      { approvedPolicyDigest: saved.state.approvedPolicy.digest, runtimePolicyDigest: runtime.digest });
    const target = normalizePolicy(targetPolicy);
    if (target.digest === runtime.digest) throw new AgenticError("RETENTION_FRESHNESS_POLICY_NO_CHANGE", "Kebijakan target sama dengan kebijakan runtime", 409);
    const createdAt = now(), id = `retention-freshness-policy-approval-${randomUUID()}`, expiresAt = new Date(Date.parse(createdAt) + TTL_MS).toISOString();
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "prepared", expectedRevision: saved.state?.revision ?? 0,
      expectedRuntimePolicyDigest: runtime.digest, targetPolicy: target, reason: reason.trim(), createdAt, expiresAt };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, expectedRevision: challenge.expectedRevision, expectedRuntimePolicyDigest: runtime.digest,
      targetPolicy: target, challengeDigest: challenge.digest, createdAt, expiresAt,
      confirmation: `APPROVE FRESHNESS POLICY ${challenge.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function apply(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id), unsignedChallenge = clean(challenge || {}); delete unsignedChallenge.digest;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.status !== "prepared"
      || challenge.digest !== digestRecord(unsignedChallenge) || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `APPROVE FRESHNESS POLICY ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_CHALLENGE_INVALID", "Challenge approval tidak valid, kedaluwarsa, atau konfirmasinya tidak cocok", 409);
    }
    const [runtime, saved] = await Promise.all([currentPolicy(), readState(ownerId)]);
    if (saved.status === "unhealthy" || (saved.state?.revision ?? 0) !== challenge.expectedRevision || runtime.digest !== challenge.expectedRuntimePolicyDigest
      || (saved.state && saved.state.approvedPolicy.digest !== runtime.digest)) {
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_STALE", "Runtime policy atau approval revision berubah sejak challenge disiapkan", 409);
    }
    const sequence = challenge.expectedRevision + 1, previous = saved.state?.events.at(-1)?.eventDigest || null;
    const eventUnsigned = { domain: "agentic-v4-retention-freshness-policy-approval", schemaVersion: 1, ownerId, sequence,
      previousEventDigest: previous, fromPolicyDigest: runtime.digest, toPolicy: challenge.targetPolicy, toPolicyDigest: challenge.targetPolicy.digest,
      challengeDigest: challenge.digest, reason: challenge.reason, approvedAt: now() };
    const event = { ...eventUnsigned, eventDigest: sha256(canonical(eventUnsigned)) };
    const stateUnsigned = { id: stateId(ownerId), ownerId, kind: STATE_KIND, schemaVersion: 1, revision: sequence,
      approvedPolicy: challenge.targetPolicy, events: [...(saved.state?.events || []), event], updatedAt: now() };
    const state = { ...stateUnsigned, digest: digestRecord(stateUnsigned) };
    await store.putEvidence(ownerId, state, saved.state ? { expectedVersion: saved.state._storage?.version } : { overwrite: false });
    const persisted = await store.getEvidence(ownerId, state.id);
    if (!validateState(ownerId, persisted) || persisted.revision !== sequence) throw new AgenticError("RETENTION_FRESHNESS_POLICY_APPROVAL_WRITE_VERIFY_FAILED", "Approval policy gagal diverifikasi setelah penyimpanan", 409);
    const completedUnsigned = { ...clean(challenge), status: "completed", completedAt: now(), resultRevision: sequence, resultEventDigest: event.eventDigest };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version });
    return { status: "approved_deployment_pending", ownerId, revision: sequence, approvedPolicy: challenge.targetPolicy,
      runtimePolicy: runtime, eventDigest: event.eventDigest, readOnly: false, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [saved, current] = await Promise.all([readState(ownerId), currentPolicy()]);
    if (saved.status === "unhealthy") return { status: "unhealthy", ownerId, findings: [{ code: "RETENTION_FRESHNESS_POLICY_APPROVAL_STATE_INVALID" }], readOnly: true, mutationAllowed: false };
    if (!saved.state) return { status: "not_initialized", ownerId, revision: 0, runtimePolicy: current, readOnly: true, mutationAllowed: false };
    const statusValue = saved.state.approvedPolicy.digest === current.digest ? "healthy" : "deployment_pending";
    return { status: statusValue, ownerId, revision: saved.state.revision, eventCount: saved.state.events.length,
      approvedPolicy: saved.state.approvedPolicy, runtimePolicy: current, lastEventDigest: saved.state.events.at(-1)?.eventDigest || null,
      findings: statusValue === "healthy" ? [] : [{ code: "RETENTION_FRESHNESS_POLICY_APPROVED_BUT_NOT_DEPLOYED" }], readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ getRecoverySloRetentionFreshnessPolicyApprovalStatus: status,
    prepareRecoverySloRetentionFreshnessPolicyChangeApproval: prepare,
    applyRecoverySloRetentionFreshnessPolicyChangeApproval: apply,
    auditRecoverySloRetentionFreshnessPolicyApprovals: audit, configured: true });
}
