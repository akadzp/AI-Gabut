import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const KIND = "recovery-slo-root-recovery-trust-external-anchor";
const MARKER_KIND = "recovery-slo-root-recovery-trust-anchor-marker";
const ENROLLMENT_KIND = "recovery-slo-root-recovery-trust-anchor-enrollment";
const DOMAIN = "root_recovery_trust";
const DIGEST = /^[a-f0-9]{64}$/;
const TTL_MS = 10 * 60 * 1000;
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
const scopeFor = ownerId => `root-recovery-trust-${ownerHash(ownerId)}`;
const markerId = ownerId => `recovery-slo-root-recovery-trust-anchor-marker-${ownerHash(ownerId)}`;
const challengeId = () => `recovery-slo-root-recovery-trust-anchor-enrollment-${randomUUID()}`;

function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_OWNER_REQUIRED", "Owner root-trust anchor wajib ditentukan", 400);
  }
}
function validateAnchor(anchor, ownerId) {
  const scope = scopeFor(ownerId);
  if (!anchor || anchor.ownerId !== scope || anchor.sourceOwnerHash !== sha256(ownerId) || anchor.domain !== DOMAIN
    || anchor.kind !== KIND || anchor.schemaVersion !== 1 || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
    || !Number.isSafeInteger(anchor.revision) || anchor.revision < 1 || !DIGEST.test(anchor.policyDigest || "")
    || (anchor.previousPolicyDigest !== null && !DIGEST.test(anchor.previousPolicyDigest || ""))
    || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
    || !["genesis", "advance", "legacy_enrollment"].includes(anchor.anchorType)
    || typeof anchor.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(anchor.anchoredAt))
    || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) {
    return { valid: false, code: "ROOT_RECOVERY_TRUST_EXTERNAL_ANCHOR_INVALID" };
  }
  if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null)
    || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) return { valid: false, code: "ROOT_RECOVERY_TRUST_ANCHOR_CHAIN_INVALID" };
  if (anchor.anchorType === "genesis" && (anchor.anchorSequence !== 1 || anchor.revision !== 1 || anchor.previousPolicyDigest !== null)) {
    return { valid: false, code: "ROOT_RECOVERY_TRUST_ANCHOR_GENESIS_INVALID" };
  }
  if (anchor.anchorType === "legacy_enrollment" && !anchor.historyNotProven) return { valid: false, code: "ROOT_RECOVERY_TRUST_ANCHOR_LEGACY_FLAG_REQUIRED" };
  return { valid: true };
}
function validateMarker(marker, ownerId) {
  if (!marker || marker.id !== markerId(ownerId) || marker.ownerId !== ownerId || marker.kind !== MARKER_KIND || marker.schemaVersion !== 1
    || !DIGEST.test(marker.anchorDigest || "") || !DIGEST.test(marker.policyDigest || "")
    || !Number.isSafeInteger(marker.revision) || marker.revision < 1 || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1
    || !Number.isFinite(Date.parse(marker.updatedAt)) || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker)) {
    return { valid: false, code: "ROOT_RECOVERY_TRUST_ANCHOR_MARKER_INVALID" };
  }
  return { valid: true };
}

export function createRecoverySloRootRecoveryTrustAnchorService({ store, provider = null, required = false,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || typeof clock !== "function"
    || (provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function")) || (required && !provider)) {
    throw new TypeError("Root-recovery trust anchor membutuhkan evidence store dan provider CAS jika diwajibkan");
  }
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_CLOCK_INVALID", "Clock root-trust anchor tidak valid", 500);
    return new Date(ms).toISOString();
  }
  async function readMarker(ownerId) {
    const marker = await store.getEvidence(ownerId, markerId(ownerId));
    if (!marker) return { status: "missing", marker: null };
    const checked = validateMarker(marker, ownerId);
    return checked.valid ? { status: "present", marker } : { status: "invalid", marker: null, finding: checked.code };
  }
  async function saveMarker(ownerId, anchor) {
    const id = markerId(ownerId), old = await store.getEvidence(ownerId, id);
    const unsigned = { id, ownerId, kind: MARKER_KIND, schemaVersion: 1, anchorDigest: anchor.digest,
      policyDigest: anchor.policyDigest, revision: anchor.revision, anchorSequence: anchor.anchorSequence, updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, old ? { expectedVersion: old._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!validateMarker(saved, ownerId).valid || saved.anchorDigest !== anchor.digest) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_MARKER_WRITE_FAILED", "Marker root-trust anchor gagal diverifikasi", 409);
    }
    return saved;
  }
  async function readRemote(ownerId) {
    if (!provider) return { status: required ? "unavailable" : "local_only", anchor: null, scope: scopeFor(ownerId),
      finding: required ? "ROOT_RECOVERY_TRUST_EXTERNAL_ANCHOR_REQUIRED" : "ROOT_RECOVERY_TRUST_EXTERNAL_ANCHOR_NOT_CONFIGURED" };
    const scope = scopeFor(ownerId);
    try {
      const anchor = await provider.read(scope);
      if (!anchor) return { status: "missing", anchor: null, scope };
      const checked = validateAnchor(anchor, ownerId);
      return checked.valid ? { status: "present", anchor, scope } : { status: "invalid", anchor: null, scope, finding: checked.code };
    } catch (error) {
      return { status: "unavailable", anchor: null, scope, finding: error?.code || "ROOT_RECOVERY_TRUST_EXTERNAL_READ_FAILED" };
    }
  }
  async function inspect(ownerId, policy) {
    assertOwner(ownerId);
    const [remote, local] = await Promise.all([readRemote(ownerId), readMarker(ownerId)]);
    const common = { ownerId, required, revision: policy?.revision ?? null, policyDigest: policy?.digest ?? null,
      anchorSequence: remote.anchor?.anchorSequence ?? null, anchorDigest: remote.anchor?.digest ?? null,
      historyNotProven: remote.anchor?.historyNotProven ?? policy?.historyNotProven ?? null, readOnly: true, mutationAllowed: false };
    if (remote.status === "local_only" || remote.status === "unavailable") return { ...common, status: remote.status, trusted: remote.status === "local_only" && !required, finding: remote.finding };
    if (local.status === "invalid") return { ...common, status: "unhealthy", trusted: false, finding: local.finding };
    if (remote.status === "invalid") return { ...common, status: "unhealthy", trusted: false, finding: remote.finding };
    if (remote.status === "missing") {
      const status = local.status === "present" ? "rollback_suspected" : "enrollment_required";
      return { ...common, status, trusted: false, finding: status === "rollback_suspected"
        ? "ROOT_RECOVERY_TRUST_ANCHOR_MISSING_AFTER_ENROLLMENT" : "ROOT_RECOVERY_TRUST_ANCHOR_ENROLLMENT_REQUIRED" };
    }
    const anchor = remote.anchor;
    if (local.status === "present") {
      if (anchor.anchorSequence < local.marker.anchorSequence) return { ...common, status: "rollback_suspected", trusted: false, finding: "ROOT_RECOVERY_TRUST_ANCHOR_BEHIND_LOCAL_MARKER" };
      if (anchor.anchorSequence === local.marker.anchorSequence && anchor.digest !== local.marker.anchorDigest) return { ...common, status: "mismatch", trusted: false, finding: "ROOT_RECOVERY_TRUST_ANCHOR_MARKER_MISMATCH" };
    }
    if (!policy) {
      if (local.status === "missing") return { ...common, status: "rollback_suspected", trusted: false, finding: "ROOT_RECOVERY_TRUST_ANCHOR_MARKER_MISSING" };
      return { ...common, status: "anchored", trusted: true, anchorType: anchor.anchorType, finding: null };
    }
    if (anchor.revision === policy.revision && anchor.policyDigest === policy.digest) {
      if (local.status === "missing") return { ...common, status: "rollback_suspected", trusted: false, finding: "ROOT_RECOVERY_TRUST_ANCHOR_MARKER_MISSING" };
      if (anchor.anchorSequence !== local.marker.anchorSequence || anchor.digest !== local.marker.anchorDigest) return { ...common, status: "mismatch", trusted: false, finding: "ROOT_RECOVERY_TRUST_ANCHOR_MARKER_MISMATCH" };
      return { ...common, status: "anchored", trusted: true, anchorType: anchor.anchorType, finding: null };
    }
    if (anchor.revision > policy.revision) return { ...common, status: "rollback_detected", trusted: false, finding: "ROOT_RECOVERY_TRUST_LOCAL_POLICY_ROLLBACK_DETECTED" };
    if (policy.revision === anchor.revision + 1 && policy.previousPolicyDigest === anchor.policyDigest) {
      return { ...common, status: "behind_local", trusted: false, finding: "ROOT_RECOVERY_TRUST_EXTERNAL_ANCHOR_BEHIND_LOCAL_POLICY" };
    }
    return { ...common, status: "continuity_unproven", trusted: false, finding: "ROOT_RECOVERY_TRUST_POLICY_CONTINUITY_UNPROVEN" };
  }
  async function advance(ownerId, policy, { legacyEnrollment = false } = {}) {
    assertOwner(ownerId);
    if (!policy || policy.ownerId !== ownerId || !Number.isSafeInteger(policy.revision) || policy.revision < 1
      || !DIGEST.test(policy.digest || "") || policy.digest !== digestRecord(policy)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_POLICY_INVALID", "Root trust policy tidak valid untuk anchoring", 409);
    }
    if (!provider) {
      if (required) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_EXTERNAL_ANCHOR_UNAVAILABLE", "External root-trust anchor diwajibkan", 503);
      return { status: "local_only", trusted: true, ownerId, revision: policy.revision, policyDigest: policy.digest, readOnly: false, mutationAllowed: false };
    }
    const remote = await readRemote(ownerId), marker = await readMarker(ownerId);
    if (remote.status === "unavailable" || remote.status === "invalid" || marker.status === "invalid") {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_UNHEALTHY", "External root-trust anchor tidak sehat", 409, { status: remote.status, finding: remote.finding || marker.finding });
    }
    if (remote.status === "present" && remote.anchor.revision === policy.revision && remote.anchor.policyDigest === policy.digest) {
      await saveMarker(ownerId, remote.anchor);
      return { status: "anchored", trusted: true, ownerId, revision: policy.revision, policyDigest: policy.digest,
        anchorSequence: remote.anchor.anchorSequence, anchorDigest: remote.anchor.digest, idempotent: true, readOnly: false, mutationAllowed: false };
    }
    let expectedDigest = null, sequence = 1, previousAnchorDigest = null, anchorType = "genesis";
    if (remote.status === "missing" && marker.status === "present") {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ROLLBACK_SUSPECTED", "External anchor hilang setelah enrollment; genesis baru ditolak", 409);
    }
    if (remote.status === "present") {
      if (policy.revision !== remote.anchor.revision + 1 || policy.previousPolicyDigest !== remote.anchor.policyDigest) {
        throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_CONTINUITY_UNPROVEN", "Root-trust anchor hanya dapat dimajukan satu revision dengan previous digest yang cocok", 409,
          { remoteRevision: remote.anchor.revision, localRevision: policy.revision });
      }
      expectedDigest = remote.anchor.digest; sequence = remote.anchor.anchorSequence + 1; previousAnchorDigest = remote.anchor.digest; anchorType = "advance";
    } else if (!legacyEnrollment && (policy.revision !== 1 || policy.previousPolicyDigest !== null)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_REQUIRED", "Kebijakan historis memerlukan enrollment eksplisit sebelum anchoring", 409);
    }
    if (legacyEnrollment) {
      if (remote.status !== "missing" || marker.status !== "missing") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_BLOCKED", "Legacy enrollment hanya berlaku jika remote anchor dan marker belum ada", 409);
      anchorType = "legacy_enrollment";
    }
    const unsigned = { ownerId: scopeFor(ownerId), sourceOwnerHash: sha256(ownerId), domain: DOMAIN, kind: KIND, schemaVersion: 1,
      anchorSequence: sequence, revision: policy.revision, policyDigest: policy.digest, previousPolicyDigest: policy.previousPolicyDigest ?? null,
      previousAnchorDigest, anchorType, historyNotProven: Boolean(policy.historyNotProven || remote.anchor?.historyNotProven || legacyEnrollment), anchoredAt: now() };
    const candidate = { ...unsigned, digest: digestRecord(unsigned) };
    let result;
    try { result = await provider.compareAndSet(scopeFor(ownerId), expectedDigest, candidate); }
    catch (error) { throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_WRITE_FAILED", "External root-trust anchor gagal ditulis", 502, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
    if (!result?.applied) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_CAS_CONFLICT", "External root-trust anchor berubah bersamaan", 409);
    const reread = await readRemote(ownerId);
    if (reread.status !== "present" || reread.anchor.digest !== candidate.digest) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_VERIFY_FAILED", "External root-trust anchor gagal diverifikasi setelah penulisan", 409);
    await saveMarker(ownerId, candidate);
    return { status: "anchored", trusted: true, ownerId, revision: candidate.revision, policyDigest: candidate.policyDigest,
      anchorSequence: candidate.anchorSequence, anchorDigest: candidate.digest, historyNotProven: candidate.historyNotProven,
      anchorType: candidate.anchorType, readOnly: false, mutationAllowed: false };
  }
  async function reconcile(ownerId, policy) {
    const current = await inspect(ownerId, policy);
    if (current.status === "local_only") return { ...current, reconciled: false, readOnly: false, mutationAllowed: false };
    const remote = await readRemote(ownerId), marker = await readMarker(ownerId);
    if (current.status === "behind_local") return { ...(await advance(ownerId, policy)), reconciled: true, readOnly: false, mutationAllowed: false };
    if (current.status === "rollback_suspected" && remote.status === "present" && marker.status === "missing" && policy) {
      const exact = remote.anchor.revision === policy.revision && remote.anchor.policyDigest === policy.digest;
      const immediate = policy.revision === remote.anchor.revision + 1 && policy.previousPolicyDigest === remote.anchor.policyDigest;
      if (exact || immediate) {
        await saveMarker(ownerId, remote.anchor);
        if (exact) return { ...(await inspect(ownerId, policy)), reconciled: true, markerRepaired: true, readOnly: false, mutationAllowed: false };
        return { ...(await advance(ownerId, policy)), reconciled: true, markerRepaired: true, readOnly: false, mutationAllowed: false };
      }
    }
    throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_RECONCILIATION_BLOCKED", "Root-trust anchor tidak berada pada kondisi yang dapat direkonsiliasi secara aman", 409,
      { status: current.status, finding: current.finding });
  }
  async function prepareEnrollment(ownerId, policy, { reason } = {}) {
    assertOwner(ownerId);
    if (!provider) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_NOT_CONFIGURED", "External root-trust anchor belum dikonfigurasi", 503);
    if (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const state = await inspect(ownerId, policy);
    if (state.status !== "enrollment_required") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_BLOCKED", "Enrollment hanya berlaku untuk kebijakan lama yang belum pernah di-anchor", 409, { status: state.status });
    const createdAt = now(), id = challengeId(), expiresAt = new Date(Date.parse(createdAt) + TTL_MS).toISOString();
    const unsigned = { id, ownerId, kind: ENROLLMENT_KIND, schemaVersion: 1, status: "prepared", expectedPolicyRevision: policy.revision,
      expectedPolicyDigest: policy.digest, reason: reason.trim(), createdAt, expiresAt };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, ownerId, expectedPolicyRevision: policy.revision, expectedPolicyDigest: policy.digest,
      challengeDigest: challenge.digest, createdAt, expiresAt,
      confirmation: `ENROLL ROOT RECOVERY TRUST ANCHOR ${challenge.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function applyEnrollment(ownerId, policy, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== ENROLLMENT_KIND || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_INVALID", "Challenge enrollment root-trust anchor tidak valid", 409);
    }
    if (challenge.status === "used") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_REPLAY", "Challenge enrollment sudah digunakan", 409);
    if (challenge.status !== "prepared" || Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_EXPIRED", "Challenge enrollment kedaluwarsa", 409);
    if (confirmation !== `ENROLL ROOT RECOVERY TRUST ANCHOR ${challenge.digest.slice(0, 12)}`) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_CONFIRMATION_INVALID", "Konfirmasi enrollment tidak cocok", 403);
    if (!policy || policy.revision !== challenge.expectedPolicyRevision || policy.digest !== challenge.expectedPolicyDigest || policy.digest !== digestRecord(policy)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_POLICY_STALE", "Root-trust policy berubah setelah enrollment disiapkan", 409);
    }
    const current = await inspect(ownerId, policy);
    if (current.status !== "enrollment_required") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_STALE", "Keadaan external anchor berubah setelah enrollment disiapkan", 409, { status: current.status });
    const result = await advance(ownerId, policy, { legacyEnrollment: true });
    const used = { ...clean(challenge), status: "used", usedAt: now(), appliedAnchorDigest: result.anchorDigest };
    used.digest = digestRecord(used);
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { ...result, challengeId: id, reason: challenge.reason, readOnly: false, mutationAllowed: false };
  }
  return Object.freeze({ inspectRecoverySloRootRecoveryTrustAnchor: inspect, advanceRecoverySloRootRecoveryTrustAnchor: advance,
    reconcileRecoverySloRootRecoveryTrustAnchor: reconcile, prepareRecoverySloRootRecoveryTrustAnchorEnrollment: prepareEnrollment,
    applyRecoverySloRootRecoveryTrustAnchorEnrollment: applyEnrollment, configured: Boolean(provider), required });
}
