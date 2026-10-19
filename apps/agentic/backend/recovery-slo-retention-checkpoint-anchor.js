import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";

const CHECKPOINT_KIND = "recovery-slo-evidence-retention-policy-checkpoint";
const ANCHOR_KIND = "recovery-slo-evidence-retention-policy-checkpoint-external-anchor";
const MARKER_KIND = "recovery-slo-evidence-retention-policy-checkpoint-anchor-marker";
const DIGEST = /^[a-f0-9]{64}$/;
const MAX_RETRIES = 3;
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
const ownerHash = ownerId => sha256(ownerId).slice(0, 32);
const checkpointScope = ownerId => `retention-checkpoint-${ownerHash(ownerId)}`;
const checkpointIdHash = id => sha256(id).slice(0, 32);
const markerId = ownerId => `recovery-slo-retention-checkpoint-anchor-marker-${ownerHash(ownerId)}`;

function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
  }
}
function validateCheckpoint(checkpoint, ownerId) {
  if (!checkpoint || checkpoint.ownerId !== ownerId || checkpoint.kind !== CHECKPOINT_KIND
    || !Number.isSafeInteger(checkpoint.highWaterRevision) || checkpoint.highWaterRevision < 1
    || !DIGEST.test(checkpoint.highWaterEventHash || "") || !Number.isSafeInteger(checkpoint.retentionDays)
    || checkpoint.retentionDays < 1 || checkpoint.retentionDays > 3650 || !DIGEST.test(checkpoint.digest || "")) {
    return { valid: false, code: "RETENTION_CHECKPOINT_SHAPE_INVALID" };
  }
  const check = digestRecord(checkpoint) === checkpoint.digest;
  return check ? { valid: true } : { valid: false, code: "RETENTION_CHECKPOINT_DIGEST_INVALID" };
}
function validateAnchor(anchor, scope, checkpoint) {
  if (!anchor || anchor.ownerId !== scope || anchor.kind !== ANCHOR_KIND || anchor.schemaVersion !== 1
    || anchor.sourceOwnerHash !== sha256(checkpoint.ownerId) || anchor.checkpointIdHash !== checkpointIdHash(checkpoint.id)
    || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
    || !Number.isSafeInteger(anchor.highWaterRevision) || anchor.highWaterRevision < 1
    || !DIGEST.test(anchor.checkpointDigest || "") || !DIGEST.test(anchor.highWaterEventHash || "")
    || !Number.isSafeInteger(anchor.retentionDays) || anchor.retentionDays < 1 || anchor.retentionDays > 3650
    || !["genesis", "legacy_enrollment", "advance"].includes(anchor.checkpointType)
    || (anchor.previousCheckpointDigest !== null && !DIGEST.test(anchor.previousCheckpointDigest || ""))
    || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
    || !Number.isFinite(Date.parse(anchor.anchoredAt)) || anchor.digest !== digestRecord(anchor)) {
    return { valid: false, code: "RETENTION_EXTERNAL_ANCHOR_INVALID" };
  }
  if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null)
    || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) {
    return { valid: false, code: "RETENTION_EXTERNAL_ANCHOR_CHAIN_INVALID" };
  }
  return { valid: true };
}
function validateMarker(marker, ownerId) {
  if (!marker || marker.ownerId !== ownerId || marker.id !== markerId(ownerId) || marker.kind !== MARKER_KIND
    || marker.schemaVersion !== 1 || !DIGEST.test(marker.anchorDigest || "") || !DIGEST.test(marker.checkpointDigest || "")
    || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1
    || !Number.isSafeInteger(marker.highWaterRevision) || marker.highWaterRevision < 1
    || !Number.isFinite(Date.parse(marker.updatedAt)) || marker.digest !== digestRecord(marker)) {
    return { valid: false, code: "RETENTION_ANCHOR_MARKER_INVALID" };
  }
  return { valid: true };
}

export function createRecoverySloRetentionCheckpointAnchorService({ store, provider = null, required = false,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !provider && required
    || provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function")
    || typeof clock !== "function") {
    throw new TypeError("Retention checkpoint anchor membutuhkan store, provider CAS, dan clock yang valid");
  }
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_CLOCK_INVALID", "Clock retention anchor tidak valid", 500);
    return new Date(ms).toISOString();
  }
  async function readMarker(ownerId) {
    const marker = await store.getEvidence(ownerId, markerId(ownerId));
    if (!marker) return { status: "missing", marker: null };
    const check = validateMarker(marker, ownerId);
    return check.valid ? { status: "present", marker } : { status: "invalid", marker: null, finding: check.code };
  }
  async function saveMarker(ownerId, anchor) {
    const id = markerId(ownerId);
    const current = await store.getEvidence(ownerId, id);
    const unsigned = { id, ownerId, kind: MARKER_KIND, schemaVersion: 1, anchorDigest: anchor.digest,
      checkpointDigest: anchor.checkpointDigest, anchorSequence: anchor.anchorSequence,
      highWaterRevision: anchor.highWaterRevision, updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, current ? { expectedVersion: current._storage?.version } : { overwrite: false });
    const after = await store.getEvidence(ownerId, id);
    if (!validateMarker(after, ownerId).valid || after.anchorDigest !== anchor.digest) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_MARKER_WRITE_FAILED", "Marker lokal retention anchor gagal diverifikasi", 409);
    }
    return after;
  }
  async function readExternal(ownerId, checkpoint) {
    const scope = checkpointScope(ownerId);
    let anchor;
    try { anchor = await provider.read(scope); }
    catch (error) { return { status: "unavailable", anchor: null, scope, finding: error?.code || "EXTERNAL_ANCHOR_READ_FAILED" }; }
    if (anchor == null) return { status: "missing", anchor: null, scope };
    const check = validateAnchor(anchor, scope, checkpoint);
    return check.valid ? { status: "present", anchor, scope } : { status: "invalid", anchor: null, scope, finding: check.code };
  }
  async function status(ownerId, checkpoint) {
    assertOwner(ownerId);
    if (!checkpoint) return { status: "not_initialized", ownerId, readOnly: true, mutationAllowed: false };
    const local = validateCheckpoint(checkpoint, ownerId);
    if (!local.valid) return { status: "local_checkpoint_invalid", ownerId, revision: checkpoint.highWaterRevision ?? null,
      finding: local.code, readOnly: true, mutationAllowed: false };
    if (!provider) return { status: required ? "not_configured" : "not_required", ownerId,
      revision: checkpoint.highWaterRevision, required, readOnly: true, mutationAllowed: false };
    const markerState = await readMarker(ownerId);
    if (markerState.status === "invalid") return { status: "marker_invalid", ownerId, revision: checkpoint.highWaterRevision,
      finding: markerState.finding, readOnly: true, mutationAllowed: false };
    const external = await readExternal(ownerId, checkpoint);
    if (external.status === "unavailable" || external.status === "invalid") return { status: external.status,
      ownerId, revision: checkpoint.highWaterRevision, finding: external.finding, readOnly: true, mutationAllowed: false };
    if (external.status === "missing") {
      if (markerState.status === "present") return { status: "rollback_suspected", ownerId, revision: checkpoint.highWaterRevision,
        markerAnchorSequence: markerState.marker.anchorSequence, finding: "RETENTION_EXTERNAL_ANCHOR_MISSING_AFTER_ENROLLMENT",
        readOnly: true, mutationAllowed: false };
      if (checkpoint.checkpointType === "genesis" && checkpoint.highWaterRevision === 1) return { status: "missing_genesis",
        ownerId, revision: checkpoint.highWaterRevision, checkpointDigest: checkpoint.digest,
        readOnly: true, mutationAllowed: false };
      return { status: "enrollment_required", ownerId, revision: checkpoint.highWaterRevision,
        checkpointDigest: checkpoint.digest, historyNotProven: true,
        finding: "RETENTION_EXTERNAL_ANCHOR_LEGACY_ENROLLMENT_REQUIRED", readOnly: true, mutationAllowed: false };
    }
    const anchor = external.anchor;
    if (markerState.status === "present") {
      const marker = markerState.marker;
      if (marker.anchorSequence > anchor.anchorSequence) return { status: "rollback_suspected", ownerId,
        revision: checkpoint.highWaterRevision, anchorRevision: anchor.highWaterRevision,
        finding: "RETENTION_EXTERNAL_ANCHOR_BEHIND_LOCAL_MARKER", readOnly: true, mutationAllowed: false };
      if (marker.anchorSequence === anchor.anchorSequence && marker.anchorDigest !== anchor.digest) return { status: "mismatch", ownerId,
        revision: checkpoint.highWaterRevision, anchorRevision: anchor.highWaterRevision,
        finding: "RETENTION_EXTERNAL_ANCHOR_MARKER_MISMATCH", readOnly: true, mutationAllowed: false };
      if (marker.anchorSequence < anchor.anchorSequence
        && !(marker.anchorSequence + 1 === anchor.anchorSequence && anchor.previousAnchorDigest === marker.anchorDigest)) {
        return { status: "mismatch", ownerId, revision: checkpoint.highWaterRevision, anchorRevision: anchor.highWaterRevision,
          finding: "RETENTION_EXTERNAL_ANCHOR_MARKER_CONTINUITY_UNPROVEN", readOnly: true, mutationAllowed: false };
      }
    }
    if (anchor.highWaterRevision > checkpoint.highWaterRevision) return { status: "rollback_detected", ownerId,
      revision: checkpoint.highWaterRevision, anchorRevision: anchor.highWaterRevision,
      anchorDigest: anchor.digest, finding: "RETENTION_EXTERNAL_ANCHOR_ROLLBACK_DETECTED", readOnly: true, mutationAllowed: false };
    if (anchor.highWaterRevision === checkpoint.highWaterRevision) {
      const matches = anchor.checkpointDigest === checkpoint.digest && anchor.highWaterEventHash === checkpoint.highWaterEventHash
        && anchor.retentionDays === checkpoint.retentionDays;
      if (!matches) return { status: "mismatch", ownerId, revision: checkpoint.highWaterRevision,
        anchorRevision: anchor.highWaterRevision, finding: "RETENTION_EXTERNAL_ANCHOR_SAME_REVISION_MISMATCH", readOnly: true, mutationAllowed: false };
      return { status: "anchored", ownerId, revision: checkpoint.highWaterRevision,
        anchorRevision: anchor.highWaterRevision, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
        checkpointDigest: checkpoint.digest, retentionDays: anchor.retentionDays, checkpointType: anchor.checkpointType,
        historyNotProven: anchor.checkpointType === "legacy_enrollment",
        readOnly: true, mutationAllowed: false };
    }
    if (checkpoint.highWaterRevision === anchor.highWaterRevision + 1
      && checkpoint.previousCheckpointDigest === anchor.checkpointDigest) {
      return { status: "behind_local", ownerId, revision: checkpoint.highWaterRevision,
        anchorRevision: anchor.highWaterRevision, anchorDigest: anchor.digest,
        checkpointDigest: checkpoint.digest, readOnly: true, mutationAllowed: false };
    }
    return { status: "mismatch", ownerId, revision: checkpoint.highWaterRevision,
      anchorRevision: anchor.highWaterRevision, finding: "RETENTION_EXTERNAL_ANCHOR_CONTINUITY_UNPROVEN",
      readOnly: true, mutationAllowed: false };
  }
  async function writeAnchor(ownerId, checkpoint, previous, { legacyEnrollment = false } = {}) {
    const scope = checkpointScope(ownerId);
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const unsigned = { ownerId: scope, kind: ANCHOR_KIND, schemaVersion: 1,
        sourceOwnerHash: sha256(ownerId), checkpointIdHash: checkpointIdHash(checkpoint.id),
        highWaterRevision: checkpoint.highWaterRevision, checkpointDigest: checkpoint.digest,
        highWaterEventHash: checkpoint.highWaterEventHash, retentionDays: checkpoint.retentionDays,
        checkpointType: legacyEnrollment ? "legacy_enrollment" : checkpoint.checkpointType,
        previousCheckpointDigest: checkpoint.previousCheckpointDigest ?? null,
        anchorSequence: previous ? previous.anchorSequence + 1 : 1,
        previousAnchorDigest: previous?.digest ?? null, anchoredAt: now() };
      const candidate = { ...unsigned, digest: digestRecord(unsigned) };
      let result;
      try { result = await provider.compareAndSet(scope, previous?.digest ?? null, candidate); }
      catch (error) { throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_WRITE_FAILED", "External retention checkpoint anchor gagal ditulis", 503, { cause: error?.code || "PROVIDER_ERROR" }); }
      if (!result?.applied) {
        let observed;
        try { observed = await provider.read(scope); }
        catch (error) { throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_VERIFY_UNAVAILABLE", "External retention anchor tidak dapat dibaca setelah konflik CAS", 503, { cause: error?.code || "PROVIDER_ERROR" }); }
        if (observed?.digest === candidate.digest) { await saveMarker(ownerId, candidate); return { status: "anchored", ownerId, revision: checkpoint.highWaterRevision, anchorDigest: candidate.digest, idempotent: true, historyNotProven: legacyEnrollment }; }
        if (observed) {
          const observedCheck = validateAnchor(observed, scope, checkpoint);
          if (!observedCheck.valid) throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_CONFLICT", "Anchor yang diamati setelah konflik CAS tidak valid", 409, { finding: observedCheck.code });
          if (observed.highWaterRevision === checkpoint.highWaterRevision && observed.checkpointDigest === checkpoint.digest) {
            await saveMarker(ownerId, observed);
            return { status: "anchored", ownerId, revision: checkpoint.highWaterRevision, anchorSequence: observed.anchorSequence,
              anchorDigest: observed.digest, idempotent: true, historyNotProven: observed.checkpointType === "legacy_enrollment" };
          }
          if (!(checkpoint.highWaterRevision === observed.highWaterRevision + 1
            && checkpoint.previousCheckpointDigest === observed.checkpointDigest)) {
            throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_CONFLICT", "Perubahan anchor tidak membuktikan kontinuitas ke checkpoint lokal; pembaruan ditolak", 409);
          }
          previous = observed;
        } else {
          throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_CONFLICT", "Anchor hilang setelah konflik CAS; enrollment ulang ditolak", 409);
        }
        if (attempt + 1 < MAX_RETRIES) continue;
        throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_CAS_CONFLICT", "External retention anchor CAS terus konflik", 409);
      }
      let after;
      try { after = await provider.read(scope); }
      catch (error) { throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_VERIFY_UNAVAILABLE", "Anchor tertulis tetapi pembacaan ulang gagal", 503, { cause: error?.code || "PROVIDER_ERROR" }); }
      const check = validateAnchor(after, scope, checkpoint);
      if (!check.valid || after.digest !== candidate.digest) throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_POSTWRITE_MISMATCH", "External retention anchor gagal diverifikasi setelah penulisan", 409, { finding: check.code || "POSTWRITE_DIGEST_MISMATCH" });
      await saveMarker(ownerId, candidate);
      return { status: "anchored", ownerId, revision: checkpoint.highWaterRevision, anchorRevision: candidate.highWaterRevision,
        anchorSequence: candidate.anchorSequence, anchorDigest: candidate.digest, idempotent: false,
        historyNotProven: legacyEnrollment, readOnly: false, mutationAllowed: false };
    }
    throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_CAS_CONFLICT", "External retention anchor tidak dapat direkonsiliasi", 409);
  }
  async function ensure(ownerId, checkpoint) {
    assertOwner(ownerId);
    if (!provider) {
      if (required) throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_REQUIRED", "External retention checkpoint anchor wajib dikonfigurasi", 503);
      return { status: "not_configured", ownerId, revision: checkpoint.highWaterRevision, readOnly: true, mutationAllowed: false };
    }
    const before = await status(ownerId, checkpoint);
    if (before.status === "anchored") {
      const marker = await readMarker(ownerId);
      if (marker.status === "missing") await saveMarker(ownerId, await provider.read(checkpointScope(ownerId)));
      return { ...before, idempotent: true };
    }
    if (before.status === "missing_genesis") return writeAnchor(ownerId, checkpoint, null);
    if (before.status === "behind_local") {
      const external = await readExternal(ownerId, checkpoint);
      return writeAnchor(ownerId, checkpoint, external.anchor);
    }
    throw new AgenticError(before.status === "enrollment_required" ? "RECOVERY_SLO_RETENTION_ANCHOR_ENROLLMENT_REQUIRED" :
      "RECOVERY_SLO_RETENTION_ANCHOR_NOT_TRUSTED", "Retention checkpoint external anchor belum dapat dipercaya; mutasi ditolak fail-closed", 409,
      { status: before.status, finding: before.finding || null });
  }
  async function anchorLegacy(ownerId, checkpoint, input = {}) {
    assertOwner(ownerId);
    if (!provider) throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_REQUIRED", "External retention checkpoint anchor wajib dikonfigurasi", 503);
    const before = await status(ownerId, checkpoint);
    if (!new Set(["enrollment_required", "missing_genesis"]).has(before.status)) {
      if (before.status === "anchored") return { ...before, idempotent: true };
      throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_NOT_ENROLLABLE", "Keadaan retention checkpoint tidak dapat di-enroll secara aman", 409, { status: before.status });
    }
    const expected = `ANCHOR RETENTION CHECKPOINT ${checkpoint.digest.slice(0, 12)}`;
    if (input.confirmation !== expected) throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_CONFIRMATION_INVALID", "Konfirmasi anchor retention checkpoint tidak cocok", 403);
    if (typeof input.reason !== "string" || input.reason.trim().length < 12 || input.reason.trim().length > 240) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_REASON_INVALID", "Alasan enrollment harus 12–240 karakter", 400);
    }
    return writeAnchor(ownerId, checkpoint, null, { legacyEnrollment: before.status === "enrollment_required" });
  }
  async function reconcile(ownerId, checkpoint) {
    const before = await status(ownerId, checkpoint);
    if (before.status === "anchored") return { ...before, reconciled: true, idempotent: true };
    if (before.status === "behind_local") {
      try { return { ...(await ensure(ownerId, checkpoint)), reconciled: true }; }
      catch (error) { return { status: "blocked", ownerId, reconciled: false, finding: error.code || "RETENTION_ANCHOR_RECONCILIATION_FAILED", reason: "TRUST_CONFLICT_REQUIRES_OPERATOR_REVIEW", readOnly: true, mutationAllowed: false }; }
    }
    return { ...before, reconciled: false, reason: "TRUST_CONFLICT_REQUIRES_OPERATOR_REVIEW", readOnly: true, mutationAllowed: false };
  }
  async function assertTrusted(ownerId, checkpoint) {
    if (!required && !provider) return true;
    await ensure(ownerId, checkpoint);
    const current = await status(ownerId, checkpoint);
    if (current.status !== "anchored") throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_NOT_TRUSTED", "Retention checkpoint tidak memiliki external anchor terkini yang valid", 409, { status: current.status });
    return true;
  }
  return Object.freeze({ getRecoverySloRetentionCheckpointAnchorStatus: status,
    ensureRecoverySloRetentionCheckpointAnchor: ensure,
    anchorRecoverySloRetentionCheckpoint: anchorLegacy,
    reconcileRecoverySloRetentionCheckpointAnchor: reconcile,
    assertRecoverySloRetentionCheckpointAnchorTrusted: assertTrusted,
    configured: Boolean(provider), required });
}
