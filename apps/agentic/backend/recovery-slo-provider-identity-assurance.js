import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";
import { createRecoverySloProviderIdentityTrustPolicyService } from "./recovery-slo-provider-identity-trust-policy.js";

const BASELINE_ANCHOR_KIND = "recovery-slo-provider-identity-baseline-anchor";
const BASELINE_MARKER_KIND = "recovery-slo-provider-identity-baseline-anchor-marker";
const BASELINE_ENROLLMENT_CHALLENGE_KIND = "recovery-slo-provider-identity-baseline-anchor-enrollment-challenge";
const DRIFT_EVENT_DOMAIN = "agentic-v4-provider-identity-drift-event";
const CHAIN_RECOVERY_DOMAIN = "agentic-v4-retained-evidence-chain-recovery-attestation";
const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const CHALLENGE_TTL_MS = 10 * 60 * 1000;
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
  const out = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item);
  return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
const baselineScope = ownerId => `provider-identity-baseline-${ownerHash(ownerId)}`;
const markerId = ownerId => `recovery-slo-provider-identity-baseline-anchor-marker-${ownerHash(ownerId)}`;
const challengeId = () => `recovery-slo-provider-identity-baseline-anchor-enrollment-${randomUUID()}`;
const reportDigest = report => { const copy = clone(report); delete copy.reportDigest; return sha256(canonical(copy)); };
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_ASSURANCE_OWNER_REQUIRED", "Owner provider identity assurance wajib ditentukan", 400);
  }
}
function parsePublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Public key assurance harus Ed25519");
  return key;
}
function makeKeyMap(values, label) {
  const map = new Map();
  if (values instanceof Map) {
    for (const [id, value] of values) {
      if (!KEY_ID.test(String(id))) throw new TypeError(`${label} key ID tidak valid`);
      map.set(String(id), parsePublicKey(value));
    }
  } else if (values && typeof values === "object") {
    for (const [id, value] of Object.entries(values)) {
      if (!KEY_ID.test(id)) throw new TypeError(`${label} key ID tidak valid`);
      map.set(id, parsePublicKey(value));
    }
  }
  return map;
}
function verifyEd25519(key, payload, signature) {
  try {
    if (typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
    const bytes = Buffer.from(signature, "base64url");
    return bytes.length === 64 && bytes.toString("base64url") === signature
      && verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes);
  } catch { return false; }
}
function validateBaselineAnchor(anchor, scope, ownerId) {
  if (!anchor || anchor.ownerId !== scope || anchor.kind !== BASELINE_ANCHOR_KIND || anchor.schemaVersion !== 1
    || anchor.sourceOwnerHash !== sha256(ownerId) || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
    || !Number.isSafeInteger(anchor.revision) || anchor.revision < 1 || anchor.baselineRevision !== anchor.revision
    || !DIGEST.test(anchor.baselineDigest || "") || !DIGEST.test(anchor.snapshotDigest || "")
    || (anchor.previousBaselineDigest !== null && !DIGEST.test(anchor.previousBaselineDigest || ""))
    || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
    || !["genesis", "advance", "legacy_enrollment"].includes(anchor.anchorType)
    || typeof anchor.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(anchor.anchoredAt))
    || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) return { valid: false, code: "PROVIDER_IDENTITY_BASELINE_EXTERNAL_ANCHOR_INVALID" };
  if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null)
    || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) return { valid: false, code: "PROVIDER_IDENTITY_BASELINE_ANCHOR_CHAIN_INVALID" };
  if (anchor.anchorType === "genesis" && (anchor.revision !== 1 || anchor.previousBaselineDigest !== null || anchor.historyNotProven)) {
    return { valid: false, code: "PROVIDER_IDENTITY_BASELINE_GENESIS_INVALID" };
  }
  if (anchor.anchorType === "legacy_enrollment" && !anchor.historyNotProven) return { valid: false, code: "PROVIDER_IDENTITY_BASELINE_LEGACY_FLAG_REQUIRED" };
  return { valid: true };
}
function validateMarker(marker, ownerId) {
  if (!marker || marker.ownerId !== ownerId || marker.id !== markerId(ownerId) || marker.kind !== BASELINE_MARKER_KIND
    || marker.schemaVersion !== 1 || !DIGEST.test(marker.anchorDigest || "") || !DIGEST.test(marker.baselineDigest || "")
    || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1
    || !Number.isSafeInteger(marker.baselineRevision) || marker.baselineRevision < 1
    || !Number.isFinite(Date.parse(marker.updatedAt)) || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker)) {
    return { valid: false, code: "PROVIDER_IDENTITY_BASELINE_ANCHOR_MARKER_INVALID" };
  }
  return { valid: true };
}
function validateSignedEnvelope(ownerId, value, domain, keys) {
  const findings = [];
  if (!value || value.ownerId !== ownerId || value.domain !== domain || value.schemaVersion !== 1
    || !DIGEST.test(value.attestationDigest || "") || !value.signing || value.signing.algorithm !== "Ed25519"
    || !KEY_ID.test(value.signing.keyId || "") || typeof value.signature !== "string") {
    return { valid: false, signatureValid: false, findings: [{ code: "SIGNED_EVIDENCE_SHAPE_INVALID" }] };
  }
  const payload = clone(value);
  delete payload.signature;
  const unsigned = clone(payload);
  delete unsigned.attestationDigest;
  if (sha256(canonical(unsigned)) !== value.attestationDigest) findings.push({ code: "SIGNED_EVIDENCE_DIGEST_INVALID" });
  const key = keys.get(value.signing.keyId);
  const signatureValid = Boolean(key && verifyEd25519(key, payload, value.signature));
  if (!key) findings.push({ code: "SIGNED_EVIDENCE_KEY_UNTRUSTED" });
  else if (!signatureValid) findings.push({ code: "SIGNED_EVIDENCE_SIGNATURE_INVALID" });
  return { valid: findings.length === 0 && signatureValid, signatureValid, findings };
}

export function createRecoverySloProviderIdentityAssuranceService({
  store, provider = null, required = false, clock = () => new Date().toISOString(), identityDriftService,
  retainedEvidenceService, retainedEvidenceChainService, driftSigner = null, driftKeyId = null, driftPublicKeys = null,
  requireSignedDriftEvents = false, recoverySigner = null, recoveryKeyId = null, recoveryPublicKeys = null,
  requireSignedChainRecoveryAttestation = false, policyAuthorityPublicKeys = null, policyAuthorityInitialKeyId = null, policyAuthorityRootRecoveryPublicKeys = null,
  trustPolicyAnchorProvider = null, requireTrustPolicyAnchor = false, rootRecoveryTrustAnchorProvider = null, requireRootRecoveryTrustAnchor = false
} = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function"
    || !identityDriftService?.getRecoverySloAnchorProviderIdentityBaseline || !identityDriftService?.auditRecoverySloAnchorProviderIdentityDrift
    || !retainedEvidenceService?.retainRecoverySloAnchorEvidence || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence
    || !retainedEvidenceChainService?.auditRecoverySloRetainedEvidenceChain || !retainedEvidenceChainService?.verifyRecoverySloRetainedEvidenceChainCheckpoint
    || provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") || !provider && required) {
    throw new TypeError("Provider identity assurance membutuhkan store, baseline service, evidence retention, chain verification, dan provider CAS jika diwajibkan");
  }
  if (requireSignedDriftEvents && (!driftSigner || !driftKeyId || !driftPublicKeys)) throw new TypeError("Signed provider identity drift events diwajibkan tetapi signer dan trusted public keys belum lengkap");
  if ((driftSigner || driftKeyId || driftPublicKeys) && (!driftSigner || !driftKeyId || !driftPublicKeys)) throw new TypeError("Konfigurasi provider identity drift signer harus lengkap");
  if (driftKeyId && !KEY_ID.test(driftKeyId)) throw new TypeError("Provider identity drift key ID tidak valid");
  if (requireSignedChainRecoveryAttestation && (!recoverySigner || !recoveryKeyId || !recoveryPublicKeys)) throw new TypeError("Signed retained-evidence chain recovery attestation diwajibkan tetapi signer dan trusted public keys belum lengkap");
  if ((recoverySigner || recoveryKeyId || recoveryPublicKeys) && (!recoverySigner || !recoveryKeyId || !recoveryPublicKeys)) throw new TypeError("Konfigurasi retained-evidence chain recovery signer harus lengkap");
  if (recoveryKeyId && !KEY_ID.test(recoveryKeyId)) throw new TypeError("Retained-evidence chain recovery key ID tidak valid");
  const driftKeys = makeKeyMap(driftPublicKeys, "Provider identity drift");
  const recoveryKeys = makeKeyMap(recoveryPublicKeys, "Retained-evidence chain recovery");
  const trustPolicyService = createRecoverySloProviderIdentityTrustPolicyService({ store, clock, driftPublicKeys: driftKeys,
    initialDriftKeyId: driftKeyId, recoveryPublicKeys: recoveryKeys, initialRecoveryKeyId: recoveryKeyId, policyAuthorityPublicKeys,
    initialPolicyAuthorityKeyId: policyAuthorityInitialKeyId, policyAuthorityRootRecoveryPublicKeys, trustPolicyAnchorProvider, requireTrustPolicyAnchor,
    rootRecoveryTrustAnchorProvider, requireRootRecoveryTrustAnchor });
  if (driftSigner && !driftKeys.has(driftKeyId)) throw new TypeError("Provider identity drift signing key harus ada di trusted registry");
  if (recoverySigner && !recoveryKeys.has(recoveryKeyId)) throw new TypeError("Recovery attestation signing key harus ada di trusted registry");

  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_ASSURANCE_CLOCK_INVALID", "Clock provider identity assurance tidak valid", 500);
    return new Date(ms).toISOString();
  }
  async function readBaseline(ownerId) {
    const result = await identityDriftService.getRecoverySloAnchorProviderIdentityBaseline(ownerId);
    if (result.status !== "present") return { status: result.status, baseline: null, finding: result.finding || null };
    return { status: "present", baseline: result.baseline };
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
    const unsigned = { id, ownerId, kind: BASELINE_MARKER_KIND, schemaVersion: 1, anchorDigest: anchor.digest,
      baselineDigest: anchor.baselineDigest, baselineRevision: anchor.baselineRevision, anchorSequence: anchor.anchorSequence, updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, current ? { expectedVersion: current._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!validateMarker(saved, ownerId).valid || saved.anchorDigest !== anchor.digest) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_MARKER_WRITE_FAILED", "Marker external baseline anchor gagal diverifikasi", 409);
    }
    return saved;
  }
  async function readExternal(ownerId, baseline) {
    const scope = baselineScope(ownerId);
    let anchor;
    try { anchor = await provider.read(scope); }
    catch (error) { return { status: "unavailable", anchor: null, scope, finding: error?.code || "PROVIDER_READ_FAILED" }; }
    if (!anchor) return { status: "missing", anchor: null, scope };
    const check = validateBaselineAnchor(anchor, scope, ownerId);
    return check.valid ? { status: "present", anchor, scope } : { status: "invalid", anchor: null, scope, finding: check.code };
  }
  async function status(ownerId) {
    assertOwner(ownerId);
    const local = await readBaseline(ownerId);
    if (local.status !== "present") return { status: local.status === "missing" ? "baseline_missing" : "baseline_invalid", ownerId,
      finding: local.finding, readOnly: true, mutationAllowed: false };
    const baseline = local.baseline;
    if (!provider) return { status: required ? "not_configured" : "not_required", ownerId, baselineRevision: baseline.revision,
      baselineDigest: baseline.digest, required, readOnly: true, mutationAllowed: false };
    const markerState = await readMarker(ownerId);
    if (markerState.status === "invalid") return { status: "unhealthy", ownerId, baselineRevision: baseline.revision,
      finding: markerState.finding, readOnly: true, mutationAllowed: false };
    const external = await readExternal(ownerId, baseline);
    if (external.status === "unavailable" || external.status === "invalid") return { status: "unhealthy", ownerId,
      baselineRevision: baseline.revision, finding: external.finding, readOnly: true, mutationAllowed: false };
    if (external.status === "missing") {
      if (markerState.status === "present") return { status: "rollback_suspected", ownerId, baselineRevision: baseline.revision,
        markerRevision: markerState.marker.baselineRevision, finding: "PROVIDER_IDENTITY_BASELINE_ANCHOR_MISSING_AFTER_ENROLLMENT", readOnly: true, mutationAllowed: false };
      if (baseline.revision === 1 && baseline.previousBaselineDigest == null) return { status: "missing_genesis", ownerId,
        baselineRevision: baseline.revision, baselineDigest: baseline.digest, readOnly: true, mutationAllowed: false };
      return { status: "enrollment_required", ownerId, baselineRevision: baseline.revision, baselineDigest: baseline.digest,
        historyNotProven: true, readOnly: true, mutationAllowed: false };
    }
    const anchor = external.anchor;
    if (markerState.status === "present") {
      const marker = markerState.marker;
      if (marker.anchorSequence > anchor.anchorSequence || marker.baselineRevision > anchor.baselineRevision) return { status: "rollback_suspected", ownerId,
        baselineRevision: baseline.revision, anchorRevision: anchor.baselineRevision, finding: "PROVIDER_IDENTITY_BASELINE_ANCHOR_BEHIND_MARKER", readOnly: true, mutationAllowed: false };
      if (marker.anchorSequence === anchor.anchorSequence && marker.anchorDigest !== anchor.digest) return { status: "mismatch", ownerId,
        baselineRevision: baseline.revision, anchorRevision: anchor.baselineRevision, finding: "PROVIDER_IDENTITY_BASELINE_ANCHOR_MARKER_MISMATCH", readOnly: true, mutationAllowed: false };
      if (marker.anchorSequence < anchor.anchorSequence && !(marker.anchorSequence + 1 === anchor.anchorSequence && anchor.previousAnchorDigest === marker.anchorDigest)) {
        return { status: "rollback_suspected", ownerId, baselineRevision: baseline.revision,
          finding: "PROVIDER_IDENTITY_BASELINE_ANCHOR_MARKER_DISCONTINUITY", readOnly: true, mutationAllowed: false };
      }
    } else {
      return { status: "rollback_suspected", ownerId, baselineRevision: baseline.revision,
        finding: "PROVIDER_IDENTITY_BASELINE_ANCHOR_MARKER_MISSING", readOnly: true, mutationAllowed: false };
    }
    if (anchor.baselineRevision > baseline.revision) return { status: "rollback_detected", ownerId, baselineRevision: baseline.revision,
      anchorRevision: anchor.baselineRevision, finding: "PROVIDER_IDENTITY_BASELINE_ROLLBACK_DETECTED", readOnly: true, mutationAllowed: false };
    if (anchor.baselineRevision === baseline.revision) {
      if (anchor.baselineDigest !== baseline.digest || anchor.snapshotDigest !== baseline.snapshotDigest) return { status: "mismatch", ownerId,
        baselineRevision: baseline.revision, anchorRevision: anchor.baselineRevision, finding: "PROVIDER_IDENTITY_BASELINE_DIGEST_MISMATCH", readOnly: true, mutationAllowed: false };
      return { status: "anchored", ownerId, baselineRevision: baseline.revision, baselineDigest: baseline.digest,
        anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, historyNotProven: anchor.historyNotProven, readOnly: true, mutationAllowed: false };
    }
    if (baseline.revision === anchor.baselineRevision + 1 && baseline.previousBaselineDigest === anchor.baselineDigest) {
      return { status: "behind_local", ownerId, baselineRevision: baseline.revision, baselineDigest: baseline.digest,
        anchorRevision: anchor.baselineRevision, anchorDigest: anchor.digest, readOnly: true, mutationAllowed: false };
    }
    return { status: "continuity_unproven", ownerId, baselineRevision: baseline.revision, anchorRevision: anchor.baselineRevision,
      finding: "PROVIDER_IDENTITY_BASELINE_CONTINUITY_UNPROVEN", readOnly: true, mutationAllowed: false };
  }
  async function writeAnchor(ownerId, baseline, { legacyEnrollment = false } = {}) {
    if (!provider) {
      if (required) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_REQUIRED", "External provider identity baseline anchor diwajibkan", 503);
      return { status: "not_required", baselineRevision: baseline.revision };
    }
    const currentStatus = await status(ownerId);
    if (currentStatus.status === "anchored") return currentStatus;
    if (!legacyEnrollment && !["missing_genesis", "behind_local"].includes(currentStatus.status)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_BLOCKED", "Baseline anchor tidak dapat dimajukan tanpa kontinuitas yang terbukti", 409, { finding: currentStatus.status });
    }
    if (legacyEnrollment && currentStatus.status !== "enrollment_required") {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_LEGACY_ENROLLMENT_NOT_APPLICABLE", "Legacy enrollment hanya diizinkan ketika histori anchor tidak tersedia", 409);
    }
    const scope = baselineScope(ownerId);
    let previous = null;
    try { previous = await provider.read(scope); }
    catch (error) { throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_UNAVAILABLE", "External baseline anchor tidak tersedia", 503, { cause: error?.code || "PROVIDER_READ_FAILED" }); }
    if (previous) {
      const check = validateBaselineAnchor(previous, scope, ownerId);
      if (!check.valid) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_INVALID", "External baseline anchor tidak valid", 409, { finding: check.code });
      if (currentStatus.status !== "behind_local" && !legacyEnrollment) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_CONFLICT", "External anchor berubah sejak pemeriksaan status", 409);
      if (currentStatus.status === "behind_local" && (previous.digest !== currentStatus.anchorDigest || previous.baselineRevision !== currentStatus.anchorRevision)) {
        throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_STALE", "External baseline anchor berubah sebelum rekonsiliasi", 409);
      }
    } else if (legacyEnrollment) {
      // Explicit operator enrollment is the only allowed path for an older baseline with no external history.
    } else if (baseline.revision !== 1 || baseline.previousBaselineDigest !== null) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_REQUIRED", "Baseline lama memerlukan enrollment eksternal eksplisit", 409);
    }
    const anchorType = legacyEnrollment ? "legacy_enrollment" : previous ? "advance" : "genesis";
    const unsigned = { ownerId: scope, kind: BASELINE_ANCHOR_KIND, schemaVersion: 1, sourceOwnerHash: sha256(ownerId),
      anchorSequence: previous ? previous.anchorSequence + 1 : 1, revision: baseline.revision, baselineRevision: baseline.revision,
      baselineDigest: baseline.digest, snapshotDigest: baseline.snapshotDigest, previousBaselineDigest: baseline.previousBaselineDigest ?? null,
      previousAnchorDigest: previous?.digest || null, anchorType, historyNotProven: Boolean(legacyEnrollment), anchoredAt: now() };
    const candidate = { ...unsigned, digest: digestRecord(unsigned) };
    let result;
    try { result = await provider.compareAndSet(scope, previous?.digest ?? null, candidate); }
    catch (error) { throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_WRITE_FAILED", "External baseline anchor gagal ditulis", 503, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
    if (!result?.applied) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_CAS_CONFLICT", "External baseline anchor berubah bersamaan", 409);
    let after;
    try { after = await provider.read(scope); }
    catch (error) { throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_VERIFY_UNAVAILABLE", "Pembacaan ulang baseline anchor gagal", 503, { cause: error?.code || "PROVIDER_READ_FAILED" }); }
    if (!validateBaselineAnchor(after, scope, ownerId).valid || after.digest !== candidate.digest) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_POSTWRITE_MISMATCH", "Baseline anchor gagal diverifikasi setelah penulisan", 409);
    await saveMarker(ownerId, after);
    return { status: "anchored", ownerId, baselineRevision: baseline.revision, baselineDigest: baseline.digest,
      anchorSequence: after.anchorSequence, anchorDigest: after.digest, historyNotProven: after.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function anchorCurrentBaseline(ownerId) {
    assertOwner(ownerId);
    const local = await readBaseline(ownerId);
    if (local.status !== "present") throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_NOT_AVAILABLE", "Baseline provider identity tidak tersedia untuk di-anchor", 409);
    return writeAnchor(ownerId, local.baseline);
  }
  async function reconcileBaselineAnchor(ownerId) {
    try { return await anchorCurrentBaseline(ownerId); }
    catch (error) { return { status: "blocked", ownerId, finding: error.code || "PROVIDER_IDENTITY_BASELINE_RECONCILIATION_FAILED",
      message: error.message, readOnly: true, mutationAllowed: false }; }
  }
  async function prepareLegacyEnrollment(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!provider) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_NOT_CONFIGURED", "External baseline anchor belum dikonfigurasi", 503);
    if (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const local = await readBaseline(ownerId);
    if (local.status !== "present") throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_NOT_AVAILABLE", "Baseline tidak tersedia", 409);
    const current = await status(ownerId);
    if (current.status !== "enrollment_required") throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_LEGACY_ENROLLMENT_NOT_APPLICABLE", "Enrollment hanya berlaku jika histori eksternal belum tersedia", 409);
    const createdAt = now();
    const unsigned = { id: challengeId(), ownerId, kind: BASELINE_ENROLLMENT_CHALLENGE_KIND, schemaVersion: 1,
      status: "prepared", expectedBaselineDigest: local.baseline.digest, expectedBaselineRevision: local.baseline.revision,
      reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + CHALLENGE_TTL_MS).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: challenge.id, challengeDigest: challenge.digest, expiresAt: challenge.expiresAt,
      confirmation: `ENROLL PROVIDER IDENTITY BASELINE ANCHOR ${challenge.digest.slice(0, 12)}`, historyNotProven: true,
      readOnly: true, mutationAllowed: false };
  }
  async function applyLegacyEnrollment(ownerId, id, { confirmation, reason = null } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== BASELINE_ENROLLMENT_CHALLENGE_KIND || challenge.schemaVersion !== 1
      || !["prepared", "used"].includes(challenge.status) || challenge.digest !== digestRecord(challenge)) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_CHALLENGE_INVALID", "Challenge enrollment tidak valid", 409);
    if (challenge.status !== "prepared") throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_REPLAY", "Challenge enrollment sudah digunakan", 409);
    if (Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_EXPIRED", "Challenge enrollment kedaluwarsa", 409);
    if (confirmation !== `ENROLL PROVIDER IDENTITY BASELINE ANCHOR ${challenge.digest.slice(0, 12)}`) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_CONFIRMATION_INVALID", "Konfirmasi enrollment tidak cocok", 409);
    if (reason != null && (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240)) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const local = await readBaseline(ownerId);
    if (local.status !== "present" || local.baseline.digest !== challenge.expectedBaselineDigest || local.baseline.revision !== challenge.expectedBaselineRevision) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ENROLLMENT_STALE", "Baseline berubah sejak enrollment disiapkan", 409);
    const result = await writeAnchor(ownerId, local.baseline, { legacyEnrollment: true });
    const usedUnsigned = { ...clean(challenge), status: "used", usedAt: now(), appliedAnchorDigest: result.anchorDigest,
      appliedReason: (reason || challenge.reason).trim() };
    delete usedUnsigned.digest;
    const used = { ...usedUnsigned, digest: digestRecord(usedUnsigned) };
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { ...result, historyNotProven: true, readOnly: false, mutationAllowed: false };
  }
  async function auditAndAttestDrift(ownerId) {
    assertOwner(ownerId);
    const keyPolicy = await trustPolicyService.ensureRecoverySloProviderIdentityTrustPolicy(ownerId, "drift_event");
    const activeDriftKeyId = keyPolicy.status === "healthy" ? keyPolicy.activeKeyId : null;
    if (!driftSigner || !activeDriftKeyId || !driftKeys.has(activeDriftKeyId)) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_SIGNER_NOT_CONFIGURED", "External signer atau active drift key tidak tersedia menurut trust policy", 503);
    let report = await identityDriftService.auditRecoverySloAnchorProviderIdentityDrift(ownerId);
    if (provider) {
      const baselineAnchor = await status(ownerId);
      if (baselineAnchor.status !== "anchored") throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_BASELINE_ANCHOR_UNTRUSTED", "Signed drift event tidak dapat diterbitkan ketika baseline anchor tidak tepercaya", 409, { status: baselineAnchor.status });
      const { reportDigest: _oldDigest, ...withoutDigest } = report;
      report = { ...withoutDigest, baselineAnchor: { status: baselineAnchor.status, baselineRevision: baselineAnchor.baselineRevision,
        baselineDigest: baselineAnchor.baselineDigest, anchorSequence: baselineAnchor.anchorSequence, anchorDigest: baselineAnchor.anchorDigest } };
      report.reportDigest = sha256(canonical(report));
    }
    if (report.status !== "drift_detected") return { status: "no_drift_event", report, readOnly: true, mutationAllowed: false };
    if (!DIGEST.test(report.reportDigest || "") || reportDigest(report) !== report.reportDigest) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_REPORT_INVALID", "Digest laporan drift tidak valid", 409);
    const sourceId = report.reportDigest;
    const existing = (await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 200, includePayload: true })).items
      .find(item => item.artifactType === "provider_identity_drift_event" && item.sourceId === sourceId && item.status === "retained");
    if (existing) {
      const verification = await verifyDriftEvent(ownerId, existing.payload);
      if (!verification.valid) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_RETAINED_EVENT_INVALID", "Drift event yang tersimpan tidak valid", 409);
      return { status: "signed", event: existing.payload, retention: { id: existing.id, status: existing.status, idempotent: true }, readOnly: true, mutationAllowed: false };
    }
    const issuedAt = now();
    const unsignedBase = { domain: DRIFT_EVENT_DOMAIN, schemaVersion: 1, eventId: `provider-identity-drift-${ownerHash(ownerId)}-${sourceId.slice(0, 24)}`,
      ownerId, eventType: "provider_identity_drift_detected", issuedAt, reportDigest: report.reportDigest, report,
      signing: { algorithm: "Ed25519", keyId: activeDriftKeyId }, claims: { driftReportBound: true, baselineMutationAuthorized: false } };
    const payload = { ...unsignedBase, attestationDigest: sha256(canonical(unsignedBase)) };
    let signed;
    try { signed = await driftSigner(clone(payload)); }
    catch { throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_SIGNER_FAILED", "External signer provider identity drift gagal", 502); }
    const signature = typeof signed === "string" ? signed : signed?.signature;
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== activeDriftKeyId) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID yang berbeda", 502);
    if (!verifyEd25519(driftKeys.get(activeDriftKeyId), payload, signature)) throw new AgenticError("RECOVERY_SLO_PROVIDER_DRIFT_SIGNATURE_INVALID", "Signature drift event tidak cocok dengan trusted public key", 502);
    const event = { ...payload, signature };
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: "provider_identity_drift_event", sourceId, payload: event });
    return { status: "signed", event, retention, readOnly: true, mutationAllowed: false };
  }
  async function verifyDriftEvent(ownerId, event) {
    assertOwner(ownerId);
    const envelope = validateSignedEnvelope(ownerId, event, DRIFT_EVENT_DOMAIN, driftKeys);
    const findings = [...envelope.findings];
    if (!event?.report || event.report.ownerId !== ownerId || event.eventType !== "provider_identity_drift_detected"
      || event.eventId !== `provider-identity-drift-${ownerHash(ownerId)}-${event.reportDigest?.slice(0, 24)}`
      || event.report.status !== "drift_detected" || event.reportDigest !== event.report.reportDigest
      || reportDigest(event.report) !== event.reportDigest || !Number.isFinite(Date.parse(event.issuedAt))) {
      findings.push({ code: "PROVIDER_IDENTITY_DRIFT_REPORT_BINDING_INVALID" });
    }
    const trust = await trustPolicyService.evaluateRecoverySloProviderIdentityTrustSignature(ownerId, "drift_event", event?.signing?.keyId, event?.issuedAt);
    if (!trust.trusted) findings.push({ code: "PROVIDER_IDENTITY_DRIFT_KEY_POLICY_REJECTED", detail: trust.finding });
    const valid = envelope.valid && trust.trusted && findings.length === 0;
    return { valid, signatureValid: envelope.signatureValid, keyPolicyTrusted: trust.trusted, keyPolicyFinding: trust.finding,
      keyPolicyRevision: trust.policyRevision || null, historyNotProven: trust.historyNotProven ?? null, findings, signedEventIsApproval: false, readOnly: true, mutationAllowed: false };
  }
  async function attestChainRecovery(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    const keyPolicy = await trustPolicyService.ensureRecoverySloProviderIdentityTrustPolicy(ownerId, "recovery_attestation");
    const activeRecoveryKeyId = keyPolicy.status === "healthy" ? keyPolicy.activeKeyId : null;
    if (!recoverySigner || !activeRecoveryKeyId || !recoveryKeys.has(activeRecoveryKeyId)) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECOVERY_SIGNER_NOT_CONFIGURED", "External signer atau active recovery key tidak tersedia menurut trust policy", 503);
    if (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECOVERY_REASON_INVALID", "Alasan recovery attestation wajib 12–240 karakter", 400);
    const audit = await retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId);
    if (!["healthy", "local_only"].includes(audit.status)) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECOVERY_NOT_HEALTHY", "Chain harus sehat sebelum recovery attestation diterbitkan", 409, { status: audit.status });
    if (audit.sequence < 1 || !DIGEST.test(audit.headDigest || "")) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECOVERY_SNAPSHOT_INVALID", "Chain belum memiliki checkpoint yang dapat di-attest", 409);
    const issuedAt = now();
    const snapshot = { status: audit.status, sequence: audit.sequence, headDigest: audit.headDigest,
      anchorStatus: audit.anchor?.status || "unknown", anchorSequence: audit.anchor?.anchorSequence || null,
      anchorDigest: audit.anchor?.anchorDigest || null, auditedAt: issuedAt,
      claims: { hashChainValidated: true, externalAnchorVerified: audit.anchor?.status === "anchored", recoveryMutationAuthorized: false } };
    const unsignedBase = { domain: CHAIN_RECOVERY_DOMAIN, schemaVersion: 1,
      attestationId: `retained-evidence-chain-recovery-${ownerHash(ownerId)}-${randomUUID()}`, ownerId, issuedAt,
      reason: reason.trim(), snapshot, signing: { algorithm: "Ed25519", keyId: activeRecoveryKeyId } };
    const payload = { ...unsignedBase, attestationDigest: sha256(canonical(unsignedBase)) };
    let signed;
    try { signed = await recoverySigner(clone(payload)); }
    catch { throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECOVERY_SIGNER_FAILED", "External signer chain recovery gagal", 502); }
    const signature = typeof signed === "string" ? signed : signed?.signature;
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== activeRecoveryKeyId) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECOVERY_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID yang berbeda", 502);
    if (!verifyEd25519(recoveryKeys.get(activeRecoveryKeyId), payload, signature)) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECOVERY_SIGNATURE_INVALID", "Signature recovery attestation tidak cocok dengan trusted public key", 502);
    const attestation = { ...payload, signature };
    const sourceId = `${snapshot.sequence}:${snapshot.headDigest}`;
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: "retained_evidence_chain_recovery_attestation", sourceId, payload: attestation });
    return { status: "signed", attestation, retention, readOnly: true, mutationAllowed: false };
  }
  async function verifyChainRecovery(ownerId, attestation) {
    assertOwner(ownerId);
    const envelope = validateSignedEnvelope(ownerId, attestation, CHAIN_RECOVERY_DOMAIN, recoveryKeys);
    const findings = [...envelope.findings];
    if (!attestation?.snapshot || !Number.isSafeInteger(attestation.snapshot.sequence) || attestation.snapshot.sequence < 1
      || !DIGEST.test(attestation.snapshot.headDigest || "") || !["healthy", "local_only"].includes(attestation.snapshot.status)) {
      findings.push({ code: "RECOVERY_ATTESTATION_SNAPSHOT_INVALID" });
    }
    let checkpoint = { valid: false };
    let currentAudit = null;
    let retained = false;
    if (!findings.some(item => item.code === "RECOVERY_ATTESTATION_SNAPSHOT_INVALID")) {
      checkpoint = await retainedEvidenceChainService.verifyRecoverySloRetainedEvidenceChainCheckpoint(ownerId,
        { sequence: attestation.snapshot.sequence, headDigest: attestation.snapshot.headDigest });
      currentAudit = await retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId);
      const records = (await store.listEvidence(ownerId)).filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record");
      retained = records.some(item => item.artifactType === "retained_evidence_chain_recovery_attestation" && item.status === "retained"
        && item.payload?.attestationId === attestation.attestationId && item.payload?.attestationDigest === attestation.attestationDigest);
      if (!checkpoint.valid) findings.push({ code: "RECOVERY_ATTESTATION_CHECKPOINT_NOT_IN_CHAIN" });
      if (!retained) findings.push({ code: "RECOVERY_ATTESTATION_NOT_RETAINED" });
      if (!currentAudit || !["healthy", "local_only"].includes(currentAudit.status)) findings.push({ code: "RECOVERY_ATTESTATION_CURRENT_CHAIN_UNHEALTHY" });
    }
    const trust = await trustPolicyService.evaluateRecoverySloProviderIdentityTrustSignature(ownerId, "recovery_attestation", attestation?.signing?.keyId, attestation?.issuedAt);
    if (!trust.trusted) findings.push({ code: "RECOVERY_ATTESTATION_KEY_POLICY_REJECTED", detail: trust.finding });
    const valid = envelope.valid && trust.trusted && checkpoint.valid && retained && currentAudit && ["healthy", "local_only"].includes(currentAudit.status) && findings.length === 0;
    return { valid, signatureValid: envelope.signatureValid, keyPolicyTrusted: trust.trusted, keyPolicyFinding: trust.finding,
      keyPolicyRevision: trust.policyRevision || null, historyNotProven: trust.historyNotProven ?? null, checkpointValid: Boolean(checkpoint.valid), retained,
      currentChainStatus: currentAudit?.status || null, findings, readOnly: true, mutationAllowed: false };
  }
  async function auditAssuranceEvidence(ownerId) {
    assertOwner(ownerId);
    const retentionAudit = await retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId);
    const records = (await store.listEvidence(ownerId)).filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record" && item.status === "retained");
    const findings = [...(retentionAudit.findings || [])];
    if (driftKeyId && driftKeys.size) {
      const trustAudit = await trustPolicyService.auditRecoverySloProviderIdentityTrustPolicy(ownerId, "drift_event");
      if (trustAudit.status !== "healthy") findings.push({ code: "PROVIDER_IDENTITY_DRIFT_TRUST_POLICY_UNHEALTHY", detail: trustAudit.findings[0]?.code || null });
    }
    if (recoveryKeyId && recoveryKeys.size) {
      const trustAudit = await trustPolicyService.auditRecoverySloProviderIdentityTrustPolicy(ownerId, "recovery_attestation");
      if (trustAudit.status !== "healthy") findings.push({ code: "RECOVERY_ATTESTATION_TRUST_POLICY_UNHEALTHY", detail: trustAudit.findings[0]?.code || null });
    }
    for (const record of records) {
      if (record.artifactType === "provider_identity_drift_event") {
        const checked = await verifyDriftEvent(ownerId, record.payload);
        if (!checked.valid) findings.push({ code: "PROVIDER_IDENTITY_DRIFT_EVENT_SIGNATURE_INVALID", id: record.id, detail: checked.findings[0]?.code || null });
      } else if (record.artifactType === "retained_evidence_chain_recovery_attestation") {
        const checked = await verifyChainRecovery(ownerId, record.payload);
        if (!checked.valid) findings.push({ code: "RETAINED_EVIDENCE_CHAIN_RECOVERY_ATTESTATION_INVALID", id: record.id, detail: checked.findings[0]?.code || null });
      }
    }
    return { status: findings.length ? "unhealthy" : retentionAudit.status, ownerId, total: records.length, findings,
      chainStatus: retentionAudit.chain?.status || null, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({
    getRecoverySloProviderIdentityBaselineAnchorStatus: status,
    anchorRecoverySloProviderIdentityBaseline: anchorCurrentBaseline,
    reconcileRecoverySloProviderIdentityBaselineAnchor: reconcileBaselineAnchor,
    prepareRecoverySloProviderIdentityBaselineAnchorEnrollment: prepareLegacyEnrollment,
    applyRecoverySloProviderIdentityBaselineAnchorEnrollment: applyLegacyEnrollment,
    attestRecoverySloAnchorProviderIdentityDrift: auditAndAttestDrift,
    verifyRecoverySloAnchorProviderIdentityDriftEvent: verifyDriftEvent,
    attestRecoverySloRetainedEvidenceChainRecovery: attestChainRecovery,
    verifyRecoverySloRetainedEvidenceChainRecoveryAttestation: verifyChainRecovery,
    auditRecoverySloProviderIdentityAssuranceEvidence: auditAssuranceEvidence,
    getRecoverySloProviderIdentityTrustPolicy: trustPolicyService.getRecoverySloProviderIdentityTrustPolicy,
    ensureRecoverySloProviderIdentityTrustPolicy: trustPolicyService.ensureRecoverySloProviderIdentityTrustPolicy,
    auditRecoverySloProviderIdentityTrustPolicy: trustPolicyService.auditRecoverySloProviderIdentityTrustPolicy,
    prepareRecoverySloProviderIdentityTrustKeyTransition: trustPolicyService.prepareRecoverySloProviderIdentityTrustKeyTransition,
    applyRecoverySloProviderIdentityTrustKeyTransition: trustPolicyService.applyRecoverySloProviderIdentityTrustKeyTransition,
    getRecoverySloProviderIdentityTrustPolicyAnchorStatus: trustPolicyService.getRecoverySloProviderIdentityTrustPolicyAnchorStatus,
    reconcileRecoverySloProviderIdentityTrustPolicyAnchor: trustPolicyService.reconcileRecoverySloProviderIdentityTrustPolicyAnchor,
    enrollRecoverySloProviderIdentityTrustPolicyAnchor: trustPolicyService.enrollRecoverySloProviderIdentityTrustPolicyAnchor,
    ensureRecoverySloProviderIdentityPolicyAuthority: trustPolicyService.ensureRecoverySloProviderIdentityPolicyAuthority,
    prepareRecoverySloProviderIdentityPolicyAuthorityTransition: trustPolicyService.prepareRecoverySloProviderIdentityPolicyAuthorityTransition,
    applyRecoverySloProviderIdentityPolicyAuthorityTransition: trustPolicyService.applyRecoverySloProviderIdentityPolicyAuthorityTransition,
    prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery: trustPolicyService.prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery,
    applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery: trustPolicyService.applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery,
    auditRecoverySloProviderIdentityPolicyAuthority: trustPolicyService.auditRecoverySloProviderIdentityPolicyAuthority,
    enrollRecoverySloProviderIdentityPolicyAuthorityAnchor: trustPolicyService.enrollRecoverySloProviderIdentityPolicyAuthorityAnchor,
    evaluateRecoverySloProviderIdentityPolicyAuthoritySignature: trustPolicyService.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature,
    verifyRecoverySloProviderIdentityPolicyAuthorityHistoricalAuthorization: trustPolicyService.verifyRecoverySloProviderIdentityPolicyAuthorityHistoricalAuthorization,
    ensureRecoverySloRootRecoveryTrust: trustPolicyService.ensureRecoverySloRootRecoveryTrust,
    prepareRecoverySloRootRecoveryTrustTransition: trustPolicyService.prepareRecoverySloRootRecoveryTrustTransition,
    applyRecoverySloRootRecoveryTrustTransition: trustPolicyService.applyRecoverySloRootRecoveryTrustTransition,
    auditRecoverySloRootRecoveryTrust: trustPolicyService.auditRecoverySloRootRecoveryTrust,
    evaluateRecoverySloRootRecoveryTrustKey: trustPolicyService.evaluateRecoverySloRootRecoveryTrustKey,
    getRecoverySloRootRecoveryTrustAnchorStatus: trustPolicyService.getRecoverySloRootRecoveryTrustAnchorStatus,
    reconcileRecoverySloRootRecoveryTrustAnchor: trustPolicyService.reconcileRecoverySloRootRecoveryTrustAnchor,
    prepareRecoverySloRootRecoveryTrustAnchorEnrollment: trustPolicyService.prepareRecoverySloRootRecoveryTrustAnchorEnrollment,
    applyRecoverySloRootRecoveryTrustAnchorEnrollment: trustPolicyService.applyRecoverySloRootRecoveryTrustAnchorEnrollment,
    providerConfigured: Boolean(provider), required, configuredDriftSigner: Boolean(driftSigner), configuredRecoverySigner: Boolean(recoverySigner)
  });
}
