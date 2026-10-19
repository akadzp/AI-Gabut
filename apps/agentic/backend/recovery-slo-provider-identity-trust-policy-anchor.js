import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const KIND = "recovery-slo-provider-identity-trust-policy-external-anchor";
const MARKER_KIND = "recovery-slo-provider-identity-trust-policy-anchor-marker";
const ENROLLMENT_KIND = "recovery-slo-provider-identity-trust-policy-anchor-enrollment";
const DIGEST = /^[a-f0-9]{64}$/;
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
const scopeFor = (ownerId, domain) => `provider-identity-trust-policy-${ownerHash(ownerId)}-${domain}`;
const markerId = (ownerId, domain) => `recovery-slo-provider-identity-trust-policy-anchor-marker-${ownerHash(ownerId)}-${domain}`;
const enrollmentId = () => `recovery-slo-provider-identity-trust-policy-anchor-enrollment-${randomUUID()}`;

function validOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_OWNER_REQUIRED", "Owner trust-policy anchor wajib ditentukan", 400);
  }
}
function validDomain(domain) {
  if (!/^(drift_event|recovery_attestation|policy_authority)$/.test(String(domain))) {
    throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_DOMAIN_INVALID", "Trust-policy anchor domain tidak valid", 400);
  }
}
function validateAnchor(anchor, ownerId, domain) {
  const scope = scopeFor(ownerId, domain);
  if (!anchor || anchor.ownerId !== scope || anchor.sourceOwnerHash !== sha256(ownerId) || anchor.domain !== domain
    || anchor.kind !== KIND || anchor.schemaVersion !== 1 || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
    || !Number.isSafeInteger(anchor.revision) || anchor.revision < 1 || !DIGEST.test(anchor.policyDigest || "")
    || (anchor.previousPolicyDigest !== null && !DIGEST.test(anchor.previousPolicyDigest || ""))
    || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
    || !["genesis", "advance", "legacy_enrollment"].includes(anchor.anchorType)
    || typeof anchor.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(anchor.anchoredAt))
    || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) {
    return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_EXTERNAL_ANCHOR_INVALID" };
  }
  if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null)
    || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) {
    return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_ANCHOR_CHAIN_INVALID" };
  }
  if (anchor.anchorType === "genesis" && (anchor.anchorSequence !== 1 || anchor.revision !== 1 || anchor.previousPolicyDigest !== null)) {
    return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_ANCHOR_GENESIS_INVALID" };
  }
  if (anchor.anchorType === "legacy_enrollment" && !anchor.historyNotProven) {
    return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_ANCHOR_LEGACY_FLAG_REQUIRED" };
  }
  return { valid: true };
}

export function createRecoverySloProviderIdentityTrustPolicyAnchorService({ store, provider = null, required = false,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || typeof clock !== "function"
    || provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") || required && !provider) {
    throw new TypeError("Trust-policy external anchoring membutuhkan evidence store, clock, dan provider CAS jika diwajibkan");
  }
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_CLOCK_INVALID", "Clock trust-policy anchor tidak valid", 500);
    return new Date(time).toISOString();
  }
  function requireProvider() {
    if (!provider || typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") {
      if (required) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_UNAVAILABLE", "External trust-policy anchor wajib tersedia", 503);
      return false;
    }
    return true;
  }
  async function readMarker(ownerId, domain) {
    const marker = await store.getEvidence(ownerId, markerId(ownerId, domain));
    if (!marker) return { status: "missing", marker: null };
    if (marker.ownerId !== ownerId || marker.domain !== domain || marker.kind !== MARKER_KIND || marker.schemaVersion !== 1
      || !DIGEST.test(marker.anchorDigest || "") || !DIGEST.test(marker.policyDigest || "")
      || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1
      || !Number.isSafeInteger(marker.revision) || marker.revision < 1 || !Number.isFinite(Date.parse(marker.updatedAt))
      || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker)) {
      return { status: "invalid", marker: null, finding: "PROVIDER_IDENTITY_TRUST_POLICY_ANCHOR_MARKER_INVALID" };
    }
    return { status: "present", marker };
  }
  async function saveMarker(ownerId, domain, anchor) {
    const id = markerId(ownerId, domain);
    const old = await store.getEvidence(ownerId, id);
    const unsigned = { id, ownerId, domain, kind: MARKER_KIND, schemaVersion: 1, anchorDigest: anchor.digest,
      policyDigest: anchor.policyDigest, revision: anchor.revision, anchorSequence: anchor.anchorSequence, updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, old ? { expectedVersion: old._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!saved || saved.digest !== marker.digest || saved.digest !== digestRecord(saved)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_MARKER_WRITE_FAILED", "Marker trust-policy anchor gagal diverifikasi", 409);
    }
    return saved;
  }
  async function readExternal(ownerId, domain) {
    const scope = scopeFor(ownerId, domain);
    try {
      const anchor = await provider.read(scope);
      if (!anchor) return { status: "missing", anchor: null, scope };
      const check = validateAnchor(anchor, ownerId, domain);
      if (!check.valid) return { status: "invalid", anchor: null, scope, finding: check.code };
      return { status: "present", anchor, scope };
    } catch (error) {
      return { status: "unavailable", anchor: null, scope, finding: error?.code || "PROVIDER_READ_FAILED" };
    }
  }
  async function inspect(ownerId, domain, policy) {
    validOwner(ownerId); validDomain(domain);
    if (!requireProvider()) return { status: required ? "unavailable" : "local_only", required, trusted: !required,
      ownerId, domain, revision: policy?.revision ?? null, policyDigest: policy?.digest ?? null, anchorSequence: null, anchorDigest: null,
      finding: required ? "EXTERNAL_TRUST_POLICY_ANCHOR_REQUIRED" : "EXTERNAL_TRUST_POLICY_ANCHOR_NOT_CONFIGURED" };
    const [remote, local] = await Promise.all([readExternal(ownerId, domain), readMarker(ownerId, domain)]);
    if (local.status === "invalid") return { status: "unhealthy", required, trusted: false, ownerId, domain, finding: local.finding };
    if (remote.status === "unavailable") return { status: "unavailable", required, trusted: false, ownerId, domain, finding: remote.finding };
    if (remote.status === "invalid") return { status: "unhealthy", required, trusted: false, ownerId, domain, finding: remote.finding };
    if (remote.status === "missing") {
      const status = local.status === "present" ? "rollback_suspected" : "enrollment_required";
      return { status, required, trusted: false, ownerId, domain, revision: policy?.revision ?? null,
        policyDigest: policy?.digest ?? null, anchorSequence: null, anchorDigest: null,
        finding: status === "rollback_suspected" ? "EXTERNAL_TRUST_POLICY_ANCHOR_MISSING_AFTER_ENROLLMENT" : "EXTERNAL_TRUST_POLICY_ANCHOR_ENROLLMENT_REQUIRED" };
    }
    const anchor = remote.anchor;
    if (local.status === "present") {
      if (anchor.anchorSequence < local.marker.anchorSequence) return { status: "rollback_suspected", required, trusted: false, ownerId, domain,
        revision: anchor.revision, policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
        finding: "EXTERNAL_TRUST_POLICY_ANCHOR_BEHIND_LOCAL_MARKER" };
      if (anchor.anchorSequence === local.marker.anchorSequence && anchor.digest !== local.marker.anchorDigest) return { status: "mismatch", required, trusted: false,
        ownerId, domain, revision: anchor.revision, policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence,
        anchorDigest: anchor.digest, finding: "EXTERNAL_TRUST_POLICY_ANCHOR_MARKER_MISMATCH" };
    }
    if (!policy) return { status: "anchored", required, trusted: true, ownerId, domain, revision: anchor.revision,
      policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      historyNotProven: anchor.historyNotProven, finding: null };
    if (anchor.revision === policy.revision && anchor.policyDigest === policy.digest) {
      if (local.status === "missing") return { status: "rollback_suspected", required, trusted: false, ownerId, domain,
        revision: anchor.revision, policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
        finding: "EXTERNAL_TRUST_POLICY_ANCHOR_LOCAL_MARKER_MISSING" };
      if (local.marker.revision !== anchor.revision || local.marker.policyDigest !== anchor.policyDigest) return { status: "mismatch", required, trusted: false,
        ownerId, domain, revision: anchor.revision, policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence,
        anchorDigest: anchor.digest, finding: "EXTERNAL_TRUST_POLICY_ANCHOR_MARKER_POLICY_MISMATCH" };
      return { status: "anchored", required, trusted: true, ownerId, domain, revision: anchor.revision,
        policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
        historyNotProven: anchor.historyNotProven, finding: null };
    }
    if (anchor.revision > policy.revision) return { status: "rollback_detected", required, trusted: false, ownerId, domain,
      revision: anchor.revision, policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      finding: "LOCAL_TRUST_POLICY_BEHIND_EXTERNAL_ANCHOR" };
    const immediate = policy.revision === anchor.revision + 1 && policy.previousPolicyDigest === anchor.policyDigest;
    return { status: immediate ? "behind_local" : "continuity_unproven", required, trusted: false, ownerId, domain,
      revision: anchor.revision, policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      finding: immediate ? "EXTERNAL_TRUST_POLICY_ANCHOR_ADVANCEMENT_PENDING" : "EXTERNAL_TRUST_POLICY_ANCHOR_CONTINUITY_UNPROVEN" };
  }
  async function advance(ownerId, domain, policy, { previousPolicy = null, genesis = false, legacyEnrollment = false } = {}) {
    validOwner(ownerId); validDomain(domain);
    if (!requireProvider()) return { status: required ? "unavailable" : "local_only", trusted: !required, required };
    const scope = scopeFor(ownerId, domain);
    const remote = await readExternal(ownerId, domain);
    if (remote.status === "unavailable") throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_UNAVAILABLE", "External trust-policy anchor tidak tersedia", 503);
    if (remote.status === "invalid") throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_INVALID", "External trust-policy anchor tidak valid", 409, { finding: remote.finding });
    const current = remote.anchor;
    let anchorType;
    let expectedDigest;
    let previousAnchorDigest;
    let sequence;
    let previousPolicyDigest;
    let historyNotProven = false;
    if (!current) {
      if (genesis) {
        if (policy.revision !== 1 || policy.previousPolicyDigest !== null) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_GENESIS_INVALID", "Genesis trust policy harus revision pertama", 409);
        anchorType = "genesis"; expectedDigest = null; previousAnchorDigest = null; sequence = 1; previousPolicyDigest = null;
        historyNotProven = policy.historyNotProven === true;
      } else if (legacyEnrollment) {
        anchorType = "legacy_enrollment"; expectedDigest = null; previousAnchorDigest = null; sequence = 1;
        previousPolicyDigest = policy.previousPolicyDigest ?? null; historyNotProven = true;
      } else throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_ENROLLMENT_REQUIRED", "Trust policy belum memiliki external anchor; enrollment eksplisit diperlukan", 409);
    } else {
      const marker = await readMarker(ownerId, domain);
      if (marker.status !== "present" || marker.marker.anchorDigest !== current.digest || marker.marker.anchorSequence !== current.anchorSequence) {
        throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_MARKER_MISMATCH", "Marker lokal tidak cocok dengan external trust-policy anchor", 409);
      }
      if (!previousPolicy || current.policyDigest !== previousPolicy.digest || current.revision !== previousPolicy.revision
        || policy.revision !== previousPolicy.revision + 1 || policy.previousPolicyDigest !== previousPolicy.digest) {
        throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_CONTINUITY_UNPROVEN", "Transisi trust policy tidak berurutan dengan external anchor", 409);
      }
      anchorType = "advance"; expectedDigest = current.digest; previousAnchorDigest = current.digest;
      sequence = current.anchorSequence + 1; previousPolicyDigest = current.policyDigest; historyNotProven = current.historyNotProven === true;
    }
    const unsigned = { ownerId: scope, sourceOwnerHash: sha256(ownerId), domain, kind: KIND, schemaVersion: 1,
      anchorSequence: sequence, revision: policy.revision, policyDigest: policy.digest, previousPolicyDigest,
      previousAnchorDigest, anchorType, historyNotProven, anchoredAt: now() };
    const candidate = { ...unsigned, digest: digestRecord(unsigned) };
    let result;
    try { result = await provider.compareAndSet(scope, expectedDigest, candidate); }
    catch (error) { throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_WRITE_FAILED", "External trust-policy anchor gagal ditulis", 502, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
    if (!result?.applied) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_CAS_CONFLICT", "External trust-policy anchor berubah bersamaan", 409);
    const reread = await readExternal(ownerId, domain);
    if (reread.status !== "present" || reread.anchor.digest !== candidate.digest) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_VERIFY_FAILED", "External trust-policy anchor gagal diverifikasi setelah penulisan", 409);
    await saveMarker(ownerId, domain, candidate);
    return { status: "anchored", required, trusted: true, ownerId, domain, revision: candidate.revision,
      policyDigest: candidate.policyDigest, anchorSequence: candidate.anchorSequence, anchorDigest: candidate.digest,
      historyNotProven: candidate.historyNotProven, anchorType: candidate.anchorType };
  }
  async function status(ownerId, domain, policy) {
    validOwner(ownerId); validDomain(domain);
    if (!policy) return { status: "not_initialized", required, trusted: false, ownerId, domain, readOnly: true, mutationAllowed: false };
    const result = await inspect(ownerId, domain, policy);
    return { ...result, readOnly: true, mutationAllowed: false };
  }
  async function reconcile(ownerId, domain, policy) {
    validOwner(ownerId); validDomain(domain);
    if (!policy) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_NOT_INITIALIZED", "Trust policy belum diinisialisasi", 409);
    const current = await inspect(ownerId, domain, policy);
    if (current.status === "local_only") return { ...current, reconciled: false, readOnly: false, mutationAllowed: false };
    if (current.status === "rollback_suspected") {
      const [remote, local] = await Promise.all([readExternal(ownerId, domain), readMarker(ownerId, domain)]);
      if (remote.status === "present" && local.status === "missing") {
        const anchor = remote.anchor;
        const exact = anchor.revision === policy.revision && anchor.policyDigest === policy.digest;
        const immediate = policy.revision === anchor.revision + 1 && policy.previousPolicyDigest === anchor.policyDigest;
        if (exact || immediate) {
          await saveMarker(ownerId, domain, anchor);
          if (exact) return { status: "anchored", trusted: true, required, ownerId, domain, revision: anchor.revision,
            policyDigest: anchor.policyDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
            historyNotProven: anchor.historyNotProven, reconciled: true, markerRepaired: true, readOnly: false, mutationAllowed: false };
          const result = await advance(ownerId, domain, policy, { previousPolicy: { revision: anchor.revision, digest: anchor.policyDigest } });
          return { ...result, reconciled: true, markerRepaired: true, readOnly: false, mutationAllowed: false };
        }
      }
      throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_RECONCILIATION_BLOCKED", "Marker hilang tidak dapat direkonstruksi dari anchor remote yang cocok; pemulihan otomatis ditolak", 409,
        { status: current.status, finding: current.finding });
    }
    if (current.status !== "behind_local") throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_RECONCILIATION_BLOCKED", "Trust-policy anchor tidak berada pada kondisi yang dapat direkonsiliasi otomatis", 409, { status: current.status, finding: current.finding });
    const prior = await readExternal(ownerId, domain);
    const syntheticPrevious = { revision: prior.anchor.revision, digest: prior.anchor.policyDigest };
    const result = await advance(ownerId, domain, policy, { previousPolicy: syntheticPrevious });
    return { ...result, reconciled: true, readOnly: false, mutationAllowed: false };
  }
  async function enroll(ownerId, domain, policy, { confirmation, reason } = {}) {
    validOwner(ownerId); validDomain(domain);
    if (!policy || !DIGEST.test(policy.digest || "") || policy.digest !== digestRecord(policy)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_INVALID", "Trust policy tidak valid untuk enrollment", 409);
    if (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const state = await inspect(ownerId, domain, policy);
    if (state.status !== "enrollment_required") throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_ENROLLMENT_BLOCKED", "Enrollment hanya diizinkan untuk trust policy lama yang belum pernah di-anchor", 409, { status: state.status });
    const expected = `ENROLL PROVIDER IDENTITY TRUST POLICY ANCHOR ${policy.digest.slice(0, 12)}`;
    if (confirmation !== expected) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_CONFIRMATION_INVALID", "Konfirmasi enrollment trust-policy anchor tidak cocok", 403);
    const result = await advance(ownerId, domain, policy, { legacyEnrollment: true });
    return { ...result, reason: reason.trim(), readOnly: false, mutationAllowed: false };
  }
  return Object.freeze({ inspectRecoverySloProviderIdentityTrustPolicyAnchor: inspect,
    getRecoverySloProviderIdentityTrustPolicyAnchorStatus: status,
    advanceRecoverySloProviderIdentityTrustPolicyAnchor: advance,
    reconcileRecoverySloProviderIdentityTrustPolicyAnchor: reconcile,
    enrollRecoverySloProviderIdentityTrustPolicyAnchor: enroll,
    configured: Boolean(provider), required });
}
