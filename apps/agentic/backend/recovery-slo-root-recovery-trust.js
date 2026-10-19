import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";
import { createRecoverySloRootRecoveryTrustAnchorService } from "./recovery-slo-root-recovery-trust-anchor.js";

const KIND = "recovery-slo-root-recovery-trust-policy";
const CHALLENGE_KIND = "recovery-slo-root-recovery-trust-transition";
const DOMAIN = "agentic-v4-root-recovery-trust-transition";
const POP_DOMAIN = "agentic-v4-root-recovery-trust-proof-of-possession";
const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
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
  const result = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = clean(item);
  return result;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const challengeDigest = value => { const copy = clean(value); delete copy.digest; delete copy.authorizationPayload; delete copy.proofOfPossessionPayload; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
const policyId = ownerId => `recovery-slo-root-recovery-trust-policy-${ownerHash(ownerId)}`;
const challengeId = () => `recovery-slo-root-recovery-trust-transition-${randomUUID()}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_OWNER_REQUIRED", "Owner root-recovery trust wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function publicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Root-recovery trust key harus Ed25519");
  return key;
}
function keyMap(input) {
  const map = new Map();
  if (input instanceof Map) for (const [id, value] of input) {
    if (!KEY_ID.test(String(id))) throw new TypeError("Root-recovery key ID tidak valid");
    map.set(String(id), publicKey(value));
  } else if (input && typeof input === "object") for (const [id, value] of Object.entries(input)) {
    if (!KEY_ID.test(id)) throw new TypeError("Root-recovery key ID tidak valid");
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

export function createRecoverySloRootRecoveryTrustService({ store, publicKeys = null, anchorProvider = null, requireAnchor = false, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function") {
    throw new TypeError("Root-recovery trust membutuhkan evidence store dan clock");
  }
  const keys = keyMap(publicKeys);
  const anchorService = createRecoverySloRootRecoveryTrustAnchorService({ store, provider: anchorProvider, required: requireAnchor, clock });
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CLOCK_INVALID", "Clock root-recovery trust tidak valid", 500);
    return new Date(value).toISOString();
  }
  function validate(ownerId, policy) {
    if (!policy || policy.ownerId !== ownerId || policy.id !== policyId(ownerId) || policy.kind !== KIND || policy.schemaVersion !== 1
      || !Number.isSafeInteger(policy.revision) || policy.revision < 1 || !Array.isArray(policy.keys) || !Array.isArray(policy.events)
      || policy.events.length !== policy.revision || !Number.isFinite(Date.parse(policy.createdAt)) || !Number.isFinite(Date.parse(policy.updatedAt))
      || typeof policy.historyNotProven !== "boolean" || !DIGEST.test(policy.digest || "") || policy.digest !== digestRecord(policy)) {
      return { valid: false, code: "ROOT_RECOVERY_TRUST_POLICY_INVALID" };
    }
    for (let index = 0; index < policy.events.length; index++) {
      const event = policy.events[index];
      if (!event || event.sequence !== index + 1 || event.previousDigest !== (index ? policy.events[index - 1].digest : null)
        || !DIGEST.test(event.digest || "") || event.digest !== digestRecord(event) || !Number.isFinite(Date.parse(event.at))) {
        return { valid: false, code: "ROOT_RECOVERY_TRUST_EVENT_CHAIN_INVALID" };
      }
    }
    const first = policy.events[0];
    if (first.action !== "bootstrap" || first.details?.ownerId !== ownerId || !KEY_ID.test(first.details?.activeKeyId || "")
      || !Array.isArray(first.details?.keyIds) || !keys.has(first.details.activeKeyId)) return { valid: false, code: "ROOT_RECOVERY_TRUST_BOOTSTRAP_INVALID" };
    let activeKeyId = first.details.activeKeyId;
    const statuses = new Map(first.details.keyIds.map(id => [id, id === activeKeyId ? "active" : "standby"]));
    if (statuses.size !== first.details.keyIds.length || [...statuses.keys()].some(id => !keys.has(id))) return { valid: false, code: "ROOT_RECOVERY_TRUST_KEY_SET_INVALID" };
    for (const event of policy.events.slice(1)) {
      const details = event.details || {};
      const payload = details.authorizationPayload;
      if (!payload || details.signerKeyId !== activeKeyId || !verify(keys.get(activeKeyId), payload, details.authorizationSignature)
        || payload.domain !== DOMAIN || payload.schemaVersion !== 1 || payload.ownerId !== ownerId || payload.action !== event.action
        || payload.challengeId !== details.challengeId || payload.challengeDigest !== details.challengeDigest
        || payload.targetKeyId !== details.targetKeyId || payload.expectedPolicyRevision !== event.expectedPolicyRevision
        || payload.expectedPolicyDigest !== event.expectedPolicyDigest || payload.reason !== details.reason
        || payload.invalidateBefore !== details.invalidateBefore || !Number.isFinite(Date.parse(payload.expiresAt))
        || Date.parse(event.at) > Date.parse(payload.expiresAt)) return { valid: false, code: "ROOT_RECOVERY_TRUST_EVENT_AUTHORIZATION_INVALID" };
      const target = statuses.get(details.targetKeyId);
      if (!target || details.targetKeyId === activeKeyId) return { valid: false, code: "ROOT_RECOVERY_TRUST_TARGET_INVALID" };
      if (event.action === "rotate") {
        const pop = details.proofOfPossessionPayload;
        if (target !== "standby" || !keys.has(details.targetKeyId) || !pop || pop.domain !== POP_DOMAIN || pop.ownerId !== ownerId
          || pop.challengeId !== details.challengeId || pop.challengeDigest !== details.challengeDigest || pop.targetKeyId !== details.targetKeyId
          || pop.expectedPolicyDigest !== event.expectedPolicyDigest || pop.expiresAt !== payload.expiresAt
          || !verify(keys.get(details.targetKeyId), pop, details.proofOfPossessionSignature)) return { valid: false, code: "ROOT_RECOVERY_TRUST_ROTATION_PROOF_INVALID" };
        statuses.set(activeKeyId, "retired"); statuses.set(details.targetKeyId, "active"); activeKeyId = details.targetKeyId;
      } else if (event.action === "revoke") {
        if (target === "active" || target === "revoked") return { valid: false, code: "ROOT_RECOVERY_TRUST_REVOCATION_SEQUENCE_INVALID" };
        statuses.set(details.targetKeyId, "revoked");
      } else return { valid: false, code: "ROOT_RECOVERY_TRUST_EVENT_ACTION_INVALID" };
    }
    const entries = new Map(policy.keys.map(item => [item.keyId, item]));
    if (entries.size !== policy.keys.length || entries.size !== statuses.size || policy.activeKeyId !== activeKeyId) return { valid: false, code: "ROOT_RECOVERY_TRUST_KEY_SET_INVALID" };
    for (const [id, status] of statuses) {
      const item = entries.get(id);
      if (!item || item.status !== status || !Number.isFinite(Date.parse(item.addedAt))
        || !["active", "standby", "retired", "revoked"].includes(item.status)
        || (item.validFrom !== null && !Number.isFinite(Date.parse(item.validFrom)))
        || (item.retiredAt !== null && !Number.isFinite(Date.parse(item.retiredAt)))
        || (item.revokedAt !== null && !Number.isFinite(Date.parse(item.revokedAt)))
        || (item.invalidateBefore !== null && !Number.isFinite(Date.parse(item.invalidateBefore)))
        || (status === "active" && item.validFrom === null) || (status === "retired" && item.retiredAt === null)
        || (status === "revoked" && item.revokedAt === null)) return { valid: false, code: "ROOT_RECOVERY_TRUST_KEY_LIFECYCLE_INVALID" };
    }
    return { valid: true };
  }
  async function read(ownerId) {
    assertOwner(ownerId);
    const policy = await store.getEvidence(ownerId, policyId(ownerId));
    if (!policy) return { status: keys.size ? "not_initialized" : "not_configured", ownerId, policy: null, finding: "ROOT_RECOVERY_TRUST_NOT_INITIALIZED" };
    const check = validate(ownerId, policy);
    return check.valid ? { status: "healthy", ownerId, policy } : { status: "unhealthy", ownerId, policy: null, finding: check.code };
  }
  async function trustedResult(ownerId, state) {
    if (state.status !== "healthy") return { status: state.status, ownerId, finding: state.finding };
    const anchor = await anchorService.inspectRecoverySloRootRecoveryTrustAnchor(ownerId, state.policy);
    if (!["anchored", "local_only"].includes(anchor.status)) return { status: anchor.status, ownerId, finding: anchor.finding,
      anchorStatus: anchor.status, anchor, revision: state.policy.revision, policyDigest: state.policy.digest };
    return { status: "healthy", ownerId, activeKeyId: state.policy.activeKeyId, revision: state.policy.revision,
      policyDigest: state.policy.digest, historyNotProven: state.policy.historyNotProven, anchorStatus: anchor.status, anchor };
  }
  async function ensure(ownerId) {
    assertOwner(ownerId);
    if (!keys.size) return { status: "not_configured", ownerId, activeKeyId: null, finding: "ROOT_RECOVERY_TRUST_KEYS_NOT_CONFIGURED" };
    const state = await read(ownerId);
    if (state.status === "healthy") return trustedResult(ownerId, state);
    if (state.status !== "not_initialized") return { status: state.status, ownerId, finding: state.finding };
    const at = now(), firstKeyId = keys.keys().next().value;
    const keyEntries = [...keys.keys()].map(keyId => ({ keyId, status: keyId === firstKeyId ? "active" : "standby", addedAt: at,
      validFrom: keyId === firstKeyId ? at : null, retiredAt: null, revokedAt: null, invalidateBefore: null }));
    const eventUnsigned = { sequence: 1, action: "bootstrap", at, previousDigest: null, details: { ownerId, activeKeyId: firstKeyId, keyIds: [...keys.keys()] } };
    const event = { ...eventUnsigned, digest: digestRecord(eventUnsigned) };
    const unsigned = { id: policyId(ownerId), ownerId, kind: KIND, schemaVersion: 1, revision: 1, activeKeyId: firstKeyId,
      keys: keyEntries, events: [event], createdAt: at, updatedAt: at, historyNotProven: true, previousPolicyDigest: null };
    const candidate = { ...unsigned, digest: digestRecord(unsigned) };
    try { await store.putEvidence(ownerId, candidate, { overwrite: false }); }
    catch {
      const raced = await read(ownerId);
      if (raced.status === "healthy") return trustedResult(ownerId, raced);
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BOOTSTRAP_CONFLICT", "Bootstrap root trust berkonflik", 409);
    }
    const saved = await store.getEvidence(ownerId, candidate.id), checked = validate(ownerId, saved);
    if (!checked.valid) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_BOOTSTRAP_INVALID", "Bootstrap root trust gagal diverifikasi", 409);
    await anchorService.advanceRecoverySloRootRecoveryTrustAnchor(ownerId, saved);
    return trustedResult(ownerId, { status: "healthy", ownerId, policy: saved });
  }
  async function assertActive(ownerId, keyId) {
    const state = await ensure(ownerId);
    if (state.status !== "healthy") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_UNHEALTHY", "Root-recovery trust tidak sehat", 409, { status: state.status, finding: state.finding });
    if (state.activeKeyId !== keyId) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_KEY_NOT_ACTIVE", "Root-recovery key bukan kunci aktif", 403, { activeKeyId: state.activeKeyId });
    return state;
  }
  async function prepare(ownerId, input = {}) {
    assertOwner(ownerId);
    const state = await ensure(ownerId);
    if (state.status !== "healthy") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_UNHEALTHY", "Root-recovery trust tidak sehat", 409);
    const action = input.action;
    if (!new Set(["rotate", "revoke"]).has(action)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ACTION_INVALID", "Aksi root trust harus rotate atau revoke", 400);
    const reason = String(input.reason || "").trim();
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_REASON_INVALID", "Alasan wajib 12–240 karakter", 400);
    const targetKeyId = input.targetKeyId;
    if (!KEY_ID.test(targetKeyId || "") || !keys.has(targetKeyId)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_TARGET_INVALID", "Target key harus terdaftar", 400);
    const target = state && (await read(ownerId)).policy.keys.find(item => item.keyId === targetKeyId);
    if (!target || targetKeyId === state.activeKeyId || (action === "rotate" && target.status !== "standby")
      || (action === "revoke" && !["standby", "retired"].includes(target.status))) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_TARGET_STATE_INVALID", "Lifecycle target key tidak memenuhi transisi", 409);
    }
    let invalidateBefore = input.invalidateBefore ?? null;
    if (invalidateBefore !== null) {
      const timestamp = Date.parse(invalidateBefore);
      if (!Number.isFinite(timestamp) || timestamp > Date.parse(now())) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CUTOFF_INVALID", "Compromise cutoff harus timestamp valid yang tidak berada di masa depan", 400);
      invalidateBefore = new Date(timestamp).toISOString();
    }
    const createdAt = now(), id = challengeId(), expiresAt = new Date(Date.parse(createdAt) + TTL_MS).toISOString();
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "prepared", action, targetKeyId,
      signerKeyId: state.activeKeyId, expectedPolicyRevision: state.revision, expectedPolicyDigest: state.policyDigest,
      reason, invalidateBefore, createdAt, expiresAt };
    const base = { ...unsigned, digest: challengeDigest(unsigned) };
    const authorizationPayload = { domain: DOMAIN, schemaVersion: 1, ownerId, action, challengeId: id, challengeDigest: base.digest,
      targetKeyId, expectedPolicyRevision: state.revision, expectedPolicyDigest: state.policyDigest, reason, invalidateBefore, expiresAt };
    const proofOfPossessionPayload = action === "rotate" ? { domain: POP_DOMAIN, schemaVersion: 1, ownerId, action,
      challengeId: id, challengeDigest: base.digest, targetKeyId, expectedPolicyDigest: state.policyDigest, expiresAt } : null;
    const challenge = { ...base, authorizationPayload, proofOfPossessionPayload };
    challenge.digest = challengeDigest(challenge);
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, ownerId, action, targetKeyId, signerKeyId: state.activeKeyId, createdAt, expiresAt,
      expectedPolicyRevision: state.revision, expectedPolicyDigest: state.policyDigest, challengeDigest: challenge.digest,
      confirmation: `APPLY ROOT RECOVERY TRUST ${challenge.digest.slice(0, 12)}`, authorizationPayload, proofOfPossessionPayload,
      readOnly: false, mutationAllowed: false };
  }
  async function apply(ownerId, id, input = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== challengeDigest(challenge)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CHALLENGE_INVALID", "Challenge root trust tidak valid", 409);
    }
    if (challenge.status === "used") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_REPLAY", "Challenge root trust sudah digunakan", 409);
    if (challenge.status !== "prepared" || Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CHALLENGE_EXPIRED", "Challenge root trust kedaluwarsa", 409);
    if (input.confirmation !== `APPLY ROOT RECOVERY TRUST ${challenge.digest.slice(0, 12)}`) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFIRMATION_INVALID", "Konfirmasi root trust tidak cocok", 403);
    const state = await read(ownerId);
    if (state.status !== "healthy" || state.policy.revision !== challenge.expectedPolicyRevision || state.policy.digest !== challenge.expectedPolicyDigest
      || state.policy.activeKeyId !== challenge.signerKeyId) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_STALE", "Root trust berubah setelah challenge dibuat", 409);
    const anchorState = await anchorService.inspectRecoverySloRootRecoveryTrustAnchor(ownerId, state.policy);
    if (!["anchored", "local_only"].includes(anchorState.status)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_ANCHOR_NOT_TRUSTED", "Root-trust external checkpoint tidak sehat; transisi ditolak", 409,
      { status: anchorState.status, finding: anchorState.finding });
    const signer = keys.get(challenge.signerKeyId);
    if (!verify(signer, challenge.authorizationPayload, input.authorizationSignature)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_SIGNATURE_INVALID", "Signature otorisasi root trust tidak valid", 403);
    if (challenge.action === "rotate" && !verify(keys.get(challenge.targetKeyId), challenge.proofOfPossessionPayload, input.proofOfPossessionSignature)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_POP_INVALID", "Proof of possession target root tidak valid", 403);
    }
    const at = now(), policy = clean(state.policy), active = policy.keys.find(item => item.keyId === policy.activeKeyId);
    const target = policy.keys.find(item => item.keyId === challenge.targetKeyId);
    if (!target || target.keyId === active.keyId || (challenge.action === "rotate" && target.status !== "standby")
      || (challenge.action === "revoke" && !["standby", "retired"].includes(target.status))) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_TARGET_STATE_INVALID", "Lifecycle target root berubah", 409);
    }
    if (challenge.action === "rotate") {
      active.status = "retired"; active.retiredAt = at; active.invalidateBefore = challenge.invalidateBefore;
      target.status = "active"; target.validFrom = at; target.retiredAt = null; target.revokedAt = null; target.invalidateBefore = null;
      policy.activeKeyId = target.keyId;
    } else {
      target.status = "revoked"; target.revokedAt = at; target.invalidateBefore = challenge.invalidateBefore;
    }
    const previousEvent = policy.events.at(-1);
    const eventUnsigned = { sequence: policy.events.length + 1, action: challenge.action, at, previousDigest: previousEvent.digest,
      expectedPolicyRevision: state.policy.revision, expectedPolicyDigest: state.policy.digest,
      details: { challengeId: challenge.id, challengeDigest: challenge.digest, targetKeyId: challenge.targetKeyId,
        signerKeyId: challenge.signerKeyId, authorizationPayload: challenge.authorizationPayload,
        authorizationSignature: input.authorizationSignature, proofOfPossessionPayload: challenge.proofOfPossessionPayload,
        proofOfPossessionSignature: challenge.action === "rotate" ? input.proofOfPossessionSignature : null,
        invalidateBefore: challenge.invalidateBefore, reason: challenge.reason } };
    policy.events.push({ ...eventUnsigned, digest: digestRecord(eventUnsigned) });
    policy.revision += 1; policy.previousPolicyDigest = state.policy.digest; policy.updatedAt = at;
    const next = { ...policy, digest: "" }; next.digest = digestRecord(next);
    await store.putEvidence(ownerId, next, { expectedVersion: state.policy._storage?.version });
    const saved = await store.getEvidence(ownerId, next.id), checked = validate(ownerId, saved);
    if (!checked.valid || saved.digest !== next.digest) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_WRITE_INVALID", "Root trust setelah transisi gagal diverifikasi", 409);
    await anchorService.advanceRecoverySloRootRecoveryTrustAnchor(ownerId, saved);
    const used = { ...clean(challenge), status: "used", usedAt: at, authorizationSignatureDigest: sha256(input.authorizationSignature),
      proofOfPossessionSignatureDigest: input.proofOfPossessionSignature ? sha256(input.proofOfPossessionSignature) : null };
    used.digest = challengeDigest(used);
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { status: challenge.action === "rotate" ? "rotated" : "revoked", ownerId, action: challenge.action,
      revision: saved.revision, activeKeyId: saved.activeKeyId, targetKeyId: challenge.targetKeyId, policyDigest: saved.digest,
      historyNotProven: saved.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function evaluate(ownerId, keyId, issuedAt) {
    assertOwner(ownerId);
    const timestamp = Date.parse(issuedAt);
    if (!Number.isFinite(timestamp) || !keys.has(keyId)) return { trusted: false, finding: "ROOT_RECOVERY_TRUST_KEY_OR_TIME_INVALID" };
    const state = await read(ownerId);
    if (state.status !== "healthy") return { trusted: false, finding: state.finding || "ROOT_RECOVERY_TRUST_UNHEALTHY" };
    const entry = state.policy.keys.find(item => item.keyId === keyId);
    if (!entry) return { trusted: false, finding: "ROOT_RECOVERY_TRUST_KEY_NOT_IN_POLICY" };
    const from = entry.validFrom == null ? null : Date.parse(entry.validFrom), retired = entry.retiredAt == null ? null : Date.parse(entry.retiredAt);
    const revoked = entry.revokedAt == null ? null : Date.parse(entry.revokedAt), cutoff = entry.invalidateBefore == null ? null : Date.parse(entry.invalidateBefore);
    const beforeCutoff = cutoff === null || timestamp < cutoff;
    const trusted = entry.status === "active" && from !== null && timestamp >= from && beforeCutoff
      || entry.status === "retired" && from !== null && timestamp >= from && retired !== null && timestamp < retired && beforeCutoff
      || entry.status === "revoked" && from !== null && timestamp >= from && revoked !== null && timestamp < revoked
        && (retired === null || timestamp < retired) && beforeCutoff;
    return { trusted, finding: trusted ? null : entry.status === "revoked" ? "ROOT_RECOVERY_TRUST_KEY_REVOKED_OR_CUTOFF" : "ROOT_RECOVERY_TRUST_KEY_NOT_AUTHORIZED_AT_ISSUED_AT",
      keyId, issuedAt: new Date(timestamp).toISOString(), revision: state.policy.revision, historyNotProven: state.policy.historyNotProven };
  }
  async function getAnchorStatus(ownerId) {
    const state = await read(ownerId);
    return anchorService.inspectRecoverySloRootRecoveryTrustAnchor(ownerId, state.policy);
  }
  async function reconcileAnchor(ownerId) {
    const state = await read(ownerId);
    if (state.status !== "healthy") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_UNHEALTHY", "Root-trust policy tidak sehat; rekonsiliasi anchor ditolak", 409, { finding: state.finding });
    return anchorService.reconcileRecoverySloRootRecoveryTrustAnchor(ownerId, state.policy);
  }
  async function prepareAnchorEnrollment(ownerId, input = {}) {
    const state = await read(ownerId);
    if (state.status !== "healthy") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_UNHEALTHY", "Root-trust policy tidak sehat; enrollment anchor ditolak", 409, { finding: state.finding });
    return anchorService.prepareRecoverySloRootRecoveryTrustAnchorEnrollment(ownerId, state.policy, input);
  }
  async function applyAnchorEnrollment(ownerId, id, input = {}) {
    const state = await read(ownerId);
    if (state.status !== "healthy") throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_UNHEALTHY", "Root-trust policy tidak sehat; enrollment anchor ditolak", 409, { finding: state.finding });
    return anchorService.applyRecoverySloRootRecoveryTrustAnchorEnrollment(ownerId, state.policy, id, input);
  }
  async function audit(ownerId) {
    const state = await read(ownerId);
    const anchor = await anchorService.inspectRecoverySloRootRecoveryTrustAnchor(ownerId, state.policy);
    const overall = state.status === "healthy" && !["anchored", "local_only"].includes(anchor.status) ? anchor.status : state.status;
    return { status: overall, ownerId, revision: state.policy?.revision || null, activeKeyId: state.policy?.activeKeyId || null,
      policyDigest: state.policy?.digest || null, eventCount: state.policy?.events?.length || 0,
      historyNotProven: state.policy?.historyNotProven ?? null, finding: state.finding || anchor.finding || null, anchor,
      readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ ensureRecoverySloRootRecoveryTrust: ensure, assertActiveRecoverySloRootRecoveryKey: assertActive,
    prepareRecoverySloRootRecoveryTrustTransition: prepare, applyRecoverySloRootRecoveryTrustTransition: apply,
    evaluateRecoverySloRootRecoveryTrustKey: evaluate, auditRecoverySloRootRecoveryTrust: audit,
    getRecoverySloRootRecoveryTrustAnchorStatus: getAnchorStatus, reconcileRecoverySloRootRecoveryTrustAnchor: reconcileAnchor,
    prepareRecoverySloRootRecoveryTrustAnchorEnrollment: prepareAnchorEnrollment,
    applyRecoverySloRootRecoveryTrustAnchorEnrollment: applyAnchorEnrollment,
    configured: keys.size > 0, anchorConfigured: anchorService.configured, anchorRequired: anchorService.required });
}
