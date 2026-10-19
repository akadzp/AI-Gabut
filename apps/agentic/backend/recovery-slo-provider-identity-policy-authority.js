import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const POLICY_KIND = "recovery-slo-provider-identity-policy-authority-policy";
const CHALLENGE_KIND = "recovery-slo-provider-identity-policy-authority-transition";
const ROOT_RECOVERY_CHALLENGE_KIND = "recovery-slo-provider-identity-policy-authority-root-recovery";
const ROOT_RECOVERY_DOMAIN = "agentic-v4-provider-identity-policy-authority-root-recovery";
const ROOT_RECOVERY_POP_DOMAIN = "agentic-v4-provider-identity-policy-authority-root-recovery-pop";
const AUTH_DOMAIN = "agentic-v4-provider-identity-policy-authority-transition";
const POP_DOMAIN = "agentic-v4-provider-identity-policy-authority-proof-of-possession";
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
const policyId = ownerId => `recovery-slo-provider-identity-policy-authority-policy-${ownerHash(ownerId)}`;
const challengeId = () => `recovery-slo-provider-identity-policy-authority-transition-${randomUUID()}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_OWNER_REQUIRED", "Owner policy-authority wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function parsePublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Policy-authority public key harus Ed25519");
  return key;
}
function keyMap(values) {
  const result = new Map();
  if (values instanceof Map) for (const [id, value] of values) {
    if (!KEY_ID.test(String(id))) throw new TypeError("Policy-authority key ID tidak valid");
    result.set(String(id), parsePublicKey(value));
  } else if (values && typeof values === "object") for (const [id, value] of Object.entries(values)) {
    if (!KEY_ID.test(id)) throw new TypeError("Policy-authority key ID tidak valid");
    result.set(id, parsePublicKey(value));
  }
  return result;
}
function verify(key, payload, signature) {
  try {
    if (!key || typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
    const bytes = Buffer.from(signature, "base64url");
    return bytes.length === 64 && bytes.toString("base64url") === signature
      && verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes);
  } catch { return false; }
}
const policyDigest = value => digestRecord(value);
const challengeDigest = value => {
  const copy = clean(value); delete copy.digest; delete copy.authorizationPayload; delete copy.proofOfPossessionPayload; delete copy.rootRecoveryPayload;
  return sha256(canonical(copy));
};
const eventDigest = value => digestRecord(value);

export function createRecoverySloProviderIdentityPolicyAuthorityService({ store, clock = () => new Date().toISOString(),
  publicKeys = null, initialKeyId = null, anchorService = null, rootRecoveryPublicKeys = null, rootRecoveryTrustService = null } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function") {
    throw new TypeError("Policy-authority lifecycle membutuhkan evidence store dan clock");
  }
  const keys = keyMap(publicKeys);
  const rootKeys = keyMap(rootRecoveryPublicKeys);
  const operationalFingerprints = new Set([...keys.values()].map(key => key.export({ format: "der", type: "spki" }).toString("base64")));
  if ([...rootKeys.values()].some(key => operationalFingerprints.has(key.export({ format: "der", type: "spki" }).toString("base64")))) {
    throw new TypeError("Policy-authority root recovery keys harus terpisah dari operational policy-authority keys");
  }
  const firstKeyId = initialKeyId || (keys.size ? keys.keys().next().value : null);
  if (initialKeyId && (!KEY_ID.test(initialKeyId) || !keys.has(initialKeyId))) throw new TypeError("Initial policy-authority key harus ada di registry tepercaya");
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_CLOCK_INVALID", "Clock policy-authority tidak valid", 500);
    return new Date(time).toISOString();
  }
  function verifyAuthorityEvent(ownerId, event, activeKeyId) {
    const details = event.details;
    if (!details || details.signerKeyId !== activeKeyId || !keys.has(details.signerKeyId)
      || !details.authorizationPayload || !verify(keys.get(details.signerKeyId), details.authorizationPayload, details.authorizationSignature)) return false;
    const payload = details.authorizationPayload;
    if (payload.domain !== AUTH_DOMAIN || payload.ownerId !== ownerId || payload.action !== event.action
      || payload.targetKeyId !== details.targetKeyId || payload.expectedPolicyDigest !== event.expectedPolicyDigest
      || payload.expectedPolicyRevision !== event.expectedPolicyRevision || payload.challengeId !== details.challengeId
      || !Number.isFinite(Date.parse(event.at)) || !Number.isFinite(Date.parse(payload.expiresAt))
      || Date.parse(event.at) > Date.parse(payload.expiresAt)) return false;
    if (event.action === "rotate") {
      if (!keys.has(details.targetKeyId) || !details.proofOfPossessionPayload
        || !verify(keys.get(details.targetKeyId), details.proofOfPossessionPayload, details.proofOfPossessionSignature)) return false;
    }
    return event.action === "rotate" || event.action === "revoke";
  }
  function verifyRootRecoveryEvent(ownerId, event, activeKeyId) {
    const details = event.details;
    const payload = details?.rootRecoveryPayload;
    if (event.action !== "root_recover" || !details || details.previousActiveKeyId !== activeKeyId
      || !rootKeys.has(details.rootKeyId) || !payload
      || !verify(rootKeys.get(details.rootKeyId), payload, details.rootRecoverySignature)
      || payload.domain !== ROOT_RECOVERY_DOMAIN || payload.schemaVersion !== 1 || payload.ownerId !== ownerId
      || payload.action !== "root_recover" || payload.challengeId !== details.challengeId
      || payload.challengeDigest !== details.challengeDigest || payload.expectedPolicyRevision !== event.expectedPolicyRevision
      || payload.expectedPolicyDigest !== event.expectedPolicyDigest || payload.targetKeyId !== details.targetKeyId
      || payload.previousActiveKeyId !== activeKeyId || payload.rootKeyId !== details.rootKeyId
      || payload.invalidateBefore !== details.invalidateBefore || payload.reason !== details.reason
      || !Number.isFinite(Date.parse(event.at)) || !Number.isFinite(Date.parse(payload.expiresAt))
      || Date.parse(event.at) > Date.parse(payload.expiresAt)) return false;
    const pop = details.proofOfPossessionPayload;
    return keys.has(details.targetKeyId) && pop?.domain === ROOT_RECOVERY_POP_DOMAIN && pop.ownerId === ownerId
      && pop.action === "root_recover" && pop.challengeId === details.challengeId && pop.challengeDigest === details.challengeDigest
      && pop.expectedPolicyDigest === event.expectedPolicyDigest && pop.targetKeyId === details.targetKeyId
      && pop.expiresAt === payload.expiresAt && verify(keys.get(details.targetKeyId), pop, details.proofOfPossessionSignature);
  }
  function validatePolicy(ownerId, value) {
    if (!value || value.ownerId !== ownerId || value.id !== policyId(ownerId) || value.kind !== POLICY_KIND || value.schemaVersion !== 1
      || !Number.isSafeInteger(value.revision) || value.revision < 1 || !Array.isArray(value.keys) || !Array.isArray(value.events)
      || value.events.length !== value.revision || !Number.isFinite(Date.parse(value.createdAt)) || !Number.isFinite(Date.parse(value.updatedAt))
      || typeof value.historyNotProven !== "boolean" || (value.previousPolicyDigest !== null && !DIGEST.test(value.previousPolicyDigest || ""))
      || !DIGEST.test(value.digest || "") || value.digest !== policyDigest(value)) return { valid: false, code: "POLICY_AUTHORITY_POLICY_INVALID" };
    const seen = new Set();
    for (let i = 0; i < value.events.length; i++) {
      const event = value.events[i];
      if (!event || event.sequence !== i + 1 || event.previousDigest !== (i ? value.events[i - 1].digest : null)
        || !DIGEST.test(event.digest || "") || event.digest !== eventDigest(event)) return { valid: false, code: "POLICY_AUTHORITY_EVENT_CHAIN_INVALID" };
    }
    const bootstrap = value.events[0];
    if (bootstrap.action !== "bootstrap" || bootstrap.details?.ownerId !== ownerId || !KEY_ID.test(bootstrap.details?.activeKeyId || "")
      || !Array.isArray(bootstrap.details?.keyIds) || !keys.has(bootstrap.details.activeKeyId)) return { valid: false, code: "POLICY_AUTHORITY_BOOTSTRAP_INVALID" };
    let activeKeyId = bootstrap.details.activeKeyId;
    const statuses = new Map(bootstrap.details.keyIds.map(keyId => [keyId, keyId === activeKeyId ? "active" : "standby"]));
    if (statuses.size !== bootstrap.details.keyIds.length || [...statuses.keys()].some(keyId => !keys.has(keyId))) return { valid: false, code: "POLICY_AUTHORITY_BOOTSTRAP_KEYS_INVALID" };
    for (const event of value.events.slice(1)) {
      const details = event.details;
      const rootRecovery = event.action === "root_recover";
      if (rootRecovery ? !verifyRootRecoveryEvent(ownerId, event, activeKeyId) : !verifyAuthorityEvent(ownerId, event, activeKeyId)) {
        return { valid: false, code: rootRecovery ? "POLICY_AUTHORITY_ROOT_RECOVERY_AUTHORIZATION_INVALID" : "POLICY_AUTHORITY_HISTORICAL_AUTHORIZATION_INVALID" };
      }
      const targetId = details.targetKeyId;
      const targetStatus = statuses.get(targetId);
      if (!targetStatus || targetId === activeKeyId) return { valid: false, code: "POLICY_AUTHORITY_TARGET_INVALID" };
      if (event.action === "rotate") {
        if (targetStatus !== "standby") return { valid: false, code: "POLICY_AUTHORITY_ROTATION_SEQUENCE_INVALID" };
        statuses.set(activeKeyId, "retired"); statuses.set(targetId, "active"); activeKeyId = targetId;
      } else if (event.action === "root_recover") {
        if (targetStatus !== "standby") return { valid: false, code: "POLICY_AUTHORITY_ROOT_RECOVERY_TARGET_INVALID" };
        statuses.set(activeKeyId, "revoked"); statuses.set(targetId, "active"); activeKeyId = targetId;
      } else {
        if (targetStatus === "active" || targetStatus === "revoked") return { valid: false, code: "POLICY_AUTHORITY_REVOCATION_SEQUENCE_INVALID" };
        statuses.set(targetId, "revoked");
      }
    }
    const entries = new Map(value.keys.map(entry => [entry.keyId, entry]));
    if (entries.size !== value.keys.length || entries.size !== statuses.size) return { valid: false, code: "POLICY_AUTHORITY_KEY_SET_INVALID" };
    for (const [keyId, status] of statuses) if (entries.get(keyId)?.status !== status) return { valid: false, code: "POLICY_AUTHORITY_KEY_LIFECYCLE_INVALID" };
    const active = value.keys.filter(entry => entry.status === "active");
    if (active.length > 1 || (activeKeyId === null ? active.length !== 0 : active.length !== 1 || active[0]?.keyId !== activeKeyId)
      || value.activeKeyId !== activeKeyId) return { valid: false, code: "POLICY_AUTHORITY_ACTIVE_KEY_INVALID" };
    for (const entry of value.keys) {
      if (!KEY_ID.test(entry.keyId || "") || !keys.has(entry.keyId) || !Number.isFinite(Date.parse(entry.addedAt))
        || !["active", "standby", "retired", "revoked"].includes(entry.status)
        || (entry.validFrom !== null && !Number.isFinite(Date.parse(entry.validFrom)))
        || (entry.retiredAt !== null && !Number.isFinite(Date.parse(entry.retiredAt)))
        || (entry.revokedAt !== null && !Number.isFinite(Date.parse(entry.revokedAt)))
        || (entry.invalidateBefore !== null && !Number.isFinite(Date.parse(entry.invalidateBefore)))
        || (entry.status === "active" && entry.validFrom === null)
        || (entry.status === "retired" && entry.retiredAt === null)
        || (entry.status === "revoked" && entry.revokedAt === null)) return { valid: false, code: "POLICY_AUTHORITY_KEY_ENTRY_INVALID" };
    }
    return { valid: true };
  }
  async function checkAnchor(ownerId, policy) {
    if (!anchorService) return { status: "local_only", trusted: true, required: false, finding: "POLICY_AUTHORITY_EXTERNAL_ANCHOR_NOT_CONFIGURED" };
    return anchorService.inspectRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, "policy_authority", policy);
  }
  async function readExisting(ownerId) {
    assertOwner(ownerId);
    const current = await store.getEvidence(ownerId, policyId(ownerId));
    if (!current) return { status: keys.size ? "not_initialized" : "not_configured", policy: null, finding: "POLICY_AUTHORITY_POLICY_NOT_INITIALIZED" };
    const check = validatePolicy(ownerId, current);
    if (!check.valid) return { status: "unhealthy", policy: null, finding: check.code };
    const anchor = await checkAnchor(ownerId, current);
    if (!new Set(["anchored", "local_only"]).has(anchor.status)) return { status: "unhealthy", policy: null, finding: anchor.finding || `POLICY_AUTHORITY_ANCHOR_${anchor.status.toUpperCase()}`, anchorStatus: anchor.status };
    return { status: "healthy", policy: current, anchorStatus: anchor.status };
  }
  async function ensure(ownerId) {
    assertOwner(ownerId);
    if (rootRecoveryTrustService?.configured) await rootRecoveryTrustService.ensureRecoverySloRootRecoveryTrust(ownerId);
    if (!keys.size || !firstKeyId) return { status: "not_configured", ownerId, activeKeyId: null, finding: "POLICY_AUTHORITY_KEYS_NOT_CONFIGURED" };
    const state = await readExisting(ownerId);
    if (state.status === "healthy") return { status: "healthy", ownerId, activeKeyId: state.policy.activeKeyId,
      revision: state.policy.revision, policyDigest: state.policy.digest, anchorStatus: state.anchorStatus, historyNotProven: state.policy.historyNotProven };
    if (state.status !== "not_initialized") return { status: state.status, ownerId, finding: state.finding, anchorStatus: state.anchorStatus || null };
    const at = now();
    const keyEntries = [...keys.keys()].map(keyId => ({ keyId, status: keyId === firstKeyId ? "active" : "standby", addedAt: at,
      validFrom: keyId === firstKeyId ? at : null, retiredAt: null, revokedAt: null, invalidateBefore: null }));
    const eventUnsigned = { sequence: 1, action: "bootstrap", at, previousDigest: null,
      details: { ownerId, activeKeyId: firstKeyId, keyIds: [...keys.keys()] } };
    const event = { ...eventUnsigned, digest: eventDigest(eventUnsigned) };
    const unsigned = { id: policyId(ownerId), ownerId, kind: POLICY_KIND, schemaVersion: 1, revision: 1, activeKeyId: firstKeyId,
      keys: keyEntries, events: [event], createdAt: at, updatedAt: at, historyNotProven: true, previousPolicyDigest: null };
    const policy = { ...unsigned, digest: policyDigest(unsigned) };
    try { await store.putEvidence(ownerId, policy, { overwrite: false }); }
    catch {
      const raced = await readExisting(ownerId);
      if (raced.status === "healthy") return { status: "healthy", ownerId, activeKeyId: raced.policy.activeKeyId, revision: raced.policy.revision,
        policyDigest: raced.policy.digest, anchorStatus: raced.anchorStatus, historyNotProven: raced.policy.historyNotProven };
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_BOOTSTRAP_CONFLICT", "Bootstrap policy authority berkonflik", 409);
    }
    const saved = await store.getEvidence(ownerId, policy.id);
    const valid = validatePolicy(ownerId, saved);
    if (!valid.valid) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_BOOTSTRAP_INVALID", "Bootstrap policy authority gagal diverifikasi", 409);
    if (anchorService?.configured) await anchorService.advanceRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, "policy_authority", saved, { genesis: true });
    else if (anchorService?.required) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_UNAVAILABLE", "External trust-policy anchor diwajibkan", 503);
    return { status: "healthy", ownerId, activeKeyId: saved.activeKeyId, revision: saved.revision, policyDigest: saved.digest,
      anchorStatus: anchorService?.configured ? "anchored" : "local_only", historyNotProven: saved.historyNotProven };
  }
  async function assertActive(ownerId, keyId) {
    const state = await ensure(ownerId);
    if (state.status !== "healthy") throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_UNHEALTHY", "Policy-authority lifecycle tidak sehat", 409, { status: state.status, finding: state.finding });
    if (state.activeKeyId !== keyId) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_KEY_NOT_ACTIVE", "Policy-authority key bukan kunci aktif", 403, { activeKeyId: state.activeKeyId });
    return state;
  }
  async function prepare(ownerId, { action, targetKeyId, reason, invalidateBefore = null } = {}) {
    assertOwner(ownerId);
    if (!keys.size) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_NOT_CONFIGURED", "Policy-authority public keys belum dikonfigurasi", 503);
    if (!new Set(["rotate", "revoke"]).has(action)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ACTION_INVALID", "Aksi policy-authority tidak valid", 400);
    if (!KEY_ID.test(targetKeyId || "") || !keys.has(targetKeyId)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_TARGET_UNKNOWN", "Target policy-authority key tidak ada di registry", 409);
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_REASON_INVALID", "Alasan wajib 12–240 karakter", 400);
    if (invalidateBefore != null && (!Number.isFinite(Date.parse(invalidateBefore)) || Date.parse(invalidateBefore) > Date.parse(now()))) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_CUTOFF_INVALID", "Compromise cutoff harus timestamp valid yang tidak di masa depan", 400);
    }
    const authority = await ensure(ownerId);
    if (authority.status !== "healthy" || !authority.activeKeyId) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_UNHEALTHY", "Tidak ada policy-authority aktif yang tepercaya", 409);
    const state = await readExisting(ownerId);
    const policy = state.policy;
    const target = policy?.keys.find(item => item.keyId === targetKeyId);
    if (!policy) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_POLICY_UNAVAILABLE", "Policy-authority policy tidak tersedia", 409);
    if (action === "rotate" && (!target || target.status !== "standby")) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_TARGET_NOT_ROTATABLE", "Target key tidak dapat dirotasi", 409);
    if (action === "revoke" && (!target || target.status === "active" || target.status === "revoked")) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_TARGET_NOT_REVOCABLE", "Kunci aktif harus dirotasi sebelum dicabut", 409);
    const createdAt = now();
    const id = challengeId();
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "prepared", action, targetKeyId,
      signerKeyId: policy.activeKeyId, expectedPolicyRevision: policy.revision, expectedPolicyDigest: policy.digest,
      reason: reason.trim(), invalidateBefore: invalidateBefore == null ? null : new Date(Date.parse(invalidateBefore)).toISOString(),
      createdAt, expiresAt: new Date(Date.parse(createdAt) + TTL_MS).toISOString() };
    const digest = challengeDigest(unsigned);
    const authorizationPayload = { domain: AUTH_DOMAIN, schemaVersion: 1, ownerId, action, challengeId: id, challengeDigest: digest,
      expectedPolicyRevision: policy.revision, expectedPolicyDigest: policy.digest, targetKeyId, signerKeyId: policy.activeKeyId,
      invalidateBefore: unsigned.invalidateBefore, reason: unsigned.reason, expiresAt: unsigned.expiresAt };
    const proofOfPossessionPayload = { domain: POP_DOMAIN, schemaVersion: 1, ownerId, action: "rotate", challengeId: id,
      challengeDigest: digest, expectedPolicyDigest: policy.digest, targetKeyId, expiresAt: unsigned.expiresAt };
    const challenge = { ...unsigned, digest, authorizationPayload, proofOfPossessionPayload };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, ownerId, action, targetKeyId, signerKeyId: policy.activeKeyId, expectedPolicyRevision: policy.revision,
      expectedPolicyDigest: policy.digest, expiresAt: challenge.expiresAt, challengeDigest: digest,
      authorizationPayload: clone(authorizationPayload), proofOfPossessionPayload: action === "rotate" ? clone(proofOfPossessionPayload) : null,
      confirmation: `APPLY POLICY AUTHORITY TRANSITION ${digest.slice(0, 12)}`, readOnly: true, mutationAllowed: false };
  }
  async function apply(ownerId, id, { confirmation, authoritySignature, proofOfPossessionSignature } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== challengeDigest(challenge)) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_CHALLENGE_INVALID", "Challenge policy-authority tidak valid", 409);
    }
    if (challenge.status !== "prepared") throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_CHALLENGE_REPLAY", "Challenge policy-authority sudah digunakan", 409);
    if (Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_CHALLENGE_EXPIRED", "Challenge policy-authority kedaluwarsa", 409);
    if (confirmation !== `APPLY POLICY AUTHORITY TRANSITION ${challenge.digest.slice(0, 12)}`) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_CONFIRMATION_INVALID", "Konfirmasi policy-authority tidak cocok", 403);
    const currentState = await readExisting(ownerId);
    if (currentState.status !== "healthy" || currentState.policy.digest !== challenge.expectedPolicyDigest
      || currentState.policy.revision !== challenge.expectedPolicyRevision || currentState.policy.activeKeyId !== challenge.signerKeyId) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_STALE", "Policy authority berubah sejak challenge dibuat", 409);
    }
    const signer = keys.get(challenge.signerKeyId);
    if (!verify(signer, challenge.authorizationPayload, authoritySignature)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_AUTHORIZATION_INVALID", "Signature policy-authority transition tidak valid", 403);
    if (challenge.action === "rotate" && !verify(keys.get(challenge.targetKeyId), challenge.proofOfPossessionPayload, proofOfPossessionSignature)) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_PROOF_OF_POSSESSION_INVALID", "Proof of possession target policy-authority tidak valid", 403);
    }
    const policy = clone(currentState.policy);
    const at = now();
    const target = policy.keys.find(item => item.keyId === challenge.targetKeyId);
    if (challenge.action === "rotate") {
      const active = policy.keys.find(item => item.keyId === policy.activeKeyId);
      active.status = "retired"; active.retiredAt = at;
      target.status = "active"; target.validFrom = at; target.retiredAt = null; target.revokedAt = null; target.invalidateBefore = null;
      policy.activeKeyId = target.keyId;
    } else {
      target.status = "revoked"; target.revokedAt = at; target.invalidateBefore = challenge.invalidateBefore || at;
    }
    const previousEvent = policy.events.at(-1);
    const eventUnsigned = { sequence: policy.events.length + 1, action: challenge.action, at, previousDigest: previousEvent.digest,
      expectedPolicyRevision: currentState.policy.revision, expectedPolicyDigest: currentState.policy.digest,
      details: { challengeId: challenge.id, targetKeyId: challenge.targetKeyId, signerKeyId: challenge.signerKeyId,
        authorizationPayload: challenge.authorizationPayload, authorizationSignature: authoritySignature,
        proofOfPossessionPayload: challenge.action === "rotate" ? challenge.proofOfPossessionPayload : null,
        proofOfPossessionSignature: challenge.action === "rotate" ? proofOfPossessionSignature : null,
        invalidateBefore: target.invalidateBefore, reason: challenge.reason } };
    policy.events.push({ ...eventUnsigned, digest: eventDigest(eventUnsigned) });
    policy.revision += 1; policy.previousPolicyDigest = currentState.policy.digest; policy.updatedAt = at;
    const unsignedNext = { ...policy, digest: "" }; unsignedNext.digest = policyDigest(unsignedNext);
    const next = unsignedNext;
    await store.putEvidence(ownerId, next, { expectedVersion: currentState.policy._storage?.version });
    const saved = await store.getEvidence(ownerId, next.id);
    const valid = validatePolicy(ownerId, saved);
    if (!valid.valid || saved.digest !== next.digest) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_WRITE_INVALID", "Policy-authority policy gagal diverifikasi setelah penulisan", 409);
    if (anchorService?.configured) await anchorService.advanceRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, "policy_authority", saved, { previousPolicy: currentState.policy });
    const used = { ...clean(challenge), status: "used", usedAt: at, authoritySignatureDigest: sha256(authoritySignature),
      proofOfPossessionDigest: proofOfPossessionSignature ? sha256(proofOfPossessionSignature) : null };
    used.digest = challengeDigest(used);
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { status: "applied", action: challenge.action, ownerId, revision: saved.revision, activeKeyId: saved.activeKeyId,
      policyDigest: saved.digest, targetKeyId: challenge.targetKeyId, anchorStatus: anchorService?.configured ? "anchored" : "local_only",
      historyNotProven: saved.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function prepareRootRecovery(ownerId, { targetKeyId, rootKeyId, reason, invalidateBefore = null } = {}) {
    assertOwner(ownerId);
    if (!rootKeys.size) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_KEYS_NOT_CONFIGURED", "Root recovery public keys belum dikonfigurasi", 503);
    if (!KEY_ID.test(rootKeyId || "") || !rootKeys.has(rootKeyId)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_KEY_UNKNOWN", "Root recovery key tidak tepercaya", 403);
    if (rootRecoveryTrustService?.configured) await rootRecoveryTrustService.assertActiveRecoverySloRootRecoveryKey(ownerId, rootKeyId);
    if (!KEY_ID.test(targetKeyId || "") || !keys.has(targetKeyId)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_TARGET_UNKNOWN", "Target recovery key tidak ada di registry", 409);
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_REASON_INVALID", "Alasan root recovery wajib 12–240 karakter", 400);
    if (invalidateBefore != null && (!Number.isFinite(Date.parse(invalidateBefore)) || Date.parse(invalidateBefore) > Date.parse(now()))) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_CUTOFF_INVALID", "Compromise cutoff harus timestamp valid yang tidak di masa depan", 400);
    }
    const state = await readExisting(ownerId);
    if (state.status !== "healthy" || !state.policy?.activeKeyId) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_UNHEALTHY", "Policy authority atau external checkpoint tidak sehat; root recovery diblokir", 409,
      { status: state.status, finding: state.finding || null });
    const policy = state.policy;
    const target = policy.keys.find(item => item.keyId === targetKeyId);
    if (!target || target.status !== "standby" || targetKeyId === policy.activeKeyId) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_TARGET_NOT_STANDBY", "Root recovery hanya boleh mengaktifkan key standby yang telah dipra-konfigurasi", 409);
    }
    const createdAt = now(), id = `recovery-slo-provider-identity-policy-authority-root-recovery-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: ROOT_RECOVERY_CHALLENGE_KIND, schemaVersion: 1, status: "prepared", action: "root_recover",
      rootKeyId, targetKeyId, previousActiveKeyId: policy.activeKeyId, expectedPolicyRevision: policy.revision,
      expectedPolicyDigest: policy.digest, reason: reason.trim(), invalidateBefore: invalidateBefore == null ? createdAt : new Date(Date.parse(invalidateBefore)).toISOString(),
      createdAt, expiresAt: new Date(Date.parse(createdAt) + TTL_MS).toISOString() };
    const digest = challengeDigest(unsigned);
    const rootRecoveryPayload = { domain: ROOT_RECOVERY_DOMAIN, schemaVersion: 1, ownerId, action: "root_recover", challengeId: id,
      challengeDigest: digest, expectedPolicyRevision: policy.revision, expectedPolicyDigest: policy.digest,
      targetKeyId, previousActiveKeyId: policy.activeKeyId, rootKeyId, invalidateBefore: unsigned.invalidateBefore,
      reason: unsigned.reason, expiresAt: unsigned.expiresAt };
    const proofOfPossessionPayload = { domain: ROOT_RECOVERY_POP_DOMAIN, schemaVersion: 1, ownerId, action: "root_recover",
      challengeId: id, challengeDigest: digest, expectedPolicyDigest: policy.digest, targetKeyId, expiresAt: unsigned.expiresAt };
    const challenge = { ...unsigned, digest, rootRecoveryPayload, proofOfPossessionPayload };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, ownerId, action: "root_recover", rootKeyId, targetKeyId, previousActiveKeyId: policy.activeKeyId,
      expectedPolicyRevision: policy.revision, expectedPolicyDigest: policy.digest, challengeDigest: digest,
      expiresAt: challenge.expiresAt, rootRecoveryPayload: clone(rootRecoveryPayload), proofOfPossessionPayload: clone(proofOfPossessionPayload),
      confirmation: `APPLY POLICY AUTHORITY ROOT RECOVERY ${digest.slice(0, 12)}`, readOnly: true, mutationAllowed: false };
  }
  async function applyRootRecovery(ownerId, id, { confirmation, rootRecoverySignature, proofOfPossessionSignature } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== ROOT_RECOVERY_CHALLENGE_KIND
      || challenge.digest !== challengeDigest(challenge)) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_CHALLENGE_INVALID", "Root recovery challenge tidak valid", 409);
    if (challenge.status !== "prepared") throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_REPLAY", "Root recovery challenge sudah digunakan", 409);
    if (Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_EXPIRED", "Root recovery challenge kedaluwarsa", 409);
    if (confirmation !== `APPLY POLICY AUTHORITY ROOT RECOVERY ${challenge.digest.slice(0, 12)}`) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_CONFIRMATION_INVALID", "Konfirmasi root recovery tidak cocok", 403);
    const state = await readExisting(ownerId);
    if (state.status !== "healthy" || state.policy.digest !== challenge.expectedPolicyDigest
      || state.policy.revision !== challenge.expectedPolicyRevision || state.policy.activeKeyId !== challenge.previousActiveKeyId) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_STALE", "Policy authority berubah atau tidak sehat sejak challenge dibuat", 409);
    }
    if (rootRecoveryTrustService?.configured) await rootRecoveryTrustService.assertActiveRecoverySloRootRecoveryKey(ownerId, challenge.rootKeyId);
    if (!verify(rootKeys.get(challenge.rootKeyId), challenge.rootRecoveryPayload, rootRecoverySignature)) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_SIGNATURE_INVALID", "Signature root recovery tidak valid", 403);
    }
    if (!verify(keys.get(challenge.targetKeyId), challenge.proofOfPossessionPayload, proofOfPossessionSignature)) {
      throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_POP_INVALID", "Proof of possession target key tidak valid", 403);
    }
    const policy = clone(state.policy), at = now();
    const active = policy.keys.find(item => item.keyId === policy.activeKeyId);
    const target = policy.keys.find(item => item.keyId === challenge.targetKeyId);
    if (!active || active.status !== "active" || !target || target.status !== "standby") throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_STATE_INVALID", "Lifecycle key tidak memenuhi root recovery", 409);
    active.status = "revoked"; active.revokedAt = at; active.invalidateBefore = challenge.invalidateBefore || at;
    target.status = "active"; target.validFrom = at; target.retiredAt = null; target.revokedAt = null; target.invalidateBefore = null;
    policy.activeKeyId = target.keyId;
    const previousEvent = policy.events.at(-1);
    const eventUnsigned = { sequence: policy.events.length + 1, action: "root_recover", at, previousDigest: previousEvent.digest,
      expectedPolicyRevision: state.policy.revision, expectedPolicyDigest: state.policy.digest,
      details: { challengeId: challenge.id, challengeDigest: challenge.digest, targetKeyId: target.keyId,
        previousActiveKeyId: active.keyId, rootKeyId: challenge.rootKeyId, rootRecoveryPayload: challenge.rootRecoveryPayload,
        rootRecoverySignature, proofOfPossessionPayload: challenge.proofOfPossessionPayload, proofOfPossessionSignature,
        invalidateBefore: active.invalidateBefore, reason: challenge.reason } };
    policy.events.push({ ...eventUnsigned, digest: eventDigest(eventUnsigned) });
    policy.revision += 1; policy.previousPolicyDigest = state.policy.digest; policy.updatedAt = at;
    const next = { ...policy, digest: "" }; next.digest = policyDigest(next);
    await store.putEvidence(ownerId, next, { expectedVersion: state.policy._storage?.version });
    const saved = await store.getEvidence(ownerId, next.id), checked = validatePolicy(ownerId, saved);
    if (!checked.valid || saved.digest !== next.digest) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_WRITE_INVALID", "Policy setelah root recovery gagal diverifikasi", 409);
    if (anchorService?.configured) await anchorService.advanceRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, "policy_authority", saved, { previousPolicy: state.policy });
    const used = { ...clean(challenge), status: "used", usedAt: at, rootSignatureDigest: sha256(rootRecoverySignature), proofOfPossessionDigest: sha256(proofOfPossessionSignature) };
    used.digest = challengeDigest(used);
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { status: "recovered", ownerId, revision: saved.revision, activeKeyId: saved.activeKeyId, previousActiveKeyId: active.keyId,
      policyDigest: saved.digest, rootKeyId: challenge.rootKeyId, anchorStatus: anchorService?.configured ? "anchored" : "local_only",
      historyNotProven: saved.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    if (rootRecoveryTrustService?.configured) await rootRecoveryTrustService.ensureRecoverySloRootRecoveryTrust(ownerId);
    const state = await readExisting(ownerId);
    const rootTrust = rootRecoveryTrustService?.configured
      ? await rootRecoveryTrustService.auditRecoverySloRootRecoveryTrust(ownerId)
      : { status: "not_configured", readOnly: true, mutationAllowed: false };
    const status = rootTrust.status === "unhealthy" ? "unhealthy" : state.status;
    return { status, ownerId, revision: state.policy?.revision || null, activeKeyId: state.policy?.activeKeyId || null,
      policyDigest: state.policy?.digest || null, anchorStatus: state.anchorStatus || null, finding: state.finding || null,
      eventCount: state.policy?.events?.length || 0, historyNotProven: state.policy?.historyNotProven ?? null,
      rootRecoveryTrust: rootTrust, readOnly: true, mutationAllowed: false };
  }
  async function evaluate(ownerId, keyId, issuedAt) {
    assertOwner(ownerId);
    const timestamp = Date.parse(issuedAt);
    if (!Number.isFinite(timestamp) || !keys.has(keyId)) return { trusted: false, finding: "POLICY_AUTHORITY_KEY_OR_TIME_INVALID" };
    const state = await readExisting(ownerId);
    if (state.status !== "healthy") return { trusted: false, finding: state.finding || "POLICY_AUTHORITY_POLICY_UNHEALTHY" };
    const entry = state.policy.keys.find(item => item.keyId === keyId);
    if (!entry) return { trusted: false, finding: "POLICY_AUTHORITY_KEY_NOT_IN_POLICY" };
    const validFrom = entry.validFrom == null ? null : Date.parse(entry.validFrom);
    const retiredAt = entry.retiredAt == null ? null : Date.parse(entry.retiredAt);
    const revokedAt = entry.revokedAt == null ? null : Date.parse(entry.revokedAt);
    const cutoff = entry.invalidateBefore == null ? null : Date.parse(entry.invalidateBefore);
    const beforeCutoff = cutoff === null || timestamp < cutoff;
    if (entry.status === "active" && validFrom !== null && timestamp >= validFrom && beforeCutoff) return { trusted: true, finding: null, revision: state.policy.revision, historyNotProven: state.policy.historyNotProven };
    if (entry.status === "retired" && retiredAt !== null && timestamp < retiredAt && beforeCutoff) return { trusted: true, finding: null, revision: state.policy.revision, historyNotProven: state.policy.historyNotProven };
    if (entry.status === "revoked" && revokedAt !== null && timestamp < revokedAt
      && (retiredAt === null || timestamp < retiredAt) && beforeCutoff) return { trusted: true, finding: null, revision: state.policy.revision, historyNotProven: state.policy.historyNotProven };
    return { trusted: false, finding: entry.status === "revoked" ? "POLICY_AUTHORITY_KEY_REVOKED_OR_CUTOFF" : "POLICY_AUTHORITY_KEY_NOT_AUTHORIZED_AT_ISSUED_AT",
      revision: state.policy.revision, historyNotProven: state.policy.historyNotProven };
  }
  async function verifyHistoricalAuthorization(ownerId, eventInput) {
    assertOwner(ownerId);
    const raw = await store.getEvidence(ownerId, policyId(ownerId));
    const check = validatePolicy(ownerId, raw);
    if (!check.valid) return { valid: false, signatureValid: false, policyTrusted: false, finding: check.code, readOnly: true, mutationAllowed: false };
    const requestedSequence = Number.isSafeInteger(eventInput?.sequence) ? eventInput.sequence : null;
    const event = requestedSequence ? raw.events[requestedSequence - 1] : raw.events.find(item => item.digest === eventInput?.digest);
    if (!event || event.digest !== eventInput?.digest || (requestedSequence !== null && event.sequence !== requestedSequence)) {
      return { valid: false, signatureValid: false, policyTrusted: false, finding: "POLICY_AUTHORITY_HISTORICAL_EVENT_NOT_FOUND", readOnly: true, mutationAllowed: false };
    }
    if (event.action === "bootstrap") return { valid: false, signatureValid: false, policyTrusted: false,
      finding: "POLICY_AUTHORITY_BOOTSTRAP_HAS_NO_TRANSITION_SIGNATURE", eventSequence: event.sequence, readOnly: true, mutationAllowed: false };
    const anchor = await checkAnchor(ownerId, raw);
    const policyTrusted = new Set(["anchored", "local_only"]).has(anchor.status);
    const signatureValid = event.action === "root_recover"
      ? verifyRootRecoveryEvent(ownerId, event, event.details?.previousActiveKeyId)
      : verifyAuthorityEvent(ownerId, event, event.details?.signerKeyId);
    const rootTrust = event.action === "root_recover" && rootRecoveryTrustService?.configured
      ? await rootRecoveryTrustService.evaluateRecoverySloRootRecoveryTrustKey(ownerId, event.details?.rootKeyId, event.at)
      : { trusted: true, finding: null, historyNotProven: false };
    const rootTrustValid = event.action !== "root_recover" || rootTrust.trusted;
    return { valid: signatureValid && policyTrusted && rootTrustValid, signatureValid, policyTrusted, rootTrustTrusted: rootTrustValid,
      rootTrustFinding: rootTrust.finding || null, eventSequence: event.sequence,
      action: event.action, signerKeyId: event.details?.signerKeyId || event.details?.rootKeyId || null, policyRevision: raw.revision,
      anchorStatus: anchor.status, historyNotProven: raw.historyNotProven || Boolean(rootTrust.historyNotProven),
      findings: [
        ...(!signatureValid ? [{ code: "POLICY_AUTHORITY_HISTORICAL_SIGNATURE_INVALID" }] : []),
        ...(!policyTrusted ? [{ code: "POLICY_AUTHORITY_HISTORICAL_POLICY_UNTRUSTED", status: anchor.status }] : []),
        ...(!rootTrustValid ? [{ code: "POLICY_AUTHORITY_ROOT_TRUST_REJECTED", detail: rootTrust.finding || null }] : [])
      ], readOnly: true, mutationAllowed: false };
  }
  async function anchorStatus(ownerId) {
    assertOwner(ownerId);
    const raw = await store.getEvidence(ownerId, policyId(ownerId));
    if (!raw) return { status: "not_initialized", ownerId, domain: "policy_authority", required: anchorService?.required || false, readOnly: true, mutationAllowed: false };
    const valid = validatePolicy(ownerId, raw);
    if (!valid.valid) return { status: "unhealthy", ownerId, domain: "policy_authority", finding: valid.code, readOnly: true, mutationAllowed: false };
    return anchorService ? { ...await anchorService.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(ownerId, "policy_authority", raw), readOnly: true, mutationAllowed: false }
      : { status: "local_only", ownerId, domain: "policy_authority", required: false, trusted: true, readOnly: true, mutationAllowed: false };
  }
  async function reconcileAnchor(ownerId) {
    assertOwner(ownerId);
    const raw = await store.getEvidence(ownerId, policyId(ownerId));
    const valid = validatePolicy(ownerId, raw);
    if (!valid.valid) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_POLICY_UNHEALTHY", "Policy-authority policy tidak valid", 409);
    if (!anchorService) return { status: "local_only", reconciled: false, readOnly: false, mutationAllowed: false };
    return anchorService.reconcileRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, "policy_authority", raw);
  }
  async function enrollAnchor(ownerId, input = {}) {
    assertOwner(ownerId);
    const raw = await store.getEvidence(ownerId, policyId(ownerId));
    const valid = validatePolicy(ownerId, raw);
    if (!valid.valid) throw new AgenticError("RECOVERY_SLO_POLICY_AUTHORITY_POLICY_UNHEALTHY", "Policy-authority policy tidak valid untuk enrollment anchor", 409);
    if (!anchorService) return { status: "local_only", enrolled: false, readOnly: false, mutationAllowed: false };
    return anchorService.enrollRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, "policy_authority", raw, input);
  }
  return Object.freeze({ ensureRecoverySloProviderIdentityPolicyAuthority: ensure,
    assertRecoverySloProviderIdentityPolicyAuthorityActive: assertActive,
    prepareRecoverySloProviderIdentityPolicyAuthorityTransition: prepare,
    applyRecoverySloProviderIdentityPolicyAuthorityTransition: apply,
    prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery: prepareRootRecovery,
    applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery: applyRootRecovery,
    auditRecoverySloProviderIdentityPolicyAuthority: audit,
    evaluateRecoverySloProviderIdentityPolicyAuthoritySignature: evaluate,
    verifyRecoverySloProviderIdentityPolicyAuthorityHistoricalAuthorization: verifyHistoricalAuthorization,
    getRecoverySloProviderIdentityPolicyAuthorityAnchorStatus: anchorStatus,
    reconcileRecoverySloProviderIdentityPolicyAuthorityAnchor: reconcileAnchor,
    enrollRecoverySloProviderIdentityPolicyAuthorityAnchor: enrollAnchor,
    ensureRecoverySloRootRecoveryTrust: rootRecoveryTrustService?.ensureRecoverySloRootRecoveryTrust || (async ownerId => ({ status: "not_configured", ownerId })),
    prepareRecoverySloRootRecoveryTrustTransition: rootRecoveryTrustService?.prepareRecoverySloRootRecoveryTrustTransition || null,
    applyRecoverySloRootRecoveryTrustTransition: rootRecoveryTrustService?.applyRecoverySloRootRecoveryTrustTransition || null,
    auditRecoverySloRootRecoveryTrust: rootRecoveryTrustService?.auditRecoverySloRootRecoveryTrust || (async ownerId => ({ status: "not_configured", ownerId, readOnly: true, mutationAllowed: false })),
    evaluateRecoverySloRootRecoveryTrustKey: rootRecoveryTrustService?.evaluateRecoverySloRootRecoveryTrustKey || (async () => ({ trusted: false, finding: "ROOT_RECOVERY_TRUST_NOT_CONFIGURED" })),
    getRecoverySloRootRecoveryTrustAnchorStatus: rootRecoveryTrustService?.getRecoverySloRootRecoveryTrustAnchorStatus || (async ownerId => ({ status: "not_configured", ownerId, readOnly: true, mutationAllowed: false })),
    reconcileRecoverySloRootRecoveryTrustAnchor: rootRecoveryTrustService?.reconcileRecoverySloRootRecoveryTrustAnchor || null,
    prepareRecoverySloRootRecoveryTrustAnchorEnrollment: rootRecoveryTrustService?.prepareRecoverySloRootRecoveryTrustAnchorEnrollment || null,
    applyRecoverySloRootRecoveryTrustAnchorEnrollment: rootRecoveryTrustService?.applyRecoverySloRootRecoveryTrustAnchorEnrollment || null,
    configured: keys.size > 0 });
}
