import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";
import { createRecoverySloProviderIdentityTrustPolicyAnchorService } from "./recovery-slo-provider-identity-trust-policy-anchor.js";
import { createRecoverySloProviderIdentityPolicyAuthorityService } from "./recovery-slo-provider-identity-policy-authority.js";
import { createRecoverySloRootRecoveryTrustService } from "./recovery-slo-root-recovery-trust.js";

const POLICY_KIND = "recovery-slo-provider-identity-attestation-trust-policy";
const CHALLENGE_KIND = "recovery-slo-provider-identity-trust-key-transition-challenge";
const AUTH_DOMAIN = "agentic-v4-provider-identity-trust-key-transition-authorization";
const POP_DOMAIN = "agentic-v4-provider-identity-trust-key-proof-of-possession";
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
const policyId = (ownerId, domain) => `recovery-slo-provider-identity-trust-policy-${ownerHash(ownerId)}-${domain}`;
const challengeId = () => `recovery-slo-provider-identity-trust-key-transition-${randomUUID()}`;

function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_OWNER_REQUIRED", "Owner trust policy wajib ditentukan", 400);
  }
}
function parsePublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Trust-policy public key harus Ed25519");
  return key;
}
function keyMap(values, label) {
  const result = new Map();
  if (values instanceof Map) {
    for (const [id, value] of values) {
      if (!KEY_ID.test(String(id))) throw new TypeError(`${label} key ID tidak valid`);
      result.set(String(id), parsePublicKey(value));
    }
  } else if (values && typeof values === "object") {
    for (const [id, value] of Object.entries(values)) {
      if (!KEY_ID.test(id)) throw new TypeError(`${label} key ID tidak valid`);
      result.set(id, parsePublicKey(value));
    }
  }
  return result;
}
function publicKeyFingerprint(key) {
  return sha256(key.export({ format: "der", type: "spki" }).toString("base64"));
}
function verify(key, payload, signature) {
  try {
    if (!key || typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
    const bytes = Buffer.from(signature, "base64url");
    return bytes.length === 64 && bytes.toString("base64url") === signature
      && verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes);
  } catch { return false; }
}
function policyDigest(value) { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); }
function challengeDigest(value) {
  const copy = clean(value); delete copy.digest; delete copy.authorizationPayload; delete copy.proofOfPossessionPayload;
  return sha256(canonical(copy));
}
function eventDigest(value) { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); }

export function createRecoverySloProviderIdentityTrustPolicyService({ store, clock = () => new Date().toISOString(),
  driftPublicKeys = null, initialDriftKeyId = null, recoveryPublicKeys = null, initialRecoveryKeyId = null,
  policyAuthorityPublicKeys = null, initialPolicyAuthorityKeyId = null, policyAuthorityRootRecoveryPublicKeys = null, trustPolicyAnchorService = null,
  trustPolicyAnchorProvider = null, requireTrustPolicyAnchor = false, rootRecoveryTrustAnchorProvider = null, requireRootRecoveryTrustAnchor = false } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function") {
    throw new TypeError("Provider identity trust policy membutuhkan evidence store dan clock");
  }
  const driftKeys = keyMap(driftPublicKeys, "Drift event");
  const recoveryKeys = keyMap(recoveryPublicKeys, "Recovery attestation");
  const authorityKeys = keyMap(policyAuthorityPublicKeys, "Policy authority");
  const rootRecoveryKeys = keyMap(policyAuthorityRootRecoveryPublicKeys, "Policy authority root recovery");
  const anchorService = trustPolicyAnchorService || createRecoverySloProviderIdentityTrustPolicyAnchorService({
    store, provider: trustPolicyAnchorProvider, required: requireTrustPolicyAnchor, clock });
  const policyAuthorityInitialKeyId = initialPolicyAuthorityKeyId || (authorityKeys.size === 1 ? authorityKeys.keys().next().value : null);
  if (policyAuthorityInitialKeyId && (!KEY_ID.test(policyAuthorityInitialKeyId) || !authorityKeys.has(policyAuthorityInitialKeyId))) {
    throw new TypeError("Initial policy-authority key harus ada di trusted registry");
  }
  const operationalFingerprints = new Set([...driftKeys.values(), ...recoveryKeys.values()].map(publicKeyFingerprint));
  if ([...authorityKeys.values()].some(key => operationalFingerprints.has(publicKeyFingerprint(key)))) {
    throw new TypeError("Policy-authority public keys harus terpisah dari drift-event dan recovery-attestation signing keys");
  }
  const authorityFingerprints = new Set([...authorityKeys.values()].map(publicKeyFingerprint));
  if ([...rootRecoveryKeys.values()].some(key => operationalFingerprints.has(publicKeyFingerprint(key)) || authorityFingerprints.has(publicKeyFingerprint(key)))) {
    throw new TypeError("Root recovery public keys harus terpisah dari operational signing keys dan policy-authority keys");
  }
  const rootRecoveryTrustService = createRecoverySloRootRecoveryTrustService({ store, publicKeys: rootRecoveryKeys,
    anchorProvider: rootRecoveryTrustAnchorProvider, requireAnchor: requireRootRecoveryTrustAnchor, clock });
  const policyAuthorityService = createRecoverySloProviderIdentityPolicyAuthorityService({ store, clock,
    publicKeys: authorityKeys, initialKeyId: policyAuthorityInitialKeyId, anchorService, rootRecoveryPublicKeys: rootRecoveryKeys,
    rootRecoveryTrustService });
  if (initialDriftKeyId && (!KEY_ID.test(initialDriftKeyId) || !driftKeys.has(initialDriftKeyId))) throw new TypeError("Initial drift key harus ada di trusted public-key registry");
  if (initialRecoveryKeyId && (!KEY_ID.test(initialRecoveryKeyId) || !recoveryKeys.has(initialRecoveryKeyId))) throw new TypeError("Initial recovery key harus ada di trusted public-key registry");

  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CLOCK_INVALID", "Clock trust policy tidak valid", 500);
    return new Date(ms).toISOString();
  }
  function config(domain) {
    if (domain === "drift_event") return { keys: driftKeys, initialKeyId: initialDriftKeyId };
    if (domain === "recovery_attestation") return { keys: recoveryKeys, initialKeyId: initialRecoveryKeyId };
    throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_DOMAIN_INVALID", "Trust policy domain tidak valid", 400);
  }
  function validatePolicy(ownerId, domain, value) {
    if (!value || value.ownerId !== ownerId || value.id !== policyId(ownerId, domain) || value.kind !== POLICY_KIND
      || value.schemaVersion !== 1 || value.domain !== domain || !Number.isSafeInteger(value.revision) || value.revision < 1
      || !Array.isArray(value.keys) || !Array.isArray(value.events) || !Number.isFinite(Date.parse(value.createdAt))
      || typeof value.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(value.updatedAt))
      || value.events.length !== value.revision
      || (value.revision === 1 ? value.previousPolicyDigest !== null : !DIGEST.test(value.previousPolicyDigest || ""))
      || !DIGEST.test(value.digest || "") || value.digest !== policyDigest(value)) {
      return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_INVALID" };
    }
    const configured = config(domain);
    const seen = new Set();
    for (let index = 0; index < value.events.length; index++) {
      const event = value.events[index];
      if (!event || event.sequence !== index + 1 || event.previousDigest !== (index ? value.events[index - 1].digest : null)
        || !DIGEST.test(event.digest || "") || event.digest !== eventDigest(event) || typeof event.action !== "string") {
        return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_EVENT_CHAIN_INVALID" };
      }
    }
    for (const entry of value.keys) {
      if (!KEY_ID.test(entry.keyId || "") || !configured.keys.has(entry.keyId) || seen.has(entry.keyId) || !["active", "standby", "retired", "revoked", "legacy_trusted"].includes(entry.status)
        || !Number.isFinite(Date.parse(entry.addedAt)) || (entry.validFrom !== null && !Number.isFinite(Date.parse(entry.validFrom)))
        || (entry.retiredAt !== null && !Number.isFinite(Date.parse(entry.retiredAt)))
        || (entry.revokedAt !== null && !Number.isFinite(Date.parse(entry.revokedAt)))
        || (entry.invalidateBefore !== null && !Number.isFinite(Date.parse(entry.invalidateBefore)))
        || (entry.status === "active" && entry.validFrom === null)
        || (entry.status === "retired" && entry.retiredAt === null)
        || (entry.status === "revoked" && entry.revokedAt === null)) {
        return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_KEY_ENTRY_INVALID" };
      }
      seen.add(entry.keyId);
    }
    const active = value.keys.filter(entry => entry.status === "active");
    if (active.length > 1 || (value.activeKeyId === null ? active.length !== 0 : active.length !== 1 || active[0].keyId !== value.activeKeyId)) {
      return { valid: false, code: "PROVIDER_IDENTITY_TRUST_POLICY_ACTIVE_KEY_INVALID" };
    }
    return { valid: true };
  }
  async function readOrBootstrap(ownerId, domain) {
    assertOwner(ownerId);
    const configured = config(domain);
    const id = policyId(ownerId, domain);
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      const check = validatePolicy(ownerId, domain, existing);
      if (!check.valid) return { status: "unhealthy", policy: null, finding: check.code };
      const anchor = await anchorService.inspectRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, domain, existing);
      if (!new Set(["anchored", "local_only"]).has(anchor.status)) return { status: "unhealthy", policy: null,
        finding: anchor.finding || `TRUST_POLICY_ANCHOR_${anchor.status.toUpperCase()}`, anchorStatus: anchor.status };
      return { status: "healthy", policy: existing, anchorStatus: anchor.status };
    }
    if (!configured.initialKeyId || !configured.keys.has(configured.initialKeyId)) return { status: "not_configured", policy: null, finding: "INITIAL_SIGNING_KEY_NOT_CONFIGURED" };
    const createdAt = now();
    const keys = [...configured.keys.keys()].map(keyId => ({ keyId, status: keyId === configured.initialKeyId ? "active" : "standby",
      addedAt: createdAt, validFrom: keyId === configured.initialKeyId ? createdAt : null, retiredAt: null, revokedAt: null, invalidateBefore: null }));
    const firstEventUnsigned = { sequence: 1, action: "bootstrap", at: createdAt, previousDigest: null,
      details: { activeKeyId: configured.initialKeyId, trustedKeyCount: keys.length, legacyRegistryImported: true } };
    const firstEvent = { ...firstEventUnsigned, digest: eventDigest(firstEventUnsigned) };
    const unsigned = { id, ownerId, kind: POLICY_KIND, schemaVersion: 1, domain, revision: 1, activeKeyId: configured.initialKeyId,
      keys, events: [firstEvent], createdAt, updatedAt: createdAt, historyNotProven: true, previousPolicyDigest: null };
    const candidate = { ...unsigned, digest: policyDigest(unsigned) };
    try { await store.putEvidence(ownerId, candidate, { overwrite: false }); }
    catch {
      const raced = await store.getEvidence(ownerId, id);
      if (!raced) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_BOOTSTRAP_CONFLICT", "Trust policy bootstrap berkonflik", 409);
      const check = validatePolicy(ownerId, domain, raced);
      if (!check.valid) return { status: "unhealthy", policy: null, finding: check.code };
      const anchor = await anchorService.inspectRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, domain, raced);
      if (!new Set(["anchored", "local_only"]).has(anchor.status)) return { status: "unhealthy", policy: null,
        finding: anchor.finding || `TRUST_POLICY_ANCHOR_${anchor.status.toUpperCase()}`, anchorStatus: anchor.status };
      return { status: "healthy", policy: raced, anchorStatus: anchor.status };
    }
    const saved = await store.getEvidence(ownerId, id);
    const check = validatePolicy(ownerId, domain, saved);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_BOOTSTRAP_INVALID", "Trust policy hasil bootstrap gagal diverifikasi", 409);
    if (anchorService.configured) await anchorService.advanceRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, domain, saved, { genesis: true });
    else if (anchorService.required) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_UNAVAILABLE", "External trust-policy anchor diwajibkan", 503);
    return { status: "healthy", policy: saved, anchorStatus: anchorService.configured ? "anchored" : "local_only" };
  }
  async function readExisting(ownerId, domain) {
    assertOwner(ownerId);
    const configured = config(domain);
    const existing = await store.getEvidence(ownerId, policyId(ownerId, domain));
    if (!existing) return { status: configured.initialKeyId && configured.keys.has(configured.initialKeyId) ? "not_initialized" : "not_configured",
      policy: null, finding: "TRUST_POLICY_NOT_INITIALIZED" };
    const check = validatePolicy(ownerId, domain, existing);
    if (!check.valid) return { status: "unhealthy", policy: null, finding: check.code };
    const anchor = await anchorService.inspectRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, domain, existing);
    if (!new Set(["anchored", "local_only"]).has(anchor.status)) return { status: "unhealthy", policy: null,
      finding: anchor.finding || `TRUST_POLICY_ANCHOR_${anchor.status.toUpperCase()}`, anchorStatus: anchor.status };
    return { status: "healthy", policy: existing, anchorStatus: anchor.status };
  }
  async function getPolicy(ownerId, domain) {
    const state = await readExisting(ownerId, domain);
    if (state.status !== "healthy") return { status: state.status, ownerId, domain, finding: state.finding || null,
      readOnly: true, mutationAllowed: false };
    const { keys, events, ...summary } = state.policy;
    return { status: "healthy", ...summary, keys: keys.map(entry => ({ ...entry })), eventCount: events.length,
      anchorStatus: state.anchorStatus || "local_only", readOnly: true, mutationAllowed: false };
  }
  async function audit(ownerId, domain = null) {
    assertOwner(ownerId);
    const domains = domain ? [domain] : ["drift_event", "recovery_attestation"];
    const results = [];
    for (const item of domains) {
      config(item);
      const state = await readExisting(ownerId, item);
      results.push({ domain: item, status: state.status, revision: state.policy?.revision || null,
        activeKeyId: state.policy?.activeKeyId || null, anchorStatus: state.anchorStatus || null, finding: state.finding || null,
        eventCount: state.policy?.events?.length || 0, historyNotProven: state.policy?.historyNotProven ?? null });
    }
    const findings = results.filter(item => !["healthy", "not_configured"].includes(item.status)).map(item => ({ code: "PROVIDER_IDENTITY_TRUST_POLICY_NOT_HEALTHY", domain: item.domain, status: item.status, detail: item.finding }));
    const configuredCount = results.filter(item => item.status !== "not_configured").length;
    return { status: findings.length ? "unhealthy" : configuredCount ? "healthy" : "not_configured", ownerId, policies: results, findings, readOnly: true, mutationAllowed: false };
  }
  async function prepareTransition(ownerId, { domain, action, targetKeyId, reason, invalidateBefore = null, policyAuthorityKeyId } = {}) {
    assertOwner(ownerId);
    const configured = config(domain);
    if (!authorityKeys.size) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_AUTHORITY_NOT_CONFIGURED", "Policy authority public key belum dikonfigurasi", 503);
    if (!KEY_ID.test(policyAuthorityKeyId || "") || !authorityKeys.has(policyAuthorityKeyId)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_AUTHORITY_KEY_UNTRUSTED", "Policy authority key tidak tepercaya", 403);
    await policyAuthorityService.assertRecoverySloProviderIdentityPolicyAuthorityActive(ownerId, policyAuthorityKeyId);
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_REASON_INVALID", "Alasan transisi wajib 12–240 karakter", 400);
    if (!(["rotate", "revoke"].includes(action))) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ACTION_INVALID", "Aksi trust-key tidak valid", 400);
    if (!KEY_ID.test(targetKeyId || "") || !configured.keys.has(targetKeyId)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_TARGET_KEY_UNKNOWN", "Target key tidak ada di registry public key tepercaya", 409);
    if (invalidateBefore != null && (!Number.isFinite(Date.parse(invalidateBefore)) || Date.parse(invalidateBefore) > Date.parse(now()))) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CUTOFF_INVALID", "Compromise cutoff harus berupa timestamp valid yang tidak berada di masa depan", 400);
    }
    const state = await readOrBootstrap(ownerId, domain);
    if (state.status !== "healthy") throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_UNHEALTHY", "Trust policy tidak sehat", 409, { status: state.status, finding: state.finding });
    const policy = state.policy;
    const target = policy.keys.find(entry => entry.keyId === targetKeyId);
    if (action === "rotate" && target && !["standby", "legacy_trusted"].includes(target.status)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_TARGET_NOT_ROTATABLE", "Target key tidak berada pada status yang dapat dirotasi", 409);
    }
    if (action === "revoke" && (!target || target.status === "revoked")) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_TARGET_NOT_REVOCABLE", "Target key tidak tersedia atau sudah dicabut", 409);
    const createdAt = now();
    const id = challengeId();
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "prepared", domain, action, targetKeyId,
      expectedPolicyRevision: policy.revision, expectedPolicyDigest: policy.digest, reason: reason.trim(), invalidateBefore: invalidateBefore == null ? null : new Date(Date.parse(invalidateBefore)).toISOString(),
      policyAuthorityKeyId, createdAt, expiresAt: new Date(Date.parse(createdAt) + TTL_MS).toISOString() };
    const digest = challengeDigest(unsigned);
    const authorizationPayload = { domain: AUTH_DOMAIN, schemaVersion: 1, ownerId, policyDomain: domain, action, challengeId: id,
      challengeDigest: digest, expectedPolicyRevision: policy.revision, expectedPolicyDigest: policy.digest, targetKeyId,
      invalidateBefore: unsigned.invalidateBefore, reason: unsigned.reason, expiresAt: unsigned.expiresAt };
    const proofOfPossessionPayload = { domain: POP_DOMAIN, schemaVersion: 1, ownerId, policyDomain: domain, action: "rotate",
      challengeId: id, challengeDigest: digest, expectedPolicyDigest: policy.digest, targetKeyId, expiresAt: unsigned.expiresAt };
    const challenge = { ...unsigned, digest, authorizationPayload, proofOfPossessionPayload };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, ownerId, domain, action, targetKeyId, expectedPolicyRevision: policy.revision,
      expectedPolicyDigest: policy.digest, expiresAt: challenge.expiresAt, challengeDigest: digest,
      authorizationPayload: clone(authorizationPayload), proofOfPossessionPayload: action === "rotate" ? clone(proofOfPossessionPayload) : null,
      confirmation: `APPLY PROVIDER IDENTITY TRUST KEY TRANSITION ${digest.slice(0, 12)}`, readOnly: true, mutationAllowed: false };
  }
  async function saveChallenge(ownerId, current, patch) {
    const next = { ...clean(current), ...patch }; next.digest = challengeDigest(next);
    return store.putEvidence(ownerId, next, { expectedVersion: current._storage?.version });
  }
  async function applyTransition(ownerId, id, { confirmation, policyAuthoritySignature, proofOfPossessionSignature } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.schemaVersion !== 1
      || challenge.digest !== challengeDigest(challenge)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CHALLENGE_INVALID", "Challenge trust-key tidak valid", 409);
    if (challenge.status !== "prepared") throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CHALLENGE_REPLAY", "Challenge trust-key sudah digunakan", 409);
    if (Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CHALLENGE_EXPIRED", "Challenge trust-key kedaluwarsa", 409);
    if (confirmation !== `APPLY PROVIDER IDENTITY TRUST KEY TRANSITION ${challenge.digest.slice(0, 12)}`) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CONFIRMATION_INVALID", "Konfirmasi trust-key tidak cocok", 403);
    await policyAuthorityService.assertRecoverySloProviderIdentityPolicyAuthorityActive(ownerId, challenge.policyAuthorityKeyId);
    const authority = authorityKeys.get(challenge.policyAuthorityKeyId);
    if (!verify(authority, challenge.authorizationPayload, policyAuthoritySignature)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_AUTHORIZATION_INVALID", "Signature policy authority tidak valid", 403);
    const configured = config(challenge.domain);
    if (challenge.action === "rotate" && !verify(configured.keys.get(challenge.targetKeyId), challenge.proofOfPossessionPayload, proofOfPossessionSignature)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_PROOF_OF_POSSESSION_INVALID", "Proof of possession target key tidak valid", 403);
    }
    const current = await readExisting(ownerId, challenge.domain);
    if (current.status !== "healthy" || current.policy.digest !== challenge.expectedPolicyDigest || current.policy.revision !== challenge.expectedPolicyRevision) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_STALE", "Trust policy berubah sejak challenge dibuat", 409);
    }
    const policy = clone(current.policy);
    const at = now();
    let target = policy.keys.find(entry => entry.keyId === challenge.targetKeyId);
    if (challenge.action === "revoke" && (!target || target.status === "revoked")) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_TARGET_CHANGED", "Status target key berubah sejak challenge dibuat", 409);
    if (challenge.action === "rotate") {
      if (!target) {
        target = { keyId: challenge.targetKeyId, status: "standby", addedAt: at, validFrom: null, retiredAt: null, revokedAt: null, invalidateBefore: null };
        policy.keys.push(target);
      }
      if (!["standby", "legacy_trusted"].includes(target.status)) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_TARGET_NOT_ROTATABLE", "Target key tidak lagi dapat dirotasi", 409);
      const oldActive = policy.keys.find(entry => entry.keyId === policy.activeKeyId);
      if (oldActive) { oldActive.status = "retired"; oldActive.retiredAt = at; }
      target.status = "active"; target.validFrom = at; target.retiredAt = null; target.revokedAt = null; target.invalidateBefore = null;
      policy.activeKeyId = target.keyId;
    } else {
      target.status = "revoked"; target.revokedAt = at; target.invalidateBefore = challenge.invalidateBefore || at;
      if (policy.activeKeyId === target.keyId) policy.activeKeyId = null;
    }
    const prevEvent = policy.events.at(-1) || null;
    const eventUnsigned = { sequence: policy.events.length + 1, action: challenge.action, at, previousDigest: prevEvent?.digest || null,
      details: { targetKeyId: challenge.targetKeyId, priorActiveKeyId: current.policy.activeKeyId, activeKeyId: policy.activeKeyId,
        invalidateBefore: target.invalidateBefore, reason: challenge.reason, challengeDigest: challenge.digest,
        policyAuthorityKeyId: challenge.policyAuthorityKeyId, policyAuthoritySignatureDigest: sha256(policyAuthoritySignature),
        proofOfPossessionDigest: proofOfPossessionSignature ? sha256(proofOfPossessionSignature) : null } };
    policy.events.push({ ...eventUnsigned, digest: eventDigest(eventUnsigned) });
    policy.revision += 1; policy.previousPolicyDigest = current.policy.digest; policy.updatedAt = at;
    const next = { ...policy, digest: "" }; next.digest = policyDigest(next);
    const used = { ...clean(challenge), status: "used", usedAt: at, appliedPolicyDigest: next.digest,
      authoritySignatureDigest: sha256(policyAuthoritySignature), proofOfPossessionDigest: proofOfPossessionSignature ? sha256(proofOfPossessionSignature) : null };
    used.digest = challengeDigest(used);
    const expectedVersion = current.policy._storage?.version;
    delete next._storage;
    await store.putEvidence(ownerId, next, { expectedVersion });
    const saved = await store.getEvidence(ownerId, next.id);
    const check = validatePolicy(ownerId, challenge.domain, saved);
    if (!check.valid || saved.digest !== next.digest) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_WRITE_INVALID", "Trust policy hasil transisi gagal diverifikasi", 409);
    if (anchorService.configured) await anchorService.advanceRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, challenge.domain, saved, { previousPolicy: current.policy });
    else if (anchorService.required) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_ANCHOR_UNAVAILABLE", "External trust-policy anchor diwajibkan", 503);
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { status: "applied", domain: challenge.domain, action: challenge.action, revision: saved.revision,
      activeKeyId: saved.activeKeyId, policyDigest: saved.digest, targetKeyId: challenge.targetKeyId,
      historyNotProven: saved.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function evaluateSignature(ownerId, domain, keyId, issuedAt) {
    assertOwner(ownerId);
    const configured = config(domain);
    const timestamp = Date.parse(issuedAt);
    if (!Number.isFinite(timestamp) || !configured.keys.has(keyId)) return { trusted: false, finding: "SIGNATURE_KEY_OR_TIME_INVALID", historyNotProven: null };
    const state = await readExisting(ownerId, domain);
    if (state.status !== "healthy") return { trusted: false, finding: state.finding || "TRUST_POLICY_UNHEALTHY", historyNotProven: null };
    const policy = state.policy;
    const entry = policy.keys.find(item => item.keyId === keyId);
    if (!entry) return { trusted: false, finding: "SIGNATURE_KEY_NOT_IN_POLICY", historyNotProven: policy.historyNotProven };
    const issued = timestamp;
    const validFrom = entry.validFrom == null ? null : Date.parse(entry.validFrom);
    const retiredAt = entry.retiredAt == null ? null : Date.parse(entry.retiredAt);
    const revokedAt = entry.revokedAt == null ? null : Date.parse(entry.revokedAt);
    const cutoff = entry.invalidateBefore == null ? null : Date.parse(entry.invalidateBefore);
    if (entry.status === "active" && validFrom !== null && issued >= validFrom && (cutoff === null || issued < cutoff)) {
      return { trusted: true, finding: null, historyNotProven: policy.historyNotProven, policyRevision: policy.revision };
    }
    if (entry.status === "retired" && retiredAt !== null && issued < retiredAt && (cutoff === null || issued < cutoff)) {
      return { trusted: true, finding: null, historyNotProven: policy.historyNotProven, policyRevision: policy.revision };
    }
    if (entry.status === "revoked" && revokedAt !== null && issued < revokedAt
      && (retiredAt === null || issued < retiredAt) && (cutoff === null || issued < cutoff)) {
      return { trusted: true, finding: null, historyNotProven: policy.historyNotProven, policyRevision: policy.revision };
    }
    if (entry.status === "legacy_trusted" && policy.historyNotProven && issued <= Date.parse(policy.createdAt)) {
      return { trusted: true, finding: "LEGACY_TRUST_HISTORY_NOT_PROVEN", historyNotProven: true, policyRevision: policy.revision };
    }
    return { trusted: false, finding: entry.status === "revoked" ? "SIGNATURE_KEY_REVOKED_OR_CUTOFF" : "SIGNATURE_KEY_NOT_AUTHORIZED_AT_ISSUED_AT",
      historyNotProven: policy.historyNotProven, policyRevision: policy.revision };
  }
  async function getAnchorStatus(ownerId, domain = null) {
    assertOwner(ownerId);
    const domains = domain ? [domain] : ["drift_event", "recovery_attestation", "policy_authority"];
    const results = [];
    for (const item of domains) {
      if (item === "policy_authority") {
        results.push(await policyAuthorityService.getRecoverySloProviderIdentityPolicyAuthorityAnchorStatus(ownerId));
        continue;
      }
      config(item);
      const raw = await store.getEvidence(ownerId, policyId(ownerId, item));
      if (!raw) { results.push({ status: "not_initialized", ownerId, domain: item, required: anchorService.required, readOnly: true, mutationAllowed: false }); continue; }
      const check = validatePolicy(ownerId, item, raw);
      if (!check.valid) { results.push({ status: "unhealthy", ownerId, domain: item, finding: check.code, readOnly: true, mutationAllowed: false }); continue; }
      results.push(await anchorService.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(ownerId, item, raw));
    }
    return domain ? results[0] : { status: results.some(item => !["anchored", "local_only", "not_initialized"].includes(item.status)) ? "unhealthy"
      : results.some(item => item.status === "anchored") ? "anchored" : "local_only", ownerId, domains: results, readOnly: true, mutationAllowed: false };
  }
  async function reconcileAnchor(ownerId, domain) {
    assertOwner(ownerId);
    if (domain === "policy_authority") return policyAuthorityService.reconcileRecoverySloProviderIdentityPolicyAuthorityAnchor(ownerId);
    config(domain);
    const raw = await store.getEvidence(ownerId, policyId(ownerId, domain));
    const check = validatePolicy(ownerId, domain, raw);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_UNHEALTHY", "Trust policy tidak valid untuk rekonsiliasi anchor", 409);
    return anchorService.reconcileRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, domain, raw);
  }
  async function enrollAnchor(ownerId, domain, input = {}) {
    assertOwner(ownerId);
    if (domain === "policy_authority") return policyAuthorityService.enrollRecoverySloProviderIdentityPolicyAuthorityAnchor(ownerId, input);
    config(domain);
    const raw = await store.getEvidence(ownerId, policyId(ownerId, domain));
    const check = validatePolicy(ownerId, domain, raw);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_PROVIDER_TRUST_POLICY_UNHEALTHY", "Trust policy tidak valid untuk enrollment anchor", 409);
    return anchorService.enrollRecoverySloProviderIdentityTrustPolicyAnchor(ownerId, domain, raw, input);
  }
  return Object.freeze({ getRecoverySloProviderIdentityTrustPolicy: getPolicy,
    ensureRecoverySloProviderIdentityTrustPolicy: async (ownerId, domain) => {
      const state = await readOrBootstrap(ownerId, domain);
      if (state.status !== "healthy") return { status: state.status, ownerId, domain, finding: state.finding || null, readOnly: false, mutationAllowed: false };
      return { status: "healthy", ownerId, domain, revision: state.policy.revision, activeKeyId: state.policy.activeKeyId,
        policyDigest: state.policy.digest, historyNotProven: state.policy.historyNotProven, initialized: true, readOnly: false, mutationAllowed: false };
    },
    auditRecoverySloProviderIdentityTrustPolicy: audit,
    prepareRecoverySloProviderIdentityTrustKeyTransition: prepareTransition,
    applyRecoverySloProviderIdentityTrustKeyTransition: applyTransition,
    evaluateRecoverySloProviderIdentityTrustSignature: evaluateSignature,
    getRecoverySloProviderIdentityTrustPolicyAnchorStatus: getAnchorStatus,
    reconcileRecoverySloProviderIdentityTrustPolicyAnchor: reconcileAnchor,
    enrollRecoverySloProviderIdentityTrustPolicyAnchor: enrollAnchor,
    ensureRecoverySloProviderIdentityPolicyAuthority: policyAuthorityService.ensureRecoverySloProviderIdentityPolicyAuthority,
    prepareRecoverySloProviderIdentityPolicyAuthorityTransition: policyAuthorityService.prepareRecoverySloProviderIdentityPolicyAuthorityTransition,
    applyRecoverySloProviderIdentityPolicyAuthorityTransition: policyAuthorityService.applyRecoverySloProviderIdentityPolicyAuthorityTransition,
    prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery: policyAuthorityService.prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery,
    applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery: policyAuthorityService.applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery,
    auditRecoverySloProviderIdentityPolicyAuthority: policyAuthorityService.auditRecoverySloProviderIdentityPolicyAuthority,
    enrollRecoverySloProviderIdentityPolicyAuthorityAnchor: policyAuthorityService.enrollRecoverySloProviderIdentityPolicyAuthorityAnchor,
    evaluateRecoverySloProviderIdentityPolicyAuthoritySignature: policyAuthorityService.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature,
    verifyRecoverySloProviderIdentityPolicyAuthorityHistoricalAuthorization: policyAuthorityService.verifyRecoverySloProviderIdentityPolicyAuthorityHistoricalAuthorization,
    ensureRecoverySloRootRecoveryTrust: policyAuthorityService.ensureRecoverySloRootRecoveryTrust,
    prepareRecoverySloRootRecoveryTrustTransition: policyAuthorityService.prepareRecoverySloRootRecoveryTrustTransition,
    applyRecoverySloRootRecoveryTrustTransition: policyAuthorityService.applyRecoverySloRootRecoveryTrustTransition,
    auditRecoverySloRootRecoveryTrust: policyAuthorityService.auditRecoverySloRootRecoveryTrust,
    evaluateRecoverySloRootRecoveryTrustKey: policyAuthorityService.evaluateRecoverySloRootRecoveryTrustKey,
    getRecoverySloRootRecoveryTrustAnchorStatus: policyAuthorityService.getRecoverySloRootRecoveryTrustAnchorStatus,
    reconcileRecoverySloRootRecoveryTrustAnchor: policyAuthorityService.reconcileRecoverySloRootRecoveryTrustAnchor,
    prepareRecoverySloRootRecoveryTrustAnchorEnrollment: policyAuthorityService.prepareRecoverySloRootRecoveryTrustAnchorEnrollment,
    applyRecoverySloRootRecoveryTrustAnchorEnrollment: policyAuthorityService.applyRecoverySloRootRecoveryTrustAnchorEnrollment,
    configuredPolicyAuthorityKeys: authorityKeys.size });
}
