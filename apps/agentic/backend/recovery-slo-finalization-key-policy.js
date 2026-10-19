import { createHash, createPublicKey, verify as verifySignature, randomBytes, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const POLICY_KIND = "recovery-slo-finalization-key-policy";
const CHALLENGE_KIND = "recovery-slo-finalization-key-transition-challenge";
const MAX_EVENTS = 1000;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const EPOCH = "1970-01-01T00:00:00.000Z";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item);
  return out;
};
function digestRecord(record) {
  const value = clean(record);
  delete value.digest;
  return sha256(canonical(value));
}
function parsePublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Public key harus Ed25519");
  return key;
}
function publicKeyPem(value) { return parsePublicKey(value).export({ type: "spki", format: "pem" }).toString(); }
function verify(key, payload, signature) {
  try {
    const bytes = Buffer.from(signature, "base64url");
    return SIGNATURE.test(signature) && bytes.length === 64 && verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes);
  } catch { return false; }
}
const policyIdFor = ownerId => `recovery-slo-finalization-key-policy-${sha256(ownerId).slice(0, 48)}`;
const genesisHash = (ownerId, id) => sha256(`agentic-v4-finalization-key-policy:${ownerId}:${id}`);
const eventHash = event => sha256(canonical({ sequence: event.sequence, type: event.type, at: event.at,
  previousHash: event.previousHash, payload: event.payload, signerKeyId: event.signerKeyId,
  signature: event.signature, newKeyProofSignature: event.newKeyProofSignature ?? null }));
const reasonValid = reason => typeof reason === "string" && reason.trim().length >= 12 && reason.trim().length <= 240;

export function createRecoverySloFinalizationKeyPolicyService({ store, clock = () => new Date().toISOString(),
  trustedPublicKeys = null, initialActiveKeyId = null, recoveryAuthorityPublicKeys = null,
  externalAnchor = null, requireExternalAnchor = false, assertExternalAnchorContract = null } = {}) {
  if (!store?.getEvidence || !store?.listEvidence || !store?.putEvidence || !store?.mutateEvidence || typeof clock !== "function") {
    throw new TypeError("Finalization key policy membutuhkan evidence store yang valid");
  }
  if (externalAnchor != null && (typeof externalAnchor.read !== "function" || typeof externalAnchor.compareAndSet !== "function")) {
    throw new TypeError("Finalization key-policy external anchor harus menyediakan read() dan compareAndSet()");
  }
  if (requireExternalAnchor && !externalAnchor) {
    throw new TypeError("External anchor wajib dikonfigurasi ketika requireExternalAnchor aktif");
  }
  if (assertExternalAnchorContract != null && typeof assertExternalAnchorContract !== "function") {
    throw new TypeError("assertExternalAnchorContract harus berupa function");
  }
  const configuredKeys = new Map();
  const source = trustedPublicKeys instanceof Map ? [...trustedPublicKeys.entries()]
    : trustedPublicKeys && typeof trustedPublicKeys === "object" && !Array.isArray(trustedPublicKeys) ? Object.entries(trustedPublicKeys) : [];
  for (const [keyId, value] of source.slice(0, 100)) {
    if (typeof keyId !== "string" || !KEY_ID.test(keyId)) continue;
    try { configuredKeys.set(keyId, { key: parsePublicKey(value), pem: publicKeyPem(value) }); } catch { /* invalid roots are not trusted */ }
  }
  const recoveryAuthorities = new Map();
  const recoverySource = recoveryAuthorityPublicKeys instanceof Map ? [...recoveryAuthorityPublicKeys.entries()]
    : recoveryAuthorityPublicKeys && typeof recoveryAuthorityPublicKeys === "object" && !Array.isArray(recoveryAuthorityPublicKeys)
      ? Object.entries(recoveryAuthorityPublicKeys) : [];
  for (const [keyId, value] of recoverySource.slice(0, 20)) {
    if (typeof keyId !== "string" || !KEY_ID.test(keyId)) continue;
    try { recoveryAuthorities.set(keyId, { key: parsePublicKey(value), pem: publicKeyPem(value) }); } catch { /* invalid recovery roots are not trusted */ }
  }
  if (initialActiveKeyId != null && (!KEY_ID.test(initialActiveKeyId) || !configuredKeys.has(initialActiveKeyId))) {
    throw new TypeError("Active finalization key harus ada dalam trusted public key registry");
  }

  function assertOwner(ownerId) {
    if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
    }
  }
  function now() {
    const value = String(clock());
    if (!Number.isFinite(Date.parse(value))) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_CLOCK_INVALID", "Clock key policy tidak valid", 500);
    return new Date(value).toISOString();
  }
  function makeEvent(sequence, type, at, previousHash, payload, signerKeyId = null, signature = null, newKeyProofSignature = null) {
    const event = { sequence, type, at, previousHash, payload, signerKeyId, signature, newKeyProofSignature };
    event.eventHash = eventHash(event);
    return event;
  }
  function makePolicy(ownerId, at) {
    const keys = [...configuredKeys.entries()].map(([keyId, entry]) => ({ keyId, publicKeyPem: entry.pem,
      status: keyId === initialActiveKeyId ? "active" : "trusted", validFrom: EPOCH, retiredAt: null,
      revokedAt: null, invalidateBefore: null }));
    const payload = { domain: "agentic-v4-finalization-key-policy-bootstrap", schemaVersion: 1, ownerId,
      activeKeyId: initialActiveKeyId, keys, bootstrapKeyIds: keys.map(key => key.keyId).sort(), createdAt: at };
    const id = policyIdFor(ownerId);
    const first = makeEvent(1, "policy_bootstrapped", at, genesisHash(ownerId, id), payload);
    const record = { id, ownerId, kind: POLICY_KIND, schemaVersion: 1, revision: 1, activeKeyId: initialActiveKeyId,
      keys, events: [first], createdAt: at, updatedAt: at };
    record.digest = digestRecord(record);
    return record;
  }
  function rootTrustMatches(policy) {
    if (configuredKeys.size === 0) return false;
    const genesis = policy.events?.[0]?.payload;
    if (!Array.isArray(genesis?.keys) || !Array.isArray(genesis?.bootstrapKeyIds)) return false;
    const expected = [...configuredKeys.entries()].map(([keyId, entry]) => ({ keyId, publicKeyPem: entry.pem,
      status: keyId === initialActiveKeyId ? "active" : "trusted", validFrom: EPOCH, retiredAt: null,
      revokedAt: null, invalidateBefore: null })).sort((a, b) => a.keyId.localeCompare(b.keyId));
    const actual = [...genesis.keys].sort((a, b) => String(a?.keyId).localeCompare(String(b?.keyId)));
    const ids = expected.map(item => item.keyId).sort();
    return genesis.activeKeyId === initialActiveKeyId
      && canonical(genesis.bootstrapKeyIds) === canonical(ids)
      && canonical(actual) === canonical(expected);
  }
  function verifyPolicyRecord(record, ownerId, { requireConfiguredRoot = true } = {}) {
    const fail = code => ({ valid: false, code, record: null, keys: new Map(), activeKeyId: null });
    if (!record || record.ownerId !== ownerId || record.id !== policyIdFor(ownerId) || record.kind !== POLICY_KIND
      || record.schemaVersion !== 1 || !Number.isSafeInteger(record.revision) || record.revision < 1
      || !Array.isArray(record.events) || record.events.length < 1 || record.events.length > MAX_EVENTS
      || !Array.isArray(record.keys) || record.keys.length > 100 || !Number.isFinite(Date.parse(record.createdAt))
      || !Number.isFinite(Date.parse(record.updatedAt))) return fail("KEY_POLICY_SHAPE_INVALID");
    const first = record.events[0];
    if (!first || first.sequence !== 1 || first.type !== "policy_bootstrapped" || first.previousHash !== genesisHash(ownerId, record.id)
      || first.signerKeyId !== null || first.signature !== null || first.newKeyProofSignature !== null
      || first.eventHash !== eventHash(first) || first.at !== record.createdAt || first.payload?.domain !== "agentic-v4-finalization-key-policy-bootstrap"
      || first.payload?.ownerId !== ownerId || first.payload?.schemaVersion !== 1 || first.payload?.createdAt !== record.createdAt
      || !Array.isArray(first.payload.keys) || !Array.isArray(first.payload.bootstrapKeyIds)) return fail("KEY_POLICY_GENESIS_INVALID");
    const keys = new Map();
    for (const item of first.payload.keys) {
      if (!item || !KEY_ID.test(item.keyId || "") || keys.has(item.keyId) || !["active", "trusted"].includes(item.status)
        || item.validFrom !== EPOCH || item.retiredAt !== null || item.revokedAt !== null || item.invalidateBefore !== null) return fail("KEY_POLICY_GENESIS_KEY_INVALID");
      try { keys.set(item.keyId, { ...item, key: parsePublicKey(item.publicKeyPem) }); } catch { return fail("KEY_POLICY_PUBLIC_KEY_INVALID"); }
    }
    let activeKeyId = first.payload.activeKeyId;
    if (activeKeyId !== null && (!keys.has(activeKeyId) || keys.get(activeKeyId).status !== "active")) return fail("KEY_POLICY_ACTIVE_KEY_INVALID");
    if ([...keys.values()].filter(item => item.status === "active").length !== (activeKeyId === null ? 0 : 1)) return fail("KEY_POLICY_ACTIVE_KEY_COUNT_INVALID");
    const reconstructed = { id: record.id, ownerId, kind: POLICY_KIND, schemaVersion: 1, revision: 1,
      activeKeyId, keys: [...keys.values()].map(({ key, ...item }) => item), events: [first],
      createdAt: record.createdAt, updatedAt: first.at };
    reconstructed.digest = digestRecord(reconstructed);
    const bootstrapDigest = sha256(canonical(first.payload));
    const revisionStates = [{ revision: 1, policyDigest: reconstructed.digest, headHash: first.eventHash, bootstrapDigest }];
    let previousHash = first.eventHash;
    for (let index = 1; index < record.events.length; index += 1) {
      const event = record.events[index];
      if (!event || event.sequence !== index + 1 || event.previousHash !== previousHash || !Number.isFinite(Date.parse(event.at))
        || event.eventHash !== eventHash(event) || !event.payload || event.payload.ownerId !== ownerId || event.at !== event.payload.effectiveAt
        || event.payload.expectedRevision !== reconstructed.revision || event.payload.expectedPolicyDigest !== reconstructed.digest
        || event.payload.challengeId == null || typeof event.payload.reason !== "string") return fail("KEY_POLICY_EVENT_CHAIN_INVALID");
      const recoveryMode = event.payload.authorizationMode === "recovery";
      if (recoveryMode) {
        const recoveryKeyId = event.payload.recoveryAuthorityKeyId;
        const recoveryKey = recoveryAuthorities.get(recoveryKeyId);
        if (!recoveryKey || event.signerKeyId !== recoveryKeyId || !verify(recoveryKey.key, event.payload, event.signature)) {
          return fail("KEY_POLICY_RECOVERY_AUTHORIZATION_INVALID");
        }
        if (!((event.payload.action === "revoke" && event.payload.targetKeyId === activeKeyId)
          || (event.payload.action === "rotate" && activeKeyId === null))) return fail("KEY_POLICY_RECOVERY_SCOPE_INVALID");
      } else {
        const signer = keys.get(event.signerKeyId);
        if (event.payload.authorizationMode !== "current_key" || !signer || event.signerKeyId !== activeKeyId
          || !["active", "trusted"].includes(signer.status) || !verify(signer.key, event.payload, event.signature)) {
          return fail("KEY_POLICY_EVENT_SIGNATURE_INVALID");
        }
      }
      if (event.payload.action === "rotate") {
        if (event.type !== "key_rotated" || !KEY_ID.test(event.payload.newKeyId || "") || keys.has(event.payload.newKeyId)
          || typeof event.payload.newPublicKeyPem !== "string" || !SIGNATURE.test(event.newKeyProofSignature || "")) return fail("KEY_POLICY_ROTATION_INVALID");
        let nextKey;
        try { nextKey = parsePublicKey(event.payload.newPublicKeyPem); } catch { return fail("KEY_POLICY_ROTATION_PUBLIC_KEY_INVALID"); }
        if (!verify(nextKey, event.payload, event.newKeyProofSignature)) return fail("KEY_POLICY_NEW_KEY_PROOF_INVALID");
        if (activeKeyId !== null) {
          if (recoveryMode) return fail("KEY_POLICY_RECOVERY_SCOPE_INVALID");
          const old = keys.get(activeKeyId);
          if (!old || old.status !== "active") return fail("KEY_POLICY_ACTIVE_KEY_INVALID");
          old.status = "retired"; old.retiredAt = event.at;
        } else if (!recoveryMode) return fail("KEY_POLICY_ACTIVE_KEY_INVALID");
        keys.set(event.payload.newKeyId, { keyId: event.payload.newKeyId, publicKeyPem: publicKeyPem(nextKey), key: nextKey,
          status: "active", validFrom: event.at, retiredAt: null, revokedAt: null, invalidateBefore: null });
        activeKeyId = event.payload.newKeyId;
      } else if (event.payload.action === "revoke") {
        if (event.type !== "key_revoked" || !KEY_ID.test(event.payload.targetKeyId || "")) return fail("KEY_POLICY_REVOCATION_INVALID");
        const target = keys.get(event.payload.targetKeyId);
        if (!target || target.status === "revoked") return fail("KEY_POLICY_REVOCATION_TARGET_INVALID");
        if (event.payload.targetKeyId === activeKeyId) {
          if (!recoveryMode) return fail("KEY_POLICY_REVOCATION_INVALID");
          activeKeyId = null;
        } else if (recoveryMode) return fail("KEY_POLICY_RECOVERY_SCOPE_INVALID");
        if (event.payload.invalidateBefore != null && (!Number.isFinite(Date.parse(event.payload.invalidateBefore))
          || Date.parse(event.payload.invalidateBefore) > Date.parse(event.at))) return fail("KEY_POLICY_COMPROMISE_CUTOFF_INVALID");
        target.status = "revoked"; target.revokedAt = event.at; target.invalidateBefore = event.payload.invalidateBefore ?? null;
      } else return fail("KEY_POLICY_EVENT_TYPE_INVALID");
      reconstructed.revision += 1;
      reconstructed.activeKeyId = activeKeyId;
      reconstructed.keys = [...keys.values()].map(({ key, ...item }) => item);
      reconstructed.events.push(event);
      reconstructed.updatedAt = event.at;
      reconstructed.digest = digestRecord(reconstructed);
      revisionStates.push({ revision: reconstructed.revision, policyDigest: reconstructed.digest,
        headHash: event.eventHash, bootstrapDigest });
      previousHash = event.eventHash;
    }
    const comparable = value => canonical(clean(value));
    if (record.revision !== reconstructed.revision || record.activeKeyId !== reconstructed.activeKeyId
      || record.updatedAt !== reconstructed.updatedAt || record.digest !== reconstructed.digest
      || comparable(record.keys) !== comparable(reconstructed.keys) || record.events.length !== reconstructed.events.length) return fail("KEY_POLICY_SNAPSHOT_MISMATCH");
    if (requireConfiguredRoot && !rootTrustMatches(record)) return fail("KEY_POLICY_BOOTSTRAP_TRUST_MISMATCH");
    return { valid: true, code: null, record, keys, activeKeyId, revisionStates, bootstrapDigest };
  }
  function externalAnchorDigest(anchor) {
    const { digest, ...unsigned } = anchor || {};
    return sha256(canonical(unsigned));
  }
  function validateExternalAnchor(anchor, ownerId) {
    if (!anchor || typeof anchor !== "object" || anchor.schemaVersion !== 1 || anchor.ownerId !== ownerId
      || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
      || !Number.isSafeInteger(anchor.revision) || anchor.revision < 1 || anchor.anchorSequence !== anchor.revision
      || !DIGEST.test(anchor.trustDigest || "") || !DIGEST.test(anchor.headHash || "")
      || !DIGEST.test(anchor.bootstrapDigest || "")
      || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
      || ((anchor.anchorSequence === 1) !== (anchor.previousAnchorDigest === null))
      || !Number.isFinite(Date.parse(anchor.anchoredAt))
      || !["genesis", "trust_transition", "reconciliation"].includes(anchor.reason)
      || anchor.digest !== externalAnchorDigest(anchor)) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_INVALID", "External anchor finalization key policy tidak valid", 409);
    }
    return anchor;
  }
  function stateAtRevision(check, revision) {
    return check.revisionStates.find(state => state.revision === revision) || null;
  }
  function anchorSummary(status, extra = {}) {
    return { status, configured: Boolean(externalAnchor), rollbackProtectionEnabled: Boolean(externalAnchor),
      mutationAllowed: status === "anchored" || (status === "not_configured" && !requireExternalAnchor), readOnly: true, ...extra };
  }
  async function readExternalAnchor(ownerId) {
    if (!externalAnchor) return anchorSummary("not_configured", { ownerId, anchorRevision: null, localRevision: null });
    try {
      const anchor = await externalAnchor.read(ownerId);
      return anchor == null ? anchorSummary("missing", { ownerId, anchorRevision: null, anchor: null })
        : anchorSummary("present", { ownerId, anchorRevision: anchor.revision ?? null, anchorDigest: anchor.digest ?? null, anchor });
    } catch (error) {
      return anchorSummary("unavailable", { ownerId, anchorRevision: null, errorCode: String(error?.code || "EXTERNAL_ANCHOR_READ_FAILED").slice(0, 80) });
    }
  }
  async function inspectExternalAnchor(ownerId, check) {
    if (!externalAnchor) return anchorSummary("not_configured", { ownerId, localRevision: check?.record?.revision ?? null, anchorRevision: null });
    if (!check?.valid) {
      const remote = await readExternalAnchor(ownerId);
      if (remote.status === "unavailable") return anchorSummary("unavailable", { ownerId, localRevision: null, anchorRevision: null, errorCode: remote.errorCode });
      if (remote.status === "missing") return anchorSummary("missing", { ownerId, localRevision: null, anchorRevision: null });
      try { validateExternalAnchor(remote.anchor, ownerId); }
      catch (error) { return anchorSummary("invalid", { ownerId, localRevision: null, anchorRevision: remote.anchor?.revision ?? null, errorCode: error.code, anchorSnapshot: clean(remote.anchor) }); }
      return anchorSummary("rollback_detected", { ownerId, localRevision: null, anchorRevision: remote.anchor.revision, anchorDigest: remote.anchor.digest, anchorSnapshot: clean(remote.anchor) });
    }
    let anchor;
    try { anchor = await externalAnchor.read(ownerId); }
    catch (error) { return anchorSummary("unavailable", { ownerId, localRevision: check.record.revision, anchorRevision: null,
      errorCode: String(error?.code || "EXTERNAL_ANCHOR_READ_FAILED").slice(0, 80) }); }
    if (anchor == null) return anchorSummary("missing", { ownerId, localRevision: check.record.revision, anchorRevision: null });
    try { validateExternalAnchor(anchor, ownerId); }
    catch (error) { return anchorSummary("invalid", { ownerId, localRevision: check.record.revision,
      anchorRevision: Number.isSafeInteger(anchor?.revision) ? anchor.revision : null, errorCode: error.code, anchorSnapshot: clean(anchor) }); }
    const currentState = stateAtRevision(check, anchor.revision);
    if (anchor.bootstrapDigest !== check.bootstrapDigest) return anchorSummary("mismatch", { ownerId, localRevision: check.record.revision,
      anchorRevision: anchor.revision, anchorDigest: anchor.digest, anchorSnapshot: clean(anchor) });
    if (anchor.revision > check.record.revision) return anchorSummary("rollback_detected", { ownerId, localRevision: check.record.revision,
      anchorRevision: anchor.revision, anchorDigest: anchor.digest, anchorSnapshot: clean(anchor) });
    if (!currentState || currentState.policyDigest !== anchor.trustDigest || currentState.headHash !== anchor.headHash
      || currentState.bootstrapDigest !== anchor.bootstrapDigest) return anchorSummary("mismatch", { ownerId,
        localRevision: check.record.revision, anchorRevision: anchor.revision, anchorDigest: anchor.digest, anchorSnapshot: clean(anchor) });
    if (anchor.revision < check.record.revision) return anchorSummary("behind_registry", { ownerId, localRevision: check.record.revision,
      anchorRevision: anchor.revision, anchorDigest: anchor.digest, anchorSequence: anchor.anchorSequence, anchorSnapshot: clean(anchor) });
    return anchorSummary("anchored", { ownerId, localRevision: check.record.revision, anchorRevision: anchor.revision,
      anchorDigest: anchor.digest, anchorSequence: anchor.anchorSequence, anchorSnapshot: clean(anchor) });
  }
  function makeExternalAnchor(ownerId, check, previous, reason) {
    const state = stateAtRevision(check, check.record.revision);
    if (!state) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_STATE_INVALID", "State key policy tidak dapat di-anchor", 409);
    const previousTime = previous ? Date.parse(previous.anchoredAt) : 0;
    const recordTime = Date.parse(check.record.updatedAt);
    const nowTime = Date.parse(now());
    const anchoredAt = new Date(Math.max(nowTime, recordTime, previousTime + 1)).toISOString();
    const unsigned = { schemaVersion: 1, ownerId, anchorSequence: previous ? previous.anchorSequence + 1 : 1,
      revision: check.record.revision, trustDigest: state.policyDigest, headHash: state.headHash,
      bootstrapDigest: state.bootstrapDigest, previousAnchorDigest: previous?.digest ?? null, anchoredAt,
      reason: previous ? reason : "genesis" };
    return { ...unsigned, digest: externalAnchorDigest(unsigned) };
  }
  async function reconcileExternalAnchor(ownerId, check, { reason = "reconciliation", allowAdvance = true } = {}) {
    if (!externalAnchor) return anchorSummary("not_configured", { ownerId, localRevision: check?.record?.revision ?? null, anchorRevision: null });
    let status = await inspectExternalAnchor(ownerId, check);
    if (status.status === "anchored" || status.status === "not_configured" || status.status === "rollback_detected"
      || status.status === "mismatch" || status.status === "invalid" || status.status === "unavailable") return status;
    if (!allowAdvance) return status;
    let previous = null;
    try { previous = await externalAnchor.read(ownerId); }
    catch (error) { return anchorSummary("unavailable", { ownerId, localRevision: check.record.revision, anchorRevision: null,
      errorCode: String(error?.code || "EXTERNAL_ANCHOR_READ_FAILED").slice(0, 80) }); }
    if (previous == null) {
      if (check.record.revision !== 1 || check.record.events.length !== 1) return status;
    } else {
      try { validateExternalAnchor(previous, ownerId); }
      catch (error) { return anchorSummary("invalid", { ownerId, localRevision: check.record.revision,
        anchorRevision: previous.revision ?? null, errorCode: error.code }); }
      const ancestor = stateAtRevision(check, previous.revision);
      if (!ancestor || ancestor.policyDigest !== previous.trustDigest || ancestor.headHash !== previous.headHash
        || ancestor.bootstrapDigest !== previous.bootstrapDigest || previous.revision >= check.record.revision) return status;
    }
    const candidate = makeExternalAnchor(ownerId, check, previous, reason);
    try {
      await externalAnchor.compareAndSet(ownerId, previous?.digest ?? null, candidate);
      return await inspectExternalAnchor(ownerId, check);
    } catch (error) {
      return anchorSummary("unavailable", { ownerId, localRevision: check.record.revision, anchorRevision: previous?.revision ?? null,
        errorCode: String(error?.code || "EXTERNAL_ANCHOR_WRITE_FAILED").slice(0, 80) });
    }
  }
  async function assertExternalAnchorCurrent(ownerId, check) {
    if (!externalAnchor) {
      if (requireExternalAnchor) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_REQUIRED", "External anchor finalization key policy wajib dikonfigurasi", 503);
      return anchorSummary("not_configured", { ownerId, localRevision: check.record.revision, anchorRevision: null });
    }
    let status = await inspectExternalAnchor(ownerId, check);
    if (status.status === "missing" && check.record.revision === 1 && check.record.events.length === 1) {
      status = await reconcileExternalAnchor(ownerId, check, { reason: "genesis", allowAdvance: true });
    }
    if (status.status !== "anchored") {
      const code = status.status === "rollback_detected" ? "RECOVERY_SLO_FINALIZATION_KEY_POLICY_ROLLBACK_DETECTED"
        : status.status === "behind_registry" ? "RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_BEHIND_REGISTRY"
          : status.status === "mismatch" || status.status === "invalid" ? "RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_MISMATCH"
            : status.status === "missing" ? "RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_MISSING"
              : "RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_UNAVAILABLE";
      throw new AgenticError(code, "External anchor finalization key policy belum konsisten; operasi ditolak fail-closed", status.status === "unavailable" ? 503 : 409,
        { anchorStatus: status.status, localRevision: status.localRevision, anchorRevision: status.anchorRevision });
    }
    return status;
  }
  async function ensurePolicy(ownerId) {
    assertOwner(ownerId);
    if (assertExternalAnchorContract) await assertExternalAnchorContract(ownerId);
    const id = policyIdFor(ownerId);
    const current = await store.getEvidence(ownerId, id);
    if (current) {
      const check = verifyPolicyRecord(current, ownerId);
      if (!check.valid) throw new AgenticError(`RECOVERY_SLO_FINALIZATION_${check.code}`, "Finalization key policy tidak valid; operasi ditolak", 409);
      await assertExternalAnchorCurrent(ownerId, check);
      return check;
    }
    if (externalAnchor) {
      let remote;
      try { remote = await externalAnchor.read(ownerId); }
      catch { throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_UNAVAILABLE", "Tidak dapat memeriksa external anchor sebelum bootstrap policy", 503); }
      if (remote != null) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ROLLBACK_DETECTED", "External anchor ada tetapi policy lokal hilang; bootstrap ulang ditolak", 409,
        { anchorRevision: remote.revision ?? null });
    } else if (requireExternalAnchor) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_REQUIRED", "External anchor finalization key policy wajib dikonfigurasi", 503);
    }
    const at = now();
    const initial = makePolicy(ownerId, at);
    try { await store.putEvidence(ownerId, initial, { overwrite: false }); }
    catch { /* another caller may have initialized it */ }
    const saved = await store.getEvidence(ownerId, id);
    const check = verifyPolicyRecord(saved, ownerId);
    if (!check.valid) throw new AgenticError(`RECOVERY_SLO_FINALIZATION_${check.code}`, "Finalization key policy tidak dapat diinisialisasi", 409);
    await assertExternalAnchorCurrent(ownerId, check);
    return check;
  }
  async function readPolicy(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, policyIdFor(ownerId));
    if (!record) {
      const anchorStatus = await inspectExternalAnchor(ownerId, null);
      const status = ["rollback_detected", "mismatch", "invalid"].includes(anchorStatus.status) ? "unhealthy"
        : (externalAnchor && anchorStatus.status !== "missing" || requireExternalAnchor && anchorStatus.status !== "not_configured")
          ? "degraded" : "not_initialized";
      return { initialized: false, id: policyIdFor(ownerId), status, ownerId, activeKeyId: initialActiveKeyId,
        keys: [...configuredKeys.entries()].map(([keyId, entry]) => ({ keyId, status: keyId === initialActiveKeyId ? "active" : "trusted",
          fingerprint: sha256(entry.pem), validFrom: EPOCH, retiredAt: null, revokedAt: null, invalidateBefore: null })),
        revision: 0, digest: null, eventCount: 0, externalAnchor: anchorStatus, readOnly: true, mutationAllowed: false };
    }
    const check = verifyPolicyRecord(record, ownerId);
    if (!check.valid) return { initialized: true, id: record.id, status: "unhealthy", ownerId, revision: record.revision ?? null,
      digest: record.digest ?? null, findings: [check.code], readOnly: true, mutationAllowed: false };
    const anchorStatus = await inspectExternalAnchor(ownerId, check);
    const anchorBad = externalAnchor && anchorStatus.status !== "anchored";
    const status = anchorBad ? (["rollback_detected", "mismatch", "invalid"].includes(anchorStatus.status) ? "unhealthy" : "degraded") : "healthy";
    return { initialized: true, id: record.id, ownerId, status, activeKeyId: check.activeKeyId, revision: record.revision,
      digest: record.digest, eventCount: record.events.length, externalAnchor: anchorStatus,
      keys: record.keys.map(key => ({ keyId: key.keyId, status: key.status, fingerprint: sha256(key.publicKeyPem), validFrom: key.validFrom,
        retiredAt: key.retiredAt, revokedAt: key.revokedAt, invalidateBefore: key.invalidateBefore })), readOnly: true, mutationAllowed: false };
  }
  async function getSigningContext(ownerId) {
    const check = await ensurePolicy(ownerId);
    const key = check.activeKeyId ? check.keys.get(check.activeKeyId) : null;
    if (!key || key.status !== "active") throw new AgenticError("RECOVERY_SLO_FINALIZATION_NO_ACTIVE_KEY", "Tidak ada finalization signing key aktif", 503);
    return { keyId: check.activeKeyId, publicKey: key.key, policyRevision: check.record.revision, policyDigest: check.record.digest };
  }
  async function resolveKeyForReceipt(ownerId, keyId, signedAt) {
    assertOwner(ownerId);
    if (assertExternalAnchorContract) await assertExternalAnchorContract(ownerId);
    if (!KEY_ID.test(keyId || "") || !Number.isFinite(Date.parse(signedAt))) return { trusted: false, authorizedForCurrentUse: false, status: "invalid_receipt_time_or_key", publicKey: null };
    const record = await store.getEvidence(ownerId, policyIdFor(ownerId));
    if (!record) {
      if (externalAnchor || requireExternalAnchor) {
        const anchorStatus = await inspectExternalAnchor(ownerId, null);
        return { trusted: false, authorizedForCurrentUse: false, status: `policy_anchor_${anchorStatus.status}`,
          code: anchorStatus.status === "rollback_detected" ? "KEY_POLICY_ROLLBACK_DETECTED" : "KEY_POLICY_ANCHOR_REQUIRED",
          publicKey: null, keyId, externalAnchorStatus: anchorStatus.status };
      }
      const configured = configuredKeys.get(keyId);
      return configured ? { trusted: true, authorizedForCurrentUse: true, status: keyId === initialActiveKeyId ? "legacy_config_trust" : "legacy_config_historical_trust",
        publicKey: configured.key, keyId, signingKeyActive: keyId === initialActiveKeyId, policyRevision: 0 }
        : { trusted: false, authorizedForCurrentUse: false, status: "untrusted_key", publicKey: null, keyId };
    }
    const check = verifyPolicyRecord(record, ownerId);
    if (!check.valid) return { trusted: false, authorizedForCurrentUse: false,
      status: check.code === "KEY_POLICY_BOOTSTRAP_TRUST_MISMATCH" ? "untrusted_key" : "policy_unhealthy",
      code: check.code, publicKey: null, keyId };
    const anchorStatus = await inspectExternalAnchor(ownerId, check);
    if ((externalAnchor || requireExternalAnchor) && anchorStatus.status !== "anchored") {
      return { trusted: false, authorizedForCurrentUse: false, status: `policy_anchor_${anchorStatus.status}`,
        code: anchorStatus.status === "rollback_detected" ? "KEY_POLICY_ROLLBACK_DETECTED" : "KEY_POLICY_ANCHOR_NOT_CURRENT",
        publicKey: check.keys.get(keyId)?.key ?? null, keyId, policyRevision: record.revision, externalAnchorStatus: anchorStatus.status };
    }
    const key = check.keys.get(keyId);
    if (!key) return { trusted: false, authorizedForCurrentUse: false, status: "untrusted_key", publicKey: null, keyId, policyRevision: record.revision };
    const time = Date.parse(signedAt);
    if (time < Date.parse(key.validFrom)) return { trusted: false, authorizedForCurrentUse: false, status: "not_trusted_at_signing", publicKey: key.key, keyId, policyRevision: record.revision };
    if (key.status === "trusted" && keyId !== check.activeKeyId) {
      return { trusted: true, authorizedForCurrentUse: false, status: "not_authorized_signing_key", publicKey: key.key, keyId, policyRevision: record.revision };
    }
    if (key.retiredAt && time >= Date.parse(key.retiredAt)) return { trusted: false, authorizedForCurrentUse: false, status: "signed_after_retirement", publicKey: key.key, keyId, policyRevision: record.revision };
    if (key.revokedAt && time >= Date.parse(key.revokedAt)) return { trusted: false, authorizedForCurrentUse: false, status: "signed_after_revocation", publicKey: key.key, keyId, policyRevision: record.revision };
    if (key.invalidateBefore && time >= Date.parse(key.invalidateBefore)) return { trusted: false, authorizedForCurrentUse: false, status: "compromise_window", publicKey: key.key, keyId, policyRevision: record.revision };
    const status = key.status === "active" ? "valid_signed" : key.status === "retired" ? "valid_historical_retired" : key.status === "revoked" ? "valid_historical_revoked" : "valid_historical_trusted";
    return { trusted: true, authorizedForCurrentUse: true, status, publicKey: key.key, keyId,
      signingKeyActive: key.status === "active" && check.activeKeyId === keyId, policyRevision: record.revision };
  }
  async function createKeyTransitionChallenge(ownerId, input = {}) {
    const check = await ensurePolicy(ownerId);
    if (!input || !["rotate", "revoke"].includes(input.action) || input.expectedRevision !== check.record.revision || !reasonValid(input.reason)) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_TRANSITION_INPUT_INVALID", "Action, expectedRevision, atau alasan transisi tidak valid", 400);
    }
    const issuedAt = new Date(Math.max(Date.parse(now()), Date.parse(check.record.updatedAt) + 1)).toISOString();
    const challengeId = `recovery-slo-finalization-key-transition-${randomBytes(18).toString("hex")}`;
    let newKeyId = null, newPublicKeyPem = null, targetKeyId = null, invalidateBefore = null;
    let authorizationMode = "current_key", recoveryAuthorityKeyId = null;
    if (input.action === "rotate") {
      newKeyId = input.newKeyId;
      if (!KEY_ID.test(newKeyId || "") || check.keys.has(newKeyId)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_ID_CONFLICT", "Key ID baru tidak valid atau sudah ada", 409);
      try { newPublicKeyPem = publicKeyPem(input.newPublicKey); } catch { throw new AgenticError("RECOVERY_SLO_FINALIZATION_PUBLIC_KEY_INVALID", "Public key baru harus Ed25519", 400); }
    } else {
      targetKeyId = input.targetKeyId;
      if (!KEY_ID.test(targetKeyId || "") || !check.keys.has(targetKeyId) || check.keys.get(targetKeyId).status === "revoked") {
        throw new AgenticError("RECOVERY_SLO_FINALIZATION_REVOCATION_TARGET_INVALID", "Key target tidak dapat dicabut", 409);
      }
      if (targetKeyId === check.activeKeyId) {
        if (!recoveryAuthorities.has(input.recoveryAuthorityKeyId)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_RECOVERY_AUTHORITY_REQUIRED", "Mencabut active key memerlukan recovery authority yang dikonfigurasi", 403);
        authorizationMode = "recovery"; recoveryAuthorityKeyId = input.recoveryAuthorityKeyId;
      }
      if (input.invalidateBefore != null) {
        if (!Number.isFinite(Date.parse(input.invalidateBefore)) || Date.parse(input.invalidateBefore) > Date.parse(issuedAt)) {
          throw new AgenticError("RECOVERY_SLO_FINALIZATION_COMPROMISE_CUTOFF_INVALID", "invalidateBefore harus berupa timestamp valid yang tidak berada di masa depan", 400);
        }
        invalidateBefore = new Date(input.invalidateBefore).toISOString();
      }
    }
    if (input.action === "rotate" && !check.activeKeyId) {
      if (!recoveryAuthorities.has(input.recoveryAuthorityKeyId)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_RECOVERY_AUTHORITY_REQUIRED", "Memulihkan signing key memerlukan recovery authority yang dikonfigurasi", 403);
      authorizationMode = "recovery"; recoveryAuthorityKeyId = input.recoveryAuthorityKeyId;
    }
    if (input.action === "revoke" && targetKeyId !== check.activeKeyId && !check.activeKeyId) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_NO_ACTIVE_KEY", "Tanpa active key, hanya recovery-authorized key rotation yang diperbolehkan", 409);
    }
    const payload = { domain: "agentic-v4-finalization-key-transition", schemaVersion: 1, ownerId, challengeId,
      policyRevision: check.record.revision, expectedRevision: check.record.revision, expectedPolicyDigest: check.record.digest,
      action: input.action, targetKeyId, newKeyId, newPublicKeyPem, invalidateBefore,
      authorizationMode, recoveryAuthorityKeyId,
      reason: input.reason.trim(), issuedAt, effectiveAt: issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 10 * 60 * 1000).toISOString(),
      nonce: randomBytes(24).toString("base64url") };
    const challenge = { id: challengeId, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "issued", payload,
      payloadDigest: sha256(canonical(payload)), createdAt: issuedAt, expiresAt: payload.expiresAt };
    challenge.digest = digestRecord(challenge);
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId, ownerId, action: payload.action, policyRevision: payload.policyRevision,
      policyDigest: payload.expectedPolicyDigest, authorizationKeyId: authorizationMode === "recovery" ? recoveryAuthorityKeyId : check.activeKeyId, payload,
      payloadDigest: challenge.payloadDigest, expiresAt: challenge.expiresAt,
      requiresAuthorizationSignature: true, requiresNewKeyProof: payload.action === "rotate",
      readOnly: false, mutationAllowed: false };
  }
  async function applyKeyTransition(ownerId, challengeId, input = {}) {
    assertOwner(ownerId);
    if (typeof challengeId !== "string" || !challengeId.startsWith("recovery-slo-finalization-key-transition-")) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_CHALLENGE_INVALID", "Challenge ID tidak valid", 400);
    }
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.kind !== CHALLENGE_KIND || challenge.ownerId !== ownerId || challenge.digest !== digestRecord(challenge)
      || challenge.payloadDigest !== sha256(canonical(challenge.payload))) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_CHALLENGE_INVALID", "Challenge tidak ditemukan atau integritasnya gagal", 409);
    }
    let check = await ensurePolicy(ownerId);
    const already = check.record.events.find(event => event.payload?.challengeId === challengeId);
    if (already) {
      await markChallengeApplied(ownerId, challengeId, check.record.revision, already.eventHash);
      return summarizePolicy(check.record, true);
    }
    if (challenge.status !== "issued" || challenge.expiresAt !== challenge.payload?.expiresAt
      || challenge.createdAt !== challenge.payload?.issuedAt || Date.parse(now()) > Date.parse(challenge.payload?.expiresAt)) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_CHALLENGE_EXPIRED", "Challenge sudah digunakan, dimodifikasi, atau kedaluwarsa", 409);
    }
    const payload = challenge.payload;
    if (payload.ownerId !== ownerId || payload.expectedRevision !== check.record.revision || payload.expectedPolicyDigest !== check.record.digest
      || input.expectedRevision !== check.record.revision) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_STALE", "Key policy berubah sejak challenge dibuat", 409);
    }
    let signerKeyId = check.activeKeyId;
    let authorizationKey;
    if (payload.authorizationMode === "recovery") {
      authorizationKey = recoveryAuthorities.get(payload.recoveryAuthorityKeyId)?.key;
      signerKeyId = payload.recoveryAuthorityKeyId;
      const allowedScope = (payload.action === "revoke" && payload.targetKeyId === check.activeKeyId)
        || (payload.action === "rotate" && check.activeKeyId === null);
      if (!allowedScope || !authorizationKey) throw new AgenticError("RECOVERY_SLO_FINALIZATION_RECOVERY_SCOPE_INVALID", "Recovery authority tidak memiliki cakupan transisi ini", 403);
    } else {
      authorizationKey = check.keys.get(check.activeKeyId)?.key;
      if (payload.authorizationMode !== "current_key" || !check.activeKeyId) throw new AgenticError("RECOVERY_SLO_FINALIZATION_NO_ACTIVE_KEY", "Tidak ada active key untuk mengotorisasi transisi", 409);
    }
    if (!authorizationKey || !verify(authorizationKey, payload, input.authorizationSignature)) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_TRANSITION_SIGNATURE_INVALID", "Otorisasi transisi tidak valid", 403);
    }
    let newKeyProofSignature = null;
    if (payload.action === "rotate") {
      let nextKey;
      try { nextKey = parsePublicKey(payload.newPublicKeyPem); } catch { throw new AgenticError("RECOVERY_SLO_FINALIZATION_PUBLIC_KEY_INVALID", "Public key rotasi tidak valid", 409); }
      newKeyProofSignature = input.newKeyProofSignature;
      if (!verify(nextKey, payload, newKeyProofSignature)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_NEW_KEY_PROOF_INVALID", "Proof-of-possession untuk key baru tidak valid", 403);
    }
    const result = await store.mutateEvidence(ownerId, check.record.id, current => {
      if (!current) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_MISSING", "Key policy hilang", 409);
      const latest = verifyPolicyRecord(current, ownerId);
      if (!latest.valid) throw new AgenticError(`RECOVERY_SLO_FINALIZATION_${latest.code}`, "Key policy tidak sehat", 409);
      const replay = current.events.find(event => event.payload?.challengeId === challengeId);
      if (replay) return { write: false, result: current };
      if (current.revision !== payload.expectedRevision || current.digest !== payload.expectedPolicyDigest) {
        throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_STALE", "Key policy berubah sebelum transisi disimpan", 409);
      }
      const at = payload.effectiveAt;
      if (!Number.isFinite(Date.parse(at)) || Date.parse(at) <= Date.parse(current.updatedAt)) {
        throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_TRANSITION_TIME_INVALID", "Waktu efektif transisi tidak monotonik", 409);
      }
      const next = clean(current);
      if (payload.action === "rotate") {
        const old = next.keys.find(key => key.keyId === next.activeKeyId);
        if (next.keys.some(key => key.keyId === payload.newKeyId)
          || (next.activeKeyId && (!old || old.status !== "active" || payload.authorizationMode !== "current_key"))
          || (!next.activeKeyId && payload.authorizationMode !== "recovery")) {
          throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_ROTATION_CONFLICT", "Key policy tidak mengizinkan rotasi ini", 409);
        }
        if (old) { old.status = "retired"; old.retiredAt = at; }
        next.keys.push({ keyId: payload.newKeyId, publicKeyPem: payload.newPublicKeyPem, status: "active", validFrom: at,
          retiredAt: null, revokedAt: null, invalidateBefore: null });
        next.activeKeyId = payload.newKeyId;
      } else {
        const target = next.keys.find(key => key.keyId === payload.targetKeyId);
        const revokingActive = target?.keyId === next.activeKeyId;
        if (!target || target.status === "revoked" || (revokingActive && payload.authorizationMode !== "recovery")
          || (!revokingActive && payload.authorizationMode === "recovery")) {
          throw new AgenticError("RECOVERY_SLO_FINALIZATION_REVOCATION_CONFLICT", "Key tidak dapat dicabut dalam kondisi saat ini", 409);
        }
        if (revokingActive) next.activeKeyId = null;
        target.status = "revoked"; target.revokedAt = at; target.invalidateBefore = payload.invalidateBefore;
      }
      const type = payload.action === "rotate" ? "key_rotated" : "key_revoked";
      const event = makeEvent(next.events.length + 1, type, at, next.events.at(-1).eventHash, payload,
        signerKeyId, input.authorizationSignature, newKeyProofSignature);
      next.events.push(event); next.revision += 1; next.updatedAt = at; next.digest = digestRecord(next);
      const post = verifyPolicyRecord(next, ownerId);
      if (!post.valid) throw new AgenticError(`RECOVERY_SLO_FINALIZATION_${post.code}`, "Transisi menghasilkan key policy tidak valid", 500);
      return { value: next, result: next };
    });
    check = verifyPolicyRecord(result, ownerId);
    if (!check.valid) throw new AgenticError(`RECOVERY_SLO_FINALIZATION_${check.code}`, "Key policy gagal diverifikasi setelah transisi", 500);
    const event = check.record.events.find(item => item.payload?.challengeId === challengeId);
    await markChallengeApplied(ownerId, challengeId, check.record.revision, event?.eventHash ?? null);
    const anchorStatus = externalAnchor ? await reconcileExternalAnchor(ownerId, check, { reason: "trust_transition", allowAdvance: true })
      : anchorSummary("not_configured", { ownerId, localRevision: check.record.revision, anchorRevision: null });
    return { ...summarizePolicy(check.record, false), externalAnchor: anchorStatus,
      status: externalAnchor && anchorStatus.status !== "anchored" ? "anchor_pending" : "healthy",
      mutationAllowed: !externalAnchor || anchorStatus.status === "anchored" };
  }
  async function markChallengeApplied(ownerId, challengeId, revision, eventHashValue) {
    await store.mutateEvidence(ownerId, challengeId, current => {
      if (!current || current.kind !== CHALLENGE_KIND || current.ownerId !== ownerId) return { write: false, result: current };
      if (current.status === "applied") return { write: false, result: current };
      const next = clean(current); next.status = "applied"; next.appliedAt = now(); next.appliedRevision = revision; next.appliedEventHash = eventHashValue;
      next.digest = digestRecord(next); return { value: next, result: next };
    });
  }
  function summarizePolicy(record, idempotent = false) {
    return { id: record.id, ownerId: record.ownerId, status: "healthy", revision: record.revision, digest: record.digest,
      activeKeyId: record.activeKeyId, eventCount: record.events.length, keys: record.keys.map(key => ({ keyId: key.keyId,
        status: key.status, fingerprint: sha256(key.publicKeyPem), validFrom: key.validFrom, retiredAt: key.retiredAt,
        revokedAt: key.revokedAt, invalidateBefore: key.invalidateBefore })), idempotent,
      readOnly: true, mutationAllowed: false };
  }
  async function auditKeyPolicy(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, policyIdFor(ownerId));
    if (!record) {
      const anchorStatus = await inspectExternalAnchor(ownerId, null);
      const status = ["rollback_detected", "mismatch", "invalid"].includes(anchorStatus.status) ? "unhealthy"
        : (externalAnchor && anchorStatus.status !== "missing" || requireExternalAnchor && anchorStatus.status !== "not_configured")
          ? "degraded" : "not_initialized";
      return { id: policyIdFor(ownerId), ownerId, status, localStatus: "not_initialized", externalAnchor: anchorStatus,
        findings: anchorStatus.status === "rollback_detected" ? [{ code: "KEY_POLICY_ROLLBACK_DETECTED", severity: "error" }] : [],
        revision: 0, readOnly: true, mutationAllowed: false, automaticRepairAllowed: false };
    }
    const check = verifyPolicyRecord(record, ownerId);
    const anchorStatus = await inspectExternalAnchor(ownerId, check);
    const localValid = check.valid;
    const anchorBad = externalAnchor && anchorStatus.status !== "anchored";
    const status = !localValid || ["rollback_detected", "mismatch", "invalid"].includes(anchorStatus.status) ? "unhealthy"
      : anchorBad || (requireExternalAnchor && anchorStatus.status !== "anchored") ? "degraded" : "healthy";
    const findings = [];
    if (!localValid) findings.push({ code: check.code, severity: "error" });
    if (anchorBad || requireExternalAnchor && anchorStatus.status !== "anchored") findings.push({ code: `KEY_POLICY_ANCHOR_${String(anchorStatus.status).toUpperCase()}`,
      severity: ["rollback_detected", "mismatch", "invalid"].includes(anchorStatus.status) ? "error" : "warning" });
    return { id: record.id, ownerId, status, localStatus: localValid ? "healthy" : "unhealthy", externalAnchor: anchorStatus,
      revision: record.revision ?? null, digest: record.digest ?? null, activeKeyId: check.valid ? check.activeKeyId : null,
      eventCount: record.events?.length ?? 0, findings, readOnly: true, mutationAllowed: false, automaticRepairAllowed: false };
  }
  async function getAnchorStatus(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, policyIdFor(ownerId));
    if (!record) return inspectExternalAnchor(ownerId, null);
    const check = verifyPolicyRecord(record, ownerId);
    if (!check.valid) return anchorSummary("local_policy_unhealthy", { ownerId, localRevision: record.revision ?? null,
      anchorRevision: null, errorCode: check.code });
    return inspectExternalAnchor(ownerId, check);
  }
  function classifyAnchorSnapshot(ownerId, check, anchor) {
    if (!anchor) return "missing";
    try { validateExternalAnchor(anchor, ownerId); } catch { return "invalid"; }
    if (anchor.bootstrapDigest !== check.bootstrapDigest) return "mismatch";
    if (anchor.revision > check.record.revision) return "rollback_detected";
    const state = stateAtRevision(check, anchor.revision);
    if (!state || state.policyDigest !== anchor.trustDigest || state.headHash !== anchor.headHash
      || state.bootstrapDigest !== anchor.bootstrapDigest) return "mismatch";
    return anchor.revision < check.record.revision ? "behind_registry" : "anchored";
  }
  async function createAnchorContinuityProof(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, policyIdFor(ownerId));
    if (!record) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_MISSING", "Key policy belum tersedia untuk membuat continuity proof", 409);
    const check = verifyPolicyRecord(record, ownerId);
    if (!check.valid) throw new AgenticError(`RECOVERY_SLO_FINALIZATION_${check.code}`, "Key policy tidak valid; continuity proof tidak dapat dibuat", 409);
    const status = await inspectExternalAnchor(ownerId, check);
    const unsigned = { domain: "agentic-v4-finalization-key-policy-anchor-continuity-proof", schemaVersion: 1,
      proofId: `recovery-slo-key-anchor-continuity-${randomUUID()}`, ownerId, policyId: record.id,
      generatedAt: now(), observedAnchorStatus: status.status, localPolicySnapshot: clean(record),
      revisionCheckpoints: check.revisionStates, externalAnchorSnapshot: status.anchorSnapshot ?? null,
      externalHistoryProof: "latest-only-provider-does-not-expose-prior-anchor-records",
      claims: { localPolicyChainValid: true, bootstrapTrustMatched: true,
        anchorSnapshotPresent: Boolean(status.anchorSnapshot), anchorMatchesLocalChain: ["anchored", "behind_registry"].includes(status.status),
        anchorCurrent: status.status === "anchored", remoteObservationAuthenticated: false },
      readOnly: true, mutationAllowed: false };
    return { ...unsigned, proofDigest: sha256(canonical(unsigned)) };
  }
  function verifyAnchorContinuityProof(ownerId, proof) {
    assertOwner(ownerId);
    const fail = code => ({ valid: false, proofIntegrityValid: false, continuityEstablished: false,
      ownerId, status: "invalid", findings: [code], readOnly: true, mutationAllowed: false });
    if (!proof || typeof proof !== "object" || proof.domain !== "agentic-v4-finalization-key-policy-anchor-continuity-proof"
      || proof.schemaVersion !== 1 || proof.ownerId !== ownerId || proof.policyId !== policyIdFor(ownerId)
      || typeof proof.proofId !== "string" || !Number.isFinite(Date.parse(proof.generatedAt))
      || !DIGEST.test(proof.proofDigest || "")) return fail("CONTINUITY_PROOF_SHAPE_INVALID");
    const unsigned = clean(proof); delete unsigned.proofDigest;
    if (sha256(canonical(unsigned)) !== proof.proofDigest) return fail("CONTINUITY_PROOF_DIGEST_MISMATCH");
    const check = verifyPolicyRecord(proof.localPolicySnapshot, ownerId);
    if (!check.valid) return fail(`LOCAL_POLICY_${check.code}`);
    if (canonical(check.revisionStates) !== canonical(proof.revisionCheckpoints)
      || proof.localPolicySnapshot.id !== proof.policyId) return fail("CONTINUITY_PROOF_CHECKPOINT_MISMATCH");
    const anchor = proof.externalAnchorSnapshot;
    let computedStatus;
    if (anchor == null) {
      if (!["missing", "unavailable", "not_configured"].includes(proof.observedAnchorStatus)) return fail("CONTINUITY_PROOF_ANCHOR_SNAPSHOT_MISSING");
      computedStatus = proof.observedAnchorStatus;
    } else {
      computedStatus = classifyAnchorSnapshot(ownerId, check, anchor);
      if (computedStatus !== proof.observedAnchorStatus) return fail("CONTINUITY_PROOF_ANCHOR_STATUS_MISMATCH");
    }
    if (proof.externalHistoryProof !== "latest-only-provider-does-not-expose-prior-anchor-records") return fail("CONTINUITY_PROOF_HISTORY_CLAIM_INVALID");
    const expectedClaims = { localPolicyChainValid: true, bootstrapTrustMatched: true,
      anchorSnapshotPresent: Boolean(anchor), anchorMatchesLocalChain: ["anchored", "behind_registry"].includes(computedStatus),
      anchorCurrent: computedStatus === "anchored", remoteObservationAuthenticated: false };
    if (canonical(expectedClaims) !== canonical(proof.claims)) return fail("CONTINUITY_PROOF_CLAIMS_MISMATCH");
    const continuityEstablished = ["anchored", "behind_registry"].includes(computedStatus);
    return { valid: true, proofIntegrityValid: true, localPolicyValid: true, continuityEstablished,
      current: computedStatus === "anchored", status: computedStatus, ownerId, proofId: proof.proofId,
      proofDigest: proof.proofDigest, localRevision: check.record.revision,
      anchorRevision: anchor?.revision ?? null, remoteObservationAuthenticated: false,
      externalHistoryProof: proof.externalHistoryProof, readOnly: true, mutationAllowed: false,
      findings: continuityEstablished ? [] : [`ANCHOR_CONTINUITY_${String(computedStatus).toUpperCase()}`] };
  }
  async function reconcileAnchor(ownerId) {
    assertOwner(ownerId);
    if (assertExternalAnchorContract) await assertExternalAnchorContract(ownerId);
    if (!externalAnchor) {
      if (requireExternalAnchor) throw new AgenticError("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_REQUIRED", "External anchor wajib dikonfigurasi", 503);
      return anchorSummary("not_configured", { ownerId, localRevision: null, anchorRevision: null });
    }
    const record = await store.getEvidence(ownerId, policyIdFor(ownerId));
    if (!record) {
      const status = await inspectExternalAnchor(ownerId, null);
      if (status.status === "rollback_detected") return status;
      return anchorSummary(status.status === "missing" ? "local_policy_missing" : status.status,
        { ownerId, localRevision: null, anchorRevision: status.anchorRevision ?? null, errorCode: status.errorCode });
    }
    const check = verifyPolicyRecord(record, ownerId);
    if (!check.valid) return anchorSummary("local_policy_unhealthy", { ownerId, localRevision: record.revision ?? null,
      anchorRevision: null, errorCode: check.code });
    return reconcileExternalAnchor(ownerId, check, { reason: "reconciliation", allowAdvance: true });
  }
  return Object.freeze({
    getRecoverySloFinalizationKeyPolicy: readPolicy,
    auditRecoverySloFinalizationKeyPolicy: auditKeyPolicy,
    createRecoverySloFinalizationKeyTransitionChallenge: createKeyTransitionChallenge,
    applyRecoverySloFinalizationKeyTransition: applyKeyTransition,
    getRecoverySloFinalizationSigningContext: getSigningContext,
    resolveRecoverySloFinalizationReceiptKey: resolveKeyForReceipt,
    getRecoverySloFinalizationKeyPolicyAnchorStatus: getAnchorStatus,
    reconcileRecoverySloFinalizationKeyPolicyAnchor: reconcileAnchor,
    createRecoverySloFinalizationKeyPolicyAnchorContinuityProof: createAnchorContinuityProof,
    verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof: verifyAnchorContinuityProof
  });
}
