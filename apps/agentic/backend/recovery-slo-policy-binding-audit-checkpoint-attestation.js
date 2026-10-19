import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const DOMAIN = "agentic-v4-policy-binding-audit-checkpoint-freshness-attestation";
const KIND = "recovery-slo-policy-binding-audit-checkpoint-freshness-attestation";
const KEY_EVENT_KIND = `${KIND}-key-lifecycle-event`;
const KEY_CHALLENGE_KIND = `${KIND}-key-lifecycle-challenge`;
const KEY_TRANSITION_RECEIPT_KIND = `${KIND}-registry-transition-receipt`;
const KEY_TRANSITION_EXPORT_KIND = `${KIND}-registry-transition-receipt-export`;
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
const validReason = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_OWNER_REQUIRED", "Owner attestation checkpoint policy-binding wajib ditentukan", 400);
}
function keyMap(input) {
  const entries = input instanceof Map ? [...input] : input && typeof input === "object" ? Object.entries(input) : [];
  const out = new Map();
  for (const [id, value] of entries) {
    if (!KEY_ID.test(String(id))) throw new TypeError("Policy-binding checkpoint attestation key ID tidak valid");
    const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
    if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Policy-binding checkpoint attestation public key harus Ed25519");
    out.set(String(id), key);
  }
  return out;
}
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (["checkedAt", "createdAt", "updatedAt", "ageMs", "ageDays", "cacheHit"].includes(key)) continue;
    out[key] = stable(item);
  }
  return out;
}

export function createRecoverySloPolicyBindingAuditCheckpointAttestationService({ store, signer = null, keyId = null, publicKeys = null, signers = null,
  required = false, clock = () => new Date().toISOString(), maxAgeMs = 86400000, futureSkewMs = 60000,
  readCheckpoint, auditCheckpoint, auditPolicyBindingChain } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function"
    || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 60000 || !Number.isSafeInteger(futureSkewMs) || futureSkewMs < 0
    || typeof readCheckpoint !== "function" || typeof auditCheckpoint !== "function" || typeof auditPolicyBindingChain !== "function")
    throw new TypeError("Policy-binding checkpoint attestation membutuhkan store, clock, dan pembaca checkpoint/audit");
  const keys = keyMap(publicKeys);
  if (keyId != null && !KEY_ID.test(keyId)) throw new TypeError("Policy-binding checkpoint attestation key ID tidak valid");
  const signerMap = signers instanceof Map ? new Map(signers) : signers && typeof signers === "object" ? new Map(Object.entries(signers)) : new Map();
  for (const [id, fn] of signerMap) if (!KEY_ID.test(String(id)) || typeof fn !== "function") throw new TypeError("Policy-binding checkpoint attestation signer registry tidak valid");
  if (signer && keyId && !signerMap.has(keyId)) signerMap.set(keyId, signer);
  if (required && (!keyId || !keys.has(keyId) || !signerMap.has(keyId))) throw new TypeError("Attestation freshness checkpoint policy-binding wajib memiliki signer dan trusted public key Ed25519");
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_CLOCK_INVALID", "Clock attestation checkpoint policy-binding tidak valid", 500);
    return new Date(value).toISOString();
  }
  function keyFingerprint(publicKey) {
    return sha256(publicKey.export({ type: "spki", format: "der" }).toString("base64"));
  }
  function registryEntries() {
    return [...keys.entries()].map(([id, publicKey]) => ({ keyId: id, publicKeyFingerprint: keyFingerprint(publicKey) }))
      .sort((a, b) => a.keyId.localeCompare(b.keyId));
  }
  function registryDigest(entries = registryEntries()) { return sha256(canonical(entries)); }
  function transitionReceiptBody(receipt) {
    const copy = clean(receipt); delete copy.digest; delete copy.receiptDigest; return copy;
  }
  function transitionReceiptDigest(receipt) { return sha256(canonical(transitionReceiptBody(receipt))); }
  async function readKeyLifecycle(ownerId) {
    const rows = await store.listEvidence(ownerId);
    const events = rows.filter(row => row?.ownerId === ownerId && row.kind === KEY_EVENT_KIND).sort((a, b) => a.sequence - b.sequence);
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === KEY_CHALLENGE_KIND);
    const findings = [], statuses = new Map(), revokedAt = new Map(), revokedAtSequence = new Map();
    let activeKeyId = keyId, headDigest = null, expectedSequence = 1;
    for (const event of events) {
      const unsigned = clean(event); delete unsigned.digest; delete unsigned.eventDigest;
      const calculatedEventDigest = sha256(canonical(unsigned));
      if (event.digest !== digestRecord(event) || event.eventDigest !== calculatedEventDigest || event.sequence !== expectedSequence
        || (event.previousEventDigest ?? null) !== headDigest || !validReason(event.reason) || typeof event.challengeId !== "string" || !event.challengeId) {
        findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_CHAIN_INVALID", eventId: event.id });
        expectedSequence = Number.isSafeInteger(event.sequence) ? event.sequence + 1 : expectedSequence + 1;
        headDigest = event.eventDigest || null;
        continue;
      }
      const challenge = challenges.find(item => item.id === event.challengeId);
      if (!challenge || challenge.digest !== digestRecord(challenge) || challenge.status !== "completed"
        || challenge.eventId !== event.id || challenge.eventDigest !== event.eventDigest || challenge.challengeDigest !== event.challengeDigest) {
        findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_CHALLENGE_LINK_INVALID", eventId: event.id });
      }
      if (event.action === "rotate") {
        if (event.previousActiveKeyId !== activeKeyId || !keys.has(event.targetKeyId)
          || statuses.get(event.targetKeyId) === "revoked") {
          findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_ROTATION_INVALID", eventId: event.id });
        } else {
          if (activeKeyId) statuses.set(activeKeyId, "retired");
          activeKeyId = event.targetKeyId;
          statuses.set(activeKeyId, "active");
        }
      } else if (event.action === "revoke") {
        if (!keys.has(event.targetKeyId) || event.targetKeyId === activeKeyId || statuses.get(event.targetKeyId) === "revoked"
          || !Number.isFinite(Date.parse(event.revokedAt))) {
          findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_REVOCATION_INVALID", eventId: event.id });
        } else {
          statuses.set(event.targetKeyId, "revoked");
          revokedAt.set(event.targetKeyId, event.revokedAt);
          revokedAtSequence.set(event.targetKeyId, event.sequence);
        }
      } else findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_ACTION_INVALID", eventId: event.id });
      headDigest = event.eventDigest;
      expectedSequence++;
    }
    for (const challenge of challenges) {
      if (challenge.digest !== digestRecord(challenge)) findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_CHALLENGE_INVALID", challengeId: challenge.id });
      if (challenge.status === "completed" && !events.some(event => event.id === challenge.eventId && event.eventDigest === challenge.eventDigest))
        findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_EVENT_MISSING", challengeId: challenge.id });
    }
    if (activeKeyId && !statuses.has(activeKeyId)) statuses.set(activeKeyId, "active");
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, activeKeyId, headDigest, eventCount: events.length,
      events, statuses, revokedAt, revokedAtSequence, findings, readOnly: true, mutationAllowed: false };
  }
  async function readKeyLifecycleTransitionReceipts(ownerId) {
    const rows = await store.listEvidence(ownerId);
    const events = rows.filter(row => row?.ownerId === ownerId && row.kind === KEY_EVENT_KIND).sort((a, b) => a.sequence - b.sequence);
    const receipts = rows.filter(row => row?.ownerId === ownerId && row.kind === KEY_TRANSITION_RECEIPT_KIND)
      .sort((a, b) => a.sequence - b.sequence || String(a.id).localeCompare(String(b.id)));
    const findings = [], historyUnprovenEventIds = [], receiptByEvent = new Map();
    for (const receipt of receipts) {
      const list = receiptByEvent.get(receipt.lifecycleEventId) || [];
      list.push(receipt); receiptByEvent.set(receipt.lifecycleEventId, list);
    }
    let previousReceiptDigest = null, lastReceipt = null;
    for (const receipt of receipts) {
      const entries = receipt.registryEntries;
      const entriesValid = Array.isArray(entries) && entries.every((item, index) => item && KEY_ID.test(item.keyId || "") && DIGEST.test(item.publicKeyFingerprint || "")
        && (index === 0 || entries[index - 1].keyId.localeCompare(item.keyId) < 0));
      if (receipt.digest !== digestRecord(receipt) || receipt.receiptDigest !== transitionReceiptDigest(receipt)
        || !Number.isSafeInteger(receipt.sequence) || !entriesValid || receipt.registryDigest !== registryDigest(entries || [])
        || (receipt.previousReceiptDigest ?? null) !== previousReceiptDigest || !DIGEST.test(receipt.lifecycleEventDigest || "")) {
        findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_INVALID", receiptId: receipt.id });
      }
      const event = events.find(item => item.id === receipt.lifecycleEventId);
      if (!event || event.eventDigest !== receipt.lifecycleEventDigest || event.sequence !== receipt.sequence
        || event.registryTransitionReceiptRequired !== true || event.registryDigestAtTransition !== receipt.registryDigest
        || event.targetKeyFingerprint !== entries?.find(item => item.keyId === event.targetKeyId)?.publicKeyFingerprint
        || event.previousActiveKeyFingerprint !== (event.previousActiveKeyId ? entries?.find(item => item.keyId === event.previousActiveKeyId)?.publicKeyFingerprint || null : null))
        findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_EVENT_LINK_INVALID", receiptId: receipt.id, lifecycleEventId: receipt.lifecycleEventId });
      if (event && receipt.id !== `${KEY_TRANSITION_RECEIPT_KIND}-${sha256(`${ownerId}\0${event.id}`).slice(0, 32)}`)
        findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_ID_INVALID", receiptId: receipt.id });
      previousReceiptDigest = receipt.receiptDigest || null;
      lastReceipt = receipt;
    }
    for (const event of events) {
      const linked = receiptByEvent.get(event.id) || [];
      if (event.registryTransitionReceiptRequired === true && linked.length !== 1) {
        historyUnprovenEventIds.push(event.id);
        findings.push({ code: linked.length > 1 ? "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_DUPLICATE" : "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_MISSING",
          eventId: event.id, receiptCount: linked.length, historyUnproven: linked.length === 0 });
      } else if (event.registryTransitionReceiptRequired !== true && linked.length === 0) {
        historyUnprovenEventIds.push(event.id);
      }
    }
    const currentEntries = registryEntries();
    const anchoredEntries = lastReceipt?.registryEntries || null;
    const addedKeyIds = anchoredEntries ? currentEntries.filter(item => !anchoredEntries.some(old => old.keyId === item.keyId)).map(item => item.keyId) : [];
    const removedKeyIds = anchoredEntries ? anchoredEntries.filter(old => !currentEntries.some(item => item.keyId === old.keyId)).map(item => item.keyId) : [];
    const changedKeyIds = anchoredEntries ? currentEntries.filter(item => anchoredEntries.some(old => old.keyId === item.keyId && old.publicKeyFingerprint !== item.publicKeyFingerprint)).map(item => item.keyId) : [];
    const registryDrift = Boolean(anchoredEntries && (addedKeyIds.length || removedKeyIds.length || changedKeyIds.length));
    if (registryDrift) findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_REGISTRY_ROTATION_UNPROVEN", addedKeyIds, removedKeyIds, changedKeyIds });
    const invalid = findings.some(item => !item.historyUnproven && item.code !== "POLICY_BINDING_ATTESTATION_KEY_REGISTRY_ROTATION_UNPROVEN");
    const status = invalid ? "unhealthy" : registryDrift ? "registry_rotation_unproven"
      : historyUnprovenEventIds.length ? "history_unproven" : receipts.length ? "healthy" : events.length ? "history_unproven" : "not_initialized";
    return { status, ownerId, eventCount: events.length, receiptCount: receipts.length, headReceiptDigest: lastReceipt?.receiptDigest || null,
      currentRegistryDigest: registryDigest(currentEntries), lastReceiptRegistryDigest: lastReceipt?.registryDigest || null,
      addedKeyIds, removedKeyIds, changedKeyIds, registryDrift, historyUnprovenEventIds, receipts: receipts.map(item => ({ id: item.id,
        lifecycleEventId: item.lifecycleEventId, lifecycleEventDigest: item.lifecycleEventDigest, sequence: item.sequence,
        receiptDigest: item.receiptDigest, previousReceiptDigest: item.previousReceiptDigest || null, registryDigest: item.registryDigest,
        historyNotProven: Boolean(item.historyNotProven), createdAt: item.createdAt })), findings,
      readOnly: true, mutationAllowed: false };
  }
  async function ensureTransitionReceipt(ownerId, event, { recoveredAfterEventWrite = false } = {}) {
    if (event?.registryTransitionReceiptRequired !== true) return null;
    const rows = await store.listEvidence(ownerId);
    const challenge = rows.find(row => row?.ownerId === ownerId && row.id === event.challengeId && row.kind === KEY_CHALLENGE_KIND);
    if (!challenge || challenge.digest !== digestRecord(challenge) || (challenge.challengeDigest || challenge.preparedChallengeDigest || challenge.digest) !== event.challengeDigest
      || challenge.targetKeyId !== event.targetKeyId || challenge.action !== event.action)
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_CHALLENGE_INVALID", "Receipt transisi key tidak dapat dibuat tanpa challenge sumber yang valid", 409);
    const entries = registryEntries(), currentRegistryDigest = registryDigest(entries);
    if (currentRegistryDigest !== event.registryDigestAtTransition
      || event.targetKeyFingerprint !== (entries.find(item => item.keyId === event.targetKeyId)?.publicKeyFingerprint || null)
      || event.previousActiveKeyFingerprint !== (event.previousActiveKeyId ? entries.find(item => item.keyId === event.previousActiveKeyId)?.publicKeyFingerprint || null : null))
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_REGISTRY_DRIFT", "Trusted key registry berubah sejak transisi; receipt tidak boleh direkonstruksi dengan fingerprint baru", 409);
    const id = `${KEY_TRANSITION_RECEIPT_KIND}-${sha256(`${ownerId}\0${event.id}`).slice(0, 32)}`;
    const existing = rows.find(row => row?.ownerId === ownerId && row.id === id && row.kind === KEY_TRANSITION_RECEIPT_KIND);
    if (existing) {
      if (existing.digest !== digestRecord(existing) || existing.lifecycleEventDigest !== event.eventDigest || existing.receiptDigest !== transitionReceiptDigest(existing))
        throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_CONFLICT", "Receipt transisi yang sudah ada tidak konsisten", 409);
      return existing;
    }
    const previous = rows.filter(row => row?.ownerId === ownerId && row.kind === KEY_TRANSITION_RECEIPT_KIND && row.sequence < event.sequence)
      .sort((a, b) => b.sequence - a.sequence)[0] || null;
    const body = { id, ownerId, kind: KEY_TRANSITION_RECEIPT_KIND, schemaVersion: 1, lifecycleEventId: event.id,
      lifecycleEventDigest: event.eventDigest, sequence: event.sequence, action: event.action, targetKeyId: event.targetKeyId,
      targetKeyFingerprint: event.targetKeyFingerprint, previousActiveKeyId: event.previousActiveKeyId || null,
      previousActiveKeyFingerprint: event.previousActiveKeyFingerprint || null, challengeId: event.challengeId, challengeDigest: event.challengeDigest,
      previousReceiptDigest: previous?.receiptDigest || null, registryEntries: entries, registryDigest: currentRegistryDigest,
      recoveredAfterEventWrite: Boolean(recoveredAfterEventWrite), historyNotProven: false, createdAt: now() };
    const receiptDigest = sha256(canonical(body));
    const unsigned = { ...body, receiptDigest };
    const receipt = { ...unsigned, digest: digestRecord(unsigned) };
    try { await store.putEvidence(ownerId, receipt, { overwrite: false }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, id);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.receiptDigest !== receiptDigest)
        throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_WRITE_FAILED", "Receipt transisi key gagal disimpan secara konsisten", 409);
      return concurrent;
    }
    const saved = await store.getEvidence(ownerId, id);
    if (!saved || saved.digest !== digestRecord(saved) || saved.receiptDigest !== transitionReceiptDigest(saved))
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_WRITE_FAILED", "Receipt transisi key gagal diverifikasi setelah penyimpanan", 409);
    return saved;
  }
  async function recoverKeyLifecycleTransitionReceipts(ownerId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const events = rows.filter(row => row?.ownerId === ownerId && row.kind === KEY_EVENT_KIND && row.registryTransitionReceiptRequired === true)
      .sort((a, b) => a.sequence - b.sequence);
    const recovered = [];
    for (const event of events) {
      const currentRows = await store.listEvidence(ownerId);
      const id = `${KEY_TRANSITION_RECEIPT_KIND}-${sha256(`${ownerId}\0${event.id}`).slice(0, 32)}`;
      if (currentRows.some(row => row?.ownerId === ownerId && row.id === id && row.kind === KEY_TRANSITION_RECEIPT_KIND)) continue;
      if (event.digest !== digestRecord(event) || event.eventDigest !== sha256(canonical(Object.fromEntries(Object.entries(event).filter(([key]) => !["_storage", "digest", "eventDigest"].includes(key))))) )
        throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_EVENT_INVALID", "Event lifecycle tidak valid; receipt recovery ditolak", 409);
      const receipt = await ensureTransitionReceipt(ownerId, event, { recoveredAfterEventWrite: true });
      recovered.push(receipt);
      const challenge = currentRows.find(row => row?.ownerId === ownerId && row.id === event.challengeId && row.kind === KEY_CHALLENGE_KIND);
      if (challenge && challenge.status !== "completed") await updateChallenge(ownerId, challenge, { status: "completed",
        preparedChallengeDigest: challenge.preparedChallengeDigest || challenge.digest, challengeDigest: event.challengeDigest,
        eventId: event.id, eventDigest: event.eventDigest, completedAt: now(), recoveredAfterEventWrite: true });
    }
    const audit = await readKeyLifecycleTransitionReceipts(ownerId);
    return { status: audit.status, recoveredCount: recovered.length, recoveredReceiptIds: recovered.map(item => item.id), audit,
      readOnly: false, mutationAllowed: false };
  }
  async function exportKeyLifecycleTransitionReceipts(ownerId) {
    assertOwner(ownerId);
    const audit = await readKeyLifecycleTransitionReceipts(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_TRANSITION_RECEIPT_EXPORT_UNHEALTHY", "Receipt lifecycle key tidak sehat; ekspor ditolak", 409, { findings: audit.findings });
    const rows = (await store.listEvidence(ownerId)).filter(row => row?.ownerId === ownerId && row.kind === KEY_TRANSITION_RECEIPT_KIND)
      .sort((a, b) => a.sequence - b.sequence).map(row => clean(row));
    const body = { schemaVersion: 1, kind: KEY_TRANSITION_EXPORT_KIND, ownerId, exportedAt: now(), receiptCount: rows.length,
      sourceAuditStatus: audit.status, sourceHeadReceiptDigest: audit.headReceiptDigest, receipts: rows };
    return { ...body, digest: sha256(canonical(body)), integrityAlgorithm: "sha256", readOnly: true, mutationAllowed: false };
  }
  async function verifyKeyLifecycleTransitionReceiptExport(ownerId, bundle) {
    assertOwner(ownerId);
    const findings = [];
    if (!bundle || bundle.ownerId !== ownerId || bundle.kind !== KEY_TRANSITION_EXPORT_KIND || bundle.schemaVersion !== 1 || !Array.isArray(bundle.receipts))
      findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_EXPORT_ENVELOPE_INVALID" });
    const body = bundle ? clean(bundle) : {};
    delete body.digest; delete body.integrityAlgorithm; delete body.readOnly; delete body.mutationAllowed;
    if (!bundle || bundle.digest !== sha256(canonical(body))) findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_EXPORT_DIGEST_INVALID" });
    const seen = new Set(); let previousReceiptDigest = null, expectedSequence = 0;
    for (const receipt of bundle?.receipts || []) {
      if (receipt.ownerId !== ownerId || receipt.kind !== KEY_TRANSITION_RECEIPT_KIND || receipt.digest !== digestRecord(receipt)
        || receipt.receiptDigest !== transitionReceiptDigest(receipt) || seen.has(receipt.lifecycleEventId))
        findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_EXPORT_RECEIPT_INVALID", receiptId: receipt.id });
      if (receipt.previousReceiptDigest !== previousReceiptDigest) findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_EXPORT_CHAIN_INVALID", receiptId: receipt.id });
      if (!Number.isSafeInteger(receipt.sequence) || receipt.sequence <= expectedSequence) findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_EXPORT_SEQUENCE_INVALID", receiptId: receipt.id });
      seen.add(receipt.lifecycleEventId); previousReceiptDigest = receipt.receiptDigest || null; expectedSequence = receipt.sequence || expectedSequence;
    }
    const rows = await store.listEvidence(ownerId);
    for (const receipt of bundle?.receipts || []) {
      const retained = rows.find(row => row?.ownerId === ownerId && row.id === receipt.id && row.kind === KEY_TRANSITION_RECEIPT_KIND);
      if (!retained || retained.digest !== receipt.digest) findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_TRANSITION_EXPORT_NOT_RETAINED", receiptId: receipt.id });
    }
    return { status: findings.length ? "unhealthy" : "verified", ownerId, receiptCount: bundle?.receipts?.length || 0,
      digest: bundle?.digest || null, findings, authenticity: "integrity-only-no-signature", readOnly: true, mutationAllowed: false };
  }
  async function updateChallenge(ownerId, challenge, changes) {
    const unsigned = { ...clean(challenge), ...changes };
    delete unsigned.digest;
    const updated = { ...unsigned, digest: digestRecord(unsigned) };
    try { await store.putEvidence(ownerId, updated, { expectedVersion: challenge._storage?.version }); }
    catch {
      const latest = await store.getEvidence(ownerId, challenge.id);
      if (!latest || latest.digest !== digestRecord(latest) || latest.status !== "completed" || latest.eventDigest !== changes.eventDigest)
        throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_FINALIZE_CONFLICT", "Transisi lifecycle key tersimpan tetapi challenge tidak dapat difinalisasi", 409);
      return latest;
    }
    return store.getEvidence(ownerId, challenge.id);
  }
  async function prepareKeyTransition(ownerId, action, targetKeyId, reason) {
    assertOwner(ownerId);
    if (!KEY_ID.test(String(targetKeyId || "")) || !keys.has(targetKeyId)) throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_UNKNOWN", "Key target tidak dikenal oleh trusted public-key registry", 400);
    if (!validReason(reason)) throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_REASON_INVALID", "Alasan lifecycle key wajib 12–240 karakter", 400);
    const lifecycle = await readKeyLifecycle(ownerId);
    if (lifecycle.status !== "healthy") throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_UNHEALTHY", "Histori lifecycle key tidak sehat", 409, { findings: lifecycle.findings });
    await recoverKeyLifecycleTransitionReceipts(ownerId);
    const receiptAudit = await readKeyLifecycleTransitionReceipts(ownerId);
    const onlyTargetAddition = action === "rotate" && receiptAudit.registryDrift && receiptAudit.addedKeyIds.length === 1
      && receiptAudit.addedKeyIds[0] === targetKeyId && receiptAudit.removedKeyIds.length === 0 && receiptAudit.changedKeyIds.length === 0;
    if (receiptAudit.status === "unhealthy" || receiptAudit.registryDrift && !onlyTargetAddition)
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_REGISTRY_TRANSITION_UNPROVEN", "Trusted key registry berubah tanpa transisi yang dapat dibuktikan", 409,
        { status: receiptAudit.status, findings: receiptAudit.findings });
    if (action === "rotate") {
      if (targetKeyId === lifecycle.activeKeyId || !signerMap.has(targetKeyId) || lifecycle.statuses.get(targetKeyId) === "revoked")
        throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_ROTATION_TARGET_INVALID", "Key rotasi harus dikenal, belum dicabut, dan memiliki signer", 409);
    } else if (action === "revoke") {
      if (targetKeyId === lifecycle.activeKeyId) throw new AgenticError("POLICY_BINDING_ATTESTATION_ACTIVE_KEY_REVOCATION_FORBIDDEN", "Active signing key harus dirotasi sebelum dapat dicabut", 409);
      if (lifecycle.statuses.get(targetKeyId) === "revoked") throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_ALREADY_REVOKED", "Signing key sudah dicabut", 409);
    }
    const createdAt = now(), id = `${KEY_CHALLENGE_KIND}-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: KEY_CHALLENGE_KIND, schemaVersion: 1, status: "prepared", action, targetKeyId,
      expectedActiveKeyId: lifecycle.activeKeyId, expectedHeadDigest: lifecycle.headDigest, expectedRegistryDigest: registryDigest(), reason: reason.trim(), createdAt,
      expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { status: "prepared", challengeId: id, challengeDigest: challenge.digest, action, targetKeyId,
      expectedActiveKeyId: lifecycle.activeKeyId, expiresAt: challenge.expiresAt,
      confirmation: `${action === "rotate" ? "ROTATE" : "REVOKE"} ATTESTATION KEY ${targetKeyId} ${challenge.digest.slice(0, 12)}` };
  }
  async function applyKeyTransition(ownerId, challengeId, confirmation) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== KEY_CHALLENGE_KIND || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_CHALLENGE_INVALID", "Challenge lifecycle key tidak valid", 409);
    const existingEvents = (await store.listEvidence(ownerId)).filter(row => row?.ownerId === ownerId && row.kind === KEY_EVENT_KIND && row.challengeId === challengeId);
    if (existingEvents.length) {
      const event = existingEvents[0];
      if (existingEvents.length !== 1 || event.digest !== digestRecord(event) || event.eventDigest !== challenge.eventDigest && challenge.status === "completed")
        throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_EVENT_CONFLICT", "Event lifecycle key tidak konsisten", 409);
      const receipt = await ensureTransitionReceipt(ownerId, event, { recoveredAfterEventWrite: true });
      if (challenge.status !== "completed") await updateChallenge(ownerId, challenge, { status: "completed", preparedChallengeDigest: challenge.preparedChallengeDigest || challenge.digest,
        challengeDigest: challenge.digest, eventId: event.id, eventDigest: event.eventDigest, completedAt: now(), recoveredAfterEventWrite: true });
      return { status: event.action === "rotate" ? "rotated" : "revoked", event, transitionReceipt: receipt, idempotent: true, activeKeyId: (await readKeyLifecycle(ownerId)).activeKeyId };
    }
    if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `${challenge.action === "rotate" ? "ROTATE" : "REVOKE"} ATTESTATION KEY ${challenge.targetKeyId} ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_CHALLENGE_EXPIRED", "Challenge lifecycle key kedaluwarsa, telah digunakan, atau konfirmasinya tidak cocok", 409);
    const lifecycle = await readKeyLifecycle(ownerId);
    if (lifecycle.status !== "healthy" || lifecycle.headDigest !== challenge.expectedHeadDigest || lifecycle.activeKeyId !== challenge.expectedActiveKeyId
      || registryDigest() !== challenge.expectedRegistryDigest)
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_CHALLENGE_STALE", "Lifecycle key atau trusted registry berubah sejak challenge dibuat", 409);
    if (challenge.action === "rotate" && (!signerMap.has(challenge.targetKeyId) || !keys.has(challenge.targetKeyId)
      || lifecycle.statuses.get(challenge.targetKeyId) === "revoked")) throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_ROTATION_TARGET_INVALID", "Key rotasi tidak lagi memenuhi syarat", 409);
    if (challenge.action === "revoke" && (challenge.targetKeyId === lifecycle.activeKeyId || lifecycle.statuses.get(challenge.targetKeyId) === "revoked"))
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_REVOCATION_TARGET_INVALID", "Key aktif atau sudah dicabut tidak dapat dicabut ulang", 409);
    const createdAt = now(), eventId = `${KEY_EVENT_KIND}-${sha256(`${ownerId}\0${challengeId}`).slice(0, 32)}`;
    const body = { id: eventId, ownerId, kind: KEY_EVENT_KIND, schemaVersion: 1, sequence: lifecycle.eventCount + 1,
      previousEventDigest: lifecycle.headDigest, action: challenge.action, targetKeyId: challenge.targetKeyId,
      previousActiveKeyId: lifecycle.activeKeyId, registryTransitionReceiptRequired: true, registryDigestAtTransition: registryDigest(),
      targetKeyFingerprint: keyFingerprint(keys.get(challenge.targetKeyId)),
      previousActiveKeyFingerprint: lifecycle.activeKeyId ? keyFingerprint(keys.get(lifecycle.activeKeyId)) : null,
      challengeId, challengeDigest: challenge.digest, reason: challenge.reason, createdAt,
      ...(challenge.action === "revoke" ? { revokedAt: createdAt } : {}) };
    const event = { ...body, eventDigest: sha256(canonical(body)), digest: "" };
    event.digest = digestRecord(event);
    try { await store.putEvidence(ownerId, event, { overwrite: false }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, eventId);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.challengeId !== challengeId)
        throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_EVENT_WRITE_FAILED", "Event lifecycle key gagal disimpan secara konsisten", 409);
    }
    const saved = await store.getEvidence(ownerId, eventId);
    if (!saved || saved.digest !== digestRecord(saved) || saved.eventDigest !== sha256(canonical(Object.fromEntries(Object.entries(saved).filter(([key]) => !["_storage", "digest", "eventDigest"].includes(key))))))
      throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_EVENT_WRITE_FAILED", "Event lifecycle key gagal diverifikasi setelah penyimpanan", 409);
    const transitionReceipt = await ensureTransitionReceipt(ownerId, saved);
    await updateChallenge(ownerId, challenge, { status: "completed", preparedChallengeDigest: challenge.digest, challengeDigest: challenge.digest,
      eventId, eventDigest: saved.eventDigest, completedAt: now() });
    const audited = await readKeyLifecycle(ownerId);
    if (audited.status !== "healthy") throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_UNHEALTHY", "Lifecycle key gagal diaudit setelah transisi", 409, { findings: audited.findings });
    return { status: challenge.action === "rotate" ? "rotated" : "revoked", event: saved, transitionReceipt, idempotent: false, activeKeyId: audited.activeKeyId };
  }
  async function capture(ownerId) {
    const [checkpoint, checkpointAudit, policyBindingAudit] = await Promise.all([
      readCheckpoint(ownerId), auditCheckpoint(ownerId), auditPolicyBindingChain(ownerId)
    ]);
    const anchoredAt = checkpoint?.anchorAnchoredAt || checkpoint?.anchoredAt || null;
    const anchorTime = Date.parse(String(anchoredAt || "")), nowMs = Date.parse(now());
    const ageMs = Number.isFinite(anchorTime) ? nowMs - anchorTime : null;
    const checkpointSnapshot = {
      status: checkpoint?.status || "unavailable", domain: checkpoint?.domain || "cross_domain_policy_binding_audit_chain",
      anchorSequence: checkpoint?.anchorSequence ?? null, anchorDigest: checkpoint?.anchorDigest ?? null,
      sourceDigest: checkpoint?.sourceDigest ?? null, sourceCount: checkpoint?.sourceCount ?? null,
      anchoredAt, policyBindingStatus: checkpoint?.policyBindingStatus || null,
      currentPolicyDigest: checkpoint?.currentPolicyDigest || null, anchoredPolicyDigest: checkpoint?.anchoredPolicyDigest || null,
      freshnessStatus: checkpoint?.freshnessStatus || "unknown", historyNotProven: Boolean(checkpoint?.historyNotProven)
    };
    const checkpointAuditSnapshot = { status: checkpointAudit?.status || "unavailable",
      anchorSequence: checkpointAudit?.anchorSequence ?? checkpointAudit?.anchor?.anchorSequence ?? null,
      anchorDigest: checkpointAudit?.anchorDigest ?? checkpointAudit?.anchor?.digest ?? null,
      findings: (checkpointAudit?.findings || []).map(item => ({ code: item.code || "UNKNOWN", domain: item.domain || null })).sort((a, b) => canonical(a).localeCompare(canonical(b))) };
    const chainSnapshot = { status: policyBindingAudit?.status || "unavailable", eventCount: policyBindingAudit?.eventCount ?? 0,
      domains: (policyBindingAudit?.domains || []).map(item => ({ domain: item.domain, status: item.status,
        eventCount: item.eventCount ?? 0, eventHead: item.eventHead || null })).sort((a, b) => String(a.domain).localeCompare(String(b.domain))),
      findings: (policyBindingAudit?.findings || []).map(item => ({ code: item.code || "UNKNOWN", domain: item.domain || null })).sort((a, b) => canonical(a).localeCompare(canonical(b))) };
    const freshnessPolicy = { schemaVersion: 1, maxAgeMs, futureSkewMs };
    const fingerprint = sha256(canonical({ checkpoint: checkpointSnapshot, checkpointAudit: checkpointAuditSnapshot,
      policyBindingAudit: chainSnapshot, freshnessPolicy }));
    const findings = [];
    if (checkpointSnapshot.status !== "anchored") findings.push({ code: "POLICY_BINDING_CHECKPOINT_NOT_ANCHORED" });
    if (checkpointSnapshot.freshnessStatus !== "fresh") findings.push({ code: "POLICY_BINDING_CHECKPOINT_NOT_FRESH", freshnessStatus: checkpointSnapshot.freshnessStatus });
    if (checkpointSnapshot.policyBindingStatus !== "current" || !DIGEST.test(checkpointSnapshot.currentPolicyDigest || "")
      || checkpointSnapshot.currentPolicyDigest !== checkpointSnapshot.anchoredPolicyDigest)
      findings.push({ code: "POLICY_BINDING_CHECKPOINT_POLICY_NOT_CURRENT" });
    if (["history_unproven", "recoverable"].includes(checkpointAuditSnapshot.status)) findings.push({ code: "POLICY_BINDING_CHECKPOINT_HISTORY_NOT_PROVEN" });
    else if (checkpointAuditSnapshot.status !== "healthy") findings.push({ code: "POLICY_BINDING_CHECKPOINT_AUDIT_NOT_HEALTHY", status: checkpointAuditSnapshot.status });
    if (["history_unproven", "recoverable"].includes(chainSnapshot.status)) findings.push({ code: "POLICY_BINDING_CHECKPOINT_HISTORY_NOT_PROVEN" });
    else if (chainSnapshot.status !== "healthy") findings.push({ code: "POLICY_BINDING_AUDIT_CHAIN_NOT_HEALTHY", status: chainSnapshot.status });
    if (!Number.isFinite(anchorTime) || anchorTime > nowMs + futureSkewMs) findings.push({ code: "POLICY_BINDING_CHECKPOINT_TIME_INVALID" });
    if (Number.isFinite(ageMs) && ageMs > maxAgeMs) findings.push({ code: "POLICY_BINDING_CHECKPOINT_STALE", ageMs, maxAgeMs });
    if (checkpointSnapshot.historyNotProven) findings.push({ code: "POLICY_BINDING_CHECKPOINT_HISTORY_NOT_PROVEN" });
    const onlyUnprovenHistory = findings.length > 0 && findings.every(item => item.code === "POLICY_BINDING_CHECKPOINT_HISTORY_NOT_PROVEN");
    return { checkpointSnapshot, checkpointAuditSnapshot, chainSnapshot, fingerprint, findings,
      validForAttestation: findings.length === 0, signableForAttestation: findings.length === 0 || onlyUnprovenHistory,
      freshnessPolicy, ageMs, validUntil: Number.isFinite(anchorTime) ? new Date(anchorTime + maxAgeMs).toISOString() : null };
  }
  function validateEnvelope(ownerId, attestation) {
    const findings = [];
    if (!attestation || attestation.domain !== DOMAIN || attestation.schemaVersion !== 1 || attestation.ownerId !== ownerId
      || typeof attestation.attestationId !== "string" || !Number.isFinite(Date.parse(attestation.issuedAt))
      || !Number.isFinite(Date.parse(attestation.validUntil)) || !validReason(attestation.reason)
      || !DIGEST.test(attestation.checkpointFingerprint || "") || !DIGEST.test(attestation.attestationDigest || "")
      || typeof attestation.historyNotProven !== "boolean" || !Number.isSafeInteger(attestation.freshnessPolicy?.maxAgeMs)
      || attestation.freshnessPolicy.maxAgeMs < 60000 || attestation.freshnessPolicy.maxAgeMs > 30 * 86400000
      || !Number.isSafeInteger(attestation.freshnessPolicy?.futureSkewMs) || attestation.freshnessPolicy.futureSkewMs < 0
      || attestation.freshnessPolicy.futureSkewMs > 600000 || attestation.freshnessPolicy.schemaVersion !== 1
      || !KEY_ID.test(attestation.signing?.keyId || "") || attestation.signing?.algorithm !== "Ed25519"
      || (attestation.signing?.lifecycleSequence !== undefined && (!Number.isSafeInteger(attestation.signing.lifecycleSequence) || attestation.signing.lifecycleSequence < 0))
      || !SIGNATURE.test(attestation.signature || ""))
      return { valid: false, signatureValid: false, findings: [{ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_SCHEMA_INVALID" }] };
    const unsigned = clean(attestation); delete unsigned.attestationDigest; delete unsigned.signature;
    const digestValid = attestation.attestationDigest === sha256(canonical(unsigned));
    if (!digestValid) findings.push({ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_DIGEST_INVALID" });
    const key = keys.get(attestation.signing.keyId); let signatureValid = false;
    if (!key) findings.push({ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_KEY_UNKNOWN" });
    else {
      try { signatureValid = verifySignature(null, Buffer.from(canonical({ ...unsigned, attestationDigest: attestation.attestationDigest }), "utf8"), key,
        Buffer.from(attestation.signature, "base64url")); } catch { signatureValid = false; }
      if (!signatureValid) findings.push({ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_SIGNATURE_INVALID" });
    }
    if (sha256(canonical({ checkpoint: attestation.checkpoint, checkpointAudit: attestation.checkpointAudit,
      policyBindingAudit: attestation.policyBindingAudit, freshnessPolicy: attestation.freshnessPolicy })) !== attestation.checkpointFingerprint
      || Boolean(attestation.checkpoint?.historyNotProven) !== attestation.historyNotProven)
      findings.push({ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_SNAPSHOT_INVALID" });
    return { valid: digestValid && signatureValid && findings.length === 0, signatureValid, findings };
  }
  async function create(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!validReason(reason)) throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_REASON_INVALID", "Alasan attestation wajib 12–240 karakter", 400);
    const lifecycle = await readKeyLifecycle(ownerId);
    if (lifecycle.status !== "healthy") throw new AgenticError("POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_UNHEALTHY", "Histori lifecycle key tidak sehat", 409, { findings: lifecycle.findings });
    const activeKeyId = lifecycle.activeKeyId, activeSigner = signerMap.get(activeKeyId);
    if (!activeSigner || !activeKeyId || !keys.has(activeKeyId) || lifecycle.statuses.get(activeKeyId) === "revoked")
      throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_SIGNER_REQUIRED", "Signer aktif dan trusted public key Ed25519 wajib dikonfigurasi", 503);
    const snapshot = await capture(ownerId);
    if (!snapshot.signableForAttestation) throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_NOT_CURRENT", "Checkpoint policy-binding tidak memenuhi syarat attestation freshness", 409,
      { findings: snapshot.findings });
    const issuedAt = now();
    const unsigned = { domain: DOMAIN, schemaVersion: 1, attestationId: `policy-binding-checkpoint-attestation-${randomUUID()}`,
      ownerId, issuedAt, validUntil: snapshot.validUntil, reason: reason.trim(), checkpointFingerprint: snapshot.fingerprint,
      checkpoint: snapshot.checkpointSnapshot, checkpointAudit: snapshot.checkpointAuditSnapshot, policyBindingAudit: snapshot.chainSnapshot,
      freshnessPolicy: snapshot.freshnessPolicy, signing: { algorithm: "Ed25519", keyId: activeKeyId, lifecycleSequence: lifecycle.eventCount },
      historyNotProven: Boolean(snapshot.checkpointSnapshot.historyNotProven) };
    const payload = { ...unsigned, attestationDigest: sha256(canonical(unsigned)) };
    let signed;
    try { signed = await activeSigner(structuredClone(payload)); }
    catch { throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_SIGNER_FAILED", "Signer attestation checkpoint policy-binding gagal", 502); }
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== activeKeyId)
      throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_KEY_MISMATCH", "Signer mengembalikan key ID yang berbeda", 502);
    const signature = typeof signed === "string" ? signed : signed?.signature;
    const attestation = { ...payload, signature };
    const envelope = validateEnvelope(ownerId, attestation);
    if (!envelope.valid) throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_SIGNATURE_INVALID", "Signature attestation checkpoint policy-binding tidak valid", 502,
      { findings: envelope.findings });
    const unsignedRecord = { id: attestation.attestationId, ownerId, kind: KIND, schemaVersion: 1, attestation, createdAt: now() };
    const record = { ...unsignedRecord, digest: digestRecord(unsignedRecord) };
    await store.putEvidence(ownerId, record, { overwrite: false });
    const saved = await store.getEvidence(ownerId, record.id);
    if (!saved || saved.digest !== digestRecord(saved) || !validateEnvelope(ownerId, saved.attestation).valid)
      throw new AgenticError("POLICY_BINDING_CHECKPOINT_ATTESTATION_WRITE_FAILED", "Attestation tidak lolos verifikasi setelah penyimpanan", 409);
    const current = snapshot.validForAttestation;
    return { status: current ? "signed" : "signed_history_unproven", attestation: saved.attestation, retainedRecordId: saved.id,
      validUntil: saved.attestation.validUntil, historicallyValid: true, current, usableForCurrentDecision: current,
      findings: snapshot.findings, readOnly: false, mutationAllowed: false };
  }
  async function verify(ownerId, valueOrId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const record = typeof valueOrId === "string" ? rows.find(row => row?.ownerId === ownerId && row.id === valueOrId && row.kind === KIND)
      : rows.find(row => row?.ownerId === ownerId && row.kind === KIND && row.attestation?.attestationId === valueOrId?.attestationId);
    const attestation = typeof valueOrId === "string" ? record?.attestation : valueOrId;
    const envelope = validateEnvelope(ownerId, attestation);
    const retained = Boolean(record && record.digest === digestRecord(record) && record.attestation?.attestationDigest === attestation?.attestationDigest
      && record.id === attestation?.attestationId);
    if (!retained) envelope.findings.push({ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_NOT_RETAINED" });
    const lifecycle = await readKeyLifecycle(ownerId);
    if (lifecycle.status !== "healthy") envelope.findings.push({ code: "POLICY_BINDING_ATTESTATION_KEY_LIFECYCLE_UNHEALTHY", details: lifecycle.findings });
    const attestedKeyId = attestation?.signing?.keyId;
    const keyStatus = lifecycle.statuses.get(attestedKeyId) || (attestedKeyId === keyId ? "active" : "available");
    const revokedAt = lifecycle.revokedAt.get(attestedKeyId) || null;
    const revokedSequence = lifecycle.revokedAtSequence.get(attestedKeyId);
    const attestedSequence = attestation?.signing?.lifecycleSequence;
    const cutoffUnproven = Boolean(revokedAt && !Number.isSafeInteger(attestedSequence));
    const signedBeforeRevocation = !revokedAt || (Number.isSafeInteger(revokedSequence) && Number.isSafeInteger(attestedSequence)
      && attestedSequence < revokedSequence && Date.parse(attestation?.issuedAt) <= Date.parse(revokedAt));
    let activeKeyAtSigning = null;
    const sequenceAhead = Number.isSafeInteger(attestedSequence) && attestedSequence > lifecycle.eventCount;
    if (sequenceAhead) envelope.findings.push({ code: "POLICY_BINDING_ATTESTATION_SIGNING_SEQUENCE_AHEAD_OF_LIFECYCLE" });
    if (Number.isSafeInteger(attestedSequence) && attestedSequence <= lifecycle.eventCount) {
      let historicalActiveKeyId = keyId;
      for (const event of lifecycle.events) if (event.sequence <= attestedSequence && event.action === "rotate") historicalActiveKeyId = event.targetKeyId;
      activeKeyAtSigning = historicalActiveKeyId === attestedKeyId;
      if (!activeKeyAtSigning) envelope.findings.push({ code: "POLICY_BINDING_ATTESTATION_SIGNING_KEY_NOT_ACTIVE_AT_SEQUENCE", attestedSequence });
    }
    if (cutoffUnproven) envelope.findings.push({ code: "POLICY_BINDING_ATTESTATION_REVOCATION_CUTOFF_UNPROVEN" });
    let current = false;
    if (envelope.valid && retained && lifecycle.status === "healthy") {
      const snapshot = await capture(ownerId);
      current = snapshot.validForAttestation && snapshot.fingerprint === attestation.checkpointFingerprint
        && Date.parse(now()) < Date.parse(attestation.validUntil) && keyStatus === "active" && !revokedAt;
      if (!current) envelope.findings.push({ code: keyStatus === "revoked" || revokedAt ? "POLICY_BINDING_ATTESTATION_SIGNING_KEY_REVOKED"
        : keyStatus === "retired" ? "POLICY_BINDING_ATTESTATION_SIGNING_KEY_RETIRED" : "POLICY_BINDING_CHECKPOINT_ATTESTATION_NOT_CURRENT", findings: snapshot.findings });
    }
    const historicallyValid = envelope.valid && retained && lifecycle.status === "healthy" && signedBeforeRevocation
      && (activeKeyAtSigning !== false);
    return { status: !envelope.valid || !retained || lifecycle.status !== "healthy" || activeKeyAtSigning === false || sequenceAhead ? "unhealthy"
        : cutoffUnproven ? "history_unproven" : !historicallyValid ? "key_revoked" : current ? "current"
          : revokedAt ? "key_revoked" : keyStatus === "retired" ? "key_rotated" : attestation?.historyNotProven ? "history_unproven" : "stale", valid: historicallyValid,
      signatureValid: envelope.signatureValid, historicallyValid, current, usableForCurrentDecision: Boolean(historicallyValid && current),
      signingKeyId: attestedKeyId || null, signingKeyStatus: keyStatus, revokedAt, retained, validUntil: attestation?.validUntil || null,
      findings: envelope.findings, readOnly: true, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId), records = rows.filter(row => row?.ownerId === ownerId && row.kind === KIND), findings = [];
    for (const record of records) {
      if (record.digest !== digestRecord(record) || record.id !== record.attestation?.attestationId) findings.push({ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_RECORD_INVALID", recordId: record.id });
      else {
        const result = validateEnvelope(ownerId, record.attestation);
        if (!result.valid) findings.push({ code: "POLICY_BINDING_CHECKPOINT_ATTESTATION_INVALID", recordId: record.id, details: result.findings });
      }
    }
    const lifecycle = await readKeyLifecycle(ownerId);
    findings.push(...lifecycle.findings);
    return { status: findings.length ? "unhealthy" : records.length || lifecycle.eventCount ? "healthy" : "not_initialized", ownerId,
      recordCount: records.length, keyLifecycle: { activeKeyId: lifecycle.activeKeyId, eventCount: lifecycle.eventCount, headDigest: lifecycle.headDigest },
      findings, readOnly: true, mutationAllowed: false };
  }
  async function auditKeyLifecycle(ownerId) {
    assertOwner(ownerId);
    const lifecycle = await readKeyLifecycle(ownerId);
    const keysAudit = [...keys.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([id, publicKey]) => ({ keyId: id,
      publicKeyFingerprint: keyFingerprint(publicKey),
      status: lifecycle.statuses.get(id) || "available", revokedAt: lifecycle.revokedAt.get(id) || null,
      revokedAtSequence: lifecycle.revokedAtSequence.get(id) ?? null, signerAvailable: signerMap.has(id) }));
    return { status: lifecycle.status, ownerId, activeKeyId: lifecycle.activeKeyId, eventCount: lifecycle.eventCount,
      headDigest: lifecycle.headDigest, keys: keysAudit, findings: lifecycle.findings, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ create, verify, audit, auditKeyLifecycle, auditKeyLifecycleTransitionReceipts: readKeyLifecycleTransitionReceipts,
    recoverKeyLifecycleTransitionReceipts, exportKeyLifecycleTransitionReceipts, verifyKeyLifecycleTransitionReceiptExport,
    prepareKeyRotation: (ownerId, targetKeyId, options = {}) => prepareKeyTransition(ownerId, "rotate", targetKeyId, options.reason),
    applyKeyRotation: (ownerId, challengeId, options = {}) => applyKeyTransition(ownerId, challengeId, options.confirmation),
    prepareKeyRevocation: (ownerId, targetKeyId, options = {}) => prepareKeyTransition(ownerId, "revoke", targetKeyId, options.reason),
    applyKeyRevocation: (ownerId, challengeId, options = {}) => applyKeyTransition(ownerId, challengeId, options.confirmation) });
}
