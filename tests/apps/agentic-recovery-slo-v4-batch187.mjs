import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
function anchorProvider(baseUrl) {
  const records = new Map();
  return { baseUrl, records, failWrites: false,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      if (this.failWrites) return { applied: false };
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
function keyMaterial() {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  return { pairs, options: {
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)]))
  } };
}
function makeApp(storage, keyOptions, anchors, clock = () => "2026-10-14T00:00:00.000Z") {
  return createAgenticApplication({ storage, clock, ...keyOptions,
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: anchors.receipt,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: anchors.finalization,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: anchors.reconciliation,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation: true,
    ...(anchors.lifecycleRecovery ? {
      recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: anchors.lifecycleRecovery,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: true
    } : {}),
    ...(anchors.lifecycleIntent ? {
      recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: anchors.lifecycleIntent,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: true
    } : {})
  });
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the key for Batch 187 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate the key to verify lifecycle recovery-receipt cutoff." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollReceiptCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll receipt checkpoint for Batch 187.");
}
async function enrollFinalizationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 187.");
}
async function enrollReconciliationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 187.");
}
async function enrollLifecycleRecoveryCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery-receipt checkpoint for Batch 187.");
}
async function enrollLifecycleIntentCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle recovery-intent checkpoint for Batch 187.");
}
async function createFinalization(app, storage, owner) {
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  return app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
}
async function setupOwner(t, owner, { lifecycleRecovery = true } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b187-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    ...(lifecycleRecovery ? { lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`) } : {}),
    lifecycleIntent: anchorProvider(`https://${owner}-lifecycle-intent.example`) };
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors);
  await activateKey(app, owner);
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enrollFinalizationCheckpoint(app, owner);
  await enrollReconciliationCheckpoint(app, owner);
  if (lifecycleRecovery) await enrollLifecycleRecoveryCheckpoint(app, owner);
  await enrollLifecycleIntentCheckpoint(app, owner);
  const recovered = await createFinalization(app, storage, owner);
  return { app, storage, anchors, keyOptions, recovered, owner };
}
async function applyLifecycle(app, owner, targetId, action = "renew") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, targetId,
    { action, reason: `Batch 187 ${action} operation for current lifecycle recovery receipt evidence.` });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  return { challenge, result };
}


test("Batch 187: recovery-intent status transitions are signed, chained, and bound to the current intent digest", async t => {
  const context = await setupOwner(t, "b187-transition");
  const { app, recovered, owner } = context;
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Create a lifecycle intent for transition-attestation coverage." });
  const before = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitions(owner);
  assert.equal(before.status, "not_initialized");
  const applied = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    prepared.challengeId, { confirmation: prepared.confirmation });
  assert.equal(applied.recoveryIntent.status, "completed");
  const after = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitions(owner);
  assert.equal(after.status, "healthy");
  assert.equal(after.transitionCount, 2);
  assert.ok(after.transitions[0].attestation?.signature);
  assert.equal(after.transitions[0].fromStatus, null);
  assert.equal(after.transitions[0].toStatus, "prepared");
  assert.equal(after.transitions.at(-1).fromStatus, "prepared");
  assert.equal(after.transitions.at(-1).toStatus, "completed");
  assert.equal(after.transitions.at(-1).toIntentDigest, applied.recoveryIntent.digest);
  assert.equal(after.usableForCurrentDecision, true);
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner);
  assert.equal(lifecycleAudit.usableForCurrentDecision, true);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.status, "healthy");
  assert.equal(closure.closureComplete, true);
  assert.equal(closure.usableForCurrentDecision, true);
});

test("Batch 187: orphaned intent requires an explicit signed disposition and remains unusable for decisions", async t => {
  const context = await setupOwner(t, "b187-orphan-disposition");
  const { app, recovered, owner, anchors, storage } = context;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Create a pending intent before explicit orphan disposition." });
  anchors.lifecycleIntent.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_INTENT_CHECKPOINT_ADVANCE_PENDING");
  anchors.lifecycleIntent.failWrites = false;
  await app.reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpoint(owner);
  const store = createAgenticStore({ storage });
  const intentRows = (await store.listEvidence(owner)).filter(row => row?.ownerId === owner
    && row.kind === "recovery-slo-cross-domain-recovery-decision-gate-receipt-recovery-attestation-lifecycle-intent");
  assert.equal(intentRows.length, 1);
  const intent = intentRows[0];
  const savedChallenge = await store.getEvidence(owner, challenge.challengeId);
  assert.ok(savedChallenge);
  await store.state.delete("evidence", `${owner}--${challenge.challengeId}`, { expectedVersion: savedChallenge._storage?.version });
  const initial = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(initial.status, "recovery_required");
  assert.equal(initial.unresolvedOrphans.length, 1);
  assert.equal(initial.usableForCurrentDecision, false);
  const dispositionChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, intent.id,
    { disposition: "quarantine", reason: "Original challenge is missing and cannot be reconstructed safely." });
  assert.match(dispositionChallenge.confirmation, /DISPOSITION ORPHANED RECOVERY INTENT/);
  const applied = await app.applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, dispositionChallenge.challengeId,
    { confirmation: dispositionChallenge.confirmation });
  assert.equal(applied.status, "completed");
  assert.equal(applied.disposition.disposition, "quarantine");
  assert.ok(applied.disposition.attestation?.signature);
  assert.equal(applied.closure.status, "closed_with_disposition");
  assert.equal(applied.closure.closureComplete, true);
  assert.equal(applied.closure.usableForCurrentDecision, false);
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.equal(continuity.status, "stale");
  assert.equal(continuity.usableForCurrentDecision, false);
  assert.equal(continuity.unresolvedOrphanedIntents.length, 0);
  assert.equal(continuity.orphanedIntents.length, 1);
  assert.equal(continuity.findings.some(item => item.code === "RECOVERY_ATTESTATION_LIFECYCLE_ORPHANED_INTENTS"), false);
  const replay = await app.applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, dispositionChallenge.challengeId,
    { confirmation: dispositionChallenge.confirmation });
  assert.equal(replay.idempotent, true);
  assert.equal(replay.disposition.id, applied.disposition.id);
});

test("Batch 187: orphan disposition rejects stale key lifecycle, changed source, and incorrect confirmation", async t => {
  const context = await setupOwner(t, "b187-disposition-guards");
  const { app, recovered, owner, anchors, storage } = context;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Create a pending intent for disposition guard tests." });
  anchors.lifecycleIntent.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_INTENT_CHECKPOINT_ADVANCE_PENDING");
  anchors.lifecycleIntent.failWrites = false;
  await app.reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpoint(owner);
  const store = createAgenticStore({ storage });
  const intent = (await store.listEvidence(owner)).find(row => row?.ownerId === owner
    && row.kind === "recovery-slo-cross-domain-recovery-decision-gate-receipt-recovery-attestation-lifecycle-intent");
  const savedChallenge = await store.getEvidence(owner, challenge.challengeId);
  await store.state.delete("evidence", `${owner}--${challenge.challengeId}`, { expectedVersion: savedChallenge._storage?.version });
  const dispositionChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, intent.id,
    { disposition: "mark_unrecoverable", reason: "Original challenge was removed and must be explicitly closed." });
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, dispositionChallenge.challengeId,
    { confirmation: "WRONG CONFIRMATION" }), error => error.code === "RECOVERY_INTENT_ORPHAN_DISPOSITION_CHALLENGE_EXPIRED_OR_UNCONFIRMED");
  await rotateKey(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, dispositionChallenge.challengeId,
    { confirmation: dispositionChallenge.confirmation }), error => error.code === "RECOVERY_INTENT_ORPHAN_DISPOSITION_KEY_CUTOFF");
});

test("Batch 187: transition-attestation audit detects tampered transition ledger and fails closed", async t => {
  const context = await setupOwner(t, "b187-transition-tamper");
  const { app, recovered, owner, storage } = context;
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const store = createAgenticStore({ storage });
  const ledgerId = `recovery-intent-status-transitions-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  assert.ok(ledger?.events?.length);
  const mutated = structuredClone(ledger);
  mutated.events[0].toStatus = "completed";
  const unsigned = { ...mutated }; delete unsigned.digest; delete unsigned._storage;
  mutated.digest = sha256(canonical(unsigned));
  await store.putEvidence(owner, mutated, { expectedVersion: ledger._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitions(owner);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.findings.some(item => /TRANSITION|LEDGER/.test(item.code)));
});

test("Batch 187: closure and transition audit APIs are exposed in the authenticated HTTP routes", async t => {
  const context = await setupOwner(t, "b187-api");
  const { app, owner } = context;
  assert.equal(typeof app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitions, "function");
  assert.equal(typeof app.auditRecoverySloCrossDomainRecoveryIntentClosure, "function");
  assert.equal(typeof app.prepareRecoverySloCrossDomainRecoveryIntentOrphanDisposition, "function");
  assert.equal(typeof app.applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition, "function");
  const transitionAudit = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitions(owner);
  assert.equal(transitionAudit.status, "not_initialized");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /attestation-lifecycle\/status-transitions\/audit/);
  assert.match(server, /attestation-lifecycle\/closure\/audit/);
  assert.match(server, /orphans\/:intentId\/disposition\/challenges/);
  assert.match(server, /orphan-disposition-challenges\/:id\/apply/);
});
