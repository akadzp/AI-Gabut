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
  return { options: {
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
    ...(anchors.lifecycleRecovery ? { recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: anchors.lifecycleRecovery,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: true } : {}),
    ...(anchors.lifecycleIntent ? { recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: anchors.lifecycleIntent,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: true } : {}),
    ...(anchors.transition ? { recoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: anchors.transition,
      requireRecoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: true } : {}),
    ...(anchors.disposition ? { recoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: anchors.disposition,
      requireRecoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: true } : {})
  });
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the key for Batch 188 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollReceiptCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll receipt checkpoint for Batch 188.");
}
async function enrollFinalizationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 188.");
}
async function enrollReconciliationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 188.");
}
async function enrollLifecycleRecoveryCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery-receipt checkpoint for Batch 188.");
}
async function enrollLifecycleIntentCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle recovery-intent checkpoint for Batch 188.");
}
async function enrollClosureCheckpoints(app, owner) {
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 188.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition receipt checkpoint for Batch 188.");
}
async function createFinalization(app, storage, owner) {
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  return app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
}
async function setupOwner(t, owner) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b188-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`),
    lifecycleIntent: anchorProvider(`https://${owner}-lifecycle-intent.example`),
    transition: anchorProvider(`https://${owner}-transition.example`),
    disposition: anchorProvider(`https://${owner}-disposition.example`) };
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors);
  await activateKey(app, owner);
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enrollFinalizationCheckpoint(app, owner);
  await enrollReconciliationCheckpoint(app, owner);
  await enrollLifecycleRecoveryCheckpoint(app, owner);
  await enrollLifecycleIntentCheckpoint(app, owner);
  await enrollClosureCheckpoints(app, owner);
  const recovered = await createFinalization(app, storage, owner);
  return { app, storage, anchors, keyOptions, recovered, owner };
}
async function applyLifecycle(app, owner, targetId, action = "renew") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, targetId,
    { action, reason: `Batch 188 ${action} operation for closure checkpoint regression coverage.` });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  return { challenge, result };
}
async function orphanIntent(context) {
  const { app, owner, recovered, anchors, storage } = context;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Create a pending intent for closure checkpoint coverage." });
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
  return { intent, challenge };
}

test("Batch 188: transition and disposition ledgers are independently anchored and closure audits enforce both", async t => {
  const context = await setupOwner(t, "b188-anchors");
  const { app, owner, recovered, anchors } = context;
  assert.notEqual(anchors.transition.baseUrl, anchors.disposition.baseUrl);
  const beforeTransition = await app.getRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointStatus(owner);
  const beforeDisposition = await app.getRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointStatus(owner);
  assert.equal(beforeTransition.status, "anchored");
  assert.equal(beforeDisposition.status, "anchored");
  assert.equal(beforeTransition.sourceCount, 0);
  assert.equal(beforeDisposition.sourceCount, 0);
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const transitionAudit = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  const dispositionAudit = await app.auditRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpoint(owner);
  assert.equal(transitionAudit.status, "healthy");
  assert.equal(transitionAudit.usableForCurrentDecision, true);
  assert.equal(dispositionAudit.status, "healthy");
  assert.equal(dispositionAudit.usableForCurrentDecision, true);
  const transitionState = await app.getRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointStatus(owner);
  assert.equal(transitionState.status, "anchored");
  assert.equal(transitionState.sourceCount, 2);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.status, "healthy");
  assert.equal(closure.closureComplete, true);
  assert.equal(closure.transitionCheckpoint.usableForCurrentDecision, true);
  assert.equal(closure.dispositionCheckpoint.usableForCurrentDecision, true);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /status-transition-checkpoint\/reconcile/);
  assert.match(server, /orphan-disposition-checkpoint\/enrollments/);
});

test("Batch 188: failed external transition commit leaves a recoverable one-event gap and blocks new transitions", async t => {
  const context = await setupOwner(t, "b188-transition-crash");
  const { app, owner, recovered, anchors } = context;
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Prepare transition before simulated anchor interruption." });
  const initial = await app.getRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointStatus(owner);
  assert.equal(initial.sourceCount, 0);
  anchors.transition.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    prepared.challengeId, { confirmation: prepared.confirmation }), error => error.code === "RECOVERY_INTENT_TRANSITION_CHECKPOINT_ADVANCE_PENDING");
  const pending = await app.getRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointStatus(owner);
  assert.equal(pending.status, "behind_local");
  const transitionAudit = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitions(owner);
  assert.equal(transitionAudit.usableForCurrentDecision, false);
  anchors.transition.failWrites = false;
  const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(reconciled.status, "anchored");
  const resumed = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    prepared.challengeId, { confirmation: prepared.confirmation });
  assert.equal(resumed.recoveryIntent.status, "completed");
  const after = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitions(owner);
  assert.equal(after.status, "healthy");
  assert.equal(after.usableForCurrentDecision, true);
  const checkpointAudit = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(checkpointAudit.status, "healthy");
});

test("Batch 188: disposition receipt checkpoint is reconciled idempotently after external CAS failure", async t => {
  const context = await setupOwner(t, "b188-disposition-crash");
  const { app, owner, recovered, anchors } = context;
  const { intent } = await orphanIntent(context);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, intent.id,
    { disposition: "quarantine", reason: "Original challenge is missing and cannot be reconstructed safely." });
  anchors.disposition.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_INTENT_ORPHAN_DISPOSITION_CHECKPOINT_ADVANCE_PENDING");
  const pending = await app.getRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointStatus(owner);
  assert.equal(pending.status, "behind_local");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).usableForCurrentDecision, false);
  anchors.disposition.failWrites = false;
  const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpoint(owner);
  assert.equal(reconciled.status, "anchored");
  const retried = await app.applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(retried.status, "completed");
  assert.equal(retried.idempotent, true);
  assert.equal(retried.disposition.disposition, "quarantine");
  const state = await app.getRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointStatus(owner);
  assert.equal(state.status, "anchored");
  assert.equal(state.sourceCount, 1);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.closureComplete, true);
  assert.equal(closure.usableForCurrentDecision, false);
});

test("Batch 188: rollback/tampering in transition history makes its checkpoint and closure unhealthy", async t => {
  const context = await setupOwner(t, "b188-transition-tamper");
  const { app, owner, recovered, storage } = context;
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const store = createAgenticStore({ storage });
  const ledgerId = `recovery-intent-status-transitions-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const mutated = structuredClone(ledger);
  mutated.events[0].toStatus = "completed";
  const unsigned = { ...mutated }; delete unsigned.digest; delete unsigned._storage;
  mutated.digest = sha256(canonical(unsigned));
  await store.putEvidence(owner, mutated, { expectedVersion: ledger._storage?.version });
  const checkpoint = await app.auditRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(checkpoint.status, "unhealthy");
  assert.equal(checkpoint.usableForCurrentDecision, false);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.status, "unhealthy");
  assert.equal(closure.usableForCurrentDecision, false);
  assert.ok(closure.findings.some(item => /TRANSITION|CHECKPOINT|LEDGER/.test(item.code)));
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner);
  assert.equal(lifecycleAudit.usableForCurrentDecision, false);
  assert.ok(lifecycleAudit.findings.some(item => /CLOSURE_UNHEALTHY|TRANSITION_CHECKPOINT_NOT_CURRENT/.test(item.code)));
});


test("Batch 188: closure trust domains reject a reused external provider", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b188-provider-reuse-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider("https://b188-reuse-receipt.example"),
    finalization: anchorProvider("https://b188-reuse-finalization.example"),
    reconciliation: anchorProvider("https://b188-reuse-reconciliation.example"),
    lifecycleRecovery: anchorProvider("https://b188-reuse-lifecycle-recovery.example"),
    lifecycleIntent: anchorProvider("https://b188-reuse-lifecycle-intent.example"),
    transition: anchorProvider("https://b188-reuse-transition.example") };
  anchors.disposition = anchors.transition;
  const { options } = keyMaterial();
  assert.throws(() => makeApp(createStorage({ root }), options, anchors), /external anchor provider terpisah/);
});


test("Batch 188: missing transition anchor blocks new recovery intent before local mutation", async t => {
  const context = await setupOwner(t, "b188-preflight");
  const { app, owner, recovered, anchors, storage } = context;
  anchors.transition.records.clear();
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Verify strict checkpoint preflight prevents an unanchored intent." });
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_INTENT_TRANSITION_CHECKPOINT_NOT_CURRENT");
  const store = createAgenticStore({ storage });
  const intents = (await store.listEvidence(owner)).filter(row => row?.ownerId === owner
    && row.kind === "recovery-slo-cross-domain-recovery-decision-gate-receipt-recovery-attestation-lifecycle-intent");
  assert.equal(intents.length, 0);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.usableForCurrentDecision, false);
});
