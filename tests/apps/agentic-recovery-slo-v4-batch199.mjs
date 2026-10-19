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
  return { baseUrl, records, failWrites: false, throwAfterCommitOnce: false,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      if (this.failWrites) return { applied: false };
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); if (this.throwAfterCommitOnce) { this.throwAfterCommitOnce = false; throw new Error("simulated response loss after external commit"); } return { applied: true };
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
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: anchors.lifecycleRecovery,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: anchors.lifecycleIntent,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: true,
    recoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: anchors.transition,
    requireRecoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: true,
    recoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: anchors.disposition,
    requireRecoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: true,
    recoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptAnchor: anchors.closureRecoveryReceipts,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptAnchor: true,
    recoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAnchor: anchors.markerRecoveryJournal || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAnchor: Boolean(anchors.requireMarkerRecoveryJournal),
    recoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionAnchor: anchors.lifecycleDisposition || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionAnchor: Boolean(anchors.requireLifecycleDispositionCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleAnchor: anchors.revalidationLifecycle || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleAnchor: Boolean(anchors.requireRevalidationLifecycleCheckpoint),
    requireRecoverySloCrossDomainRecoveryIntentClosureFreshnessAttestation: Boolean(anchors.requireFreshness),
    requireRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation: Boolean(anchors.requireMarkerRecoveryJournalAttestation),
    recoverySloCrossDomainRecoveryIntentClosureFreshnessAttestationMaxAgeMs: 300000
  });
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the signing key for Batch 199 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate signing key to validate Batch 199 cutoff enforcement." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKeyToOld(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_old", reason: "Rotate back to the prior key to validate stale challenge rejection." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollClosureCheckpoints(app, owner) {
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition closure checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment", "Enroll closure recovery receipt checkpoint for Batch 199.");
}
async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false, lifecycleDispositionCheckpoint = false, enrollLifecycleDispositionCheckpoint = true, reuseLifecycleDispositionProvider = false, revalidationLifecycleCheckpoint = false, enrollRevalidationLifecycleCheckpoint = true, reuseRevalidationLifecycleProvider = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b199-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`),
    lifecycleIntent: anchorProvider(`https://${owner}-lifecycle-intent.example`),
    transition: anchorProvider(`https://${owner}-transition.example`),
    disposition: anchorProvider(`https://${owner}-disposition.example`),
    closureRecoveryReceipts: anchorProvider(`https://${owner}-closure-recovery-receipts.example`),
    ...(markerRecoveryJournal ? { markerRecoveryJournal: anchorProvider(`https://${owner}-marker-recovery-journal.example`), requireMarkerRecoveryJournal: true } : {}),
    ...(lifecycleDispositionCheckpoint ? { lifecycleDisposition: anchorProvider(`https://${owner}-lifecycle-disposition.example`), requireLifecycleDispositionCheckpoint: true } : {}),
    ...(revalidationLifecycleCheckpoint ? { revalidationLifecycle: anchorProvider(`https://${owner}-revalidation-lifecycle.example`), requireRevalidationLifecycleCheckpoint: true } : {}),
    requireFreshness, requireMarkerRecoveryJournalAttestation };
  if (reuseMarkerRecoveryJournalProvider && anchors.markerRecoveryJournal)
    anchors.markerRecoveryJournal = anchors.closureRecoveryReceipts;
  if (reuseLifecycleDispositionProvider && anchors.lifecycleDisposition)
    anchors.lifecycleDisposition = anchors.closureRecoveryReceipts;
  if (reuseRevalidationLifecycleProvider && anchors.revalidationLifecycle)
    anchors.revalidationLifecycle = anchors.closureRecoveryReceipts;
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors, clock);
  await activateKey(app, owner);
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll base receipt checkpoint for Batch 199.");
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle intent checkpoint for Batch 199.");
  await enrollClosureCheckpoints(app, owner);
  if (markerRecoveryJournal && enrollMarkerRecoveryJournal)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment", "Enroll marker-recovery journal checkpoint for Batch 196.");
  if (lifecycleDispositionCheckpoint && enrollLifecycleDispositionCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointEnrollment", "Enroll independent lifecycle-disposition checkpoint for Batch 196.");
  if (revalidationLifecycleCheckpoint && enrollRevalidationLifecycleCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointEnrollment", "Enroll independent revalidation lifecycle checkpoint for Batch 200.");
  return { app, owner, storage, anchors };
}

async function prepareUnrecoverableLifecycle(app, owner, anchors) {
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const lifecycle = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew only while lifecycle and checkpoint bindings remain current." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    lifecycle.challengeId, { confirmation: lifecycle.confirmation }));
  anchors.closureRecoveryReceipts.failWrites = false;
  await rotateKey(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    lifecycle.challengeId, { confirmation: lifecycle.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_KEY_CUTOFF");
  return lifecycle;
}


async function createCurrentRevalidation(t, owner, { revalidationLifecycleCheckpoint = false } = {}) {
  const { app, anchors } = await setupOwner(t, owner, { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true,
    revalidationLifecycleCheckpoint });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Prepare current rollback revalidation lifecycle evidence." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [scope, latestAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const rollback = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "quarantine", reason: "Prepare rollback lifecycle for revalidation lifecycle tests." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollback.challengeId, { confirmation: rollback.confirmation });
  anchors.lifecycleDisposition.records.set(scope, latestAnchor);
  const revalidated = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner, rollback.challengeId);
  assert.equal(revalidated.status, "revalidated_current");
  assert.equal(revalidated.results[0].usableForCurrentDecision, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  const latest = audit.latestRevalidations.find(item => item.challengeId === rollback.challengeId);
  assert.ok(latest?.attestationId);
  assert.equal(latest.current, true);
  return { app, owner, anchors, rollback, attestation: revalidated.results[0].attestation, audit };
}

test("Batch 199: rollback recovery emits a six-phase signed continuity ledger and independent external revalidation attestation", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b199-continuity", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "mark_unrecoverable", reason: "Record unresolved lifecycle intent for continuity validation." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [, latestAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  const [scope] = [...anchors.lifecycleDisposition.records.keys()];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const rollback = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "quarantine", reason: "Quarantine the rolled-back lifecycle checkpoint for independent revalidation." });
  const applied = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollback.challengeId, { confirmation: rollback.confirmation });
  assert.equal(applied.externalAnchorChanged, false);
  assert.equal(applied.continuityAudit.status, "verified_current");
  assert.equal(applied.continuityAudit.eventCount, 6);
  assert.equal(applied.continuityAudit.pendingCount, 0);
  assert.equal(applied.revalidation.results.length, 1);
  assert.equal(applied.revalidation.results[0].status, "rollback_unresolved");
  assert.equal(applied.revalidation.results[0].usableForCurrentDecision, false);
  assert.ok(applied.revalidation.results[0].externalReceiptId);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.revalidationAttestationCount, 1);
  assert.equal(audit.revalidationPendingCount, 0);
  assert.equal(audit.usableForCurrentDecision, false);
  assert.equal(anchors.lifecycleDisposition.records.get(scope).anchorSequence, enrolledAnchor.anchorSequence);
  assert.ok(latestAnchor.anchorSequence > enrolledAnchor.anchorSequence);
});

test("Batch 199: multi-receipt recovery resumes after local continuity and external mirror commits are interrupted", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b199-multi-receipt-recovery", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Prepare a deterministic multi-receipt recovery scenario." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [scope, latestAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "mark_unrecoverable", reason: "Record interrupted rollback receipt processing without anchor mutation." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }));
  anchors.closureRecoveryReceipts.failWrites = false;
  const resumed = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner,
    challenge.challengeId);
  assert.equal(resumed.status, "reconciled");
  assert.equal(resumed.continuityAudit.status, "verified_current");
  assert.equal(resumed.continuityAudit.pendingCount, 0);
  assert.equal(resumed.continuityAudit.eventCount, 6);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.revalidationPendingCount, 0);
  assert.equal(audit.continuityPendingCount, 0);
  assert.equal(anchors.lifecycleDisposition.records.get(scope).anchorSequence, enrolledAnchor.anchorSequence);
  assert.ok(latestAnchor.anchorSequence > enrolledAnchor.anchorSequence);
});

test("Batch 199: independent revalidation becomes current only after the external lifecycle anchor is restored", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b199-revalidation-current", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Prepare an independently revalidatable lifecycle checkpoint." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [scope, latestAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "quarantine", reason: "Quarantine the lifecycle checkpoint until the anchor is restored." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  anchors.lifecycleDisposition.records.set(scope, latestAnchor);
  const revalidated = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner,
    challenge.challengeId);
  assert.equal(revalidated.status, "revalidated_current");
  assert.equal(revalidated.usableForCurrentDecision, true);
  assert.equal(revalidated.results[0].status, "revalidated_current");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.status, "revalidated");
  assert.equal(audit.usableForCurrentDecision, true);
  assert.equal(audit.cases[0].revalidationCurrent, true);
});

test("Batch 199: continuity ledger tampering is detected and blocks closure", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b199-continuity-tamper", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Prepare a tamper-detection lifecycle disposition." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [scope] = [...anchors.lifecycleDisposition.records.keys()];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "quarantine", reason: "Create a rollback continuity chain for tamper testing." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage });
  const ledgerId = `lifecycle-disposition-rollback-continuity-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const changed = structuredClone(ledger);
  changed.events[0].phase = "tampered_phase";
  await store.putEvidence(owner, changed, { expectedVersion: ledger._storage?.version });
  const continuity = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackContinuity(owner);
  assert.equal(continuity.status, "unhealthy");
  assert.equal(continuity.usableForCurrentDecision, false);
  assert.ok(continuity.findings.some(item => /INVALID/.test(item.code)));
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.closureComplete, true);
  assert.notEqual(closure.usableForCurrentDecision, true);
});

test("Batch 199: revalidation attestation is marked stale after signing-key lifecycle changes", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b199-key-cutoff", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Prepare signing-key cutoff revalidation coverage." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [scope] = [...anchors.lifecycleDisposition.records.keys()];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "mark_unrecoverable", reason: "Capture rollback evidence before key lifecycle changes." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  await rotateKeyToOld(app, owner);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.ok(audit.staleRevalidationCount >= 1);
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_STALE"));
});

test("Batch 199: continuity audit, reconciliation, and revalidation routes are exposed", async () => {
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /rollback-recovery\/continuity\/audit/);
  assert.match(serverSource, /rollback-recovery\/reconcile/);
  assert.match(serverSource, /rollback-recovery\/revalidate/);
});


test("Batch 199: renewal creates an anchored replacement and replaying the same challenge is idempotent", async t => {
  const { app, owner, attestation } = await createCurrentRevalidation(t, "b199-renewal");
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Renew the current rollback revalidation with a new signed generation." });
  const first = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(first.status, "completed");
  assert.ok(first.replacementAttestation);
  assert.notEqual(first.replacementAttestation.id, attestation.id);
  assert.equal(first.replacementAttestation.generation, challenge.challengeId);
  assert.equal(first.usableForCurrentDecision, true);
  const before = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(before.pendingCount, 0);
  assert.equal(before.supersededCount, 1);
  const retry = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(retry.finalizationReceipt.id, first.finalizationReceipt.id);
  const after = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(after.eventCount, before.eventCount);
  assert.equal(after.pendingCount, 0);
  const rollbackAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(rollbackAudit.usableForCurrentDecision, true);
  assert.equal(rollbackAudit.externalAnchorDriftDetected, false);
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Attempt to replay lifecycle against superseded evidence." }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ALREADY_SUPERSEDED");
});

test("Batch 199: revocation is irreversible and blocks use of the target attestation", async t => {
  const { app, owner, attestation } = await createCurrentRevalidation(t, "b199-revocation");
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "revoke", attestationId: attestation.id, reason: "Revoke the current rollback revalidation due to evidence withdrawal." });
  const applied = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(applied.status, "completed");
  assert.equal(applied.replacementAttestation, null);
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(lifecycleAudit.revokedCount, 1);
  assert.equal(lifecycleAudit.pendingCount, 0);
  const rollbackAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(rollbackAudit.usableForCurrentDecision, false);
  assert.ok(rollbackAudit.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_REVOKED"));
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.closureComplete, true);
  assert.notEqual(closure.usableForCurrentDecision, true);
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Attempt to renew evidence after explicit revocation." }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ALREADY_REVOKED");
});

test("Batch 199: lifecycle recovery resumes after intent commit when external checkpoint writes fail", async t => {
  const { app, owner, anchors, attestation } = await createCurrentRevalidation(t, "b199-crash-recovery");
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Exercise crash recovery after the lifecycle intent commit." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }));
  anchors.closureRecoveryReceipts.failWrites = false;
  const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(resumed.status, "completed");
  assert.ok(resumed.replacementAttestation);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.cases[0].eventCount, 3);
});

test("Batch 199: signing-key rotation before lifecycle intent invalidates the prepared challenge", async t => {
  const { app, owner, attestation } = await createCurrentRevalidation(t, "b199-key-cutoff");
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Validate key-cutoff protection before durable lifecycle intent." });
  await rotateKeyToOld(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_SNAPSHOT_CHANGED");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.eventCount, 0);
});

test("Batch 199: key cutoff after durable intent finalizes as stale evidence without reopening decision use", async t => {
  const { app, owner, anchors, attestation } = await createCurrentRevalidation(t, "b199-durable-key-cutoff");
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Exercise key cutoff after durable lifecycle intent and recovery." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }));
  anchors.closureRecoveryReceipts.failWrites = false;
  await rotateKeyToOld(app, owner);
  const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(resumed.status, "completed");
  assert.equal(resumed.keyCutoffDetected, true);
  assert.equal(resumed.usableForCurrentDecision, false);
  assert.ok(resumed.replacementAttestation);
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(lifecycleAudit.pendingCount, 0);
  assert.equal(lifecycleAudit.keyCutoffCount, 1);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.staleRevalidationCount >= 1);
});

test("Batch 199: external anchor drift invalidates the prior revalidation and blocks lifecycle changes", async t => {
  const { app, owner, anchors, attestation } = await createCurrentRevalidation(t, "b199-anchor-drift");
  const [scope, currentAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, { ...currentAnchor, anchorSequence: Math.max(0, currentAnchor.anchorSequence - 1), digest: "0".repeat(64) });
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.staleRevalidationCount >= 1 || audit.activeRollback === true);
  const drift = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationExternalAnchorDrift(owner);
  assert.equal(drift.externalAnchorDriftDetected, true);
  assert.equal(drift.usableForCurrentDecision, false);
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Attempt renewal while external anchor drift remains unresolved." }));
});

test("Batch 199: lifecycle audit routes and generation-aware revalidation are exposed", async () => {
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /revalidation-lifecycle\/audit/);
  assert.match(serverSource, /revalidation-lifecycle\/prepare/);
  assert.match(serverSource, /revalidation-lifecycle\/apply/);
  assert.match(serverSource, /revalidation-lifecycle\/drift/);
  assert.match(serverSource, /generation:q.body\?\.generation/);
  const applicationSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.match(applicationSource, /options = \{\}\) \{\s*return crossDomainRecoveryIntentClosureService\.revalidateLifecycleDispositionCheckpointRollbackRecovery\(ownerId, challengeId, options\)/);
});
