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
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the signing key for Batch 197 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate signing key to validate Batch 197 cutoff enforcement." });
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
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 197.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition closure checkpoint for Batch 197.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment", "Enroll closure recovery receipt checkpoint for Batch 197.");
}
async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false, lifecycleDispositionCheckpoint = false, enrollLifecycleDispositionCheckpoint = true, reuseLifecycleDispositionProvider = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b197-${owner}-`));
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
    requireFreshness, requireMarkerRecoveryJournalAttestation };
  if (reuseMarkerRecoveryJournalProvider && anchors.markerRecoveryJournal)
    anchors.markerRecoveryJournal = anchors.closureRecoveryReceipts;
  if (reuseLifecycleDispositionProvider && anchors.lifecycleDisposition)
    anchors.lifecycleDisposition = anchors.closureRecoveryReceipts;
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors, clock);
  await activateKey(app, owner);
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll base receipt checkpoint for Batch 197.");
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 197.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 197.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery checkpoint for Batch 197.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle intent checkpoint for Batch 197.");
  await enrollClosureCheckpoints(app, owner);
  if (markerRecoveryJournal && enrollMarkerRecoveryJournal)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment", "Enroll marker-recovery journal checkpoint for Batch 196.");
  if (lifecycleDispositionCheckpoint && enrollLifecycleDispositionCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointEnrollment", "Enroll independent lifecycle-disposition checkpoint for Batch 196.");
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

test("Batch 197: lifecycle-disposition checkpoint marker pending is recovered from the exact external anchor", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b197-marker-recovery", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const store = createAgenticStore({ storage });
  const initialAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const anchorHistory = [];
  const originalCas = anchors.lifecycleDisposition.compareAndSet.bind(anchors.lifecycleDisposition);
  anchors.lifecycleDisposition.compareAndSet = async (scope, expected, candidate) => {
    const result = await originalCas(scope, expected, candidate);
    if (result?.applied) anchorHistory.push(structuredClone(candidate));
    return result;
  };
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Quarantine lifecycle intent for exact marker-recovery validation." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.ok(anchorHistory.length >= 2);
  const remote = [...anchors.lifecycleDisposition.records.values()][0];
  const prior = anchorHistory.at(-2);
  assert.equal(remote.anchorSequence, prior.anchorSequence + 1);
  const markerId = `recovery-intent-closure-lifecycle-disposition-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  const unsignedMarker = { id: marker.id, ownerId: marker.ownerId, kind: marker.kind, schemaVersion: marker.schemaVersion,
    anchorSequence: prior.anchorSequence, anchorDigest: prior.digest, snapshotDigest: prior.snapshotDigest,
    sourceCount: prior.sourceCount, ...(prior.policyDigest ? { policyDigest: prior.policyDigest } : {}), updatedAt: marker.updatedAt };
  const staleMarker = { ...unsignedMarker, digest: sha256(canonical(unsignedMarker)) };
  await store.putEvidence(owner, staleMarker, { expectedVersion: marker._storage?.version });
  const status = await app.getRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointStatus(owner);
  assert.equal(status.status, "marker_pending");
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpoint(owner);
  assert.equal(recovered.status, "marker_recovered");
  assert.equal(recovered.finalizationReceipt.receipt.checkpointName, "lifecycle_disposition");
  const after = await app.getRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointStatus(owner);
  assert.equal(after.usableForCurrentDecision, true);
  const recoveryAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(recoveryAudit.pendingCount, 0);
  assert.equal(initialAnchor.anchorSequence, 1);
});

test("Batch 197: external anchor rollback creates signed incident disposition without mutating the anchor", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b197-anchor-rollback", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "mark_unrecoverable", reason: "Record unresolved lifecycle intent before rollback test." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  const [scope, latestAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  assert.ok(latestAnchor.anchorSequence > enrolledAnchor.anchorSequence);
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(inspection.status, "rollback_suspected");
  const before = structuredClone(anchors.lifecycleDisposition.records.get(scope));
  const rollbackChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "quarantine", reason: "Quarantine rollback evidence pending independent anchor review." });
  const applied = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollbackChallenge.challengeId, { confirmation: rollbackChallenge.confirmation });
  assert.equal(applied.status, "recorded_without_anchor_mutation");
  assert.equal(applied.externalAnchorChanged, false);
  assert.deepEqual(anchors.lifecycleDisposition.records.get(scope), before);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.activeRollback, true);
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.recoveryReceiptCheckpoint.usableForCurrentDecision, true);
  assert.equal(audit.usableForCurrentDecision, false);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.closureComplete, true);
  assert.notEqual(closure.usableForCurrentDecision, true);
});

test("Batch 197: rollback challenge rejects a changed anchor fingerprint", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b197-stale-rollback", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const originalAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Quarantine lifecycle challenge for stale-anchor regression." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  const [scope, latestAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, originalAnchor);
  const rollbackChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "mark_unrecoverable", reason: "Mark rollback case unrecoverable until continuity is restored." });
  anchors.lifecycleDisposition.records.set(scope, latestAnchor);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollbackChallenge.challengeId, { confirmation: rollbackChallenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_SNAPSHOT_CHANGED");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.status, "recovery_required");
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 197: rollback audit detects tampered finalization receipts and preserves fail-closed closure", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b197-tampered-receipt", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Quarantine lifecycle intent for receipt integrity test." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  const [scope] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const rollbackChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "quarantine", reason: "Quarantine suspected rollback pending operator review." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollbackChallenge.challengeId, { confirmation: rollbackChallenge.confirmation });
  const store = createAgenticStore({ storage });
  const rows = await store.listEvidence(owner);
  const target = rows.find(row => row?.ownerId === owner && row.kind === "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-finalization");
  assert.ok(target);
  const alteredUnsigned = { ...target, observedCheckpointStatus: "anchored" };
  delete alteredUnsigned.digest;
  await store.putEvidence(owner, { ...alteredUnsigned, digest: sha256(canonical(alteredUnsigned)) }, { expectedVersion: target._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.usableForCurrentDecision, false);
  assert.notEqual((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).closureComplete, true);
});

test("Batch 197: rollback receipt resumes after local commit and external recovery-receipt checkpoint failure", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "crash", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true
  });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Quarantine unresolved lifecycle intent for rollback crash test." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [scope] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const rollback = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "mark_unrecoverable", reason: "Mark rollback incident pending external receipt recovery." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollback.challengeId, { confirmation: rollback.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  const store = createAgenticStore({ storage });
  const pendingRows = await store.listEvidence(owner);
  assert.equal(pendingRows.filter(row => row?.ownerId === owner
    && row.kind === "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-event").length, 1);
  assert.equal(pendingRows.filter(row => row?.ownerId === owner
    && row.kind === "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-finalization").length, 0);
  anchors.closureRecoveryReceipts.failWrites = false;
  const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollback.challengeId, { confirmation: rollback.confirmation });
  assert.equal(resumed.status, "recorded_without_anchor_mutation");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.recoveryReceiptCheckpoint.usableForCurrentDecision, true);
  assert.equal(audit.usableForCurrentDecision, false);
  const rows = await store.listEvidence(owner);
  assert.equal(rows.filter(row => row?.ownerId === owner
    && row.kind === "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-event").length, 1);
  assert.equal(rows.filter(row => row?.ownerId === owner
    && row.kind === "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-finalization").length, 1);
});

test("Batch 197: recovery and rollback audit routes are exposed", async t => {
  const { app, owner } = await setupOwner(t, "b197-route-coverage", { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true });
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-intent-disposition\/checkpoint\/recovery\/inspect/);
  assert.match(server, /recovery-intent-disposition\/checkpoint\/rollback-recovery\/prepare/);
  assert.match(server, /recovery-intent-disposition\/checkpoint\/rollback-recovery\/audit/);
  assert.equal((await app.inspectRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner)).status, "current");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner)).usableForCurrentDecision, true);
});
