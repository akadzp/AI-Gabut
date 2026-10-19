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

test("Batch 200: lifecycle renewal is anchored in an independent lifecycle-only external checkpoint", async t => {
  const { app, owner, anchors, attestation } = await createCurrentRevalidation(t, "b200-independent-ledger", {
    revalidationLifecycleCheckpoint: true
  });
  const before = await app.getRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointStatus(owner);
  assert.equal(before.enabled, true);
  assert.equal(before.usableForCurrentDecision, true);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Renew under independent lifecycle checkpoint enforcement." });
  const applied = await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(applied.status, "completed");
  assert.equal(applied.revalidationLifecycleCheckpoint.usableForCurrentDecision, true);
  const status = await app.getRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointStatus(owner);
  assert.equal(status.status, "anchored");
  assert.equal(status.usableForCurrentDecision, true);
  assert.equal(status.sourceCount, 3);
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(lifecycleAudit.eventCount, 3);
  assert.equal(lifecycleAudit.pendingCount, 0);
  assert.equal(lifecycleAudit.independentLifecycleCheckpointCurrent, true);
  assert.equal(lifecycleAudit.usableForCurrentDecision, true);
  const [scope, anchor] = [...anchors.revalidationLifecycle.records.entries()][0];
  assert.equal(anchors.revalidationLifecycle.records.get(scope).digest, anchor.digest);
  assert.equal(anchor.domain, "cross_domain_recovery_intent_closure_revalidation_lifecycle");
  assert.notEqual(anchors.revalidationLifecycle, anchors.closureRecoveryReceipts);
});

test("Batch 200: reconciliation resumes a lifecycle intent after independent anchor write failure without duplicate phases", async t => {
  const { app, owner, anchors, attestation } = await createCurrentRevalidation(t, "b200-drift-recovery", {
    revalidationLifecycleCheckpoint: true
  });
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Exercise recovery after the independent lifecycle anchor write fails." });
  anchors.revalidationLifecycle.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }));
  anchors.revalidationLifecycle.failWrites = false;
  const resumed = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId);
  assert.equal(resumed.status, "reconciled");
  assert.equal(resumed.resumedCount, 1);
  assert.equal(resumed.audit.pendingCount, 0);
  assert.equal(resumed.audit.eventCount, 3);
  assert.equal(resumed.usableForCurrentDecision, true);
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointStatus(owner);
  assert.equal(checkpoint.usableForCurrentDecision, true);
  assert.equal(checkpoint.sourceCount, 3);
  const ledgerAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.deepEqual(ledgerAudit.cases.map(item => item.eventCount), [3]);
});

test("Batch 200: reconciliation completes a durable finalization receipt after challenge-state write was interrupted", async t => {
  const { app, owner, anchors, attestation } = await createCurrentRevalidation(t, "b200-finalization-recovery", {
    revalidationLifecycleCheckpoint: true
  });
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Exercise recovery after finalization receipt persistence." });
  const provider = anchors.revalidationLifecycle;
  const originalCompareAndSet = provider.compareAndSet.bind(provider);
  let writes = 0;
  provider.compareAndSet = async (...args) => {
    writes++;
    if (writes >= 3) return { applied: false };
    return originalCompareAndSet(...args);
  };
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }));
  provider.compareAndSet = originalCompareAndSet;
  const resumed = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId);
  assert.equal(resumed.status, "reconciled");
  assert.equal(resumed.resumedCount, 1);
  assert.equal(resumed.audit.pendingCount, 0);
  assert.equal(resumed.audit.eventCount, 3);
  assert.equal(resumed.usableForCurrentDecision, true);
  const challengeAfter = await app.store.getEvidence(owner, challenge.challengeId);
  assert.equal(challengeAfter.status, "completed");
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointStatus(owner);
  assert.equal(checkpoint.sourceCount, 3);
  assert.equal(checkpoint.usableForCurrentDecision, true);
});

test("Batch 200: external lifecycle anchor rollback is detected and drift recovery refuses to rewrite the anchor", async t => {
  const { app, owner, anchors, attestation } = await createCurrentRevalidation(t, "b200-anchor-rollback", {
    revalidationLifecycleCheckpoint: true
  });
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Create a lifecycle event chain before rollback detection." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  const [scope, currentAnchor] = [...anchors.revalidationLifecycle.records.entries()][0];
  const tampered = { ...currentAnchor, anchorSequence: Math.max(0, currentAnchor.anchorSequence - 1), digest: "0".repeat(64) };
  anchors.revalidationLifecycle.records.set(scope, tampered);
  const drift = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationExternalAnchorDrift(owner);
  assert.equal(drift.externalAnchorDriftDetected, true);
  assert.equal(drift.usableForCurrentDecision, false);
  assert.equal(drift.revalidationLifecycleCheckpoint.usableForCurrentDecision, false);
  const reconciliation = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    challenge.challengeId);
  assert.equal(reconciliation.status, "recovery_blocked");
  assert.equal(reconciliation.usableForCurrentDecision, false);
  assert.deepEqual(anchors.revalidationLifecycle.records.get(scope), tampered);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.usableForCurrentDecision, true);
});

test("Batch 200: independent lifecycle checkpoint provider reuse is detected and enrollment is blocked", async t => {
  const { app, owner } = await setupOwner(t, "b200-provider-collision", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true, revalidationLifecycleCheckpoint: true,
    enrollRevalidationLifecycleCheckpoint: false, reuseRevalidationLifecycleProvider: true
  });
  const state = await app.getRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointStatus(owner);
  assert.equal(state.status, "unhealthy");
  assert.equal(state.usableForCurrentDecision, false);
  assert.ok(state.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ANCHOR_PROVIDER_REUSED"));
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointEnrollment(owner,
    { reason: "Attempt enrollment while the lifecycle provider is shared." }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ANCHOR_PROVIDER_REUSED");
});

test("Batch 200: independent lifecycle checkpoint enrollment and drift-recovery APIs are wired", async () => {
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /revalidation-lifecycle\/checkpoint\/status/);
  assert.match(serverSource, /revalidation-lifecycle\/checkpoint\/audit/);
  assert.match(serverSource, /revalidation-lifecycle\/checkpoint\/enrollment\/prepare/);
  assert.match(serverSource, /revalidation-lifecycle\/checkpoint\/enrollment\/apply/);
  assert.match(serverSource, /revalidation-lifecycle\/checkpoint\/reconcile/);
  assert.match(serverSource, /revalidation-lifecycle\/reconcile/);
  const applicationSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.match(applicationSource, /AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ANCHOR_URL/);
  assert.match(applicationSource, /CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DOMAIN/);
});
