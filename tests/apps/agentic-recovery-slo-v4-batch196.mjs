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
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the signing key for Batch 194 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate signing key to validate Batch 194 cutoff enforcement." });
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
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 194.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition closure checkpoint for Batch 194.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment", "Enroll closure recovery receipt checkpoint for Batch 194.");
}
async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false, lifecycleDispositionCheckpoint = false, enrollLifecycleDispositionCheckpoint = true, reuseLifecycleDispositionProvider = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b194-${owner}-`));
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
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll base receipt checkpoint for Batch 194.");
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 194.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 194.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery checkpoint for Batch 194.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle intent checkpoint for Batch 194.");
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

test("Batch 196: lifecycle-disposition checkpoint is independently enrolled and current", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b196-independent-anchor", { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true });
  const status = await app.getRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointStatus(owner);
  assert.equal(status.enabled, true);
  assert.equal(status.usableForCurrentDecision, true);
  assert.equal(status.sourceCount, 0);
  assert.notEqual(anchors.lifecycleDisposition, anchors.closureRecoveryReceipts);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpoint(owner);
  assert.equal(audit.usableForCurrentDecision, true);
  assert.equal(audit.localAudit.status, "healthy");
});

test("Batch 196: challenge expiry without durable disposition is reconciled idempotently", async t => {
  let now = Date.parse("2026-10-14T00:00:00.000Z");
  const { app, owner, anchors, storage } = await setupOwner(t, "b196-expiry-no-commit", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true, clock: () => new Date(now).toISOString()
  });
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Quarantine an unresolved lifecycle intent after key cutoff." });
  now += 11 * 60 * 1000;
  const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDispositionChallenge(owner,
    challenge.challengeId);
  assert.equal(reconciled.status, "expired_without_commit");
  const retry = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDispositionChallenge(owner,
    challenge.challengeId);
  assert.equal(retry.status, "expired_without_commit");
  assert.equal(retry.idempotent, true);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_EXPIRED");
  const store = createAgenticStore({ storage });
  const ledger = await store.getEvidence(owner, `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`);
  assert.equal(ledger.events.some(event => event.operationId === `marker-recovery-journal-attestation-lifecycle-disposition:${lifecycle.challengeId}`), false);
});

test("Batch 196: expired challenge resumes after durable disposition commit and checkpoint recovery", async t => {
  let now = Date.parse("2026-10-14T00:00:00.000Z");
  const { app, owner, anchors, storage } = await setupOwner(t, "b196-expiry-after-commit", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true, clock: () => new Date(now).toISOString()
  });
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "mark_unrecoverable", reason: "Mark unrecoverable after a verified signing-key cutoff." });
  anchors.lifecycleDisposition.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_ADVANCE_PENDING");
  now += 11 * 60 * 1000;
  const pendingAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(owner);
  assert.equal(pendingAudit.usableForCurrentDecision, false);
  assert.equal(pendingAudit.lifecycleDispositionCheckpoint.usableForCurrentDecision, false);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).closureComplete, false);
  anchors.lifecycleDisposition.failWrites = false;
  const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDispositionChallenge(owner,
    challenge.challengeId);
  assert.equal(reconciled.status, "resumed_after_persisted_commit");
  assert.equal(reconciled.expiryIgnoredBecauseCommitWasDurable, true);
  assert.equal(reconciled.result.status, "completed");
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointStatus(owner);
  assert.equal(checkpoint.usableForCurrentDecision, true);
  const continuity = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(owner);
  assert.equal(continuity.pendingDispositionCount, 0);
  assert.equal(continuity.dispositionedCount, 1);
  assert.equal(continuity.usableForCurrentDecision, false);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).closureComplete, false);
  const store = createAgenticStore({ storage });
  const ledger = await store.getEvidence(owner, `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`);
  assert.equal(ledger.events.filter(event => event.operationId === `marker-recovery-journal-attestation-lifecycle-disposition:${lifecycle.challengeId}`).length, 1);
  assert.equal(ledger.events.filter(event => event.operationId === `marker-recovery-journal-attestation-lifecycle-disposition-finalization:${lifecycle.challengeId}`).length, 1);
});

test("Batch 196: strict disposition checkpoint blocks new disposition before enrollment", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b196-enrollment-required", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true, enrollLifecycleDispositionCheckpoint: false
  });
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Quarantine an intent only after checkpoint enrollment." }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_NOT_CURRENT");
  const ledgerAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(owner);
  assert.equal(ledgerAudit.lifecycleDispositionCheckpoint.usableForCurrentDecision, false);
});

test("Batch 196: lifecycle-disposition checkpoint detects provider reuse and exposes routes", async t => {
  const { app: reusedApp, owner: reusedOwner } = await setupOwner(t, "b196-provider-reuse", {
    markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true, reuseLifecycleDispositionProvider: true
  });
  const independence = await reusedApp.auditRecoverySloAnchorTrustDomainIndependence(reusedOwner);
  assert.equal(independence.status, "unhealthy");
  assert.ok(independence.collisions.some(item => item.domains.includes("cross_domain_recovery_intent_closure_lifecycle_dispositions")
    && item.domains.includes("cross_domain_recovery_intent_closure_recovery_receipts")));
  const reusedCheckpoint = await reusedApp.getRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointStatus(reusedOwner);
  assert.equal(reusedCheckpoint.status, "unhealthy");
  assert.equal(reusedCheckpoint.usableForCurrentDecision, false);
  const reusedContinuity = await reusedApp.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(reusedOwner);
  assert.equal(reusedContinuity.status, "unhealthy");
  assert.equal(reusedContinuity.usableForCurrentDecision, false);
  const reusedClosure = await reusedApp.auditRecoverySloCrossDomainRecoveryIntentClosure(reusedOwner);
  assert.notEqual(reusedClosure.closureComplete, true);
  assert.notEqual(reusedClosure.usableForCurrentDecision, true);
  const { app, owner } = await setupOwner(t, "b196-routes", { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true });
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /lifecycle\/recovery-intent-disposition\/checkpoint\/status/);
  assert.match(server, /lifecycle\/recovery-intent-disposition\/checkpoint\/enrollment\/prepare/);
  assert.match(server, /recovery-intent-disposition\/challenge\/reconcile/);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointStatus(owner)).usableForCurrentDecision, true);
});
