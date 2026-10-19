import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";

describe("Agentic AI V4 Batch 201", { concurrency: false }, () => {

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
    recoverySloCrossDomainRecoveryIntentClosureFreshnessAttestationMaxAgeMs: 300000,
    requireRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshnessAttestation: Boolean(anchors.requireRevalidationLifecycleFreshnessAttestation),
    recoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshnessAttestationMaxAgeMs: anchors.revalidationLifecycleFreshnessAttestationMaxAgeMs || 300000
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
async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false, lifecycleDispositionCheckpoint = false, enrollLifecycleDispositionCheckpoint = true, reuseLifecycleDispositionProvider = false, revalidationLifecycleCheckpoint = false, enrollRevalidationLifecycleCheckpoint = true, reuseRevalidationLifecycleProvider = false, requireRevalidationLifecycleFreshnessAttestation = false, revalidationLifecycleFreshnessAttestationMaxAgeMs = 300000 } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b201-${owner}-`));
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
    requireFreshness, requireMarkerRecoveryJournalAttestation, requireRevalidationLifecycleFreshnessAttestation, revalidationLifecycleFreshnessAttestationMaxAgeMs };
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


async function createCurrentRevalidation(t, owner, { revalidationLifecycleCheckpoint = false, requireRevalidationLifecycleFreshnessAttestation = false, revalidationLifecycleFreshnessAttestationMaxAgeMs = 300000 } = {}) {
  const { app, anchors } = await setupOwner(t, owner, { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true,
    revalidationLifecycleCheckpoint, requireRevalidationLifecycleFreshnessAttestation, revalidationLifecycleFreshnessAttestationMaxAgeMs });
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

test("Batch 201: freshness attestation binds the current independent lifecycle anchor and receipt checkpoint", async t => {
  const { app, owner } = await createCurrentRevalidation(t, "b201-freshness-current", { revalidationLifecycleCheckpoint: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: "b201-freshness-current-generation-01" });
  assert.equal(issued.status, "verified_current");
  assert.equal(issued.audit.usableForCurrentDecision, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner);
  assert.equal(audit.status, "verified_current");
  assert.equal(audit.usableForCurrentDecision, true);
  assert.ok(audit.generationId);
  assert.ok(Number.isSafeInteger(audit.receiptCheckpoint.sourceCount) && audit.receiptCheckpoint.sourceCount > 0);
  assert.ok(Number.isSafeInteger(audit.receiptCheckpoint.anchorSequence));
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(lifecycleAudit.freshnessAttestation.status, "verified_current");
  assert.equal(lifecycleAudit.usableForCurrentDecision, true);
  const repeated = await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner);
  assert.equal(repeated.idempotent, true);
  assert.equal(repeated.attestation.id, issued.attestation.id);
});

test("Batch 201: strict recovery gate rejects missing freshness attestation and accepts a current one", async t => {
  const { app, owner } = await createCurrentRevalidation(t, "b201-strict-freshness", {
    revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true
  });
  const before = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(before.freshnessAttestation.status, "missing");
  assert.equal(before.usableForCurrentDecision, false);
  assert.ok(before.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_REQUIRED_OR_STALE"));
  const gateBefore = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.equal(gateBefore.freshnessAttestation.status, "missing");
  assert.equal(gateBefore.usableForCurrentDecision, false);
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: "b201-strict-freshness-generation-01" });
  assert.equal(issued.audit.usableForCurrentDecision, true);
  const after = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(after.usableForCurrentDecision, true);
  assert.equal(after.freshnessAttestation.status, "verified_current");
  const gateAfter = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.equal(gateAfter.freshnessAttestation.status, "verified_current");
  assert.equal(gateAfter.lifecycleAudit.usableForCurrentDecision, true);
  assert.equal(gateAfter.usableForCurrentDecision, gateAfter.closureAudit.usableForCurrentDecision === true);
});

test("Batch 201: drift monitoring retains signed evidence and freshness issuance resolves it only after recovery", async t => {
  const { app, owner, anchors } = await createCurrentRevalidation(t, "b201-drift-retention", { revalidationLifecycleCheckpoint: true });
  const [scope, original] = [...anchors.revalidationLifecycle.records.entries()][0];
  const tampered = { ...original, anchorSequence: Math.max(0, original.anchorSequence - 1), digest: "1".repeat(64) };
  anchors.revalidationLifecycle.records.set(scope, tampered);
  const monitor = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationExternalAnchorDrift(owner);
  assert.equal(monitor.externalAnchorDriftDetected, true);
  assert.equal(monitor.driftEvidenceRetention.record.status, "anchored");
  assert.equal(monitor.driftEvidenceAudit.recordCount, 1);
  assert.equal(monitor.driftEvidenceAudit.unresolvedCount, 1);
  assert.equal(monitor.driftEvidenceAudit.usableForCurrentDecision, false);
  anchors.revalidationLifecycle.records.set(scope, original);
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: "b201-drift-recovered-freshness-01" });
  assert.equal(issued.status, "verified_current");
  const driftAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleDriftEvidence(owner);
  assert.equal(driftAudit.unresolvedCount, 0);
  assert.equal(driftAudit.resolvedCount, 1);
  assert.equal(driftAudit.usableForCurrentDecision, true);
  anchors.revalidationLifecycle.records.set(scope, tampered);
  const repeatedDrift = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationExternalAnchorDrift(owner);
  assert.equal(repeatedDrift.externalAnchorDriftDetected, true);
  assert.equal(repeatedDrift.driftEvidenceAudit.recordCount, 2);
  assert.equal(repeatedDrift.driftEvidenceAudit.unresolvedCount, 1);
  const staleFreshness = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner);
  assert.notEqual(staleFreshness.status, "verified_current");
  assert.equal(staleFreshness.usableForCurrentDecision, false);
});

test("Batch 201: drift-event commit survives receipt-anchor failure and reconciliation does not duplicate the event", async t => {
  const { app, owner, anchors } = await createCurrentRevalidation(t, "b201-drift-crash-recovery", { revalidationLifecycleCheckpoint: true });
  const [scope, original] = [...anchors.revalidationLifecycle.records.entries()][0];
  anchors.revalidationLifecycle.records.set(scope, { ...original, anchorSequence: Math.max(0, original.anchorSequence - 1), digest: "2".repeat(64) });
  anchors.closureRecoveryReceipts.failWrites = true;
  const monitor = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationExternalAnchorDrift(owner);
  assert.equal(monitor.externalAnchorDriftDetected, true);
  assert.equal(monitor.driftEvidenceRetention.record.status, "pending_anchor");
  const beforeLedger = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  const pendingCount = beforeLedger.driftEvidenceAudit.recordCount;
  assert.equal(pendingCount, 1);
  anchors.closureRecoveryReceipts.failWrites = false;
  const resumed = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleDriftEvidence(owner);
  assert.equal(resumed.audit.recordCount, 1);
  assert.equal(resumed.audit.pendingCount, 0);
  assert.equal(resumed.audit.anchoredCount, 1);
  const ledger = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(ledger.driftEvidenceAudit.recordCount, 1);
  assert.equal(ledger.driftEvidenceAudit.usableForCurrentDecision, false);
});

test("Batch 201: signing-key cutoff invalidates previously current freshness evidence", async t => {
  const { app, owner, anchors } = await createCurrentRevalidation(t, "b201-freshness-cutoff", {
    revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true
  });
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: "b201-freshness-cutoff-generation-01" });
  await rotateKeyToOld(app, owner);
  const afterRotation = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner);
  assert.notEqual(afterRotation.status, "verified_current");
  assert.equal(afterRotation.usableForCurrentDecision, false);
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner);
  assert.equal(lifecycleAudit.usableForCurrentDecision, false);
  assert.ok(lifecycleAudit.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_REQUIRED_OR_STALE"));
  assert.ok(anchors.revalidationLifecycle.records.size > 0);
});


test("Batch 201: replaying a freshness operation ID against a changed lifecycle generation is rejected", async t => {
  const { app, owner, attestation } = await createCurrentRevalidation(t, "b201-generation-binding", { revalidationLifecycleCheckpoint: true });
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: "b201-fixed-generation-operation" });
  const lifecycle = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    { action: "renew", attestationId: attestation.id, reason: "Advance the lifecycle generation to test freshness operation binding." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionRollbackRevalidationAttestationLifecycle(owner,
    lifecycle.challengeId, { confirmation: lifecycle.confirmation });
  await assert.rejects(() => app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: "b201-fixed-generation-operation" }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_OPERATION_CONFLICT");
});

test("Batch 201: freshness, drift evidence, and recovery-gate routes plus environment policy are wired", async () => {
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /revalidation-lifecycle\/freshness\/attest/);
  assert.match(serverSource, /revalidation-lifecycle\/freshness\/audit/);
  assert.match(serverSource, /revalidation-lifecycle\/drift-evidence\/audit/);
  assert.match(serverSource, /revalidation-lifecycle\/drift-evidence\/reconcile/);
  assert.match(serverSource, /revalidation-lifecycle\/recovery-gate\/revalidate/);
  const applicationSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.match(applicationSource, /AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION/);
  assert.match(applicationSource, /AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_MAX_AGE_MS/);
});
});
