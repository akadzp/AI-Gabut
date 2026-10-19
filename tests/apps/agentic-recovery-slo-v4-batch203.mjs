import test, { describe } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";

describe("Agentic AI V4 Batch 203", { concurrency: false }, () => {

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
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofAnchor: anchors.recoveryGateProof || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofAnchor: Boolean(anchors.requireRecoveryGateProofCheckpoint),
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
async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false, lifecycleDispositionCheckpoint = false, enrollLifecycleDispositionCheckpoint = true, reuseLifecycleDispositionProvider = false, revalidationLifecycleCheckpoint = false, enrollRevalidationLifecycleCheckpoint = true, reuseRevalidationLifecycleProvider = false, requireRevalidationLifecycleFreshnessAttestation = false, revalidationLifecycleFreshnessAttestationMaxAgeMs = 300000, recoveryGateProofCheckpoint = false, enrollRecoveryGateProofCheckpoint = true, reuseRecoveryGateProofProvider = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b203-${owner}-`));
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
    ...(recoveryGateProofCheckpoint ? { recoveryGateProof: anchorProvider(`https://${owner}-recovery-gate-proof.example`), requireRecoveryGateProofCheckpoint: true } : {}),
    requireFreshness, requireMarkerRecoveryJournalAttestation, requireRevalidationLifecycleFreshnessAttestation, revalidationLifecycleFreshnessAttestationMaxAgeMs };
  if (reuseMarkerRecoveryJournalProvider && anchors.markerRecoveryJournal)
    anchors.markerRecoveryJournal = anchors.closureRecoveryReceipts;
  if (reuseLifecycleDispositionProvider && anchors.lifecycleDisposition)
    anchors.lifecycleDisposition = anchors.closureRecoveryReceipts;
  if (reuseRevalidationLifecycleProvider && anchors.revalidationLifecycle)
    anchors.revalidationLifecycle = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofProvider && anchors.recoveryGateProof)
    anchors.recoveryGateProof = anchors.closureRecoveryReceipts;
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
  if (recoveryGateProofCheckpoint && enrollRecoveryGateProofCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointEnrollment", "Enroll independent recovery-gate proof checkpoint for Batch 203.");
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


async function createCurrentRevalidation(t, owner, { revalidationLifecycleCheckpoint = false, requireRevalidationLifecycleFreshnessAttestation = false, revalidationLifecycleFreshnessAttestationMaxAgeMs = 300000,
  recoveryGateProofCheckpoint = false, enrollRecoveryGateProofCheckpoint = true, reuseRecoveryGateProofProvider = false } = {}) {
  const { app, anchors } = await setupOwner(t, owner, { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true,
    revalidationLifecycleCheckpoint, requireRevalidationLifecycleFreshnessAttestation, revalidationLifecycleFreshnessAttestationMaxAgeMs,
    recoveryGateProofCheckpoint, enrollRecoveryGateProofCheckpoint, reuseRecoveryGateProofProvider });
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

test("Batch 203: proof ledger is independently checkpointed and required for current decision use", async t => {
  const { app, owner } = await createCurrentRevalidation(t, "b203-proof-checkpoint", { revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true, recoveryGateProofCheckpoint: true });
  const status = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(owner);
  assert.equal(status.usableForCurrentDecision, true);
  const checkpointAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpoint(owner);
  assert.ok(["healthy", "not_initialized"].includes(checkpointAudit.status));
  const gate = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.ok(gate.recoveryGateProof?.id);
  assert.equal(gate.proofCheckpoint.usableForCurrentDecision, true);
  assert.equal(gate.recoveryGateProofAudit.proofCheckpoint.usableForCurrentDecision, true);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(owner)).usableForCurrentDecision, true);
});

test("Batch 203: proof checkpoint reconciliation resumes after local proof commit and external write failure", async t => {
  const { app, owner, anchors } = await createCurrentRevalidation(t, "b203-proof-crash", { revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true, recoveryGateProofCheckpoint: true });
  anchors.recoveryGateProof.failWrites = true;
  const gate = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.equal(gate.usableForCurrentDecision, false);
  assert.ok(gate.recoveryGateProof?.id);
  assert.ok(gate.checkpointError);
  anchors.recoveryGateProof.failWrites = false;
  const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpoint(owner);
  assert.ok(["anchored", "marker_repaired"].includes(reconciled.status));
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleRecoveryGateProof(owner);
  assert.ok(["verified_current", "decision_blocked"].includes(audit.status));
  assert.equal(audit.proofCheckpoint.usableForCurrentDecision, true);
});

test("Batch 203: strict proof checkpoint requirement blocks decisions until enrollment is complete", async t => {
  const { app, owner } = await createCurrentRevalidation(t, "b203-proof-enrollment-gate", { revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true, recoveryGateProofCheckpoint: true, enrollRecoveryGateProofCheckpoint: false });
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: "b203-proof-enrollment-freshness-01" });
  const blocked = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.equal(blocked.usableForCurrentDecision, false);
  assert.equal(blocked.recoveryGateProof, null);
  assert.equal(blocked.proofCheckpoint.status, "not_initialized");
  assert.equal(blocked.proofCheckpoint.sourceCount, 0);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointEnrollment(owner,
    { reason: "Enroll independent recovery-gate proof checkpoint after durable proof creation." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointEnrollment(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(owner);
  assert.equal(checkpoint.usableForCurrentDecision, true);
  const retried = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.ok(retried.recoveryGateProof?.id);
  assert.equal(retried.proofCheckpoint.usableForCurrentDecision, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleRecoveryGateProof(owner);
  assert.equal(audit.proofCheckpoint.usableForCurrentDecision, true);
});

test("Batch 203: external commit response loss is reconciled by repairing the checkpoint marker", async t => {
  const { app, owner, anchors } = await createCurrentRevalidation(t, "b203-proof-response-loss", { revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true, recoveryGateProofCheckpoint: true });
  anchors.recoveryGateProof.throwAfterCommitOnce = true;
  const gate = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.equal(gate.usableForCurrentDecision, false);
  assert.ok(gate.checkpointError);
  const pending = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(owner);
  assert.equal(pending.status, "marker_pending");
  const repaired = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpoint(owner);
  assert.equal(repaired.status, "marker_repaired");
  const current = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(owner);
  assert.equal(current.usableForCurrentDecision, true);
});


});
