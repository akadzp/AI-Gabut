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
async function enrollClosureCheckpoints(app, owner) {
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 194.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition closure checkpoint for Batch 194.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment", "Enroll closure recovery receipt checkpoint for Batch 194.");
}
async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false } = {}) {
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
    requireFreshness, requireMarkerRecoveryJournalAttestation };
  if (reuseMarkerRecoveryJournalProvider && anchors.markerRecoveryJournal)
    anchors.markerRecoveryJournal = anchors.closureRecoveryReceipts;
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
      "applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment", "Enroll marker-recovery journal checkpoint for Batch 194.");
  return { app, owner, storage, anchors };
}
async function removeTransitionMarker(storage, owner) {
  const store = createAgenticStore({ storage });
  const markerId = `recovery-intent-status-transition-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
}


async function removeRecoveryReceiptMarker(storage, owner) {
  const store = createAgenticStore({ storage });
  const markerId = `recovery-intent-closure-recovery-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
}
async function writeRecoveryReceiptMarkerFromAnchor(storage, owner, anchor, updatedAt = "2026-10-14T00:00:00.000Z") {
  const store = createAgenticStore({ storage });
  const id = `recovery-intent-closure-recovery-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const unsigned = { id, ownerId: owner, kind: "recovery-intent-closure-recovery-receipt-checkpoint-marker", schemaVersion: 1,
    anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, snapshotDigest: anchor.snapshotDigest,
    sourceCount: anchor.sourceCount, ...(anchor.policyDigest ? { policyDigest: anchor.policyDigest } : {}), updatedAt };
  const marker = { ...unsigned, digest: sha256(canonical(unsigned)) };
  await store.putEvidence(owner, marker, { overwrite: false });
  return marker;
}

test("Batch 194: renewal and revocation are anchored through recovery-intent and CAS finalization receipts", async t => {
  const { app, owner, storage } = await setupOwner(t, "b194-lifecycle-intents", {
    markerRecoveryJournal: true, requireMarkerRecoveryJournalAttestation: true
  });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const renewal = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew after reviewing the current marker recovery journal." });
  const first = await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    renewal.challengeId, { confirmation: renewal.confirmation });
  const retry = await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    renewal.challengeId, { confirmation: renewal.confirmation });
  assert.equal(first.status, "completed");
  assert.equal(retry.status, "completed");
  assert.equal(retry.idempotent, true);
  assert.equal(retry.event.id, first.event.id);
  assert.ok(first.recoveryIntentEvent?.attestation);
  assert.ok(first.finalizationReceipt?.attestation);
  const store = createAgenticStore({ storage });
  const ledger = await store.getEvidence(owner, `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`);
  assert.equal(ledger.events.filter(event => event.eventType === "marker_recovery_journal_attestation_lifecycle_recovery_intent").length, 1);
  assert.equal(ledger.events.filter(event => event.eventType === "marker_recovery_journal_attestation_lifecycle_finalization").length, 1);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(owner);
  assert.equal(audit.status, "verified_current");
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "revoke", eventId: first.event.id, reason: "Revoke the renewed attestation after an explicit trust review." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    revoke.challengeId, { confirmation: revoke.confirmation });
  assert.equal(revoked.status, "completed");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner)).status, "revoked");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(owner)).status, "verified_current");
});

test("Batch 194: pending lifecycle intent survives external checkpoint failure and resumes without duplicate receipts", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b194-intent-recovery", { markerRecoveryJournal: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew after verifying the current recovery evidence." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  const pending = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(owner);
  assert.equal(pending.pendingCount, 1);
  assert.notEqual(pending.usableForCurrentDecision, true);
  anchors.closureRecoveryReceipts.failWrites = false;
  const recovered = await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(recovered.status, "completed");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(owner);
  assert.equal(audit.status, "verified_current");
  assert.equal(audit.pendingCount, 0);
  const store = createAgenticStore({ storage });
  const ledger = await store.getEvidence(owner, `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`);
  assert.equal(ledger.events.filter(event => event.eventType === "marker_recovery_journal_attestation_lifecycle_recovery_intent").length, 1);
  assert.equal(ledger.events.filter(event => event.eventType === "marker_recovery_journal_checkpoint_attestation" && event.lifecycleChallengeId === challenge.challengeId).length, 1);
  assert.equal(ledger.events.filter(event => event.eventType === "marker_recovery_journal_attestation_lifecycle_finalization").length, 1);
});

test("Batch 194: key cutoff after intent anchoring blocks stale mutation and closure reports unresolved recovery", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b194-intent-key-cutoff", { markerRecoveryJournal: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew only while the original signing key remains current." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  anchors.closureRecoveryReceipts.failWrites = false;
  await rotateKey(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_KEY_CUTOFF");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(owner);
  assert.equal(audit.status, "stale");
  assert.equal(audit.pendingCount, 1);
  assert.notEqual(audit.usableForCurrentDecision, true);
  assert.notEqual((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).closureComplete, true);
});

test("Batch 194: lifecycle recovery audit detects tampered CAS finalization binding", async t => {
  const { app, owner, storage } = await setupOwner(t, "b194-finalization-tamper", { markerRecoveryJournal: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew after validating the lifecycle finalization chain." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage });
  const record = await store.getEvidence(owner, challenge.challengeId);
  const tampered = { ...record, lifecycleFinalizationBindingDigest: "0".repeat(64) };
  delete tampered.digest; delete tampered._storage;
  tampered.digest = sha256(canonical(tampered));
  await store.putEvidence(owner, tampered, { expectedVersion: record._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(owner);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_BINDING_INVALID"));
});

test("Batch 194: lifecycle recovery audit route and closure gate include pending recovery intents", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b194-route-gate", { markerRecoveryJournal: true, requireMarkerRecoveryJournalAttestation: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew only after checking checkpoint recovery continuity." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }));
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /marker-recovery-journal\/attestation\/lifecycle\/recovery-intents\/audit/);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.closureComplete, true);
  assert.notEqual(closure.usableForCurrentDecision, true);
});

test("Batch 194: lifecycle event committed before checkpoint failure is finalized after recovery with key cutoff recorded", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b194-event-recovery", { markerRecoveryJournal: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew only after the checkpoint and signing lifecycle are revalidated." });
  const anchorRecord = [...anchors.closureRecoveryReceipts.records.values()][0];
  assert.ok(Number.isSafeInteger(anchorRecord?.sourceCount));
  const failAtSourceCount = anchorRecord.sourceCount + 2;
  const provider = anchors.closureRecoveryReceipts;
  const originalCompareAndSet = provider.compareAndSet.bind(provider);
  provider.compareAndSet = async (scope, expectedDigest, candidate) => {
    if (candidate?.sourceCount === failAtSourceCount) return { applied: false };
    return originalCompareAndSet(scope, expectedDigest, candidate);
  };
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  const store = createAgenticStore({ storage });
  const ledgerId = `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`;
  const interruptedLedger = await store.getEvidence(owner, ledgerId);
  assert.equal(interruptedLedger.events.filter(event => event.eventType === "marker_recovery_journal_checkpoint_attestation" && event.lifecycleChallengeId === challenge.challengeId).length, 1);
  assert.equal(interruptedLedger.events.filter(event => event.eventType === "marker_recovery_journal_attestation_lifecycle_finalization" && event.challengeId === challenge.challengeId).length, 0);
  provider.compareAndSet = originalCompareAndSet;
  await rotateKey(app, owner);
  const recovered = await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(recovered.status, "completed");
  assert.equal(recovered.keyCutoffDetected, true);
  assert.equal(recovered.lifecycleReceiptCurrent, false);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(owner);
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.status, "stale");
  assert.notEqual(audit.usableForCurrentDecision, true);
  const finalLedger = await store.getEvidence(owner, ledgerId);
  assert.equal(finalLedger.events.filter(event => event.eventType === "marker_recovery_journal_attestation_lifecycle_recovery_intent" && event.challengeId === challenge.challengeId).length, 1);
  assert.equal(finalLedger.events.filter(event => event.eventType === "marker_recovery_journal_checkpoint_attestation" && event.lifecycleChallengeId === challenge.challengeId).length, 1);
  assert.equal(finalLedger.events.filter(event => event.eventType === "marker_recovery_journal_attestation_lifecycle_finalization" && event.challengeId === challenge.challengeId).length, 1);
});
