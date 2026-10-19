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
    recoverySloCrossDomainRecoveryIntentClosureFreshnessAttestationMaxAgeMs: 300000
  });
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the signing key for Batch 191 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate signing key to validate Batch 191 cutoff enforcement." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollClosureCheckpoints(app, owner) {
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 191.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition closure checkpoint for Batch 191.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment", "Enroll closure recovery receipt checkpoint for Batch 191.");
}
async function setupOwner(t, owner, { requireFreshness = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b191-${owner}-`));
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
    requireFreshness };
  if (reuseMarkerRecoveryJournalProvider && anchors.markerRecoveryJournal)
    anchors.markerRecoveryJournal = anchors.closureRecoveryReceipts;
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors, clock);
  await activateKey(app, owner);
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll base receipt checkpoint for Batch 191.");
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 191.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 191.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery checkpoint for Batch 191.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle intent checkpoint for Batch 191.");
  await enrollClosureCheckpoints(app, owner);
  if (markerRecoveryJournal && enrollMarkerRecoveryJournal)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment", "Enroll marker-recovery journal checkpoint for Batch 192.");
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

test("Batch 192: marker-recovery journal is independently anchored and closure revalidates its head", async t => {
  const { app, owner, storage, anchors } = await setupOwner(t, "b192-journal-anchor", { markerRecoveryJournal: true });
  let status = await app.getRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointStatus(owner);
  assert.equal(status.usableForCurrentDecision, true);
  assert.equal(status.sourceCount, 0);
  await removeRecoveryReceiptMarker(storage, owner);
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  assert.equal(prepared.status, "prepared");
  status = await app.getRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointStatus(owner);
  assert.equal(status.usableForCurrentDecision, true);
  assert.equal(status.sourceCount, 1);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  status = await app.getRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointStatus(owner);
  assert.equal(status.usableForCurrentDecision, true);
  assert.equal(status.sourceCount, 2);
  const anchor = [...anchors.markerRecoveryJournal.records.values()][0];
  assert.equal(anchor.sourceCount, 2);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.usableForCurrentDecision, true);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.markerRecoveryAudit.journalCheckpoint.usableForCurrentDecision, true);
});

test("Batch 192: failed journal external commit resumes the same persisted recovery intent", async t => {
  const { app, owner, storage, anchors } = await setupOwner(t, "b192-journal-crash", { markerRecoveryJournal: true });
  await removeRecoveryReceiptMarker(storage, owner);
  anchors.markerRecoveryJournal.failWrites = true;
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner),
    error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_CHECKPOINT_ADVANCE_PENDING");
  anchors.markerRecoveryJournal.failWrites = false;
  const resumed = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  assert.equal(resumed.status, "prepared");
  assert.equal(resumed.idempotent, true);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointStatus(owner)).usableForCurrentDecision, true);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_intent").length, 1);
});

test("Batch 192: configured but un-enrolled journal anchor blocks marker-recovery mutation", async t => {
  const { app, owner, storage } = await setupOwner(t, "b192-unenrolled", { markerRecoveryJournal: true, enrollMarkerRecoveryJournal: false });
  await removeRecoveryReceiptMarker(storage, owner);
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner),
    error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_CHECKPOINT_NOT_CURRENT");
  const store = createAgenticStore({ storage });
  const ledgerId = `recovery-intent-closure-checkpoint-marker-recovery-${sha256(owner).slice(0, 32)}`;
  assert.equal(await store.getEvidence(owner, ledgerId), null);
});

test("Batch 192: journal rollback blocks closure and current-decision use", async t => {
  const { app, owner, storage } = await setupOwner(t, "b192-journal-rollback", { markerRecoveryJournal: true });
  await removeRecoveryReceiptMarker(storage, owner);
  await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  const store = createAgenticStore({ storage });
  const ledgerId = `recovery-intent-closure-checkpoint-marker-recovery-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  assert.ok(ledger);
  await store.state.delete("evidence", `${owner}--${ledgerId}`, { expectedVersion: ledger._storage?.version });
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointStatus(owner);
  assert.notEqual(checkpoint.usableForCurrentDecision, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  assert.notEqual(audit.usableForCurrentDecision, true);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.usableForCurrentDecision, true);
  assert.equal(closure.closureComplete, false);
});

test("Batch 192: marker-recovery journal checkpoint endpoints and exports are wired", async t => {
  const { app, owner } = await setupOwner(t, "b192-routes", { markerRecoveryJournal: true });
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-receipt-checkpoint\/marker-recovery-journal\/status/);
  assert.match(server, /recovery-receipt-checkpoint\/marker-recovery-journal\/audit/);
  assert.match(server, /marker-recovery-journal\/enrollment\/prepare/);
  assert.match(server, /marker-recovery-journal\/enrollment\/apply/);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointStatus(owner)).usableForCurrentDecision, true);
});


test("Batch 192: marker-recovery journal trust domain rejects a reused external provider", async t => {
  const { app, owner } = await setupOwner(t, "b192-provider-reuse", {
    markerRecoveryJournal: true, enrollMarkerRecoveryJournal: false, reuseMarkerRecoveryJournalProvider: true
  });
  const report = await app.auditRecoverySloAnchorTrustDomainIndependence(owner);
  assert.equal(report.status, "unhealthy");
  assert.ok(report.collisions.some(item => item.domains.includes("cross_domain_recovery_intent_closure_marker_recovery_journal")
    && item.domains.includes("cross_domain_recovery_intent_closure_recovery_receipts")));
});
