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
async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b193-${owner}-`));
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

test("Batch 193: marker-recovery journal checkpoint attestation is signed, current, and required by closure when configured", async t => {
  const { app, owner } = await setupOwner(t, "b193-journal-attestation", {
    markerRecoveryJournal: true, requireMarkerRecoveryJournalAttestation: true
  });
  let closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.usableForCurrentDecision, true);
  assert.equal(closure.markerJournalAttestationAudit.status, "missing");
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  assert.equal(issued.status, "attested");
  assert.equal(issued.attestation.eventType, "marker_recovery_journal_checkpoint_attestation");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner, issued.attestation.id);
  assert.equal(audit.status, "verified_current");
  assert.equal(audit.usableForCurrentDecision, true);
  closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.markerJournalAttestationAudit.usableForCurrentDecision, true);
  assert.equal(closure.closureComplete, true);
});

test("Batch 193: marker-journal attestation renewal is idempotent and revocation blocks current-decision use", async t => {
  const { app, owner } = await setupOwner(t, "b193-journal-lifecycle", {
    markerRecoveryJournal: true, requireMarkerRecoveryJournalAttestation: true
  });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const renewal = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew marker journal attestation after checkpoint review." });
  const first = await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    renewal.challengeId, { confirmation: renewal.confirmation });
  const second = await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    renewal.challengeId, { confirmation: renewal.confirmation });
  assert.equal(first.status, "completed");
  assert.equal(second.idempotent, true);
  assert.equal(second.event.id, first.event.id);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner)).status, "verified_current");
  const supersededAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner, issued.attestation.id);
  assert.equal(supersededAudit.status, "stale");
  assert.equal(supersededAudit.supersededBy.eventId, first.event.id);
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "revoke", eventId: first.event.id, reason: "Revoke marker journal attestation after an explicit trust review." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    revoke.challengeId, { confirmation: revoke.confirmation });
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner);
  assert.equal(audit.status, "revoked");
  assert.equal(audit.usableForCurrentDecision, false);
  assert.notEqual((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).usableForCurrentDecision, true);
});

test("Batch 193: attestation is stale after marker-journal checkpoint changes and stale challenges are rejected", async t => {
  const { app, owner, storage } = await setupOwner(t, "b193-journal-stale", {
    markerRecoveryJournal: true, requireMarkerRecoveryJournalAttestation: true
  });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew after confirming the current marker journal state." });
  await removeRecoveryReceiptMarker(storage, owner);
  await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_STALE");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner, issued.attestation.id);
  assert.equal(audit.status, "stale");
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 193: local attestation commit recovers after external CAS response loss without duplicate events", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b193-journal-cas-recovery", { markerRecoveryJournal: true });
  anchors.closureRecoveryReceipts.throwAfterCommitOnce = true;
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  assert.equal(issued.status, "attested");
  const store = createAgenticStore({ storage });
  const ledgerId = `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const attestationEvents = ledger.events.filter(event => event.eventType === "marker_recovery_journal_checkpoint_attestation");
  assert.equal(attestationEvents.length, 1);
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointStatus(owner);
  assert.equal(checkpoint.usableForCurrentDecision, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner);
  assert.equal(audit.status, "verified_current");
});

test("Batch 193: aggregate freshness attestation includes marker-recovery journal continuity", async t => {
  const { app, owner, storage } = await setupOwner(t, "b193-aggregate-freshness", {
    markerRecoveryJournal: true, requireFreshness: true
  });
  const before = await app.getRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessSnapshot(owner);
  assert.equal(before.checkpoints.marker_recovery_journal.usableForCurrentDecision, true);
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(issued.status, "attested");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner)).status, "verified_current");
  await removeRecoveryReceiptMarker(storage, owner);
  await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner, issued.attestation.id);
  assert.equal(audit.status, "stale");
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 193: marker-journal attestation routes and strict deployment flag are wired", async t => {
  const { app, owner } = await setupOwner(t, "b193-routes", {
    markerRecoveryJournal: true, requireMarkerRecoveryJournalAttestation: true
  });
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /marker-recovery-journal\/attestation\/audit/);
  assert.match(server, /marker-recovery-journal\/attestation\/lifecycle\/prepare/);
  assert.match(server, /marker-recovery-journal\/attestation\/lifecycle\/apply/);
  const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.match(appSource, /AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_ATTESTATION/);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner);
  assert.equal(audit.status, "missing");
  assert.notEqual((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).usableForCurrentDecision, true);
});


test("Batch 193: signing-key cutoff invalidates current marker-journal attestation without erasing history", async t => {
  const { app, owner } = await setupOwner(t, "b193-key-cutoff", {
    markerRecoveryJournal: true, requireMarkerRecoveryJournalAttestation: true
  });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  await rotateKey(app, owner);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner, issued.attestation.id);
  assert.equal(audit.status, "stale");
  assert.equal(audit.verification.historicallyValid, true);
  assert.equal(audit.usableForCurrentDecision, false);
  assert.notEqual((await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner)).closureComplete, true);
});

test("Batch 193: strict marker-journal attestation cannot substitute for a missing external journal checkpoint", async t => {
  const { app, owner } = await setupOwner(t, "b193-missing-anchor", {
    markerRecoveryJournal: false, requireMarkerRecoveryJournalAttestation: true
  });
  await assert.rejects(() => app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner),
    error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_SNAPSHOT_NOT_CURRENT");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(audit.closureComplete, true);
  assert.equal(audit.markerJournalAttestationAudit.status, "missing");
});

test("Batch 193: marker-journal external CAS response loss reconciles the committed anchor without duplicating recovery intent", async t => {
  const { app, owner, anchors, storage } = await setupOwner(t, "b193-cas", { markerRecoveryJournal: true });
  await removeRecoveryReceiptMarker(storage, owner);
  anchors.markerRecoveryJournal.throwAfterCommitOnce = true;
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  assert.equal(prepared.status, "prepared");
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointStatus(owner)).usableForCurrentDecision, true);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_intent").length, 1);
  assert.equal(audit.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized").length, 1);
});

test("Batch 193: expired attestation recovery first repairs a pending external commit before issuing a new generation", async t => {
  let now = Date.parse("2026-10-14T00:00:00.000Z");
  const clock = () => new Date(now).toISOString();
  const { app, owner, anchors, storage } = await setupOwner(t, "b193-expired-recovery", {
    markerRecoveryJournal: true, clock
  });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner),
    error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  now += 6 * 60 * 1000;
  anchors.closureRecoveryReceipts.failWrites = false;
  const replacement = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  assert.equal(replacement.status, "attested");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation(owner, replacement.attestation.id)).status, "verified_current");
  const store = createAgenticStore({ storage });
  const ledger = await store.getEvidence(owner, `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`);
  assert.equal(ledger.events.filter(event => event.eventType === "marker_recovery_journal_checkpoint_attestation").length, 2);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointStatus(owner)).usableForCurrentDecision, true);
});
