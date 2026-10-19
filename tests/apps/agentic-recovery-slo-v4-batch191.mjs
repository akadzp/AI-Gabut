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
async function setupOwner(t, owner, { requireFreshness = false, clock = () => "2026-10-14T00:00:00.000Z" } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b191-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`),
    lifecycleIntent: anchorProvider(`https://${owner}-lifecycle-intent.example`),
    transition: anchorProvider(`https://${owner}-transition.example`),
    disposition: anchorProvider(`https://${owner}-disposition.example`),
    closureRecoveryReceipts: anchorProvider(`https://${owner}-closure-recovery-receipts.example`), requireFreshness };
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

test("Batch 191: recovery-receipt checkpoint marker recovery persists a signed intent and finalization receipt", async t => {
  const { app, owner, storage } = await setupOwner(t, "b191-marker-recovery");
  await removeRecoveryReceiptMarker(storage, owner);
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  assert.equal(prepared.status, "prepared");
  assert.equal(prepared.intent.eventType, "recovery_receipt_checkpoint_marker_recovery_intent");
  const pendingAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(pendingAudit.pendingCount, 1);
  assert.equal(pendingAudit.usableForCurrentDecision, false);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(recovered.status, "marker_recovered");
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_intent").length, 1);
  assert.equal(audit.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized").length, 1);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointStatus(owner)).usableForCurrentDecision, true);
});

test("Batch 191: marker recovery resumes after marker write but before finalization receipt", async t => {
  const { app, owner, storage, anchors } = await setupOwner(t, "b191-marker-crash");
  await removeRecoveryReceiptMarker(storage, owner);
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  assert.equal(prepared.status, "prepared");
  const anchor = [...anchors.closureRecoveryReceipts.records.values()][0];
  await writeRecoveryReceiptMarkerFromAnchor(storage, owner, anchor);
  const before = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(before.pendingCount, 1);
  const resumed = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(resumed.status, "marker_already_current");
  assert.equal(resumed.finalizationReceipt.status, "finalized");
  assert.equal(resumed.finalizationReceipt.idempotent, false);
  const repeated = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(repeated.status, "not_required");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized").length, 1);
});

test("Batch 191: caller cannot override the persisted marker-recovery anchor binding", async t => {
  const { app, owner, storage } = await setupOwner(t, "b191-binding");
  await removeRecoveryReceiptMarker(storage, owner);
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecoveryIntent(owner);
  await assert.rejects(() => app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner,
    { expectedAnchorSequence: prepared.intent.expectedAnchorSequence + 1 }),
    error => error.code === "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_CALLER_BINDING_MISMATCH");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(recovered.status, "marker_recovered");
  assert.equal(recovered.recoveryIntent.id, prepared.intent.id);
});

test("Batch 191: pending freshness renewal resumes after expiry and key cutoff without claiming current evidence", async t => {
  let now = Date.parse("2026-10-14T00:00:00.000Z");
  const clock = () => new Date(now).toISOString();
  const { app, owner, anchors } = await setupOwner(t, "b191-keycut", { requireFreshness: true, clock });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew freshness evidence and validate interrupted key-cutoff recovery." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
    error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  anchors.closureRecoveryReceipts.failWrites = false;
  await rotateKey(app, owner);
  now += 11 * 60_000;
  const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(resumed.status, "completed");
  assert.equal(resumed.idempotent, true);
  assert.equal(resumed.keyCutoffDetected, true);
  assert.equal(resumed.lifecycleReceiptCurrent, false);
  assert.equal(resumed.audit.usableForCurrentDecision, false);
  const ledger = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(ledger.events.filter(event => event.operationId === `checkpoint-freshness-lifecycle:${challenge.challengeId}`).length, 1);
});

test("Batch 191: marker-recovery finalization becomes stale after signing-key rotation", async t => {
  const { app, owner, storage } = await setupOwner(t, "b191-keyfinal");
  await removeRecoveryReceiptMarker(storage, owner);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  await rotateKey(app, owner);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointRecovery(owner);
  assert.equal(audit.status, "stale");
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_KEY_CUTOFF"));
});

test("Batch 191: marker recovery routes and revocation signature audit are present", async t => {
  const { app, owner, storage } = await setupOwner(t, "b191-route-audit", { requireFreshness: true });
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-receipt-checkpoint\/recovery\/prepare/);
  assert.match(server, /recovery-receipt-checkpoint\/recovery\/inspect/);
  assert.match(server, /recovery-receipt-checkpoint\/recovery\/audit/);
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "revoke", eventId: issued.attestation.id, reason: "Revoke the attestation to validate signed revocation evidence." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(revoked.status, "completed");
  const store = createAgenticStore({ storage });
  const ledgerId = `recovery-intent-closure-checkpoint-recovery-${sha256(owner).slice(0, 32)}`;
  const record = await store.getEvidence(owner, ledgerId);
  const changedEvents = record.events.map(event => {
    if (event.id !== revoked.event.id) return event;
    const unsigned = { ...event, attestation: { ...event.attestation, signature: "A".repeat(86) } };
    delete unsigned.digest;
    return { ...unsigned, digest: sha256(canonical(unsigned)) };
  });
  const { _storage, ...recordBase } = record;
  const ledgerUnsigned = { ...recordBase, events: changedEvents, eventCount: changedEvents.length,
    headDigest: changedEvents.at(-1).digest, updatedAt: new Date("2026-10-14T00:00:00.000Z").toISOString() };
  delete ledgerUnsigned.digest;
  const tampered = { ...ledgerUnsigned, digest: sha256(canonical(ledgerUnsigned)) };
  await store.putEvidence(owner, tampered, { expectedVersion: record._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner, issued.attestation.id);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_FRESHNESS_REVOCATION_ATTESTATION_INVALID"));
});

test("Batch 191: concurrent lifecycle applies finalize the same event exactly once", async t => {
  const { app, owner } = await setupOwner(t, "b191-concurrent", { requireFreshness: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew freshness evidence while racing identical CAS finalization calls." });
  const outcomes = await Promise.all([
    app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner, challenge.challengeId,
      { confirmation: challenge.confirmation }),
    app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner, challenge.challengeId,
      { confirmation: challenge.confirmation })
  ]);
  assert.ok(outcomes.every(item => item.status === "completed"));
  const ledger = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(ledger.events.filter(event => event.operationId === `checkpoint-freshness-lifecycle:${challenge.challengeId}`).length, 1);
});

test("Batch 191: expired freshness lifecycle challenge without a persisted event cannot create a new event", async t => {
  let now = Date.parse("2026-10-14T00:00:00.000Z");
  const clock = () => new Date(now).toISOString();
  const { app, owner } = await setupOwner(t, "b191-expired", { requireFreshness: true, clock });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew freshness evidence but allow the challenge to expire before append." });
  now += 11 * 60_000;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
    error => error.code === "RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_CHALLENGE_EXPIRED");
  const ledger = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(ledger.events.some(event => event.operationId === `checkpoint-freshness-lifecycle:${challenge.challengeId}`), false);
});
