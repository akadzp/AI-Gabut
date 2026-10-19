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
  return { pairs, options: {
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
    ...(anchors.lifecycleRecovery ? {
      recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: anchors.lifecycleRecovery,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: true
    } : {})
  });
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the key for Batch 184 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate the key to verify lifecycle recovery-receipt cutoff." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollReceiptCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll receipt checkpoint for Batch 184.");
}
async function enrollFinalizationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 184.");
}
async function enrollReconciliationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 184.");
}
async function enrollLifecycleRecoveryCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery-receipt checkpoint for Batch 184.");
}
async function createFinalization(app, storage, owner) {
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  return app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
}
async function setupOwner(t, owner, { lifecycleRecovery = true } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b185-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    ...(lifecycleRecovery ? { lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`) } : {}) };
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors);
  await activateKey(app, owner);
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enrollFinalizationCheckpoint(app, owner);
  await enrollReconciliationCheckpoint(app, owner);
  if (lifecycleRecovery) await enrollLifecycleRecoveryCheckpoint(app, owner);
  const recovered = await createFinalization(app, storage, owner);
  return { app, storage, anchors, keyOptions, recovered, owner };
}
async function applyLifecycle(app, owner, targetId, action = "renew") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, targetId,
    { action, reason: `Batch 184 ${action} operation for current lifecycle recovery receipt evidence.` });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  return { challenge, result };
}


test("Batch 185: recovery-receipt attestation can be renewed with recovery-intent CAS finalization", async t => {
  const context = await setupOwner(t, "b185-renew");
  const { app, recovered, owner } = context;
  const first = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const target = first.result.recoveryReceipt;
  assert.ok(target?.attestation);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "renew", reason: "Renew the recovery-receipt attestation with a bound intent and CAS finalization." });
  assert.match(challenge.confirmation, /RECOVERY RECEIPT ATTESTATION/);
  assert.ok(challenge.recoveryIntentBindingDigest);
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result.status, "renewed");
  assert.equal(result.lifecycleEvent.targetId, target.id);
  assert.equal(result.lifecycleEvent.targetKind, target.kind);
  assert.equal(result.recoveryIntent.status, "completed");
  assert.ok(result.recoveryIntent.recoveryIntentDigest);
  assert.equal(result.recoveryReceiptCheckpoint.status, "anchored");
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.equal(continuity.status, "healthy");
  assert.equal(continuity.recoveryIntents.pendingCount, 0);
  assert.equal(continuity.usableForCurrentDecision, true);
});

test("Batch 185: recovery-receipt attestation revocation blocks current decision use", async t => {
  const context = await setupOwner(t, "b185-revoke");
  const { app, recovered, owner } = context;
  const first = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const target = first.result.recoveryReceipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "revoke", reason: "Revoke the nested recovery-receipt attestation for cutoff enforcement." });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result.status, "revoked");
  assert.equal(result.recoveryIntent.status, "completed");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.notEqual(audit.status, "healthy");
  assert.equal(audit.usableForCurrentDecision, false);
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.notEqual(continuity.status, "healthy");
  assert.equal(continuity.usableForCurrentDecision, false);
});

test("Batch 185: lifecycle recovery-intent CAS finalization is idempotent and does not duplicate receipts", async t => {
  const context = await setupOwner(t, "b185-idempotent");
  const { app, recovered, owner } = context;
  const first = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const target = first.result.recoveryReceipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "renew", reason: "Ensure replay of the same lifecycle operation returns the same immutable evidence." });
  const result1 = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const result2 = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result1.lifecycleEvent.id, result2.lifecycleEvent.id);
  assert.equal(result1.recoveryReceipt.id, result2.recoveryReceipt.id);
  assert.equal(result2.recoveryIntent.id, result1.recoveryIntent.id);
  assert.equal(result2.recoveryIntent.status, "completed");
  assert.equal(result2.idempotent, true);
  const intentAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.equal(intentAudit.recoveryIntents.intentCount, 2);
  assert.equal(intentAudit.recoveryIntents.completedCount, 2);
  assert.equal(intentAudit.recoveryIntents.pendingCount, 0);
});

test("Batch 185: key lifecycle change invalidates a prepared recovery-receipt attestation challenge", async t => {
  const context = await setupOwner(t, "b185-stale");
  const { app, recovered, owner } = context;
  const first = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    first.result.recoveryReceipt.id, { action: "renew", reason: "The challenge must fail closed after signing-key lifecycle changes." });
  await rotateKey(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_CHALLENGE_STALE");
});

test("Batch 185: failed external recovery-receipt checkpoint leaves a pending intent that completes on retry", async t => {
  const context = await setupOwner(t, "b185-crash");
  const { app, recovered, owner, anchors } = context;
  const first = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const target = first.result.recoveryReceipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "renew", reason: "Recover after an external checkpoint write interruption without duplicating evidence." });
  anchors.lifecycleRecovery.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING"
      || error.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_RECOVERY_INTENT_FINALIZATION_PENDING");
  let continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.notEqual(continuity.status, "healthy");
  assert.ok(continuity.recoveryIntents.pendingCount >= 1);
  anchors.lifecycleRecovery.failWrites = false;
  const retried = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(retried.status, "renewed");
  assert.equal(retried.recoveryIntent.status, "completed");
  continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.equal(continuity.status, "healthy");
  assert.equal(continuity.recoveryIntents.pendingCount, 0);
});

test("Batch 185: key rotation during checkpoint interruption does not duplicate the pending recovery receipt", async t => {
  const context = await setupOwner(t, "b185-crash-key-cutoff");
  const { app, recovered, owner, anchors } = context;
  const first = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const target = first.result.recoveryReceipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "renew", reason: "A pending external commit must retry without duplicating receipts after key rotation." });
  anchors.lifecycleRecovery.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING"
      || error.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_RECOVERY_INTENT_FINALIZATION_PENDING");
  await rotateKey(app, owner);
  anchors.lifecycleRecovery.failWrites = false;
  const retried = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(retried.recoveryIntent.status, "completed");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(audit.receiptCount, 2);
  assert.notEqual(audit.status, "healthy");
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 185: continuity audit detects a missing persisted recovery intent", async t => {
  const context = await setupOwner(t, "b185-intent-tamper");
  const { app, recovered, owner, storage } = context;
  const first = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    first.result.recoveryReceipt.id, { action: "renew", reason: "Audit must fail closed when the bound recovery intent disappears." });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage });
  const intent = await store.getEvidence(owner, result.recoveryIntent.id);
  assert.ok(intent);
  await store.state.delete("evidence", `${owner}--${intent.id}`, { expectedVersion: intent._storage?.version });
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.equal(continuity.status, "unhealthy");
  assert.equal(continuity.usableForCurrentDecision, false);
  assert.ok(continuity.findings.some(item => item.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_RECOVERY_INTENT_INVALID"));
  const decisionGateLifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner);
  assert.equal(decisionGateLifecycleAudit.status, "unhealthy");
  assert.equal(decisionGateLifecycleAudit.usableForCurrentDecision, false);
});

test("Batch 185: continuity audit API is exposed and includes the new HTTP route", async t => {
  const context = await setupOwner(t, "b185-api");
  const { app, owner } = context;
  assert.equal(typeof app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity, "function");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleContinuity(owner);
  assert.equal(audit.ownerId, owner);
  assert.equal(audit.readOnly, true);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /attestation-lifecycle\/continuity\/audit/);
});
