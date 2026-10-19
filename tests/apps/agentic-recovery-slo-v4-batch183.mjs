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
async function setup(root, extra = {}, clock = () => "2026-10-14T00:00:00.000Z") {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock,
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    ...extra });
  return { app, storage, pairs };
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner, keyId = "finalization_key_old") {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId, reason: "Activate the attestation key for Batch 183 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate the key to exercise attestation renewal and cutoff." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollReceiptCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Explicit receipt checkpoint enrollment for Batch 183.");
}
async function enrollFinalizationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint genesis for Batch 183.");
}
async function enrollReconciliationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint genesis for Batch 183.");
}
async function createFinalization(app, storage, owner) {
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enrollFinalizationCheckpoint(app, owner);
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  return app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
}
async function setupAnchoredOwner(t, owner) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b183-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider(`https://${owner}-receipt.example`);
  const finalizationAnchor = anchorProvider(`https://${owner}-finalization.example`);
  const reconciliationAnchor = anchorProvider(`https://${owner}-reconciliation.example`);
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: reconciliationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation: true
  });
  await activateKey(app, owner);
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-receipt-source` });
  await enrollFinalizationCheckpoint(app, owner);
  await enrollReconciliationCheckpoint(app, owner);
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
  assert.equal(recovered.status, "recovered");
  return { app, storage, store, recovered, reconciliationAnchor };
}

test("Batch 183: attestation renewal re-signs the immutable finalization receipt under the current key and anchors lifecycle proof", async t => {
  const { app, storage, recovered } = await setupAnchoredOwner(t, "b183-renew");
  const owner = "b183-renew";
  const target = recovered.finalizationReceipt.receipt;
  await rotateKey(app, owner);
  const stale = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation(owner, target.id);
  assert.equal(stale.status, "historically_valid_stale");
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "renew", reason: "Renew finalization evidence after the approved signing-key rotation." });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result.status, "renewed");
  assert.ok(result.reconciliationReceipt);
  assert.notEqual(result.renewedAttestation.id, target.attestation.id);
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation(owner, target.id);
  assert.equal(verification.status, "verified_current");
  assert.equal(verification.renewed, true);
  assert.equal(verification.lifecycleAnchored, true);
  const lifecycle = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner);
  assert.equal(lifecycle.status, "healthy");
  assert.equal(lifecycle.usableForCurrentDecision, true);
  const finalizations = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.notEqual(finalizations.status, "unhealthy");
  assert.equal(finalizations.usableForCurrentDecision, true);
});

test("Batch 183: revocation blocks current use without mutating the original receipt", async t => {
  const { app, recovered } = await setupAnchoredOwner(t, "b183-revoke");
  const owner = "b183-revoke", target = recovered.finalizationReceipt.receipt;
  const before = structuredClone(target);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "revoke", reason: "Revoke the attestation because the evidence must no longer authorize decisions." });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result.status, "revoked");
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation(owner, target.id);
  assert.equal(verification.status, "revoked");
  assert.equal(verification.usableForCurrentDecision, false);
  const gate = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b183-gate-after-revocation" });
  assert.notEqual(gate.status, "healthy");
  assert.equal(gate.usableForCurrentDecision, false);
  const again = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(again.status, "revoked");
  assert.equal(again.idempotent, true);
  assert.deepEqual(recovered.finalizationReceipt.receipt, before);
});

test("Batch 183: lifecycle challenge rejects stale checkpoint and changed target binding", async t => {
  const { app, recovered } = await setupAnchoredOwner(t, "b183-stale");
  const owner = "b183-stale", target = recovered.finalizationReceipt.receipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "revoke", reason: "Revoke only after verifying the current receipt and checkpoint bindings." });
  await rotateKey(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), /changed|kedaluwarsa|berubah/i);
});

test("Batch 183: reconciliation checkpoint marker recovery is inspectable, intent-bound, and idempotent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b183-marker-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchor = anchorProvider("https://b183-marker-reconciliation.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: anchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: true
  });
  const owner = "b183-reconciliation-marker";
  await enrollReconciliationCheckpoint(app, owner);
  const store = createAgenticStore({ storage });
  const markerId = `recovery-reconciliation-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  const externalBefore = await app.getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointStatus(owner);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointRecovery(owner);
  assert.equal(inspection.recoverable, true);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.recoveryIntent.status, "completed");
  const after = await app.getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointStatus(owner);
  assert.equal(after.status, "anchored");
  assert.equal(after.anchorDigest, externalBefore.anchorDigest);
  const again = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint(owner);
  assert.equal(again.status, "not_required");
});

test("Batch 183: lifecycle receipt finalization recovers after an external checkpoint write interruption", async t => {
  const { app, recovered, reconciliationAnchor } = await setupAnchoredOwner(t, "b183-crash-recovery");
  const owner = "b183-crash-recovery", target = recovered.finalizationReceipt.receipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "revoke", reason: "Revoke this receipt and verify crash-safe lifecycle finalization." });
  reconciliationAnchor.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), /checkpoint|recovery/i);
  const pendingAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner);
  assert.equal(pendingAudit.status, "pending_anchor");
  reconciliationAnchor.failWrites = false;
  const recoveredApply = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(recoveredApply.status, "revoked");
  assert.equal(recoveredApply.idempotent, true);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner)).status, "healthy");
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation(owner, target.id);
  assert.equal(verification.status, "revoked");
  assert.equal(typeof app.inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointRecovery, "function");
  const server = await fs.readFile(path.resolve("apps/agentic/backend/server.js"), "utf8");
  assert.match(server, /recovery\/attestation-lifecycle\/challenges/);
  assert.match(server, /reconciliation\/checkpoint\/recovery\/inspect/);
});


test("Batch 183: reconciliation audit detects a tampered persisted lifecycle postcondition", async t => {
  const { app, storage, recovered } = await setupAnchoredOwner(t, "b183-postcondition-tamper");
  const owner = "b183-postcondition-tamper", target = recovered.finalizationReceipt.receipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, target.id,
    { action: "revoke", reason: "Revoke and then verify persisted postcondition binding integrity." });
  await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage });
  const ledgerId = `decision-gate-recovery-reconciliation-receipts-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const events = structuredClone(ledger.events);
  const event = events.find(item => item.operation === "attestation_lifecycle_revoke");
  assert.ok(event);
  event.after.lifecycleSnapshotDigest = "0".repeat(64);
  event.postconditionDigest = sha256(canonical({ ownerId: owner, operationKey: event.operationKey, operation: event.operation,
    before: event.before || null, after: event.after || null, recoveryIntentDigest: event.recoveryIntentDigest || null,
    keyLifecycleBindingDigest: event.keyLifecycleBindingDigest || null }));
  event.digest = sha256(canonical(Object.fromEntries(Object.entries(event).filter(([key]) => key !== "digest" && key !== "_storage"))));
  const ledgerUnsigned = { ...ledger, events, headDigest: events.at(-1).digest, eventCount: events.length };
  delete ledgerUnsigned.digest; delete ledgerUnsigned._storage;
  const candidate = { ...ledgerUnsigned, digest: sha256(canonical(ledgerUnsigned)) };
  await store.putEvidence(owner, candidate, { expectedVersion: ledger._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationReceipts(owner);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_FINALIZATION_RECONCILIATION_PERSISTED_POSTCONDITION_INVALID"));
});
