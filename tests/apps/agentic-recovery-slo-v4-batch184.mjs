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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b184-${owner}-`));
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

test("Batch 184: lifecycle recovery receipt is attested, externally anchored, and bound to lifecycle plus reconciliation evidence", async t => {
  const context = await setupOwner(t, "b184-anchor");
  const { app, recovered, owner } = context;
  const { result } = await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  assert.ok(result.recoveryReceipt);
  assert.equal(result.recoveryReceipt.lifecycleEventDigest, result.lifecycleEvent.digest);
  assert.equal(result.recoveryReceipt.reconciliationReceiptDigest, result.reconciliationReceipt.digest);
  assert.equal(result.recoveryReceipt.attestation.kind,
    "recovery-slo-cross-domain-recovery-decision-gate-receipt-recovery-attestation-lifecycle-recovery-receipt-attestation");
  assert.equal(result.recoveryReceiptCheckpoint.status, "anchored");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.usableForCurrentDecision, true);
  assert.equal(audit.receiptCount, 1);
  const lifecycle = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner);
  assert.equal(lifecycle.status, "healthy");
});

test("Batch 184: external checkpoint write interruption is retried without duplicate lifecycle or recovery receipts", async t => {
  const context = await setupOwner(t, "b184-crash");
  const { app, recovered, owner, anchors } = context;
  anchors.lifecycleRecovery.failWrites = true;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Recover the pending external receipt after a transient provider write failure." });
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  let audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(audit.receiptCount, 1);
  assert.notEqual(audit.status, "healthy");
  anchors.lifecycleRecovery.failWrites = false;
  const retry = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(retry.status, "renewed");
  assert.equal(retry.idempotent, true);
  audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.receiptCount, 1);
});

test("Batch 184: checkpoint marker loss is inspectable and recoverable from the existing external anchor", async t => {
  const context = await setupOwner(t, "b184-marker");
  const { app, recovered, owner, storage } = context;
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const store = createAgenticStore({ storage });
  const markerId = `recovery-attestation-lifecycle-recovery-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointRecovery(owner);
  assert.equal(inspection.recoverable, true);
  const recoveredMarker = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpoint(owner);
  assert.equal(recoveredMarker.status, "recovered");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpoint(owner);
  assert.equal(audit.status, "healthy");
});

test("Batch 184: legacy missing recovery receipt is repaired only from matching persisted lifecycle and reconciliation evidence", async t => {
  const context = await setupOwner(t, "b184-repair", { lifecycleRecovery: false });
  const { app, recovered, owner, storage, anchors, keyOptions } = context;
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const store = createAgenticStore({ storage });
  const ledgerId = `decision-gate-attestation-lifecycle-recovery-receipts-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  assert.ok(ledger);
  await store.state.delete("evidence", `${owner}--${ledgerId}`, { expectedVersion: ledger._storage?.version });
  anchors.lifecycleRecovery = anchorProvider(`https://${owner}-lifecycle-recovery-repair.example`);
  const appWithRecoveryAnchor = makeApp(storage, keyOptions, anchors);
  await enrollLifecycleRecoveryCheckpoint(appWithRecoveryAnchor, owner);
  const before = await appWithRecoveryAnchor.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(before.status, "repair_required");
  const repaired = await appWithRecoveryAnchor.repairRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(repaired.repairedCount, 1);
  assert.equal(repaired.audit.status, "healthy");
  assert.equal(repaired.audit.receiptCount, 1);
});

test("Batch 184: key cutoff marks the latest recovery receipt stale and repair re-attests it under the active key", async t => {
  const context = await setupOwner(t, "b184-cutoff");
  const { app, recovered, owner } = context;
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  await rotateKey(app, owner);
  let audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(audit.status, "stale");
  assert.equal(audit.usableForCurrentDecision, false);
  const repaired = await app.repairRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(repaired.repairedCount, 1);
  assert.equal(repaired.audit.status, "healthy");
  assert.equal(repaired.audit.receiptCount, 2);
});

test("Batch 184: required external lifecycle recovery anchor must be configured and provider endpoints must be independent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b184-config-"));
  try {
    const storage = createStorage({ root });
    const { options: keyOptions } = keyMaterial();
    assert.throws(() => createAgenticApplication({ storage, ...keyOptions,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: true }), /belum dikonfigurasi/);
    const same = anchorProvider("https://same-anchor.example");
    assert.throws(() => makeApp(storage, keyOptions, { receipt: same, finalization: anchorProvider("https://f.example"),
      reconciliation: anchorProvider("https://r.example"), lifecycleRecovery: same }), /provider terpisah|endpoint external anchor yang berbeda/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("Batch 184: decision gate blocks lifecycle evidence while its required recovery receipt checkpoint is pending", async t => {
  const context = await setupOwner(t, "b184-gate");
  const { app, recovered, owner, anchors } = context;
  anchors.lifecycleRecovery.failWrites = true;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "revoke", reason: "Exercise fail-closed decision gating while lifecycle recovery receipt anchoring is pending." });
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner);
  assert.notEqual(lifecycleAudit.status, "healthy");
  assert.equal(lifecycleAudit.usableForCurrentDecision, false);
  assert.ok(lifecycleAudit.findings.some(item => item.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_RECOVERY_RECEIPT_NOT_CURRENT"));
});

test("Batch 184: recovery-receipt chain detects payload tampering even if local event and ledger digests are recomputed", async t => {
  const context = await setupOwner(t, "b184-tamper");
  const { app, recovered, owner, storage } = context;
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id, "revoke");
  const store = createAgenticStore({ storage });
  const ledgerId = `decision-gate-attestation-lifecycle-recovery-receipts-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const events = structuredClone(ledger.events);
  events[0].targetDigest = "f".repeat(64);
  events[0].digest = sha256(canonical(Object.fromEntries(Object.entries(events[0]).filter(([key]) => key !== "digest" && key !== "_storage"))));
  const unsigned = { ...ledger, events, headDigest: events.at(-1).digest, eventCount: events.length };
  delete unsigned.digest; delete unsigned._storage;
  const candidate = { ...unsigned, digest: sha256(canonical(unsigned)) };
  await store.putEvidence(owner, candidate, { expectedVersion: ledger._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts(owner);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => /CHAIN_INVALID|ATTESTATION_INVALID|BINDING_INVALID/.test(item.code)));
});

test("Batch 184: public API exposes lifecycle recovery-receipt audit, repair, enrollment, and marker recovery", async t => {
  const context = await setupOwner(t, "b184-api");
  const { app } = context;
  for (const name of [
    "auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts",
    "repairRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryReceipts",
    "getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointStatus",
    "reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpoint",
    "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointRecovery",
    "recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpoint"
  ]) assert.equal(typeof app[name], "function", `${name} must be exported`);
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "/attestation-lifecycle/recovery-receipts/audit",
    "/attestation-lifecycle/recovery-receipts/repair",
    "/attestation-lifecycle/recovery-checkpoint/status",
    "/attestation-lifecycle/recovery-checkpoint/reconcile",
    "/attestation-lifecycle/recovery-checkpoint/enrollments",
    "/attestation-lifecycle/recovery-checkpoint/audit",
    "/attestation-lifecycle/recovery-checkpoint/recovery/inspect",
    "/attestation-lifecycle/recovery-checkpoint/recovery"
  ]) assert.ok(serverSource.includes(route), `HTTP route ${route} must be wired`);
});
