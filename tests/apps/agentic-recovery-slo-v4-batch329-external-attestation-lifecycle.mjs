import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 329: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b329-empty");
  const audit = await app.auditRecoveryGateBatch329ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch329ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch328_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch329ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch329ExternalAttestationLifecycleAudit.status, "not_initialized");
});

test("Batch 329: invalid actions and challenge parameters are rejected before mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b329-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch329ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH329_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch329ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH329_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch329ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 328 attestation", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH329_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch329ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 329: current Batch 328 external attestation is required before lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b329-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch329ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 328 external attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH329_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch329ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 329: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b329-wiring");
  assert.equal((await app.auditRecoveryGateBatch329ExternalAttestationLifecycle(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH329_INTENT_EVENT", "BATCH329_EVENT_TYPES", "batch329LifecycleBindingFields",
    "prepareBatch329ExternalAttestationLifecycle", "applyBatch329ExternalAttestationLifecycle",
    "auditBatch329ExternalAttestationLifecycle", "getBatch329ExternalAttestationLifecycleSnapshot",
    "reconcileBatch329ExternalAttestationLifecycle", "BATCH328_EVENT_TYPES", "BATCH329_EVENT_TYPES",
    "BATCH327_RECEIPT_EVENT_TYPES", "BATCH329_FINALIZED_EVENT"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart, "independent checkpoint snapshot function exists");
  assert.ok(core.slice(checkpointStart, checkpointEnd).includes("BATCH329_EVENT_TYPES"), "checkpoint snapshot inventories Batch 329 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch329ExternalAttestationLifecycle", "applyRecoveryGateBatch329ExternalAttestationLifecycle",
    "auditRecoveryGateBatch329ExternalAttestationLifecycle", "getRecoveryGateBatch329ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch329ExternalAttestationLifecycle", "batch329ExternalAttestationLifecycleAudit",
    "batch329ExternalAttestationLifecycleRequired", "batch329ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch329ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch329ExternalAttestationLifecycleRoot = `${batch328ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch329ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 329: ledger schema validates lifecycle and finalization receipt bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH329_EVENT_TYPES.includes(event.eventType) && (");
  assert.ok(start >= 0, "Batch 329 schema validator branch exists");
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId",
    "reasonDigest", "signingKeyLifecycleBindingDigest", "intentEventId", "actionEventId", "replacementAttestationId",
    "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptId"])
    assert.ok(core.includes(token), token);
});

test("Batch 329: source receipt and checkpoint bindings remain anchored to Batch 328 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch329LifecycleBindingFields");
  const end = core.indexOf("return Object.freeze({ getSnapshot", start);
  assert.ok(start >= 0 && end > start, "Batch 329 service block exists");
  const block = core.slice(start, end);
  for (const token of ["BATCH328_EVENT_TYPES", "BATCH329_EVENT_TYPES", "auditExternalBatch327LifecycleFinalizationReceiptAttestations",
    "batch329ReceiptBindingFields", "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointState"])
    assert.ok(block.includes(token), token);
  assert.ok(block.includes("BATCH327_RECEIPT_EVENT_TYPES.includes(event.eventType)"), "source lifecycle receipt is validated against Batch 327");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const reconcileStart = application.indexOf("async function reconcileRecoveryGateBatch329ExternalAttestationLifecycle");
  const reconcileEnd = application.indexOf("async function prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle", reconcileStart);
  assert.ok(reconcileStart >= 0 && reconcileEnd > reconcileStart, "Batch 329 recovery wrapper exists");
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("reconcileRecoveryGateBatch328ExternalLifecycleFinalizationReceiptAttestations"));
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("advanceBatch210FinalizationCheckpoints"));
});
