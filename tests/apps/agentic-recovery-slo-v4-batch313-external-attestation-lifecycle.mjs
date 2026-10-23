import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 313: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b313-empty");
  const audit = await app.auditRecoveryGateBatch313ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch313ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch312_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch313ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch313ExternalAttestationLifecycleAudit.status, "not_initialized");
});

test("Batch 313: invalid actions and challenge parameters are rejected before mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b313-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch313ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH313_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch313ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH313_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch313ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "A valid reason for lifecycle renewal", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH313_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch313ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 313: current Batch 312 external attestation is required before lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b313-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch313ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 312 external attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH313_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch313ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 313: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b313-wiring");
  assert.equal((await app.auditRecoveryGateBatch313ExternalAttestationLifecycle(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH313_INTENT_EVENT", "BATCH313_EVENT_TYPES", "batch313LifecycleBindingFields",
    "prepareBatch313ExternalAttestationLifecycle", "applyBatch313ExternalAttestationLifecycle",
    "auditBatch313ExternalAttestationLifecycle", "getBatch313ExternalAttestationLifecycleSnapshot",
    "reconcileBatch313ExternalAttestationLifecycle", "BATCH312_EVENT_TYPES", "BATCH311_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycleSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH313_EVENT_TYPES"), "independent checkpoint inventory includes Batch 313 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch313ExternalAttestationLifecycle", "applyRecoveryGateBatch313ExternalAttestationLifecycle",
    "auditRecoveryGateBatch313ExternalAttestationLifecycle", "getRecoveryGateBatch313ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch313ExternalAttestationLifecycle", "batch313ExternalAttestationLifecycleAudit",
    "batch313ExternalAttestationLifecycleRequired", "batch313ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch313ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch313ExternalAttestationLifecycleRoot = `${batch312ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch313ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 313: ledger schema validates lifecycle and receipt bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH313_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH304_EVENT_TYPES.includes(event.eventType)", start);
  assert.ok(start >= 0 && end > start, "Batch 313 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId",
    "reasonDigest", "signingKeyLifecycleBindingDigest", "intentEventId", "actionEventId", "replacementAttestationId",
    "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptId"])
    assert.ok(validator.includes(token), token);
});

test("Batch 313: source receipt and checkpoint bindings remain anchored to Batch 312 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch313LifecycleBindingFields");
  const end = core.indexOf("return Object.freeze({ getSnapshot", start);
  assert.ok(start >= 0 && end > start, "Batch 313 service block exists");
  const block = core.slice(start, end);
  for (const token of ["BATCH312_EVENT_TYPES", "BATCH311_RECEIPT_EVENT_TYPES", "auditExternalBatch311LifecycleFinalizationReceiptAttestations",
    "batch313ReceiptBindingFields", "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointState"])
    assert.ok(block.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const reconcileStart = application.indexOf("async function reconcileRecoveryGateBatch313ExternalAttestationLifecycle");
  const reconcileEnd = application.indexOf("async function prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle", reconcileStart);
  assert.ok(reconcileStart >= 0 && reconcileEnd > reconcileStart, "Batch 313 recovery wrapper exists");
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("reconcileRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations"));
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("advanceBatch210FinalizationCheckpoints"));
});
