import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 321: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b321-empty");
  const audit = await app.auditRecoveryGateBatch321ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch321ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch320_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch321ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch321ExternalAttestationLifecycleAudit.status, "not_initialized");
});

test("Batch 321: invalid actions and challenge parameters are rejected before mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b321-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch321ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH321_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch321ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH321_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch321ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "A valid reason for lifecycle renewal", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH321_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch321ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 321: current Batch 320 external attestation is required before lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b321-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch321ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 320 external attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH321_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch321ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 321: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b321-wiring");
  assert.equal((await app.auditRecoveryGateBatch321ExternalAttestationLifecycle(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH321_INTENT_EVENT", "BATCH321_EVENT_TYPES", "batch321LifecycleBindingFields",
    "prepareBatch321ExternalAttestationLifecycle", "applyBatch321ExternalAttestationLifecycle",
    "auditBatch321ExternalAttestationLifecycle", "getBatch321ExternalAttestationLifecycleSnapshot",
    "reconcileBatch321ExternalAttestationLifecycle", "BATCH320_EVENT_TYPES", "BATCH319_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycleSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH321_EVENT_TYPES"), "independent checkpoint inventory includes Batch 321 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch321ExternalAttestationLifecycle", "applyRecoveryGateBatch321ExternalAttestationLifecycle",
    "auditRecoveryGateBatch321ExternalAttestationLifecycle", "getRecoveryGateBatch321ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch321ExternalAttestationLifecycle", "batch321ExternalAttestationLifecycleAudit",
    "batch321ExternalAttestationLifecycleRequired", "batch321ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch321ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch321ExternalAttestationLifecycleRoot = `${batch320ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch321ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 321: ledger schema validates lifecycle and receipt bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH321_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH304_EVENT_TYPES.includes(event.eventType)", start);
  assert.ok(start >= 0 && end > start, "Batch 321 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId",
    "reasonDigest", "signingKeyLifecycleBindingDigest", "intentEventId", "actionEventId", "replacementAttestationId",
    "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptId"])
    assert.ok(validator.includes(token), token);
});

test("Batch 321: source receipt and checkpoint bindings remain anchored to Batch 320 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch321LifecycleBindingFields");
  const end = core.indexOf("return Object.freeze({ getSnapshot", start);
  assert.ok(start >= 0 && end > start, "Batch 321 service block exists");
  const block = core.slice(start, end);
  for (const token of ["BATCH320_EVENT_TYPES", "BATCH319_RECEIPT_EVENT_TYPES", "auditExternalBatch319LifecycleFinalizationReceiptAttestations",
    "batch321ReceiptBindingFields", "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointState"])
    assert.ok(block.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const reconcileStart = application.indexOf("async function reconcileRecoveryGateBatch321ExternalAttestationLifecycle");
  const reconcileEnd = application.indexOf("async function prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle", reconcileStart);
  assert.ok(reconcileStart >= 0 && reconcileEnd > reconcileStart, "Batch 321 recovery wrapper exists");
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("reconcileRecoveryGateBatch320ExternalLifecycleFinalizationReceiptAttestations"));
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("advanceBatch210FinalizationCheckpoints"));
});
