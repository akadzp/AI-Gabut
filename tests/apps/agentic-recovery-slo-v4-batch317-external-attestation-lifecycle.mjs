import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 317: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b317-empty");
  const audit = await app.auditRecoveryGateBatch317ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch317ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch316_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch317ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch317ExternalAttestationLifecycleAudit.status, "not_initialized");
});

test("Batch 317: invalid actions and challenge parameters are rejected before mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b317-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch317ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH317_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch317ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH317_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch317ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "A valid reason for lifecycle renewal", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH317_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch317ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 317: current Batch 316 external attestation is required before lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b317-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch317ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 316 external attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH317_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch317ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 317: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b317-wiring");
  assert.equal((await app.auditRecoveryGateBatch317ExternalAttestationLifecycle(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH317_INTENT_EVENT", "BATCH317_EVENT_TYPES", "batch317LifecycleBindingFields",
    "prepareBatch317ExternalAttestationLifecycle", "applyBatch317ExternalAttestationLifecycle",
    "auditBatch317ExternalAttestationLifecycle", "getBatch317ExternalAttestationLifecycleSnapshot",
    "reconcileBatch317ExternalAttestationLifecycle", "BATCH316_EVENT_TYPES", "BATCH315_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycleSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH317_EVENT_TYPES"), "independent checkpoint inventory includes Batch 317 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch317ExternalAttestationLifecycle", "applyRecoveryGateBatch317ExternalAttestationLifecycle",
    "auditRecoveryGateBatch317ExternalAttestationLifecycle", "getRecoveryGateBatch317ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch317ExternalAttestationLifecycle", "batch317ExternalAttestationLifecycleAudit",
    "batch317ExternalAttestationLifecycleRequired", "batch317ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch317ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch317ExternalAttestationLifecycleRoot = `${batch316ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch317ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 317: ledger schema validates lifecycle and receipt bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH317_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH304_EVENT_TYPES.includes(event.eventType)", start);
  assert.ok(start >= 0 && end > start, "Batch 317 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId",
    "reasonDigest", "signingKeyLifecycleBindingDigest", "intentEventId", "actionEventId", "replacementAttestationId",
    "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptId"])
    assert.ok(validator.includes(token), token);
});

test("Batch 317: source receipt and checkpoint bindings remain anchored to Batch 316 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch317LifecycleBindingFields");
  const end = core.indexOf("return Object.freeze({ getSnapshot", start);
  assert.ok(start >= 0 && end > start, "Batch 317 service block exists");
  const block = core.slice(start, end);
  for (const token of ["BATCH316_EVENT_TYPES", "BATCH315_RECEIPT_EVENT_TYPES", "auditExternalBatch315LifecycleFinalizationReceiptAttestations",
    "batch317ReceiptBindingFields", "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointState"])
    assert.ok(block.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const reconcileStart = application.indexOf("async function reconcileRecoveryGateBatch317ExternalAttestationLifecycle");
  const reconcileEnd = application.indexOf("async function prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle", reconcileStart);
  assert.ok(reconcileStart >= 0 && reconcileEnd > reconcileStart, "Batch 317 recovery wrapper exists");
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("reconcileRecoveryGateBatch316ExternalLifecycleFinalizationReceiptAttestations"));
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("advanceBatch210FinalizationCheckpoints"));
});
