import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 323: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b323-empty");
  const audit = await app.auditRecoveryGateBatch323ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch323ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch322_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch323ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch323ExternalAttestationLifecycleAudit.status, "not_initialized");
});

test("Batch 323: invalid actions and challenge parameters are rejected before mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b323-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch323ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH323_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch323ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH323_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch323ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "A valid reason for lifecycle renewal", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH323_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch323ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 323: current Batch 322 external attestation is required before lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b323-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch323ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 322 external attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH323_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch323ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 323: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b323-wiring");
  assert.equal((await app.auditRecoveryGateBatch323ExternalAttestationLifecycle(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH323_INTENT_EVENT", "BATCH323_EVENT_TYPES", "batch323LifecycleBindingFields",
    "prepareBatch323ExternalAttestationLifecycle", "applyBatch323ExternalAttestationLifecycle",
    "auditBatch323ExternalAttestationLifecycle", "getBatch323ExternalAttestationLifecycleSnapshot",
    "reconcileBatch323ExternalAttestationLifecycle", "BATCH322_EVENT_TYPES", "BATCH321_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycleSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH323_EVENT_TYPES"), "independent checkpoint inventory includes Batch 323 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch323ExternalAttestationLifecycle", "applyRecoveryGateBatch323ExternalAttestationLifecycle",
    "auditRecoveryGateBatch323ExternalAttestationLifecycle", "getRecoveryGateBatch323ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch323ExternalAttestationLifecycle", "batch323ExternalAttestationLifecycleAudit",
    "batch323ExternalAttestationLifecycleRequired", "batch323ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch323ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch323ExternalAttestationLifecycleRoot = `${batch322ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch323ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 323: ledger schema validates lifecycle and receipt bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH323_EVENT_TYPES.includes(event.eventType) && (");
  assert.ok(start >= 0, "Batch 323 schema validator branch exists");
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId",
    "reasonDigest", "signingKeyLifecycleBindingDigest", "intentEventId", "actionEventId", "replacementAttestationId",
    "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptId"])
    assert.ok(core.includes(token), token);
});

test("Batch 323: source receipt and checkpoint bindings remain anchored to Batch 322 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch323LifecycleBindingFields");
  const end = core.indexOf("return Object.freeze({ getSnapshot", start);
  assert.ok(start >= 0 && end > start, "Batch 323 service block exists");
  const block = core.slice(start, end);
  for (const token of ["BATCH322_EVENT_TYPES", "BATCH321_RECEIPT_EVENT_TYPES", "auditExternalBatch321LifecycleFinalizationReceiptAttestations",
    "batch323ReceiptBindingFields", "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointState"])
    assert.ok(block.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const reconcileStart = application.indexOf("async function reconcileRecoveryGateBatch323ExternalAttestationLifecycle");
  const reconcileEnd = application.indexOf("async function prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle", reconcileStart);
  assert.ok(reconcileStart >= 0 && reconcileEnd > reconcileStart, "Batch 323 recovery wrapper exists");
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("reconcileRecoveryGateBatch322ExternalLifecycleFinalizationReceiptAttestations"));
  assert.ok(application.slice(reconcileStart, reconcileEnd).includes("advanceBatch210FinalizationCheckpoints"));
});
