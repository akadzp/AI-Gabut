import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 305: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b305-empty");
  const audit = await app.auditRecoveryGateBatch305ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch305ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch304_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch305ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch305ExternalAttestationLifecycleAudit.status, "not_initialized");
  assert.equal(globalAudit.status, "not_initialized");
});

test("Batch 305: invalid actions and challenge parameters are rejected before mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b305-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch305ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH305_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch305ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH305_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch305ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "A valid reason for lifecycle renewal", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH305_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch305ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 305: current Batch 304 attestation source is required before lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b305-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch305ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 304 attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH305_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch305ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 305: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b305-wiring");
  assert.equal((await app.auditRecoveryGateBatch305ExternalAttestationLifecycle(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH305_INTENT_EVENT", "BATCH305_EVENT_TYPES", "batch305LifecycleBindingFields",
    "prepareBatch305ExternalAttestationLifecycle", "applyBatch305ExternalAttestationLifecycle",
    "auditBatch305ExternalAttestationLifecycle", "getBatch305ExternalAttestationLifecycleSnapshot",
    "reconcileBatch305ExternalAttestationLifecycle", "BATCH304_EVENT_TYPES", "BATCH303_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH305_EVENT_TYPES"), "independent checkpoint snapshot includes Batch 305 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch305ExternalAttestationLifecycle", "applyRecoveryGateBatch305ExternalAttestationLifecycle",
    "auditRecoveryGateBatch305ExternalAttestationLifecycle", "getRecoveryGateBatch305ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch305ExternalAttestationLifecycle", "batch305ExternalAttestationLifecycleAudit",
    "batch305ExternalAttestationLifecycleRequired", "batch305ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch305ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch305ExternalAttestationLifecycleRoot = `${batch304ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch305ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 305: ledger schema validates lifecycle and receipt bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH305_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH304_EVENT_TYPES.includes(event.eventType)", start);
  assert.ok(start >= 0 && end > start, "Batch 305 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId",
    "reasonDigest", "signingKeyLifecycleBindingDigest", "intentEventId", "actionEventId", "replacementAttestationId",
    "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptId"])
    assert.ok(validator.includes(token), token);
});
