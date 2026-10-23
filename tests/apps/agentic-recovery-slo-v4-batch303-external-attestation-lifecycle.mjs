import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 303: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b303-empty");
  const audit = await app.auditRecoveryGateBatch303ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch303ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch302_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch303ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch303ExternalAttestationLifecycleAudit.status, "not_initialized");
  assert.equal(globalAudit.status, "not_initialized");
});

test("Batch 303: invalid actions and challenge parameters are rejected before mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b303-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch303ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH303_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch303ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH303_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch303ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "A valid reason for lifecycle renewal", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH303_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch303ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 303: current Batch 302 attestation source is required before lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b303-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch303ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current Batch 302 attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH303_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch303ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 303: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b303-wiring");
  assert.equal((await app.auditRecoveryGateBatch303ExternalAttestationLifecycle(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH303_INTENT_EVENT", "BATCH303_EVENT_TYPES", "batch303LifecycleBindingFields",
    "prepareBatch303ExternalAttestationLifecycle", "applyBatch303ExternalAttestationLifecycle",
    "auditBatch303ExternalAttestationLifecycle", "getBatch303ExternalAttestationLifecycleSnapshot",
    "reconcileBatch303ExternalAttestationLifecycle", "BATCH302_EVENT_TYPES", "BATCH301_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH303_EVENT_TYPES"), "independent checkpoint snapshot includes Batch 303 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch303ExternalAttestationLifecycle", "applyRecoveryGateBatch303ExternalAttestationLifecycle",
    "auditRecoveryGateBatch303ExternalAttestationLifecycle", "getRecoveryGateBatch303ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch303ExternalAttestationLifecycle", "batch303ExternalAttestationLifecycleAudit",
    "batch303ExternalAttestationLifecycleRequired", "batch303ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch303ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch303ExternalAttestationLifecycleRoot = `${batch302ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch303ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 303: ledger schema validates lifecycle and receipt bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH303_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 303 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId",
    "reasonDigest", "signingKeyLifecycleBindingDigest", "intentEventId", "actionEventId", "replacementAttestationId",
    "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptId"])
    assert.ok(validator.includes(token), token);
});
