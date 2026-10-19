import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 259: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b257-empty");
  const audit = await app.auditRecoveryGateBatch259ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch259ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch258_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch259ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch259ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch259ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 258 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH259_SOURCE_NOT_CURRENT");
});

test("Batch 259: lifecycle requires current Batch 258 external attestation and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b257-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch259ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 258 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH259_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH259_EVENT_TYPES", "BATCH259_LIFECYCLE_EVENT_TYPES", "BATCH259_RECEIPT_EVENT_TYPES",
    "prepareBatch259ExternalAttestationLifecycle", "applyBatch259ExternalAttestationLifecycle",
    "auditBatch259ExternalAttestationLifecycle", "getBatch259ExternalAttestationLifecycleSnapshot",
    "resumeBatch259ExternalAttestationLifecycle", "reconcileBatch259ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH259_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH259_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_batch258_external_attestation_lifecycle", "auditExternalBatch257LifecycleFinalizationReceiptAttestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH259_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 259 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch259ExternalAttestationLifecycle", "applyRecoveryGateBatch259ExternalAttestationLifecycle",
    "auditRecoveryGateBatch259ExternalAttestationLifecycle", "getRecoveryGateBatch259ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch259ExternalAttestationLifecycle", "batch259ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch259ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("`${batch258ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch259ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 259: ledger schema rejects invalid lifecycle phases and the target must be a Batch 258 attestation", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch259CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch259ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH258_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH259_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH259_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH259_INTENT_EVENT", "BATCH259_SUPERSEDED_EVENT", "BATCH259_FINALIZED_EVENT", "BATCH259_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
