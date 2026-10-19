import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 265: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b264-empty");
  const audit = await app.auditRecoveryGateBatch265ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch265ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch264_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch265ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch265ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch265ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 264 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH265_SOURCE_NOT_CURRENT");
});

test("Batch 265: lifecycle requires current Batch 264 external attestation and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b264-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch265ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 264 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH265_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH265_EVENT_TYPES", "BATCH265_LIFECYCLE_EVENT_TYPES", "BATCH265_RECEIPT_EVENT_TYPES",
    "prepareBatch265ExternalAttestationLifecycle", "applyBatch265ExternalAttestationLifecycle",
    "auditBatch265ExternalAttestationLifecycle", "getBatch265ExternalAttestationLifecycleSnapshot",
    "resumeBatch265ExternalAttestationLifecycle", "reconcileBatch265ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH265_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH265_REVOCATION_DESCENDANT_INVALID", "batch265LifecycleBindingFields",
    "cross_domain_batch264_external_attestation_lifecycle", "auditExternalBatch263LifecycleFinalizationReceiptAttestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH265_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 265 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch265ExternalAttestationLifecycle", "applyRecoveryGateBatch265ExternalAttestationLifecycle",
    "auditRecoveryGateBatch265ExternalAttestationLifecycle", "getRecoveryGateBatch265ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch265ExternalAttestationLifecycle", "batch265ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch265ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("`${batch264ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch265ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 265: ledger schema rejects invalid lifecycle phases and target must be a Batch 264 attestation", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch265CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch265ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH264_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH265_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH265_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH265_INTENT_EVENT", "BATCH265_SUPERSEDED_EVENT", "BATCH265_FINALIZED_EVENT", "BATCH265_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
