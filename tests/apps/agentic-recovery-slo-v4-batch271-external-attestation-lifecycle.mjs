import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 271: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b270-empty");
  const audit = await app.auditRecoveryGateBatch271ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch271ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch270_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch271ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch271ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch271ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 270 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH271_SOURCE_NOT_CURRENT");
  await assert.rejects(() => app.prepareRecoveryGateBatch271ExternalAttestationLifecycle(owner,
    { action: "reactivate", reason: "attempt an invalid lifecycle action" }),
    error => error?.code === "RECOVERY_GATE_BATCH271_ACTION_INVALID");
});

test("Batch 271: lifecycle requires a current Batch 270 external attestation and wires owner-scoped checkpoint-aware APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b270-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch271ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 270 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH271_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH271_EVENT_TYPES", "BATCH271_LIFECYCLE_EVENT_TYPES", "BATCH271_RECEIPT_EVENT_TYPES",
    "prepareBatch271ExternalAttestationLifecycle", "applyBatch271ExternalAttestationLifecycle",
    "auditBatch271ExternalAttestationLifecycle", "getBatch271ExternalAttestationLifecycleSnapshot",
    "resumeBatch271ExternalAttestationLifecycle", "reconcileBatch271ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH271_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH271_REVOCATION_DESCENDANT_INVALID",
    "batch271LifecycleBindingFields", "cross_domain_batch270_external_attestation_lifecycle",
    "auditExternalBatch269LifecycleFinalizationReceiptAttestations", "BATCH269_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH271_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 271 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch271ExternalAttestationLifecycle", "applyRecoveryGateBatch271ExternalAttestationLifecycle",
    "auditRecoveryGateBatch271ExternalAttestationLifecycle", "getRecoveryGateBatch271ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch271ExternalAttestationLifecycle", "batch271ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch271ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch271ExternalAttestationLifecycleRoot = `${batch270ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch271ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 271: ledger schema rejects malformed lifecycle phases and targets only Batch 270 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch271CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch271ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH270_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH271_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH271_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH271_INTENT_EVENT", "BATCH271_SUPERSEDED_EVENT", "BATCH271_FINALIZED_EVENT", "BATCH271_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
