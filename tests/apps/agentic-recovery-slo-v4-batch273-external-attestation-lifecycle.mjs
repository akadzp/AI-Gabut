import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 273: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b270-empty");
  const audit = await app.auditRecoveryGateBatch273ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch273ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch272_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch273ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch273ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch273ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 272 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH273_SOURCE_NOT_CURRENT");
  await assert.rejects(() => app.prepareRecoveryGateBatch273ExternalAttestationLifecycle(owner,
    { action: "reactivate", reason: "attempt an invalid lifecycle action" }),
    error => error?.code === "RECOVERY_GATE_BATCH273_ACTION_INVALID");
});

test("Batch 273: lifecycle requires a current Batch 272 external attestation and wires owner-scoped checkpoint-aware APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b270-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch273ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 272 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH273_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH273_EVENT_TYPES", "BATCH273_LIFECYCLE_EVENT_TYPES", "BATCH273_RECEIPT_EVENT_TYPES",
    "prepareBatch273ExternalAttestationLifecycle", "applyBatch273ExternalAttestationLifecycle",
    "auditBatch273ExternalAttestationLifecycle", "getBatch273ExternalAttestationLifecycleSnapshot",
    "resumeBatch273ExternalAttestationLifecycle", "reconcileBatch273ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH273_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH273_REVOCATION_DESCENDANT_INVALID",
    "batch273LifecycleBindingFields", "cross_domain_batch272_external_attestation_lifecycle",
    "auditExternalBatch271LifecycleFinalizationReceiptAttestations", "BATCH271_RECEIPT_EVENT_TYPES"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH273_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 273 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch273ExternalAttestationLifecycle", "applyRecoveryGateBatch273ExternalAttestationLifecycle",
    "auditRecoveryGateBatch273ExternalAttestationLifecycle", "getRecoveryGateBatch273ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch273ExternalAttestationLifecycle", "batch273ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch273ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch273ExternalAttestationLifecycleRoot = `${batch272ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch273ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 273: ledger schema rejects malformed lifecycle phases and targets only Batch 272 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch273CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch273ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH272_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH273_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH273_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH273_INTENT_EVENT", "BATCH273_SUPERSEDED_EVENT", "BATCH273_FINALIZED_EVENT", "BATCH273_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
