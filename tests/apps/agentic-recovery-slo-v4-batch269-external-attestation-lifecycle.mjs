import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 269: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b268-empty");
  const audit = await app.auditRecoveryGateBatch269ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch269ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch268_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch269ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch269ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch269ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 268 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH269_SOURCE_NOT_CURRENT");
});

test("Batch 269: lifecycle requires a current Batch 268 external attestation and wires owner-scoped checkpoint-aware APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b268-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch269ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 268 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH269_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH269_EVENT_TYPES", "BATCH269_LIFECYCLE_EVENT_TYPES", "BATCH269_RECEIPT_EVENT_TYPES",
    "prepareBatch269ExternalAttestationLifecycle", "applyBatch269ExternalAttestationLifecycle",
    "auditBatch269ExternalAttestationLifecycle", "getBatch269ExternalAttestationLifecycleSnapshot",
    "resumeBatch269ExternalAttestationLifecycle", "reconcileBatch269ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH269_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH269_REVOCATION_DESCENDANT_INVALID",
    "batch269LifecycleBindingFields", "cross_domain_batch268_external_attestation_lifecycle",
    "auditExternalBatch267LifecycleFinalizationReceiptAttestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH269_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 269 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch269ExternalAttestationLifecycle", "applyRecoveryGateBatch269ExternalAttestationLifecycle",
    "auditRecoveryGateBatch269ExternalAttestationLifecycle", "getRecoveryGateBatch269ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch269ExternalAttestationLifecycle", "batch269ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch269ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch269ExternalAttestationLifecycleRoot = `${batch268ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch269ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 269: ledger schema rejects malformed lifecycle phases and targets only Batch 268 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch269CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch269ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH268_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH269_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH269_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH269_INTENT_EVENT", "BATCH269_SUPERSEDED_EVENT", "BATCH269_FINALIZED_EVENT", "BATCH269_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
