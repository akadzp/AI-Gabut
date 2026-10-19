import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 263: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b262-empty");
  const audit = await app.auditRecoveryGateBatch263ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch263ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch262_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch263ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch263ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch263ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 262 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH263_SOURCE_NOT_CURRENT");
});

test("Batch 263: lifecycle requires current Batch 262 external attestation and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b262-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch263ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 262 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH263_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH263_EVENT_TYPES", "BATCH263_LIFECYCLE_EVENT_TYPES", "BATCH263_RECEIPT_EVENT_TYPES",
    "prepareBatch263ExternalAttestationLifecycle", "applyBatch263ExternalAttestationLifecycle",
    "auditBatch263ExternalAttestationLifecycle", "getBatch263ExternalAttestationLifecycleSnapshot",
    "resumeBatch263ExternalAttestationLifecycle", "reconcileBatch263ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH263_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH263_REVOCATION_DESCENDANT_INVALID", "batch263LifecycleBindingFields",
    "cross_domain_batch262_external_attestation_lifecycle", "auditExternalBatch261LifecycleFinalizationReceiptAttestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH263_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 263 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch263ExternalAttestationLifecycle", "applyRecoveryGateBatch263ExternalAttestationLifecycle",
    "auditRecoveryGateBatch263ExternalAttestationLifecycle", "getRecoveryGateBatch263ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch263ExternalAttestationLifecycle", "batch263ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch263ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("`${batch262ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch263ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 263: ledger schema rejects invalid lifecycle phases and target must be a Batch 262 attestation", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch263CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch263ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH262_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH263_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH263_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH263_INTENT_EVENT", "BATCH263_SUPERSEDED_EVENT", "BATCH263_FINALIZED_EVENT", "BATCH263_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
