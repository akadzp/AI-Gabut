import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 267: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b266-empty");
  const audit = await app.auditRecoveryGateBatch267ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch267ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch266_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch267ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch267ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch267ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 266 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH267_SOURCE_NOT_CURRENT");
});

test("Batch 267: lifecycle requires current Batch 266 external attestation and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b266-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch267ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 266 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH267_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH267_EVENT_TYPES", "BATCH267_LIFECYCLE_EVENT_TYPES", "BATCH267_RECEIPT_EVENT_TYPES",
    "prepareBatch267ExternalAttestationLifecycle", "applyBatch267ExternalAttestationLifecycle",
    "auditBatch267ExternalAttestationLifecycle", "getBatch267ExternalAttestationLifecycleSnapshot",
    "resumeBatch267ExternalAttestationLifecycle", "reconcileBatch267ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH267_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH267_REVOCATION_DESCENDANT_INVALID", "batch267LifecycleBindingFields",
    "cross_domain_batch266_external_attestation_lifecycle", "auditExternalBatch265LifecycleFinalizationReceiptAttestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH267_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 267 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch267ExternalAttestationLifecycle", "applyRecoveryGateBatch267ExternalAttestationLifecycle",
    "auditRecoveryGateBatch267ExternalAttestationLifecycle", "getRecoveryGateBatch267ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch267ExternalAttestationLifecycle", "batch267ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch267ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("`${batch266ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch267ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 267: ledger schema rejects invalid lifecycle phases and target must be a Batch 266 attestation", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch267CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch267ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH266_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH267_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH267_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH267_INTENT_EVENT", "BATCH267_SUPERSEDED_EVENT", "BATCH267_FINALIZED_EVENT", "BATCH267_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
