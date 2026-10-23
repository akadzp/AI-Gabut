import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 283: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b283-empty");
  const audit = await app.auditRecoveryGateBatch283ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch283ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch282_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch283ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch283ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch283ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 282 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH283_SOURCE_NOT_CURRENT");
  await assert.rejects(() => app.prepareRecoveryGateBatch283ExternalAttestationLifecycle(owner,
    { action: "reactivate", reason: "attempt an invalid lifecycle action" }),
    error => error?.code === "RECOVERY_GATE_BATCH283_ACTION_INVALID");
});

test("Batch 283: lifecycle requires a current Batch 282 external attestation and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b283-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch283ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 282 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH283_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH283_EVENT_TYPES", "BATCH283_LIFECYCLE_EVENT_TYPES", "BATCH283_RECEIPT_EVENT_TYPES",
    "prepareBatch283ExternalAttestationLifecycle", "applyBatch283ExternalAttestationLifecycle",
    "auditBatch283ExternalAttestationLifecycle", "getBatch283ExternalAttestationLifecycleSnapshot",
    "resumeBatch283ExternalAttestationLifecycle", "reconcileBatch283ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH283_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH283_REVOCATION_DESCENDANT_INVALID",
    "batch283LifecycleBindingFields", "cross_domain_batch282_external_attestation_lifecycle",
    "auditExternalBatch279LifecycleFinalizationReceiptAttestations", "BATCH282_EVENT_TYPES"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH283_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 283 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch283ExternalAttestationLifecycle", "applyRecoveryGateBatch283ExternalAttestationLifecycle",
    "auditRecoveryGateBatch283ExternalAttestationLifecycle", "getRecoveryGateBatch283ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch283ExternalAttestationLifecycle", "batch283ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch283ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch283ExternalAttestationLifecycleRoot = `${batch282ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch283ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 283: ledger schema rejects malformed lifecycle phases and targets only Batch 282 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch283CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch283ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH282_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH283_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH283_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH283_INTENT_EVENT", "BATCH283_SUPERSEDED_EVENT", "BATCH283_FINALIZED_EVENT", "BATCH283_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
