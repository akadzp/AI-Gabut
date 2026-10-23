import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 277: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b277-empty");
  const audit = await app.auditRecoveryGateBatch277ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch277ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch276_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch277ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch277ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch277ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 276 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH277_SOURCE_NOT_CURRENT");
  await assert.rejects(() => app.prepareRecoveryGateBatch277ExternalAttestationLifecycle(owner,
    { action: "reactivate", reason: "attempt an invalid lifecycle action" }),
    error => error?.code === "RECOVERY_GATE_BATCH277_ACTION_INVALID");
});

test("Batch 277: lifecycle requires a current Batch 276 external attestation and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b277-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch277ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 276 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH277_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH277_EVENT_TYPES", "BATCH277_LIFECYCLE_EVENT_TYPES", "BATCH277_RECEIPT_EVENT_TYPES",
    "prepareBatch277ExternalAttestationLifecycle", "applyBatch277ExternalAttestationLifecycle",
    "auditBatch277ExternalAttestationLifecycle", "getBatch277ExternalAttestationLifecycleSnapshot",
    "resumeBatch277ExternalAttestationLifecycle", "reconcileBatch277ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH277_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH277_REVOCATION_DESCENDANT_INVALID",
    "batch277LifecycleBindingFields", "cross_domain_batch276_external_attestation_lifecycle",
    "auditExternalBatch275LifecycleFinalizationReceiptAttestations", "BATCH276_EVENT_TYPES"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH277_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 277 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch277ExternalAttestationLifecycle", "applyRecoveryGateBatch277ExternalAttestationLifecycle",
    "auditRecoveryGateBatch277ExternalAttestationLifecycle", "getRecoveryGateBatch277ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch277ExternalAttestationLifecycle", "batch277ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch277ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch277ExternalAttestationLifecycleRoot = `${batch276ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch277ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 277: ledger schema rejects malformed lifecycle phases and targets only Batch 276 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch277CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch277ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH276_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH277_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH277_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH277_INTENT_EVENT", "BATCH277_SUPERSEDED_EVENT", "BATCH277_FINALIZED_EVENT", "BATCH277_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
