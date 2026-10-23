import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 279: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b279-empty");
  const audit = await app.auditRecoveryGateBatch279ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch279ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch278_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch279ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch279ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch279ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 278 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH279_SOURCE_NOT_CURRENT");
  await assert.rejects(() => app.prepareRecoveryGateBatch279ExternalAttestationLifecycle(owner,
    { action: "reactivate", reason: "attempt an invalid lifecycle action" }),
    error => error?.code === "RECOVERY_GATE_BATCH279_ACTION_INVALID");
});

test("Batch 279: lifecycle requires a current Batch 278 external attestation and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b279-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch279ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 278 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH279_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH279_EVENT_TYPES", "BATCH279_LIFECYCLE_EVENT_TYPES", "BATCH279_RECEIPT_EVENT_TYPES",
    "prepareBatch279ExternalAttestationLifecycle", "applyBatch279ExternalAttestationLifecycle",
    "auditBatch279ExternalAttestationLifecycle", "getBatch279ExternalAttestationLifecycleSnapshot",
    "resumeBatch279ExternalAttestationLifecycle", "reconcileBatch279ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH279_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH279_REVOCATION_DESCENDANT_INVALID",
    "batch279LifecycleBindingFields", "cross_domain_batch278_external_attestation_lifecycle",
    "auditExternalBatch277LifecycleFinalizationReceiptAttestations", "BATCH278_EVENT_TYPES"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH279_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 279 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch279ExternalAttestationLifecycle", "applyRecoveryGateBatch279ExternalAttestationLifecycle",
    "auditRecoveryGateBatch279ExternalAttestationLifecycle", "getRecoveryGateBatch279ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch279ExternalAttestationLifecycle", "batch279ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch279ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch279ExternalAttestationLifecycleRoot = `${batch278ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch279ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 279: ledger schema rejects malformed lifecycle phases and targets only Batch 278 attestations", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("function batch279CurrentTarget(ledger)");
  const end = core.indexOf("async function prepareBatch279ExternalAttestationLifecycle", start);
  assert.ok(start >= 0 && end > start);
  assert.ok(core.slice(start, end).includes("BATCH278_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(core.slice(start, end).includes("BATCH279_RENEWED_EVENT"));
  const validationStart = core.indexOf("|| BATCH279_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["BATCH279_INTENT_EVENT", "BATCH279_SUPERSEDED_EVENT", "BATCH279_FINALIZED_EVENT", "BATCH279_RECEIPT_EVENT"])
    assert.ok(validator.includes(token), token);
});
