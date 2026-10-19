import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations/lifecycle";

test("Batch 247: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b247-empty");
  const audit = await app.auditRecoveryGateBatch247ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch247ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch246_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch247ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch247ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch247ExternalAttestationLifecycle(owner,
    { action: "activate", reason: "test reason for lifecycle" }), /renew.*revoke/i);
});

test("Batch 247: lifecycle requires current Batch 246 external attestation and exposes owner-scoped API routes", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b247-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch247ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew external attestation with source proof" }), error => error?.code === "RECOVERY_GATE_BATCH247_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH247_EVENT_TYPES", "BATCH247_LIFECYCLE_EVENT_TYPES", "BATCH247_RECEIPT_EVENT_TYPES",
    "prepareBatch247ExternalAttestationLifecycle", "applyBatch247ExternalAttestationLifecycle",
    "auditBatch247ExternalAttestationLifecycle", "getBatch247ExternalAttestationLifecycleSnapshot",
    "resumeBatch247ExternalAttestationLifecycle", "reconcileBatch247ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH247_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH247_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_batch246_external_attestation_lifecycle"
  ]) assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH247_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 247 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch247ExternalAttestationLifecycle", "applyRecoveryGateBatch247ExternalAttestationLifecycle",
    "auditRecoveryGateBatch247ExternalAttestationLifecycle", "getRecoveryGateBatch247ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch247ExternalAttestationLifecycle", "batch247ExternalAttestationLifecycleAudit"]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch247ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("`${batch246ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const suffix of ["prepare", "apply", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
