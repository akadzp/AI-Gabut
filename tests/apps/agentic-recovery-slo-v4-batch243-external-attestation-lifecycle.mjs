import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/lifecycle";

test("Batch 243: empty lifecycle history is read-only and cannot fabricate a receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b243-empty");
  const audit = await app.auditRecoveryGateBatch243ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch243ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch242_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch243ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch243ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch243ExternalAttestationLifecycle(owner,
    { action: "activate", reason: "test reason for lifecycle" }), /renew or revoke|renew|revoke/i);
});

test("Batch 243: lifecycle requires a current Batch 242 source and exposes receipt, checkpoint, and owner-scoped routes", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b243-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch243ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew external attestation with source proof" }), error => error?.code === "RECOVERY_GATE_BATCH243_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH243_EVENT_TYPES", "BATCH243_LIFECYCLE_EVENT_TYPES", "BATCH243_RECEIPT_EVENT_TYPES",
    "prepareBatch243ExternalAttestationLifecycle", "applyBatch243ExternalAttestationLifecycle",
    "auditBatch243ExternalAttestationLifecycle", "getBatch243ExternalAttestationLifecycleSnapshot",
    "resumeBatch243ExternalAttestationLifecycle", "reconcileBatch243ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH243_RECEIPT_MISSING", "RECOVERY_GATE_BATCH243_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_batch242_external_attestation_lifecycle"
  ]) assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH243_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 243 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch243ExternalAttestationLifecycle", "applyRecoveryGateBatch243ExternalAttestationLifecycle",
    "auditRecoveryGateBatch243ExternalAttestationLifecycle", "getRecoveryGateBatch243ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch243ExternalAttestationLifecycle", "batch243ExternalAttestationLifecycleAudit"]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch243ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes(ROUTE));
  for (const suffix of ["prepare", "apply", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
