import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations/lifecycle";

test("Batch 249: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b249-empty");
  const audit = await app.auditRecoveryGateBatch249ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);

  const snapshot = await app.getRecoveryGateBatch249ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch248_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);

  const reconciled = await app.reconcileRecoveryGateBatch249ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch249ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch249ExternalAttestationLifecycle(owner,
    { action: "activate", reason: "test reason for lifecycle" }), /renew.*revoke/i);
});

test("Batch 249: lifecycle requires current Batch 248 external attestation and exposes owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b249-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch249ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 248 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH249_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH249_EVENT_TYPES", "BATCH249_LIFECYCLE_EVENT_TYPES", "BATCH249_RECEIPT_EVENT_TYPES",
    "prepareBatch249ExternalAttestationLifecycle", "applyBatch249ExternalAttestationLifecycle",
    "auditBatch249ExternalAttestationLifecycle", "getBatch249ExternalAttestationLifecycleSnapshot",
    "resumeBatch249ExternalAttestationLifecycle", "reconcileBatch249ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH249_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH249_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_batch248_external_attestation_lifecycle"
  ]) assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH249_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 249 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch249ExternalAttestationLifecycle", "applyRecoveryGateBatch249ExternalAttestationLifecycle",
    "auditRecoveryGateBatch249ExternalAttestationLifecycle", "getRecoveryGateBatch249ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch249ExternalAttestationLifecycle", "batch249ExternalAttestationLifecycleAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch249ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("`${batch248ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const suffix of ["prepare", "apply", "audit", "snapshot", "reconcile"])
    assert.ok(server.includes(`/${suffix}",async`), suffix);
});
