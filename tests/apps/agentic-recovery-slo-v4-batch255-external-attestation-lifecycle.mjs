import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 255: empty lifecycle history is read-only and cannot fabricate a finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b255-empty");
  const audit = await app.auditRecoveryGateBatch255ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch255ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch254_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch255ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch255ExternalAttestationLifecycleAudit.status, "not_initialized");
  await assert.rejects(() => app.prepareRecoveryGateBatch255ExternalAttestationLifecycle(owner,
    { action: "activate", reason: "test reason for lifecycle" }), /renew.*revoke/i);
});

test("Batch 255: lifecycle requires current Batch 254 external attestation and exposes checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b255-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch255ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew Batch 254 external attestation with source proof" }),
    error => error?.code === "RECOVERY_GATE_BATCH255_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH255_EVENT_TYPES", "BATCH255_LIFECYCLE_EVENT_TYPES", "BATCH255_RECEIPT_EVENT_TYPES",
    "prepareBatch255ExternalAttestationLifecycle", "applyBatch255ExternalAttestationLifecycle",
    "auditBatch255ExternalAttestationLifecycle", "getBatch255ExternalAttestationLifecycleSnapshot",
    "resumeBatch255ExternalAttestationLifecycle", "reconcileBatch255ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH255_RECEIPT_PREDECESSOR_MISSING", "RECOVERY_GATE_BATCH255_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_batch254_external_attestation_lifecycle"]) assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH255_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 255 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch255ExternalAttestationLifecycle", "applyRecoveryGateBatch255ExternalAttestationLifecycle",
    "auditRecoveryGateBatch255ExternalAttestationLifecycle", "getRecoveryGateBatch255ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch255ExternalAttestationLifecycle", "batch255ExternalAttestationLifecycleAudit"]) assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch255ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("`${batch254ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch255ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});
