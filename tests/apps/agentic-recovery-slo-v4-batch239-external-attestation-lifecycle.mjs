import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/lifecycle";

test("Batch 239: empty lifecycle history is read-only and cannot fabricate a receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b239-empty");
  const audit = await app.auditRecoveryGateBatch239ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch239ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch238_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const convergence = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(convergence.batch239ExternalAttestationLifecycleAudit.status, "not_initialized");
  const reconciled = await app.reconcileRecoveryGateBatch239ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  await assert.rejects(() => app.prepareRecoveryGateBatch239ExternalAttestationLifecycle(owner,
    { action: "activate", reason: "test reason for lifecycle" }), /renew or revoke|renew|revoke/i);
});

test("Batch 239: lifecycle requires a current Batch 238 source and exposes recovery, receipt, and route bindings", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b239-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch239ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew attestation with source proof" }), error => error?.code === "RECOVERY_GATE_BATCH239_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH239_EVENT_TYPES", "BATCH239_LIFECYCLE_EVENT_TYPES", "BATCH239_RECEIPT_EVENT_TYPES",
    "prepareBatch239ExternalAttestationLifecycle", "applyBatch239ExternalAttestationLifecycle",
    "auditBatch239ExternalAttestationLifecycle", "getBatch239ExternalAttestationLifecycleSnapshot",
    "resumeBatch239ExternalAttestationLifecycle", "reconcileBatch239ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH239_RECEIPT_MISSING", "RECOVERY_GATE_BATCH239_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_batch238_external_attestation_lifecycle"
  ]) assert.ok(core.includes(token), token);
  const checkpointSnapshot = core.slice(core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot"),
    core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields"));
  assert.ok(checkpointSnapshot.includes("BATCH239_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 239 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch239ExternalAttestationLifecycle", "applyRecoveryGateBatch239ExternalAttestationLifecycle",
    "auditRecoveryGateBatch239ExternalAttestationLifecycle", "getRecoveryGateBatch239ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch239ExternalAttestationLifecycle", "batch239ExternalAttestationLifecycleAudit"]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch239ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes(ROUTE));
  for (const suffix of ["prepare", "apply", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
