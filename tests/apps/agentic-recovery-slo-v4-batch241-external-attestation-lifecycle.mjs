import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/lifecycle";

test("Batch 241: empty lifecycle history is read-only and cannot fabricate a receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b239-empty");
  const audit = await app.auditRecoveryGateBatch241ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch241ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch240_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const convergence = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(convergence.batch241ExternalAttestationLifecycleAudit.status, "not_initialized");
  const reconciled = await app.reconcileRecoveryGateBatch241ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  await assert.rejects(() => app.prepareRecoveryGateBatch241ExternalAttestationLifecycle(owner,
    { action: "activate", reason: "test reason for lifecycle" }), /renew or revoke|renew|revoke/i);
});

test("Batch 241: lifecycle requires a current Batch 240 source and exposes recovery, receipt, and route bindings", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b239-source-required");
  await assert.rejects(() => app.prepareRecoveryGateBatch241ExternalAttestationLifecycle(owner,
    { action: "renew", reason: "renew attestation with source proof" }), error => error?.code === "RECOVERY_GATE_BATCH241_SOURCE_NOT_CURRENT");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH241_EVENT_TYPES", "BATCH241_LIFECYCLE_EVENT_TYPES", "BATCH241_RECEIPT_EVENT_TYPES",
    "prepareBatch241ExternalAttestationLifecycle", "applyBatch241ExternalAttestationLifecycle",
    "auditBatch241ExternalAttestationLifecycle", "getBatch241ExternalAttestationLifecycleSnapshot",
    "resumeBatch241ExternalAttestationLifecycle", "reconcileBatch241ExternalAttestationLifecycle",
    "RECOVERY_GATE_BATCH241_RECEIPT_MISSING", "RECOVERY_GATE_BATCH241_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_batch240_external_attestation_lifecycle"
  ]) assert.ok(core.includes(token), token);
  const checkpointSnapshot = core.slice(core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot"),
    core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields"));
  assert.ok(checkpointSnapshot.includes("BATCH241_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 241 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch241ExternalAttestationLifecycle", "applyRecoveryGateBatch241ExternalAttestationLifecycle",
    "auditRecoveryGateBatch241ExternalAttestationLifecycle", "getRecoveryGateBatch241ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch241ExternalAttestationLifecycle", "batch241ExternalAttestationLifecycleAudit"]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch241ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes(ROUTE));
  for (const suffix of ["prepare", "apply", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
