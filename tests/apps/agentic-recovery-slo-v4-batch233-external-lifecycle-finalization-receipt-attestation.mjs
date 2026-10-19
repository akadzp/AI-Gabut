import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROOT = "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/lifecycle";

test("Batch 233: empty lifecycle history is read-only and does not fabricate an attestation target", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b233-empty");
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const convergenceAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(convergenceAudit.status, "not_initialized", JSON.stringify({ status: convergenceAudit.status }));
  const snapshot = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceiptSnapshot(owner);
  assert.equal(snapshot.lifecycleEventCount, 0);
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle(owner,
    { action: "renew", reason: "Attempt a renewal with no source attestation." }), error => error.code === "RECOVERY_GATE_BATCH233_SOURCE_NOT_CURRENT");
  await assert.rejects(() => app.applyRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle(owner,
    "missing-challenge", { confirmation: "anything" }), error => error.code === "RECOVERY_GATE_BATCH233_CHALLENGE_INVALID");
});

test("Batch 233: challenge validation fails closed and lifecycle routes are registered", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b233-validation");
  await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle(owner,
    { action: "rotate", reason: "Invalid lifecycle action for Batch 233." }), error => error.code === "RECOVERY_GATE_BATCH233_LIFECYCLE_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle(owner,
    { action: "renew", reason: "short" }), error => error.code === "RECOVERY_GATE_BATCH233_LIFECYCLE_REASON_INVALID");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH233_EVENT_TYPES",
    "batch233LifecycleBindingFields",
    "prepareFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle",
    "applyFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle",
    "RECOVERY_GATE_BATCH233_REVOCATION_DESCENDANT_INVALID",
    "cross_domain_finalization_receipt_external_attestation_lifecycle_finalization_receipts"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle",
    "applyRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle",
    "reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationLifecycle",
    "externalLifecycleFinalizationReceiptAttestationLifecycleRequired"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const suffix of ["prepare", "apply", "audit", "reconcile"]) assert.ok(server.includes(`${ROOT}/${suffix}`), suffix);
});
