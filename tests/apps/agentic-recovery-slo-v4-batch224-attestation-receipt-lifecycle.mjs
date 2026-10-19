import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 224: independent attestation-receipt checkpoint enrolls and empty history remains not initialized", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b224-empty-history", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint: true
  });
  const checkpoint = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpointStatus(owner);
  assert.equal(checkpoint.enabled, true, JSON.stringify(checkpoint));
  assert.equal(checkpoint.usableForCurrentDecision, true, JSON.stringify(checkpoint));
  const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
  assert.ok(convergence.checkpoints.some(item => item.name === "finalization_receipt_binding_attestation_lifecycle_attestation_receipt"),
    JSON.stringify(convergence.checkpoints.map(item => item.name)));
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.usableForCurrentDecision, true);
  await assert.rejects(() => app.ensureRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceipt(owner),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_ATTESTATION_MISSING");
  await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptLifecycle(owner,
    { action: "delete", reason: "Reject an unsupported lifecycle operation." }),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_ATTESTATION_RECEIPT_ACTION_INVALID");
});

test("Batch 224: reused external provider is rejected and lifecycle endpoints are registered", { timeout: 30000 }, async t => {
  await assert.rejects(() => setupOwner(t, "b224-provider-reuse", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true,
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint: true,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptProvider: true
  }), error => /ANCHOR_PROVIDER_REUSED/.test(String(error.code || "")));
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/finalize",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/lifecycle/prepare",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/lifecycle/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/lifecycle/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/checkpoint/status",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/checkpoint/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/checkpoint/enrollment/prepare",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/checkpoint/enrollment/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/checkpoint/reconcile"
  ]) assert.ok(server.includes(route), route);
});

test("Batch 224: strict key-cutoff mode fails closed without a current independent checkpoint", { timeout: 30000 }, async t => {
  const variable = "AGENTIC_REQUIRE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_ATTESTATION_RECEIPT_KEY_CUTOFF_REVALIDATION";
  const previous = process.env[variable];
  process.env[variable] = "true";
  try {
    const { app, owner } = await setupOwner(t, "b224-strict-key-cutoff", {});
    await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptLifecycle(owner,
      { action: "renew", reason: "Strict mode must require current attestation receipt evidence." }),
      error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_ATTESTATION_RECEIPT_KEY_CUTOFF_REVALIDATION_REQUIRED");
  } finally {
    if (previous === undefined) delete process.env[variable]; else process.env[variable] = previous;
  }
});
