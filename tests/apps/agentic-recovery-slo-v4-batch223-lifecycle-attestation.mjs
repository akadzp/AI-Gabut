import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 223: independent lifecycle-attestation checkpoint enrolls and empty history fails closed for attestation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b223-empty-ledger", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint: true
  });
  const checkpoint = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpointStatus(owner);
  assert.equal(checkpoint.usableForCurrentDecision, true, JSON.stringify(checkpoint));
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestation(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify(audit));
  assert.equal(audit.usableForCurrentDecision, true);
  const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint(owner);
  assert.equal(convergence.lifecycleAttestationCheckpoint.usableForCurrentDecision, true, JSON.stringify(convergence));
  await assert.rejects(() => app.attestRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_RECEIPT_LIFECYCLE_NOT_FINALIZED");
});

test("Batch 223: provider reuse is rejected and attestation/checkpoint routes are registered", { timeout: 30000 }, async t => {
  await assert.rejects(() => readyReceipt(t, "b223-provider-reuse", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true,
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint: true,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationProvider: true
  }), error => String(error.code || "").endsWith("ANCHOR_PROVIDER_REUSED"));
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/attestation/attest",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/attestation/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/attestation/checkpoint/status",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/attestation/checkpoint/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/attestation/checkpoint/enrollment/prepare",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/attestation/checkpoint/enrollment/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/attestation/checkpoint/reconcile"]) assert.ok(server.includes(route), route);
});
