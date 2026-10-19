import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 225: independent checkpoint handles empty history without inventing lifecycle finalization receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b225-empty", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint: true
  });
  const checkpoint = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpointStatus(owner);
  assert.equal(checkpoint.enabled, true, JSON.stringify(checkpoint));
  assert.equal(checkpoint.usableForCurrentDecision, true, JSON.stringify(checkpoint));
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.finalizationReceiptCount, 0);
  assert.equal(audit.pendingLifecycleCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  await assert.rejects(() => app.ensureRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceipt(owner),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_ATTESTATION_MISSING");
  const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
  assert.ok(convergence.checkpoints.some(item => item.name === "finalization_receipt_binding_attestation_lifecycle_attestation_receipt"),
    JSON.stringify(convergence.checkpoints.map(item => item.name)));
});

test("Batch 225: signed lifecycle finalization receipts and cross-generation revocation checks are wired into the audit", async () => {
  const source = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_attestation_receipt_lifecycle_finalization_receipt_finalized",
    "ensureFinalizationReceiptBindingAttestationLifecycleAttestationReceiptLifecycleFinalizationReceipt",
    "finalizationReceiptByFinalization",
    "pendingLifecycleIntents",
    "REVOCATION_DESCENDANT_PRESENT",
    "latestFinalizationReceiptDigest"
  ]) assert.ok(source.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/lifecycle/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/lifecycle/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/checkpoint/reconcile"
  ]) assert.ok(server.includes(route), route);
});
