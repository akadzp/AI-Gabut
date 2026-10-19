import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 226: independent finalization-attestation receipt checkpoint starts empty without inventing evidence", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b226-empty", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint: true
  });
  const checkpoint = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpointStatus(owner);
  assert.equal(checkpoint.enabled, true, JSON.stringify(checkpoint));
  assert.equal(checkpoint.usableForCurrentDecision, true, JSON.stringify(checkpoint));
  const snapshot = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
  assert.ok(snapshot.checkpoints.some(item => item.name === "finalization_receipt_binding_attestation_lifecycle_attestation_receipt_attestation"),
    JSON.stringify(snapshot.checkpoints.map(item => item.name)));
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.eventCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const source = await app.recoveryGateProofContinuityService?.getFinalizationReceiptBindingAttestationLifecycleAttestationReceiptSnapshot?.(owner);
  if (source) {
    assert.equal(source.snapshot.domain, "cross_domain_finalization_receipt_binding_lifecycle_attestation_receipts");
    assert.equal(source.count, 0);
  }
  await assert.rejects(() => app.attestRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_ATTESTATION_RECEIPT_LIFECYCLE_NOT_FINALIZED");
});

test("Batch 226: provider reuse is rejected and external-attestation checkpoint routes are registered", { timeout: 30000 }, async t => {
  await assert.rejects(() => setupOwner(t, "b226-provider-reuse", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint: true,
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint: true,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptProvider: true
  }), error => /ANCHOR_PROVIDER_REUSED/.test(String(error.code || "")));
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_attestation_receipt_external_attested",
    "getFinalizationReceiptBindingAttestationLifecycleAttestationReceiptSnapshot",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_ATTESTATION_RECEIPT_EXTERNAL_CHAIN_INVALID",
    "keyCutoffRevalidated"
  ]) assert.ok(core.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/attest",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/checkpoint/status",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/checkpoint/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/checkpoint/enrollment/prepare",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/checkpoint/enrollment/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/checkpoint/reconcile"
  ]) assert.ok(server.includes(route), route);
});
