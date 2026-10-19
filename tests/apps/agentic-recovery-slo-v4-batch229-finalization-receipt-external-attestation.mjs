import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 229: empty finalization-receipt external-attestation history is not fabricated and attest fails closed", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b229-empty");
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceipt(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const checkpoint = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointStatus(owner);
  assert.equal(checkpoint.enabled, false);
  assert.equal(checkpoint.usableForCurrentDecision, true);
  const snapshot = await app.recoveryGateProofContinuityService?.getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot?.(owner);
  if (snapshot) {
    assert.equal(snapshot.snapshot.domain, "cross_domain_finalization_receipt_external_attestations");
    assert.equal(snapshot.count, 0);
  }
  await assert.rejects(() => app.attestRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceipt(owner),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_FINALIZATION_RECEIPT_MISSING");
});

test("Batch 229: signed receipt-attestation chain, checkpoint independence, convergence wiring, and routes are registered", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_finalization_receipt_attested",
    "attestFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceipt",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestation",
    "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot",
    "sourceLifecycleChainDigest",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_CHAIN_INVALID",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_HISTORICAL_RECEIPT_ATTESTATION_MISSING",
    "cross_domain_finalization_receipt_external_attestations"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointState",
    "advanceRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpoint",
    "externalFinalizationReceiptAttestationRequired"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "external-attestation/finalization-receipt-attestation/attest",
    "external-attestation/finalization-receipt-attestation/audit",
    "external-attestation/finalization-receipt-attestation/checkpoint/status",
    "external-attestation/finalization-receipt-attestation/checkpoint/audit",
    "external-attestation/finalization-receipt-attestation/checkpoint/enrollment/prepare",
    "external-attestation/finalization-receipt-attestation/checkpoint/enrollment/apply",
    "external-attestation/finalization-receipt-attestation/checkpoint/reconcile"
  ]) assert.ok(server.includes(route), route);
});

test("Batch 229: independent external-attestation checkpoint enrolls and rejects provider reuse", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b229-checkpoint", {
    recoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint: true
  });
  const state = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointStatus(owner);
  assert.equal(state.enabled, true, JSON.stringify(state));
  assert.equal(state.usableForCurrentDecision, true, JSON.stringify(state));
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpoint(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  await assert.rejects(() => setupOwner(t, "b229-provider-reuse", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint: true,
    recoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint: true,
    reuseRecoveryGateProofContinuityFinalizationReceiptExternalAttestationProvider: true
  }), error => /ANCHOR_PROVIDER_REUSED/.test(String(error.code || "")));
});
