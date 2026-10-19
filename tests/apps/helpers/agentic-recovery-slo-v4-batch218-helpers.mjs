import assert from "node:assert/strict";
import { createCurrentRevalidation } from "./agentic-recovery-slo-v4-batch203-helpers.mjs";

export async function applyLifecycle(app, owner, challenge, methodName, max = 24) {
  let result = null;
  for (let attempt = 0; attempt < max; attempt++) {
    result = await app[methodName](owner, challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true && ["verified_current", "decision_blocked"].includes(result.status)) return result;
  }
  return result;
}

export async function readyReceipt(t, ownerId, options = {}) {
  const prepared = await createCurrentRevalidation(t, ownerId, {
    revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true, recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
    recoveryGateProofContinuityReceiptLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint: true,
    ...options
  });
  const { app, owner } = prepared;
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: `${owner}-batch218-freshness` });
  await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  const finalization = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
  assert.ok(finalization.finalizationAttestation?.id);
  const lifecycle = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
    { action: "renew", reason: "Seed the base finalization-attestation lifecycle for Batch 218." });
  await applyLifecycle(app, owner, lifecycle, "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle");
  const receiptLifecycle = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
    { action: "renew", reason: "Seed a finalized receipt lifecycle for Batch 218." });
  await applyLifecycle(app, owner, receiptLifecycle, "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle");
  const receiptAttestation = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner);
  assert.equal(receiptAttestation.complete, true, JSON.stringify({ status: receiptAttestation.status, phase: receiptAttestation.phase }));
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpointStatus(owner);
  assert.equal(checkpoint.usableForCurrentDecision, true, JSON.stringify(checkpoint));
  const receiptLifecycleChallenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
    { action: "renew", reason: "Seed the first finalized lifecycle receipt for Batch 218 checkpoint tests." });
  let receiptLifecycleResult = null;
  for (let attempt = 0; attempt < 12; attempt++) {
    receiptLifecycleResult = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      receiptLifecycleChallenge.challengeId, { confirmation: receiptLifecycleChallenge.confirmation });
    if (receiptLifecycleResult.phase === "finalized_receipt_pending") break;
  }
  assert.equal(receiptLifecycleResult?.phase, "finalized_receipt_pending", JSON.stringify({ status: receiptLifecycleResult?.status, phase: receiptLifecycleResult?.phase }));
  const finalizationReceipt = await app.reconcileRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt(owner);
  assert.equal(finalizationReceipt.complete, true, JSON.stringify(finalizationReceipt));
  const receiptReplay = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
    receiptLifecycleChallenge.challengeId, { confirmation: receiptLifecycleChallenge.confirmation });
  assert.equal(receiptReplay.complete, true);
  assert.equal(receiptReplay.idempotent, true);
  const finalizationReceiptCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpointStatus(owner);
  assert.equal(finalizationReceiptCheckpoint.usableForCurrentDecision, true, JSON.stringify(finalizationReceiptCheckpoint));
  return prepared;
}
