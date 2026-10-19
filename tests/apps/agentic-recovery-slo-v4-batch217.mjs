import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function readyReceipt(t, ownerId) {
  const prepared = await createCurrentRevalidation(t, ownerId, {
    revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true, recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
    recoveryGateProofContinuityReceiptLifecycleCheckpoint: true
  });
  const { app, owner } = prepared;
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: `${owner}-batch217-freshness` });
  await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  const finalization = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
  assert.ok(finalization.finalizationAttestation?.id);
  const lifecycle = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
    { action: "renew", reason: "Seed the base finalization-attestation lifecycle for Batch 217 tests." });
  await applyLifecycle(app, owner, lifecycle, "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle");
  const receiptLifecycle = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
    { action: "renew", reason: "Seed a finalized receipt lifecycle for Batch 217 tests." });
  await applyLifecycle(app, owner, receiptLifecycle, "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle");
  const receiptAttestation = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner);
  assert.equal(receiptAttestation.complete, true, JSON.stringify({ status: receiptAttestation.status, phase: receiptAttestation.phase }));
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpointStatus(owner);
  assert.equal(checkpoint.usableForCurrentDecision, true, JSON.stringify(checkpoint));
  return prepared;
}

async function applyLifecycle(app, owner, challenge, methodName, max = 24) {
  let result = null;
  for (let attempt = 0; attempt < max; attempt++) {
    result = await app[methodName](owner, challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true && ["verified_current", "decision_blocked"].includes(result.status)) return result;
  }
  return result;
}

describe("Agentic AI V4 Batch 217", { concurrency: false }, () => {
  test("Batch 217: finalization receipts form a signed, replay-safe supersession chain", { timeout: 120000 }, async t => {
    const { app, owner } = await readyReceipt(t, "b217-chain");
    const firstChallenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      { action: "renew", reason: "Renew the attestation lifecycle and finalize a receipt for Batch 217." });
    let interrupted = null;
    for (let attempt = 0; attempt < 10; attempt++) {
      interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
        firstChallenge.challengeId, { confirmation: firstChallenge.confirmation });
      if (interrupted.phase === "finalized_receipt_pending") break;
    }
    assert.equal(interrupted?.phase, "finalized_receipt_pending", JSON.stringify({ status: interrupted?.status, phase: interrupted?.phase }));
    assert.equal(interrupted.complete, false);
    assert.equal(interrupted.checkpointAdvancement.complete, true);
    const recovered = await app.reconcileRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt(owner);
    assert.equal(recovered.complete, true, JSON.stringify(recovered));
    assert.equal(recovered.recoveredCount, 1);
    const firstReceiptAudit = recovered.audit;
    assert.equal(firstReceiptAudit.status, "verified_current", JSON.stringify(firstReceiptAudit));
    assert.equal(firstReceiptAudit.receiptCount, 1);
    const firstReceiptId = firstReceiptAudit.latestReceipt.id;

    const replay = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      firstChallenge.challengeId, { confirmation: firstChallenge.confirmation });
    assert.equal(replay.complete, true);
    assert.equal(replay.idempotent, true);
    assert.equal(replay.receipt.id, firstReceiptId);
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt(owner)).receiptCount, 1);

    const revocation = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      { action: "revoke", reason: "Revoke the current attestation lifecycle generation and retain signed evidence." });
    const revoked = await applyLifecycle(app, owner, revocation,
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle", 10);
    assert.equal(revoked?.complete, true, JSON.stringify({ status: revoked?.status, phase: revoked?.phase }));
    assert.equal(revoked.status, "decision_blocked");
    const revokedAudit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt(owner);
    assert.equal(revokedAudit.status, "decision_blocked", JSON.stringify(revokedAudit));
    assert.equal(revokedAudit.receiptCount, 2);
    assert.equal(revokedAudit.latestReceipt.generation, 2);
    assert.equal(revokedAudit.latestReceipt.previousReceiptId, firstReceiptId);
    assert.equal(revokedAudit.latestReceipt.previousReceiptDigest, firstReceiptAudit.latestReceipt.digest);
    assert.equal(revokedAudit.latestReceipt.action, "revoke");
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.ok(["decision_blocked", "recovery_required"].includes(convergence.status), JSON.stringify({ status: convergence.status, blockers: convergence.blockers }));
    assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_RECEIPT_ATTESTATION_LIFECYCLE_RECEIPT_REVOKED"));
    const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt(owner);
    assert.equal(reconciled.complete, true, JSON.stringify(reconciled));
    assert.equal(reconciled.audit.receiptCount, 2);
  });

  test("Batch 217: receipt audit and reconciliation routes are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    assert.ok(server.includes("finalization-attestation-lifecycle-receipt-attestation/lifecycle/receipt/audit"));
    assert.ok(server.includes("finalization-attestation-lifecycle-receipt-attestation/lifecycle/receipt/reconcile"));
  });
});
