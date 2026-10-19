import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function readyReceipt(t, ownerId) {
  const prepared = await createCurrentRevalidation(t, ownerId, {
    revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true,
    recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true,
    recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
    recoveryGateProofContinuityReceiptLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint: true
  });
  const { app, owner } = prepared;
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
    { operationId: `${owner}-batch216-freshness` });
  await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  const finalization = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
  assert.ok(finalization.finalizationAttestation?.id);
  const lifecycle = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
    { action: "renew", reason: "Seed the base finalization-attestation lifecycle for Batch 216 tests." });
  await applyReceiptLifecycle(app, owner, lifecycle, "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle");
  const receiptLifecycle = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
    { action: "renew", reason: "Seed a finalized receipt lifecycle for Batch 216 attestation-lifecycle tests." });
  await applyReceiptLifecycle(app, owner, receiptLifecycle, "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle");
  const receiptAttestation = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner);
  assert.equal(receiptAttestation.complete, true, JSON.stringify({ status: receiptAttestation.status, phase: receiptAttestation.phase }));
  const receiptCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestationCheckpointStatus(owner);
  assert.equal(receiptCheckpoint.usableForCurrentDecision, true, JSON.stringify(receiptCheckpoint));
  const lifecycleCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpointStatus(owner);
  assert.equal(lifecycleCheckpoint.usableForCurrentDecision, true, JSON.stringify(lifecycleCheckpoint));
  return prepared;
}

async function applyReceiptLifecycle(app, owner, challenge, methodName, max = 18) {
  let result = null;
  for (let attempt = 0; attempt < max; attempt++) {
    result = await app[methodName](owner, challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true && ["verified_current", "decision_blocked"].includes(result.status)) return result;
  }
  return result;
}

describe("Agentic AI V4 Batch 216", { concurrency: false }, () => {
  test("Batch 216: renewal supersedes predecessor and revocation is terminal across generations", async t => {
    const { app, owner } = await readyReceipt(t, "b216-chain");
    const before = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner);
    assert.equal(before.status, "not_initialized");
    const renewal = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner, {
      action: "renew", reason: "Renew the lifecycle wrapper with an explicit predecessor chain for Batch 216." });
    const staleRenewal = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner, {
      action: "renew", reason: "Prepare a concurrent stale challenge to verify snapshot-bound replay rejection." });
    const renewed = await applyReceiptLifecycle(app, owner, renewal,
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle");
    assert.equal(renewed?.complete, true, JSON.stringify({ status: renewed?.status, phase: renewed?.phase }));
    assert.equal(renewed.status, "verified_current", JSON.stringify({ status: renewed.status, audit: renewed.audit }));
    assert.equal(renewed.audit.latestLifecycle.generation, 1);
    assert.equal(renewed.audit.status, "verified_current");
    await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      staleRenewal.challengeId, { confirmation: staleRenewal.confirmation }),
    error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_RECEIPT_ATTESTATION_LIFECYCLE_SNAPSHOT_CHANGED");
    const replayedRenewal = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      renewal.challengeId, { confirmation: renewal.confirmation });
    assert.equal(replayedRenewal.complete, true);
    assert.equal(replayedRenewal.idempotent, true);
    assert.equal(replayedRenewal.audit.eventCount, 4);
    const revocation = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner, {
      action: "revoke", reason: "Revoke the current attestation lifecycle generation and preserve terminal history." });
    assert.equal(revocation.attestationLifecycleGeneration, 2);
    const revoked = await applyReceiptLifecycle(app, owner, revocation,
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle");
    assert.equal(revoked?.complete, true, JSON.stringify({ status: revoked?.status, phase: revoked?.phase }));
    assert.equal(revoked.status, "decision_blocked");
    assert.equal(revoked.audit.status, "decision_blocked");
    assert.equal(revoked.audit.latestLifecycle.generation, 2);
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner, {
      action: "renew", reason: "A revoked attestation lifecycle cannot be renewed again." }),
    error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_RECEIPT_ATTESTATION_ALREADY_REVOKED");
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergence.status, "decision_blocked");
    assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_RECEIPT_ATTESTATION_LIFECYCLE_REVOKED"));
  });

  test("Batch 216: checkpoint write failure recovers without duplicate lifecycle events", async t => {
    const { app, owner, anchors } = await readyReceipt(t, "b216-recovery");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner, {
      action: "renew", reason: "Exercise interrupted attestation lifecycle external checkpoint advancement." });
    const first = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(first.phase, "intent");
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle.failWrites = true;
    let interrupted = null;
    for (let attempt = 0; attempt < 6; attempt++) {
      interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
        challenge.challengeId, { confirmation: challenge.confirmation });
      if (interrupted.status === "recovery_required") break;
    }
    assert.equal(interrupted?.status, "recovery_required", JSON.stringify({ status: interrupted?.status, phase: interrupted?.phase }));
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle.failWrites = false;
    let resumed = null;
    for (let attempt = 0; attempt < 18; attempt++) {
      resumed = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
        challenge.challengeId, { confirmation: challenge.confirmation });
      if (resumed.complete === true && resumed.status === "verified_current") break;
    }
    assert.equal(resumed?.complete, true, JSON.stringify({ status: resumed?.status, phase: resumed?.phase }));
    assert.equal(resumed.status, "verified_current");
    assert.equal(resumed.audit.intentCount, 1);
    assert.equal(resumed.audit.finalizedCount, 1);
    assert.equal(resumed.audit.eventCount, 4);
  });

  test("Batch 216: provider reuse is rejected and lifecycle API routes are registered", async t => {
    await assert.rejects(() => setupOwner(t, "b216-reuse", {
      recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint: true,
      reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleProvider: true
    }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_RECEIPT_ATTESTATION_LIFECYCLE_ANCHOR_PROVIDER_REUSED");
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["finalization-attestation-lifecycle-receipt-attestation/lifecycle/prepare",
      "finalization-attestation-lifecycle-receipt-attestation/lifecycle/apply",
      "finalization-attestation-lifecycle-receipt-attestation/lifecycle/audit",
      "finalization-attestation-lifecycle-receipt-attestation-lifecycle-checkpoint/status",
      "finalization-attestation-lifecycle-receipt-attestation-lifecycle-checkpoint/enrollment/prepare",
      "finalization-attestation-lifecycle-receipt-attestation-lifecycle-checkpoint/enrollment/apply",
      "finalization-attestation-lifecycle-receipt-attestation-lifecycle-checkpoint/reconcile"])
      assert.ok(server.includes(route), `missing route ${route}`);
  });
});
