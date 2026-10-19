import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function readyFinalization(t, owner, options = {}) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true,
    recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true,
    recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
    recoveryGateProofContinuityReceiptLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true,
    ...options
  });
  const { app, owner: user } = prepared;
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(user,
    { operationId: `${owner}-batch213-freshness` });
  await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(user);
  const finalization = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(user);
  assert.ok(["finalized_current", "decision_blocked"].includes(finalization.status),
    JSON.stringify({ status: finalization.status, audit: finalization.audit, convergence: finalization.convergence }));
  assert.ok(finalization.finalizationAttestation?.id);
  const receiptCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpointStatus(user);
  assert.equal(receiptCheckpoint.usableForCurrentDecision, true, JSON.stringify(receiptCheckpoint));
  return { ...prepared, finalization };
}

async function applyLifecycleUntilComplete(app, owner, challenge) {
  let result = null;
  for (let attempt = 0; attempt < 12; attempt++) {
    result = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true && ["verified_current", "decision_blocked"].includes(result.status)
      && result.receiptCheckpointAudit?.usableForCurrentDecision !== false) return result;
  }
  throw new Error(`lifecycle operation did not converge: ${JSON.stringify({ status: result?.status, phase: result?.phase,
    checkpointAdvancement: result?.checkpointAdvancement, audit: result?.audit })}`);
}

describe("Agentic AI V4 Batch 213", { concurrency: false }, () => {
  test("Batch 213: renewal emits a signed receipt chain and independently anchors it", async t => {
    const { app, owner, anchors } = await readyFinalization(t, "b213-renew");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "renew", reason: "Renew finalization attestation with independently checkpointed lifecycle receipt continuity."
    });
    const result = await applyLifecycleUntilComplete(app, owner, challenge);
    assert.ok(result.receipt?.id);
    assert.equal(result.receipt.stableBinding.action, "renew");
    assert.equal(result.receipt.stableBinding.finalizationAttestationLifecycleReceiptGeneration, 1);
    assert.equal(result.checkpointAdvancement.finalizationAttestationLifecycleReceiptCheckpoint.usableForCurrentDecision, true);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner);
    assert.equal(audit.status, "verified_current", JSON.stringify({ status: audit.status, receiptAudit: audit.receiptAudit }));
    assert.equal(audit.receiptAudit.receiptCount, 1);
    const receiptAnchor = [...anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt.records.values()][0];
    assert.ok(receiptAnchor?.digest);
    const replay = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(replay.idempotent, true);
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner)).receiptAudit.receiptCount, 1);
  });

  test("Batch 213: revocation receipt is externally anchored but remains decision-blocking", async t => {
    const { app, owner } = await readyFinalization(t, "b213-revoke");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "revoke", reason: "Revoke this finalization attestation and retain an independently anchored receipt."
    });
    const result = await applyLifecycleUntilComplete(app, owner, challenge);
    assert.ok(result.receipt?.id);
    assert.equal(result.receipt.stableBinding.action, "revoke");
    assert.equal(result.status, "decision_blocked");
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner);
    assert.equal(audit.status, "decision_blocked");
    assert.equal(audit.receiptAudit.status, "verified_current");
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergence.status, "decision_blocked");
  });

  test("Batch 213: external receipt checkpoint write failure resumes without duplicate receipt", async t => {
    const { app, owner, anchors } = await readyFinalization(t, "b213-recovery");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "renew", reason: "Exercise resumable lifecycle receipt checkpointing after an external write failure."
    });
    let phase = null;
    for (let attempt = 0; attempt < 12; attempt++) {
      phase = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
        challenge.challengeId, { confirmation: challenge.confirmation });
      if (phase.phase === "finalized_receipt_pending") break;
    }
    assert.equal(phase?.phase, "finalized_receipt_pending");
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt.failWrites = true;
    const interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.receipt?.id);
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt.failWrites = false;
    const resumed = await applyLifecycleUntilComplete(app, owner, challenge);
    assert.equal(resumed.receipt.id, interrupted.receipt.id);
    assert.equal(resumed.idempotent, true);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner);
    assert.equal(audit.receiptAudit.receiptCount, 1);
    assert.equal(audit.status, "verified_current");
  });

  test("Batch 213: strict receipt-checkpoint preflight and provider independence are enforced", async t => {
    const { app, owner } = await setupOwner(t, "b213-strict", {
      recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true,
      recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true,
      enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: false
    });
    const state = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpointStatus(owner);
    assert.equal(state.enabled, true);
    assert.equal(state.usableForCurrentDecision, false);
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "renew", reason: "Must not prepare a lifecycle operation until receipt checkpoint enrollment is current."
    }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_CHECKPOINT_NOT_CURRENT");
    await assert.rejects(() => setupOwner(t, "b213-reuse", {
      recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true,
      reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptProvider: true
    }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR_PROVIDER_REUSED");
  });

  test("Batch 213: receipt checkpoint routes and lifecycle receipt validation are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["finalization-attestation-lifecycle-receipt-checkpoint/status", "finalization-attestation-lifecycle-receipt-checkpoint/audit",
      "finalization-attestation-lifecycle-receipt-checkpoint/enrollment/prepare", "finalization-attestation-lifecycle-receipt-checkpoint/enrollment/apply",
      "finalization-attestation-lifecycle-receipt-checkpoint/reconcile"])
      assert.ok(server.includes(route), `missing route ${route}`);
    const service = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
    assert.match(service, /proof_continuity_finalization_attestation_lifecycle_receipt_finalized/);
    assert.match(service, /RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_INVALID/);
    const app = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(app, /AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR/);
    assert.match(app, /RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR_PROVIDER_REUSED/);
  });
});
