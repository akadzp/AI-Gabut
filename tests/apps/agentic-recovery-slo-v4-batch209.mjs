import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function currentGate(t, owner, options = {}) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true,
    recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true,
    recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
    ...options
  });
  await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
    { operationId: `${owner}-batch209-freshness` });
  const gate = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
  return { ...prepared, gate };
}

async function renewContinuity(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    { action: "renew", reason: "Create current continuity attestation before revocation-receipt lifecycle tests." });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

async function revokeContinuity(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    { action: "revoke", reason: "Revoke continuity attestation while preserving independently anchored receipt lifecycle evidence." });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

async function renewReceipt(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
    { action: "renew", reason: "Renew receipt generation and independently attest the supersession chain for Batch 209." });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

describe("Agentic AI V4 Batch 209", { concurrency: false }, () => {
  test("Batch 209: receipt renewal and supersession are independently anchored; convergence preserves terminal revocation", async t => {
    const { app, owner, anchors } = await currentGate(t, "b209-receipt-supersession", {
      recoveryGateProofContinuityReceiptLifecycleCheckpoint: true
    });
    const receiptAnchor = anchors.recoveryGateProofContinuityReceiptLifecycle;
    const [scope, enrolled] = [...receiptAnchor.records.entries()][0];
    assert.equal((await app.getRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointStatus(owner)).sourceCount, 0);
    const continuity = await renewContinuity(app, owner);
    assert.equal(continuity.complete, true);
    const revoked = await revokeContinuity(app, owner);
    assert.equal(revoked.complete, true);
    const renewed = await renewReceipt(app, owner);
    assert.equal(renewed.complete, true);
    assert.equal(renewed.receiptLifecycleAudit.status, "active");
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointStatus(owner);
    assert.equal(checkpoint.usableForCurrentDecision, true);
    assert.equal(checkpoint.sourceCount, 4, "intent, renewed, superseded, and finalized events must be anchored");
    assert.equal(receiptAnchor.records.get(scope).sourceCount, 4);
    assert.notEqual(receiptAnchor.records.get(scope).digest, enrolled.digest);
    const checkpointAudit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpoint(owner);
    assert.equal(checkpointAudit.usableForCurrentDecision, true);
    assert.equal(checkpointAudit.status, "healthy");
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergence.status, "decision_blocked", "receipt renewal must not undo revocation of the underlying attestation");
    assert.equal(convergence.usableForCurrentDecision, false);
    assert.ok(convergence.generationBindingDigest);
  });

  test("Batch 209: external receipt-lifecycle checkpoint write failure resumes without duplicate lifecycle events", async t => {
    const { app, owner, anchors } = await currentGate(t, "b209-receipt-crash", {
      recoveryGateProofContinuityReceiptLifecycleCheckpoint: true
    });
    await renewContinuity(app, owner);
    await revokeContinuity(app, owner);
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      { action: "renew", reason: "Exercise checkpoint recovery after local receipt lifecycle intent has persisted." });
    anchors.recoveryGateProofContinuityReceiptLifecycle.failWrites = true;
    const interrupted = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.checkpointError);
    anchors.recoveryGateProofContinuityReceiptLifecycle.failWrites = false;
    const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(resumed.complete, true);
    assert.equal(resumed.receiptLifecycleAudit.status, "active");
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointStatus(owner);
    assert.equal(checkpoint.usableForCurrentDecision, true);
    assert.equal(checkpoint.sourceCount, 4);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpoint(owner);
    assert.equal(audit.receiptLifecycleAudit.eventCount, 4);
  });

  test("Batch 209: strict mode blocks receipt lifecycle use before independent enrollment and detects provider reuse", async t => {
    const strict = await currentGate(t, "b209-receipt-strict", {
      recoveryGateProofContinuityReceiptLifecycleCheckpoint: true,
      enrollRecoveryGateProofContinuityReceiptLifecycleCheckpoint: false
    });
    await renewContinuity(strict.app, strict.owner);
    await revokeContinuity(strict.app, strict.owner);
    const state = await strict.app.getRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointStatus(strict.owner);
    assert.equal(state.usableForCurrentDecision, false);
    await assert.rejects(() => strict.app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(strict.owner,
      { action: "renew", reason: "Strict mode requires independent receipt lifecycle checkpoint enrollment." }),
    error => error.code === "RECOVERY_GATE_PROOF_CONTINUITY_RECEIPT_LIFECYCLE_CHECKPOINT_NOT_CURRENT");

    const reused = await currentGate(t, "b209-receipt-provider-reuse", {
      recoveryGateProofContinuityReceiptLifecycleCheckpoint: true,
      enrollRecoveryGateProofContinuityReceiptLifecycleCheckpoint: false,
      reuseRecoveryGateProofContinuityReceiptLifecycleProvider: true
    });
    const reusedState = await reused.app.getRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointStatus(reused.owner);
    assert.equal(reusedState.status, "unhealthy");
    assert.ok(reusedState.findings.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_RECEIPT_LIFECYCLE_ANCHOR_PROVIDER_REUSED"));
  });

  test("Batch 209: receipt-supersession checkpoint rollback blocks cross-domain convergence", async t => {
    const { app, owner, anchors } = await currentGate(t, "b209-receipt-rollback", {
      recoveryGateProofContinuityReceiptLifecycleCheckpoint: true
    });
    const receiptAnchor = anchors.recoveryGateProofContinuityReceiptLifecycle;
    const [scope, enrolledAnchor] = [...receiptAnchor.records.entries()][0];
    await renewContinuity(app, owner);
    await revokeContinuity(app, owner);
    const renewed = await renewReceipt(app, owner);
    assert.equal(renewed.complete, true);
    assert.equal((await app.getRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointStatus(owner)).sourceCount, 4);
    receiptAnchor.records.set(scope, structuredClone(enrolledAnchor));
    const state = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointStatus(owner);
    assert.equal(state.usableForCurrentDecision, false);
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.ok(["unhealthy", "recovery_required", "stale"].includes(convergence.status));
    assert.equal(convergence.usableForCurrentDecision, false);
    assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_CROSS_DOMAIN_CHECKPOINT_NOT_CURRENT"
      && item.checkpoint === "receipt_lifecycle"));
  });

  test("Batch 209: convergence audit binds all configured checkpoint generations and exposes HTTP routes", async t => {
    const { app, owner, anchors } = await currentGate(t, "b209-convergence", {
      recoveryGateProofContinuityReceiptLifecycleCheckpoint: true
    });
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergence.status, "decision_blocked", "the pre-existing orphan disposition remains a terminal decision blocker");
    assert.equal(convergence.usableForCurrentDecision, false);
    assert.equal(convergence.blockers.length, 0);
    assert.equal(convergence.checkpoints.length, 4);
    const receiptCheckpoint = convergence.checkpoints.find(item => item.name === "receipt_lifecycle");
    assert.equal(receiptCheckpoint.state.usableForCurrentDecision, true);
    const [scope, anchor] = [...anchors.recoveryGateProofContinuityReceiptLifecycle.records.entries()][0];
    anchors.recoveryGateProofContinuityReceiptLifecycle.records.set(scope, structuredClone(anchor));
    const after = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(after.status, "decision_blocked", "an unchanged checkpoint does not override the terminal decision blocker");
    assert.equal(after.generationBindingDigest, convergence.generationBindingDigest);
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["receipt-lifecycle-checkpoint/status", "receipt-lifecycle-checkpoint/audit",
      "receipt-lifecycle-checkpoint/enrollment/prepare", "receipt-lifecycle-checkpoint/enrollment/apply",
      "receipt-lifecycle-checkpoint/reconcile", "convergence/audit"])
      assert.ok(server.includes(route), `missing route ${route}`);
  });
});
