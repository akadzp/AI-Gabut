import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function currentGate(t, owner) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true,
    recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true,
    recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true
  });
  await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
    { operationId: `${owner}-batch208-freshness` });
  const gate = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
  return { ...prepared, gate };
}

async function renew(app, owner, reason = "Renew proof continuity lifecycle evidence for Batch 208 validation.") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    { action: "renew", reason });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

async function revoke(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    { action: "revoke", reason: "Revoke proof continuity and preserve receipt lifecycle evidence for Batch 208." });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

describe("Agentic AI V4 Batch 208", { concurrency: false }, () => {
  test("Batch 208: lifecycle drift and resolution receipts are independently anchored and reconciled", async t => {
    const { app, owner, anchors } = await currentGate(t, "b208-drift-checkpoint");
    const lifecycleAnchor = anchors.recoveryGateProofContinuityLifecycle;
    const evidenceAnchor = anchors.recoveryGateProofContinuityLifecycleDriftEvidence;
    const [scope, enrollmentAnchor] = [...lifecycleAnchor.records.entries()][0];
    const renewed = await renew(app, owner);
    assert.equal(renewed.complete, true);
    const currentLifecycleAnchor = structuredClone(lifecycleAnchor.records.get(scope));
    lifecycleAnchor.records.set(scope, structuredClone(enrollmentAnchor));

    const observed = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(observed.status, "drift_recorded");
    assert.ok(observed.event?.id);
    const evidenceStatus = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner);
    assert.equal(evidenceStatus.usableForCurrentDecision, true);
    assert.equal(evidenceStatus.sourceCount, 1);
    const repeated = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(repeated.event.id, observed.event.id, "same unresolved drift must not create a second observation");
    assert.equal((await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner)).sourceCount, 1);

    lifecycleAnchor.records.set(scope, currentLifecycleAnchor);
    const recovered = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner);
    assert.equal(recovered.driftAudit.unresolvedCount, 0);
    assert.ok(["finalized", "no_pending_drift_resolution"].includes(recovered.resolutionReceipt.status));
    const finalStatus = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner);
    assert.equal(finalStatus.usableForCurrentDecision, true);
    assert.equal(finalStatus.sourceCount, 3, "drift, continuity attestation, and resolution receipt must all be anchored");
    assert.equal([...evidenceAnchor.records.values()][0].sourceCount, 3);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint(owner);
    assert.equal(audit.status, "healthy");
    assert.equal(audit.usableForCurrentDecision, true);
  });

  test("Batch 208: external write failure retains drift evidence and recovery advances one event without duplication", async t => {
    const { app, owner, anchors } = await currentGate(t, "b208-drift-write-recovery");
    const lifecycleAnchor = anchors.recoveryGateProofContinuityLifecycle;
    const evidenceAnchor = anchors.recoveryGateProofContinuityLifecycleDriftEvidence;
    const [scope, enrollmentAnchor] = [...lifecycleAnchor.records.entries()][0];
    await renew(app, owner);
    const currentLifecycleAnchor = structuredClone(lifecycleAnchor.records.get(scope));
    lifecycleAnchor.records.set(scope, structuredClone(enrollmentAnchor));
    evidenceAnchor.failWrites = true;
    const failed = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(failed.status, "recovery_required");
    assert.ok(failed.event?.id);
    evidenceAnchor.failWrites = false;
    const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint(owner);
    assert.equal(reconciled.status, "anchored");
    const observedAgain = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(observedAgain.event.id, failed.event.id);
    assert.equal((await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner)).sourceCount, 1);
    lifecycleAnchor.records.set(scope, currentLifecycleAnchor);
    const recovered = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner);
    assert.equal(recovered.driftAudit.unresolvedCount, 0);
    assert.equal((await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner)).usableForCurrentDecision, true);
  });

  test("Batch 208: interruption between continuity attestation and drift receipt finalization resumes the same evidence chain", async t => {
    const { app, owner, anchors } = await currentGate(t, "b208-drift-int");
    const lifecycleAnchor = anchors.recoveryGateProofContinuityLifecycle;
    const evidenceAnchor = anchors.recoveryGateProofContinuityLifecycleDriftEvidence;
    const [scope, enrollmentAnchor] = [...lifecycleAnchor.records.entries()][0];
    await renew(app, owner);
    const currentLifecycleAnchor = structuredClone(lifecycleAnchor.records.get(scope));
    lifecycleAnchor.records.set(scope, structuredClone(enrollmentAnchor));
    const observed = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(observed.status, "drift_recorded");
    lifecycleAnchor.records.set(scope, currentLifecycleAnchor);
    const before = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    evidenceAnchor.failWrites = true;
    await assert.rejects(() => app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner));
    evidenceAnchor.failWrites = false;
    const interruptedAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(interruptedAudit.eventCount, before.eventCount + 1, "the continuity attestation is retained exactly once");
    const recovered = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner);
    assert.equal(recovered.driftAudit.unresolvedCount, 0);
    assert.ok(["finalized", "no_pending_drift_resolution"].includes(recovered.resolutionReceipt.status));
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner);
    assert.equal(checkpoint.usableForCurrentDecision, true);
    assert.equal(checkpoint.sourceCount, 3);
    const recoveredAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(recoveredAudit.eventCount, interruptedAudit.eventCount + 1, "finalization adds one receipt without duplicating continuity");
    assert.equal(recoveredAudit.pendingDriftResolutionReceiptCount, 0);
  });

  test("Batch 208: receipt renewal creates a linked generation and stale concurrent challenge is rejected", async t => {
    const { app, owner, anchors } = await currentGate(t, "b208-receipt-renewal");
    const revoked = await revoke(app, owner);
    assert.equal(revoked.complete, true);
    assert.equal(revoked.revocationReceipt.status, "finalized");
    const oldReceipt = revoked.revocationReceipt.event;
    const renewChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      { action: "renew", reason: "Renew the revocation recovery receipt under current checkpoint and key bindings." });
    const staleChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      { action: "revoke", reason: "Revoke a superseded receipt only after the renewal generation changes." });
    const renewed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      renewChallenge.challengeId, { confirmation: renewChallenge.confirmation });
    assert.equal(renewed.complete, true);
    assert.equal(renewed.receiptLifecycleAudit.status, "active");
    const replacement = renewed.replacementReceipt;
    assert.notEqual(replacement.id, oldReceipt.id);
    assert.equal(replacement.stableBinding.previousReceiptId, oldReceipt.id);
    assert.equal(replacement.stableBinding.previousReceiptDigest, oldReceipt.digest);
    assert.equal(replacement.stableBinding.receiptGeneration, oldReceipt.stableBinding.receiptGeneration + 1);
    const stale = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      staleChallenge.challengeId, { confirmation: staleChallenge.confirmation });
    assert.equal(stale.status, "recovery_required");
    assert.equal(stale.checkpointError.code, "RECOVERY_GATE_PROOF_CONTINUITY_RECEIPT_LIFECYCLE_SNAPSHOT_CHANGED");
    const receiptAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner);
    assert.equal(receiptAudit.status, "active");
    assert.equal(receiptAudit.usableForCurrentDecision, true, "receipt evidence is current while the underlying revocation still blocks closure");
    const closure = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.equal(closure.status, "decision_blocked");
    assert.equal(closure.generationBindingCurrent, true);
    assert.equal((await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner)).usableForCurrentDecision, true);
    assert.ok(anchors.recoveryGateProofContinuityLifecycleDriftEvidence.records.size > 0);
  });

  test("Batch 208: receipt lifecycle renewal resumes after external checkpoint failure without duplicate receipt or intent", async t => {
    const { app, owner, anchors } = await currentGate(t, "b208-receipt-crash-recovery");
    const revoked = await revoke(app, owner);
    assert.equal(revoked.complete, true);
    const previousReceipt = revoked.revocationReceipt.event;
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      { action: "renew", reason: "Recover receipt lifecycle renewal after the independent checkpoint write fails." });
    const evidenceAnchor = anchors.recoveryGateProofContinuityLifecycleDriftEvidence;
    evidenceAnchor.failWrites = true;
    const interrupted = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.checkpointError);
    evidenceAnchor.failWrites = false;
    const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(resumed.complete, true);
    assert.equal(resumed.receiptLifecycleAudit.status, "active");
    const receiptAudit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint(owner);
    assert.equal(receiptAudit.usableForCurrentDecision, true);
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(owner);
    assert.equal(checkpoint.usableForCurrentDecision, true);
    const snapshot = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(snapshot.status, "decision_blocked", "receipt recovery does not undo the original terminal revocation");
    const ledgerAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner);
    assert.equal(ledgerAudit.status, "active");
    assert.notEqual(ledgerAudit.latestReceipt.id, previousReceipt.id);
  });

  test("Batch 208: revoking a receipt lifecycle generation preserves terminal revocation and blocks closure", async t => {
    const { app, owner } = await currentGate(t, "b208-receipt-revocation");
    const revoked = await revoke(app, owner);
    assert.equal(revoked.complete, true);
    const receipt = revoked.revocationReceipt.event;
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      { action: "revoke", reason: "Withdraw this receipt generation while retaining the original revocation evidence." });
    assert.equal(challenge.targetReceiptId, receipt.id);
    const result = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(result.complete, true);
    assert.equal(result.receiptLifecycleAudit.status, "revoked");
    assert.equal(result.usableForCurrentDecision, false);
    const closure = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.equal(closure.status, "recovery_required");
    assert.equal(closure.usableForCurrentDecision, false);
  });

  test("Batch 208: lifecycle drift evidence checkpoint rejects provider reuse and strict mode blocks unenrolled use", async t => {
    const reused = await setupOwner(t, "b208-provider-reuse", {
      recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
      enrollRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: false,
      reuseRecoveryGateProofContinuityLifecycleDriftEvidenceProvider: true
    });
    const reusedState = await reused.app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(reused.owner);
    assert.equal(reusedState.status, "unhealthy");
    assert.ok(reusedState.findings.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_DRIFT_EVIDENCE_ANCHOR_PROVIDER_REUSED"));

    const strict = await setupOwner(t, "b208-unenrolled", {
      recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
      enrollRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: false
    });
    const strictState = await strict.app.getRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointStatus(strict.owner);
    assert.equal(strictState.usableForCurrentDecision, false);
    assert.ok(["enrollment_required", "not_initialized", "local_only"].includes(strictState.status));
    await assert.rejects(() => strict.app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(strict.owner,
      { action: "renew", reason: "Strict mode must reject lifecycle use before independent enrollment." }),
    error => error.code === "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_DRIFT_EVIDENCE_CHECKPOINT_NOT_CURRENT");
  });

  test("Batch 208: API registers lifecycle drift checkpoint and revocation receipt lifecycle routes", async () => {
    const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["lifecycle-drift-evidence-checkpoint/status", "lifecycle-drift-evidence-checkpoint/audit",
      "lifecycle-drift-evidence-checkpoint/enrollment/prepare", "lifecycle-drift-evidence-checkpoint/enrollment/apply",
      "lifecycle-drift-evidence-checkpoint/reconcile", "revocation-recovery/receipt/lifecycle/prepare",
      "revocation-recovery/receipt/lifecycle/apply", "revocation-recovery/receipt/lifecycle/audit"])
      assert.ok(source.includes(route), `missing route ${route}`);
  });
});
