import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, rotateKeyToOld } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function currentGate(t, owner) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true,
    recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true
  });
  await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
    { operationId: `${owner}-batch207-freshness` });
  const gate = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
  return { ...prepared, gate };
}

async function renew(app, owner, reason = "Renew proof continuity lifecycle evidence for Batch 207 validation.") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    { action: "renew", reason });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

async function revoke(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    { action: "revoke", reason: "Revoke proof continuity and preserve recovery receipt continuity evidence." });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

describe("Agentic AI V4 Batch 207", { concurrency: false }, () => {
  test("Batch 207: lifecycle checkpoint drift is retained, idempotent, and only resolved after checkpoint recovery", async t => {
    const { app, owner, anchors } = await currentGate(t, "b207-lifecycle-drift");
    const anchor = anchors.recoveryGateProofContinuityLifecycle;
    const [scope, enrolledAnchor] = [...anchor.records.entries()][0];
    const renewal = await renew(app, owner);
    assert.equal(renewal.complete, true);
    const currentAnchor = structuredClone(anchor.records.get(scope));
    assert.ok(currentAnchor.anchorSequence > enrolledAnchor.anchorSequence);
    anchor.records.set(scope, structuredClone(enrolledAnchor));
    const checkpointBefore = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    assert.notEqual(checkpointBefore.usableForCurrentDecision, true);
    const observed = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(observed.status, "drift_recorded");
    assert.equal(observed.driftAudit.unresolvedCount, 1);
    const repeated = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(repeated.event.id, observed.event.id);
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner)).unresolvedCount, 1);
    const blocked = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner);
    assert.equal(blocked.status, "recovery_required");
    assert.equal(blocked.reason, "lifecycle_checkpoint_not_current");
    assert.equal(anchor.records.get(scope).digest, enrolledAnchor.digest, "monitoring must not rewrite the external lifecycle anchor");
    anchor.records.set(scope, currentAnchor);
    const recovered = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner);
    assert.equal(recovered.driftAudit.unresolvedCount, 0);
    assert.equal(recovered.closureRevalidation.status, "stale", "a new continuity attestation invalidates the prior lifecycle generation binding");
    assert.equal(recovered.usableForCurrentDecision, false);
    const rebound = await renew(app, owner, "Rebind lifecycle generation after the recovered drift attestation changed the target.");
    assert.equal(rebound.complete, true);
    const currentClosure = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.ok(["verified_current", "decision_blocked"].includes(currentClosure.status));
    assert.equal(currentClosure.generationBindingCurrent, true);
    assert.equal(currentClosure.lifecycleGeneration, 2);
    const finalAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner);
    assert.equal(finalAudit.status, "clear");
    assert.equal(finalAudit.events.length, 1);
    assert.equal(finalAudit.events[0].resolved, true);
  });

  test("Batch 207: revocation receipt is independently anchored and receipt-commit recovery is idempotent", async t => {
    const { app, owner, anchors } = await currentGate(t, "b207-revocation-receipt");
    const continuity = anchors.recoveryGateProofContinuity;
    const [scope, anchorBefore] = [...continuity.records.entries()][0];
    const before = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpointStatus(owner);
    let originalCompareAndSet = continuity.compareAndSet.bind(continuity);
    const targetSourceCount = before.sourceCount + 4;
    continuity.compareAndSet = async function (scopeArg, expectedDigest, candidate) {
      if (candidate.sourceCount === targetSourceCount) {
        continuity.compareAndSet = originalCompareAndSet;
        return { applied: false };
      }
      return originalCompareAndSet(scopeArg, expectedDigest, candidate);
    };
    const revoked = await revoke(app, owner);
    assert.equal(revoked.complete, true);
    assert.equal(revoked.status, "recovery_required");
    assert.equal(revoked.revocationReceipt?.event?.eventType, "proof_continuity_revocation_recovery_receipt_finalized");
    assert.equal(revoked.revocationReceipt?.status, "recovery_required");
    const localReceiptId = revoked.revocationReceipt.event.id;
    const failedCheckpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpointStatus(owner);
    assert.notEqual(failedCheckpoint.usableForCurrentDecision, true);
    const resumed = await app.finalizeRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationRecoveryReceipt(owner);
    assert.equal(resumed.status, "finalized");
    assert.equal(resumed.event.id, localReceiptId);
    assert.equal(resumed.idempotent, true);
    const checkpointAfter = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpointStatus(owner);
    assert.equal(checkpointAfter.usableForCurrentDecision, true);
    assert.ok(checkpointAfter.sourceCount > anchorBefore.sourceCount);
    const closure = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.equal(closure.status, "decision_blocked");
    assert.equal(closure.usableForCurrentDecision, false);
    assert.equal(closure.revocationReceipt.id, localReceiptId);
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner);
    assert.equal(audit.status, "revoked");
    assert.equal(audit.revocationReceiptRequired, false);
    await assert.rejects(() => app.attestRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner),
      error => error.code === "RECOVERY_GATE_PROOF_CONTINUITY_ATTESTATION_REVOKED");
  });

  test("Batch 207: closure revalidation binds each lifecycle generation and rejects stale revocation evidence", async t => {
    const { app, owner } = await currentGate(t, "b207-generation-closure");
    const first = await renew(app, owner, "Renew lifecycle generation one for cross-generation closure validation.");
    assert.equal(first.complete, true);
    const closureOne = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.ok(["verified_current", "decision_blocked"].includes(closureOne.status));
    assert.equal(closureOne.generationBindingCurrent, true);
    assert.equal(closureOne.lifecycleGeneration, 1);
    const second = await renew(app, owner, "Renew lifecycle generation two for cross-generation closure validation.");
    assert.equal(second.complete, true);
    const closureTwo = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.ok(["verified_current", "decision_blocked"].includes(closureTwo.status));
    assert.equal(closureTwo.generationBindingCurrent, true);
    assert.equal(closureTwo.lifecycleGeneration, 2);
    assert.notEqual(closureTwo.generationBindingDigest, closureOne.generationBindingDigest);
    const revoked = await revoke(app, owner);
    assert.equal(revoked.complete, true);
    const closureRevoked = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.equal(closureRevoked.status, "decision_blocked");
    assert.equal(closureRevoked.generationBindingCurrent, true);
    assert.equal(closureRevoked.lifecycleGeneration, 3);
    assert.equal(closureRevoked.revocationReceipt?.id, revoked.revocationReceipt?.event?.id);
    await rotateKeyToOld(app, owner);
    const cutoff = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.equal(cutoff.status, "recovery_required");
    assert.equal(cutoff.generationBindingCurrent, false);
    const reissued = await app.finalizeRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityRevocationRecoveryReceipt(owner);
    assert.equal(reissued.status, "finalized");
    assert.equal(reissued.event.stableBinding.receiptGeneration, 2);
    assert.equal(reissued.event.stableBinding.previousReceiptId, revoked.revocationReceipt.event.id);
    assert.equal(reissued.event.stableBinding.previousReceiptDigest, revoked.revocationReceipt.event.digest);
    const afterCutoff = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleClosure(owner);
    assert.equal(afterCutoff.status, "decision_blocked");
    assert.equal(afterCutoff.generationBindingCurrent, true);
    assert.equal(afterCutoff.revocationReceipt.id, reissued.event.id);
  });

  test("Batch 207: lifecycle drift, revocation receipt, and closure revalidation routes are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-drift\/monitor/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-drift\/audit/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-drift\/reconcile/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/revocation-recovery\/receipt\/finalize/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-closure\/revalidate/);
    const service = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
    assert.match(service, /proof_continuity_revocation_recovery_receipt_finalized/);
    assert.match(service, /revalidateLifecycleClosure/);
    assert.match(service, /checkpointScope: scope/);
  });
});
