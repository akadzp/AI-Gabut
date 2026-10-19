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
    recoveryGateProofContinuityReceiptLifecycleCheckpoint: true,
    ...options
  });
  await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
    { operationId: `${owner}-batch210-freshness` });
  await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
  return prepared;
}

async function renewContinuity(app, owner, reason = "Renew proof-continuity lifecycle for Batch 210 checkpoint binding.") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    { action: "renew", reason });
  return app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

describe("Agentic AI V4 Batch 210", { concurrency: false }, () => {
  test("Batch 210: receipt-lifecycle checkpoint binding attestation is signed, current, idempotent, and strict-gated", async t => {
    const { app, owner, anchors } = await currentGate(t, "b210-binding-attestation", {
      requireReceiptLifecycleCheckpointBindingAttestation: true
    });
    const before = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBindingAttestation(owner);
    assert.equal(before.status, "missing");
    const convergenceBefore = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergenceBefore.usableForCurrentDecision, false);
    assert.ok(convergenceBefore.blockers.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_NOT_CURRENT"));

    anchors.recoveryGateProofContinuity.failWrites = true;
    const interrupted = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBinding(owner);
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.event?.id, "signed binding attestation must persist before checkpoint advancement");
    anchors.recoveryGateProofContinuity.failWrites = false;
    const issued = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBinding(owner);
    assert.equal(issued.status, "verified_current");
    assert.equal(issued.usableForCurrentDecision, true);
    assert.equal(issued.audit.bindingMatches, true);
    assert.equal(issued.event.id, interrupted.event.id);
    assert.equal(issued.idempotent, true);
    const repeated = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBinding(owner);
    assert.equal(repeated.event.id, issued.event.id);
    assert.equal(repeated.idempotent, true);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBindingAttestation(owner);
    assert.equal(audit.status, "verified_current");
    assert.equal(audit.usableForCurrentDecision, true);

    const anchor = anchors.recoveryGateProofContinuityReceiptLifecycle;
    const [scope, saved] = [...anchor.records.entries()][0];
    anchor.records.set(scope, { ...saved, anchorSequence: saved.anchorSequence + 2 });
    const stale = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBindingAttestation(owner);
    assert.notEqual(stale.status, "verified_current");
    const convergenceAfter = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergenceAfter.usableForCurrentDecision, false);
  });

  test("Batch 210: drift-resolution supersession receipt is linked, independently checkpointed, and idempotent", async t => {
    const { app, owner, anchors } = await currentGate(t, "b210-drift-supersession");
    const lifecycleAnchor = anchors.recoveryGateProofContinuityLifecycle;
    const [scope, enrolledAnchor] = [...lifecycleAnchor.records.entries()][0];
    const renewed = await renewContinuity(app, owner);
    assert.equal(renewed.complete, true);
    const recoveredAnchor = structuredClone(lifecycleAnchor.records.get(scope));
    lifecycleAnchor.records.set(scope, structuredClone(enrolledAnchor));
    const observed = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDrift(owner);
    assert.equal(observed.status, "drift_recorded");
    lifecycleAnchor.records.set(scope, recoveredAnchor);
    const recovered = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidence(owner);
    assert.equal(recovered.driftAudit.unresolvedCount, 0);
    const receipt = recovered.resolutionReceipt?.event
      || recovered.attestation?.checkpointAdvance?.driftResolutionReceipts?.find(item => item.event)?.event;
    assert.ok(receipt?.stableBinding?.continuityEventId);

    const superseded = await app.supersedeRecoverySloCrossDomainRecoveryGateProofContinuityDriftResolutionReceipt(owner,
      receipt.stableBinding.continuityEventId);
    assert.equal(superseded.status, "verified_current");
    assert.equal(superseded.usableForCurrentDecision, true);
    assert.equal(superseded.audit.bindingMatches, true);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityDriftResolutionSupersession(owner,
      receipt.stableBinding.continuityEventId);
    assert.equal(audit.status, "verified_current");
    const repeated = await app.supersedeRecoverySloCrossDomainRecoveryGateProofContinuityDriftResolutionReceipt(owner,
      receipt.stableBinding.continuityEventId);
    assert.equal(repeated.event.id, superseded.event.id);
    assert.equal(repeated.idempotent, true);
  });

  test("Batch 210: multi-checkpoint recovery-intent finalization recovers after checkpoint write failure without duplicate receipts", async t => {
    const { app, owner, anchors } = await currentGate(t, "b210-finalize");
    anchors.recoveryGateProofContinuity.failWrites = true;
    const interrupted = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.intent?.id);
    assert.equal(interrupted.usableForCurrentDecision, false);
    const ledgerBefore = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.equal(ledgerBefore.intents.length, 1);
    assert.equal(ledgerBefore.finalizations.length, 0);

    anchors.recoveryGateProofContinuity.failWrites = false;
    const resumed = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
    assert.ok(["decision_blocked", "finalized_current"].includes(resumed.status));
    assert.ok(resumed.finalization?.id);
    const ledgerAfter = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.equal(ledgerAfter.intents.length, 1);
    assert.equal(ledgerAfter.finalizations.length, 1);
    assert.equal(ledgerAfter.finalizations[0].intentEventId, ledgerAfter.intents[0].id);
    const repeated = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
    assert.equal(repeated.finalization.id, resumed.finalization.id);
    assert.equal(repeated.idempotent, true);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.ok(["decision_blocked", "finalized_current"].includes(audit.status));
    assert.equal(audit.pendingIntentIds.length, 0);
  });

  test("Batch 210: binding-attestation, supersession, and multi-checkpoint finalization routes and guards are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["receipt-lifecycle-checkpoint/binding-attestation/attest", "receipt-lifecycle-checkpoint/binding-attestation/audit",
      "drift-resolution/supersession", "drift-resolution/supersession/audit", "recovery-intent/finalize",
      "recovery-intent/finalization/audit", "recovery-intent/finalization/ledger"])
      assert.ok(server.includes(route), `missing route ${route}`);
    const service = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
    assert.match(service, /proof_continuity_receipt_lifecycle_checkpoint_binding_attested/);
    assert.match(service, /proof_continuity_drift_resolution_receipt_superseded/);
    assert.match(service, /proof_continuity_multi_checkpoint_recovery_intent_finalized/);
    const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(application, /AGENTIC_REQUIRE_RECOVERY_GATE_PROOF_CONTINUITY_RECEIPT_LIFECYCLE_CHECKPOINT_BINDING_ATTESTATION/);
  });
});
