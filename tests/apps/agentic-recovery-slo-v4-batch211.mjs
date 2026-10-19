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
    { operationId: `${owner}-batch211-freshness` });
  await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
  return prepared;
}

describe("Agentic AI V4 Batch 211", { concurrency: false }, () => {
  test("Batch 211: binding-attestation renewal is superseded, externally checkpointed, and operation-id replay is idempotent", async t => {
    const { app, owner } = await currentGate(t, "b211-renew", { requireReceiptLifecycleCheckpointBindingAttestation: true });
    const first = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBinding(owner);
    assert.equal(first.status, "verified_current");
    const renewed = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBindingAttestation(owner,
      { operationId: "b211-renew-operation-1" });
    assert.equal(renewed.status, "verified_current");
    assert.equal(renewed.event.generation, first.event.generation + 1);
    assert.ok(renewed.supersession?.id);
    assert.equal(renewed.supersession.stableBinding?.action, "renew");
    const replay = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBindingAttestation(owner,
      { operationId: "b211-renew-operation-1" });
    assert.equal(replay.event.id, renewed.event.id);
    assert.equal(replay.idempotent, true);
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBindingAttestation(owner);
    assert.equal(audit.status, "verified_current");
    assert.equal(audit.supersessionComplete, true);
    assert.equal(audit.latestSupersession.action, "renew");
  });

  test("Batch 211: multi-checkpoint finalization has a signed externally anchored attestation and replay-safe audit", async t => {
    const { app, owner, anchors } = await currentGate(t, "b211-finalize");
    const result = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
    assert.ok(["finalized_current", "decision_blocked"].includes(result.status), JSON.stringify({ status: result.status, audit: result.audit }));
    assert.ok(result.finalization?.id);
    assert.ok(result.finalizationAttestation?.id);
    assert.equal(result.finalizationAttestationAudit.status, "verified_current");
    const attestationAudit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalizationAttestation(owner);
    assert.equal(attestationAudit.status, "verified_current");
    const firstAttestationId = attestationAudit.latestAttestation.id;
    const replayAttestation = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.equal(replayAttestation.event.id, firstAttestationId);
    assert.equal(replayAttestation.idempotent, true);
    const repeated = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
    assert.equal(repeated.idempotent, true);
    const after = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalizationAttestation(owner);
    assert.equal(after.latestAttestation.id, firstAttestationId);

    const [scope, saved] = [...anchors.recoveryGateProofContinuity.records.entries()][0];
    anchors.recoveryGateProofContinuity.records.set(scope, { ...saved, anchorSequence: saved.anchorSequence + 2 });
    const stale = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalizationAttestation(owner);
    assert.notEqual(stale.status, "verified_current");
    const finalizationAudit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.notEqual(finalizationAudit.status, "finalized_current");
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.notEqual(convergence.status, "converged_current");
    assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_NOT_CURRENT"));
  });

  test("Batch 211: missing finalization attestation is resumed after an external checkpoint write failure", async t => {
    const { app, owner, anchors } = await currentGate(t, "b211-recover");
    anchors.recoveryGateProofContinuity.failWrites = true;
    const interrupted = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
    assert.equal(interrupted.status, "recovery_required");
    anchors.recoveryGateProofContinuity.failWrites = false;
    const resumed = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(owner);
    assert.ok(["finalized_current", "decision_blocked"].includes(resumed.status), JSON.stringify({ status: resumed.status, audit: resumed.audit }));
    const attestationAudit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalizationAttestation(owner);
    assert.equal(attestationAudit.status, "verified_current");
    const ledger = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.equal(ledger.intents.length, 1);
    assert.equal(ledger.finalizations.length, 1);
    assert.equal(ledger.attestations.length, 1);
  });

  test("Batch 211: renewal and finalization-attestation routes plus validation guards are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["receipt-lifecycle-checkpoint/binding-attestation/renew", "recovery-intent/finalization/attest",
      "recovery-intent/finalization/attestation/audit"])
      assert.ok(server.includes(route), `missing route ${route}`);
    const service = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
    assert.match(service, /proof_continuity_receipt_lifecycle_checkpoint_binding_attestation_superseded/);
    assert.match(service, /proof_continuity_multi_checkpoint_recovery_intent_finalization_attested/);
    assert.match(service, /BINDING_RENEWAL_OPERATION_ID_REQUIRED/);
    const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(application, /attestRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization/);
  });
});
