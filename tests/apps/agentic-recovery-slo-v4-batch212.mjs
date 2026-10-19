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
    ...options
  });
  const { app, owner: user } = prepared;
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(user,
    { operationId: `${owner}-batch212-freshness` });
  await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(user);
  const finalization = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(user);
  assert.ok(["finalized_current", "decision_blocked"].includes(finalization.status),
    JSON.stringify({ status: finalization.status, audit: finalization.audit, convergence: finalization.convergence }));
  assert.ok(finalization.finalizationAttestation?.id);
  const lifecycleCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpointStatus(user);
  assert.equal(lifecycleCheckpoint.usableForCurrentDecision, true, JSON.stringify(lifecycleCheckpoint));
  return { ...prepared, finalization };
}

async function applyLifecycleUntilComplete(app, owner, challenge) {
  let result = null;
  for (let attempt = 0; attempt < 12; attempt++) {
    result = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true) return result;
  }
  throw new Error(`lifecycle operation did not complete: ${JSON.stringify({ status: result?.status, phase: result?.phase, audit: result?.audit })}`);
}

describe("Agentic AI V4 Batch 212", { concurrency: false }, () => {
  test("Batch 212: renewal supersedes the prior finalization attestation and replay is idempotent", async t => {
    const { app, owner } = await readyFinalization(t, "b212-renew");
    const before = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalizationAttestation(owner);
    assert.equal(before.status, "verified_current");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "renew", reason: "Renew finalization evidence after independent lifecycle checkpoint verification."
    });
    const applied = await applyLifecycleUntilComplete(app, owner, challenge);
    assert.equal(applied.status, "verified_current", JSON.stringify({ status: applied.status, audit: applied.audit }));
    assert.ok(applied.replacementAttestationId);
    const after = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalizationAttestation(owner);
    assert.equal(after.status, "verified_current");
    assert.notEqual(after.latestAttestation.id, before.latestAttestation.id);
    const replay = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(replay.idempotent, true);
    assert.equal(replay.audit.status, "verified_current");
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner);
    assert.equal(lifecycle.status, "verified_current");
    assert.equal(lifecycle.latestLifecycleEvent.eventType, "proof_continuity_finalization_attestation_lifecycle_finalized");
  });

  test("Batch 212: revocation is terminal and blocks current-decision use after independent anchoring", async t => {
    const { app, owner } = await readyFinalization(t, "b212-revoke");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "revoke", reason: "Revoke this finalization attestation due to an authorized lifecycle decision."
    });
    const result = await applyLifecycleUntilComplete(app, owner, challenge);
    assert.equal(result.status, "decision_blocked", JSON.stringify({ status: result.status, audit: result.audit }));
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner);
    assert.equal(lifecycle.status, "decision_blocked");
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergence.status, "decision_blocked", JSON.stringify({ status: convergence.status, blockers: convergence.blockers }));
    assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_REVOKED"
      || item.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_REVOKED"));
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "renew", reason: "Attempt renewal after terminal revocation must be rejected."
    }));
  });

  test("Batch 212: failed lifecycle checkpoint write resumes without duplicating lifecycle events", async t => {
    const { app, owner, anchors } = await readyFinalization(t, "b212-recovery");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "renew", reason: "Exercise recovery after lifecycle checkpoint write failure."
    });
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycle.failWrites = true;
    const interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(interrupted.status, "recovery_required");
    const partial = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    const lifecycleEventsBefore = (await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner)).latestLifecycleEvent;
    assert.ok(lifecycleEventsBefore);
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycle.failWrites = false;
    const resumed = await applyLifecycleUntilComplete(app, owner, challenge);
    assert.equal(resumed.status, "verified_current", JSON.stringify({ status: resumed.status, audit: resumed.audit }));
    const after = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.equal(after.attestations.length, partial.attestations.length + 1);
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner);
    assert.equal(lifecycle.status, "verified_current");
  });

  test("Batch 212: strict mode blocks lifecycle mutation until enrollment and rejects a reused provider", async t => {
    const { app, owner } = await setupOwner(t, "b212-strict", {
      recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true,
      enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: false
    });
    const state = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpointStatus(owner);
    assert.equal(state.enabled, true);
    assert.equal(state.usableForCurrentDecision, false);
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(owner, {
      action: "renew", reason: "Strict mode must reject lifecycle changes until enrollment completes."
    }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_CHECKPOINT_NOT_CURRENT");
    await assert.rejects(() => setupOwner(t, "b212-reuse", {
      recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true,
      reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleProvider: true
    }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_ANCHOR_PROVIDER_REUSED");
  });

  test("Batch 212: independent checkpoint routes and lifecycle guards are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["finalization-attestation-lifecycle-checkpoint/status", "finalization-attestation-lifecycle-checkpoint/enrollment/prepare",
      "finalization-attestation-lifecycle-checkpoint/enrollment/apply", "finalization-attestation-lifecycle-checkpoint/reconcile",
      "finalization-attestation/lifecycle/prepare", "finalization-attestation/lifecycle/apply", "finalization-attestation/lifecycle/audit"])
      assert.ok(server.includes(route), `missing route ${route}`);
    const app = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(app, /RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_ANCHOR_PROVIDER_REUSED/);
    assert.match(app, /AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_ATTESTATION_LIFECYCLE_ANCHOR/);
    const service = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
    assert.match(service, /proof_continuity_finalization_attestation_lifecycle_revoked/);
    assert.match(service, /FINALIZATION_ATTESTATION_LIFECYCLE_SNAPSHOT_CHANGED/);
  });
});
