import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function currentGate(t, owner, options = {}) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true,
    recoveryGateProofContinuityCheckpoint: true,
    ...options
  });
  await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
    { operationId: `${owner}-batch204-freshness` });
  return { ...prepared, gate: await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner) };
}

async function rotateSigningKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_old", reason: "Rotate signing key to validate Batch 204 continuity cutoff handling." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}

describe("Agentic AI V4 Batch 204", { concurrency: false }, () => {
  test("Batch 204: proof continuity attestation is independently anchored and bound to the current proof", async t => {
    const { app, owner, anchors, gate } = await currentGate(t, "b204-continuity-current");
    assert.equal(gate.status, "recovery_required");
    assert.equal(gate.usableForCurrentDecision, false);
    assert.ok(gate.proofContinuity?.event?.id);
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(audit.status, "decision_blocked");
    assert.equal(audit.usableForCurrentDecision, false);
    assert.ok(audit.latestAttestation?.id);
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpointStatus(owner);
    assert.equal(checkpoint.usableForCurrentDecision, true);
    assert.equal([...anchors.recoveryGateProofContinuity.records.values()][0].sourceCount, audit.eventCount);
  });

  test("Batch 204: external proof-anchor drift is retained, idempotent, and resolved only after re-attestation", async t => {
    const { app, owner, anchors } = await currentGate(t, "b204-continuity-drift");
    const [scope, anchor] = [...anchors.recoveryGateProof.records.entries()][0];
    anchors.recoveryGateProof.records.delete(scope);
    const observed = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityDrift(owner);
    assert.equal(observed.status, "drift_recorded");
    assert.equal(observed.usableForCurrentDecision, false);
    assert.equal(observed.audit.status, "recovery_required");
    const firstCount = observed.audit.eventCount;
    const repeated = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityDrift(owner);
    assert.equal(repeated.event.id, observed.event.id);
    assert.equal(repeated.audit.eventCount, firstCount);
    anchors.recoveryGateProof.records.set(scope, anchor);
    const reattested = await app.attestRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(reattested.status, "decision_blocked");
    assert.equal(reattested.usableForCurrentDecision, false);
    assert.equal(reattested.audit.unresolvedDriftCount, 0);
    assert.equal(reattested.continuityCheckpoint.usableForCurrentDecision, true);
  });

  test("Batch 204: continuity event survives external-write failure and reconciles without duplication", async t => {
    const prepared = await createCurrentRevalidation(t, "b204-continuity-crash", {
      revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true,
      recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true
    });
    await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
      { operationId: "b204-continuity-crash-freshness" });
    prepared.anchors.recoveryGateProofContinuity.failWrites = true;
    const gate = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
    assert.equal(gate.usableForCurrentDecision, false);
    assert.ok(gate.proofContinuity?.event?.id);
    assert.ok(gate.proofContinuity.checkpointError);
    const before = await prepared.app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(prepared.owner);
    assert.equal(before.status, "recovery_required");
    prepared.anchors.recoveryGateProofContinuity.failWrites = false;
    const reconciled = await prepared.app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpoint(prepared.owner);
    assert.ok(["anchored", "marker_repaired"].includes(reconciled.status));
    const after = await prepared.app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(prepared.owner);
    assert.equal(after.status, "decision_blocked");
    assert.equal(after.eventCount, before.eventCount);
    const replay = await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(prepared.owner);
    assert.equal(replay.event.id, before.latestAttestation?.id || replay.event.id);
    assert.equal(replay.usableForCurrentDecision, false);
    assert.ok(replay.event?.id);
  });

  test("Batch 204: failed proof-checkpoint reconciliation persists drift evidence before returning blocked", async t => {
    const prepared = await createCurrentRevalidation(t, "b204-gap", {
      revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true,
      recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true
    });
    await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
      { operationId: "b204-gap-freshness" });
    prepared.anchors.recoveryGateProof.failWrites = true;
    const first = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
    assert.equal(first.usableForCurrentDecision, false);
    assert.ok(first.recoveryGateProof?.id);
    const retried = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
    assert.equal(retried.usableForCurrentDecision, false);
    assert.ok(retried.proofContinuityDrift?.event?.id);
    assert.equal(retried.proofContinuityDrift.audit.unresolvedDriftCount, 1);
    prepared.anchors.recoveryGateProof.failWrites = false;
    const proofReconciled = await prepared.app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpoint(prepared.owner);
    assert.ok(["anchored", "marker_repaired"].includes(proofReconciled.status));
    const continuity = await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(prepared.owner);
    assert.equal(continuity.audit.unresolvedDriftCount, 0);
    assert.equal(continuity.continuityCheckpoint.usableForCurrentDecision, true);
  });

  test("Batch 204: signing-key rotation makes prior proof-continuity attestation stale", async t => {
    const { app, owner } = await currentGate(t, "b204-continuity-key-cutoff");
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner)).status, "decision_blocked");
    await rotateSigningKey(app, owner);
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.notEqual(audit.status, "verified_current");
    assert.equal(audit.usableForCurrentDecision, false);
    assert.ok(audit.findings.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_ATTESTATION_STALE"));
  });

  test("Batch 204: strict continuity mode blocks proof creation before continuity checkpoint enrollment", async t => {
    const { app, owner } = await createCurrentRevalidation(t, "b204-enroll", {
      revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true,
      recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true,
      enrollRecoveryGateProofContinuityCheckpoint: false
    });
    await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(owner,
      { operationId: "b204-continuity-enrollment-freshness" });
    const gate = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
    assert.equal(gate.status, "recovery_required");
    assert.equal(gate.checkpointError.code, "RECOVERY_GATE_PROOF_CONTINUITY_CHECKPOINT_NOT_CURRENT");
    const proof = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleRecoveryGateProof(owner);
    assert.equal(proof.eventCount, 0);
  });

  test("Batch 204: provider reuse is rejected for the independent continuity checkpoint", async t => {
    const { app, owner } = await setupOwner(t, "b204-reuse", {
      recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true,
      enrollRecoveryGateProofContinuityCheckpoint: false, reuseRecoveryGateProofContinuityProvider: true
    });
    const status = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpointStatus(owner);
    assert.equal(status.status, "unhealthy");
    assert.equal(status.usableForCurrentDecision, false);
    assert.ok(status.findings.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_ANCHOR_PROVIDER_REUSED"));
  });

  test("Batch 204: continuity checkpoint, drift, and attestation routes are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    assert.match(server, /recovery-gate\/proof\/continuity/);
    assert.match(server, /checkpoint\/enrollment\/prepare/);
    assert.match(server, /checkpoint\/enrollment\/apply/);
    assert.match(server, /checkpoint\/reconcile/);
    assert.match(server, /\/drift\/monitor/);
    assert.match(server, /\/attest/);
    const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(appSource, /CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_DOMAIN/);
    assert.match(appSource, /auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity/);
  });
});
