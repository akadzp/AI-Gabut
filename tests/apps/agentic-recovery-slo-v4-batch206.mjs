import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function currentGate(t, owner, options = {}) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true, ...options
  });
  await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
    { operationId: `${owner}-batch206-freshness` });
  const gate = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
  return { ...prepared, gate };
}

async function lifecycleCheckpointSnapshot(anchors) {
  return [...anchors.recoveryGateProofContinuityLifecycle.records.values()][0] || null;
}

describe("Agentic AI V4 Batch 206", { concurrency: false }, () => {
  test("Batch 206: lifecycle renewal events are independently anchored and generation evidence is retained", async t => {
    const { app, owner, anchors } = await currentGate(t, "b206-renew");
    const before = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    assert.equal(before.usableForCurrentDecision, true);
    assert.equal(before.sourceCount, 0);
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Renew the continuity attestation with independent lifecycle evidence retention." });
    const result = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(result.complete, true);
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpoint(owner);
    assert.equal(checkpoint.usableForCurrentDecision, true);
    assert.equal(lifecycleAudit.usableForCurrentDecision, true);
    assert.equal(checkpoint.sourceCount, lifecycleAudit.localLifecycleAudit.eventCount);
    assert.equal((await lifecycleCheckpointSnapshot(anchors)).sourceCount, checkpoint.sourceCount);
    assert.equal(result.continuityLifecycleCheckpoint.usableForCurrentDecision, true);
  });

  test("Batch 206: failed lifecycle-anchor write is reconciled and the same challenge resumes without duplicate intent", async t => {
    const { app, owner, anchors } = await currentGate(t, "b206-crash");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Exercise multi-phase lifecycle recovery after external anchor interruption." });
    anchors.recoveryGateProofContinuityLifecycle.failWrites = true;
    const interrupted = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.checkpointError);
    assert.equal(interrupted.continuityLifecycleCheckpoint.usableForCurrentDecision, false);
    anchors.recoveryGateProofContinuityLifecycle.failWrites = false;
    const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpoint(owner);
    assert.ok(["anchored", "marker_repaired"].includes(reconciled.status));
    const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(resumed.complete, true);
    const local = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner);
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    assert.equal(lifecycle.status, "active");
    assert.equal(checkpoint.usableForCurrentDecision, true);
    assert.equal(checkpoint.sourceCount, lifecycle.eventCount);
    assert.equal(local.continuityLifecycleCheckpoint.usableForCurrentDecision, true);
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner)).eventCount,
      local.eventCount);
  });

  test("Batch 206: revocation remains anchored and lifecycle audit blocks target reuse", async t => {
    const { app, owner } = await currentGate(t, "b206-revoke");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "revoke", reason: "Retain a terminal revocation record under its independent lifecycle checkpoint." });
    const result = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(result.complete, true);
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpoint(owner);
    assert.equal(checkpoint.usableForCurrentDecision, true);
    assert.equal(audit.localLifecycleAudit.status, "revoked");
    assert.equal(audit.usableForCurrentDecision, false);
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Attempt to renew a continuity attestation after terminal revocation." }),
    error => error.code === "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_TARGET_REVOKED");
  });

  test("Batch 206: strict lifecycle mode blocks operations until independent lifecycle checkpoint enrollment", async t => {
    const { app, owner } = await currentGate(t, "b206-strict", { enrollRecoveryGateProofContinuityLifecycleCheckpoint: false });
    const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    assert.equal(checkpoint.usableForCurrentDecision, false);
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Attempt lifecycle renewal before required checkpoint enrollment." }),
    error => error.code === "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_CHECKPOINT_NOT_CURRENT");
    const enrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointEnrollment(owner,
      { reason: "Enroll the independent lifecycle checkpoint before enabling lifecycle changes." });
    await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointEnrollment(owner,
      enrollment.challengeId, { confirmation: enrollment.confirmation });
    const enrolled = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    assert.equal(enrolled.usableForCurrentDecision, true);
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Prepare renewal after the required lifecycle checkpoint is enrolled." });
    assert.equal(challenge.status, "prepared");
  });

  test("Batch 206: reused provider is rejected and cannot authorize lifecycle evidence", async t => {
    const { app, owner } = await setupOwner(t, "b206-provider-reuse", {
      recoveryGateProofContinuityLifecycleCheckpoint: true,
      enrollRecoveryGateProofContinuityLifecycleCheckpoint: false,
      reuseRecoveryGateProofContinuityLifecycleProvider: true
    });
    const status = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointStatus(owner);
    assert.equal(status.status, "unhealthy");
    assert.equal(status.usableForCurrentDecision, false);
    assert.ok(status.findings.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_ANCHOR_PROVIDER_REUSED"));
  });

  test("Batch 206: lifecycle checkpoint APIs and deployment configuration are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-checkpoint\/status/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-checkpoint\/audit/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-checkpoint\/enrollment\/prepare/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-checkpoint\/enrollment\/apply/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle-checkpoint\/reconcile/);
    const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(appSource, /AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_ANCHOR_URL/);
    assert.match(appSource, /RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_ANCHOR_PROVIDER_REUSED/);
    assert.match(appSource, /getLifecycleSnapshot/);
  });
});
