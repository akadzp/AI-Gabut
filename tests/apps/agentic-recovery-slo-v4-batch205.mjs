import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, rotateKeyToOld } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function currentGate(t, owner, options = {}) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true, requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true, recoveryGateProofContinuityCheckpoint: true, ...options
  });
  await prepared.app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(prepared.owner,
    { operationId: `${owner}-batch205-freshness` });
  const gate = await prepared.app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(prepared.owner);
  return { ...prepared, gate };
}

describe("Agentic AI V4 Batch 205", { concurrency: false }, () => {
  test("Batch 205: renewal creates a signed supersession chain and is idempotent on replay", async t => {
    const { app, owner } = await currentGate(t, "b205-renew");
    const before = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.ok(before.latestAttestation?.id);
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Renew continuity attestation under the current checkpoint and key binding." });
    const applied = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(applied.complete, true);
    assert.equal(applied.event.eventType, "proof_continuity_attestation_lifecycle_finalized");
    assert.equal(applied.usableForCurrentDecision, false); // The underlying proof audit is decision-blocked in this fixture.
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner);
    assert.equal(lifecycle.status, "active");
    assert.equal(lifecycle.latestAction.lifecycleGeneration, 1);
    const count = (await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner)).eventCount;
    const replay = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(replay.complete, true);
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner)).eventCount, count);
  });

  test("Batch 205: renewal generations advance monotonically and reject cross-generation replay", async t => {
    const { app, owner } = await currentGate(t, "b205-generation");
    const first = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Create the first managed lifecycle generation for replay protection." });
    const firstApplied = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      first.challengeId, { confirmation: first.confirmation });
    assert.equal(firstApplied.complete, true);
    const second = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Create a distinct second lifecycle generation without replaying generation one." });
    assert.equal(second.lifecycleGeneration, 2);
    const secondApplied = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      second.challengeId, { confirmation: second.confirmation });
    assert.equal(secondApplied.complete, true);
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner);
    assert.equal(lifecycle.status, "active");
    assert.equal(lifecycle.latestAction.lifecycleGeneration, 2);
    assert.equal(lifecycle.invalidSignatureCount, 0);
  });

  test("Batch 205: lifecycle intent survives external checkpoint failure and resumes without duplicate intent", async t => {
    const { app, owner, anchors } = await currentGate(t, "b205-crash-recovery");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Exercise durable lifecycle intent recovery after an external anchor write failure." });
    anchors.recoveryGateProofContinuity.failWrites = true;
    const interrupted = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.checkpointError);
    anchors.recoveryGateProofContinuity.failWrites = false;
    const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(resumed.complete, true);
    const snapshot = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    const lifecycleIntents = snapshot.eventCount && [...anchors.recoveryGateProofContinuity.records.values()][0]?.sourceCount;
    assert.equal(lifecycleIntents, snapshot.eventCount);
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner);
    assert.equal(lifecycle.status, "active");
  });

  test("Batch 205: revocation is terminal for the target and blocks current-decision use", async t => {
    const { app, owner } = await currentGate(t, "b205-revoke");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "revoke", reason: "Revoke the current continuity attestation after an explicit operator review." });
    const result = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(result.complete, true);
    const lifecycle = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner);
    assert.equal(lifecycle.status, "revoked");
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(audit.usableForCurrentDecision, false);
    assert.ok(audit.findings.some(item => item.code === "RECOVERY_GATE_PROOF_CONTINUITY_ATTESTATION_REVOKED"));
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Attempt to renew an attestation after its terminal revocation." }),
    error => error.code === "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_TARGET_REVOKED");
  });

  test("Batch 205: drift resolution receives a separately signed and checkpointed finalization receipt", async t => {
    const { app, owner, anchors } = await currentGate(t, "b205-drift-finalization");
    const [scope, anchor] = [...anchors.recoveryGateProof.records.entries()][0];
    anchors.recoveryGateProof.records.delete(scope);
    const drift = await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityDrift(owner);
    assert.equal(drift.status, "drift_recorded");
    anchors.recoveryGateProof.records.set(scope, anchor);
    const reattested = await app.attestRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(reattested.audit.unresolvedDriftCount, 0);
    assert.equal(reattested.audit.pendingDriftResolutionReceiptCount, 0);
    const snapshot = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpoint(owner);
    assert.equal(snapshot.usableForCurrentDecision, true);
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.ok(audit.eventCount >= 4);
    assert.equal(audit.pendingDriftResolutionReceiptCount, 0);
  });

  test("Batch 205: drift receipt finalization resumes after continuity anchor failure without duplicate receipts", async t => {
    const { app, owner, anchors } = await currentGate(t, "b205-drift-crash");
    const [proofScope, proofAnchor] = [...anchors.recoveryGateProof.records.entries()][0];
    anchors.recoveryGateProof.records.delete(proofScope);
    await app.monitorRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityDrift(owner);
    anchors.recoveryGateProof.records.set(proofScope, proofAnchor);
    anchors.recoveryGateProofContinuity.failWrites = true;
    const interrupted = await app.attestRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(interrupted.usableForCurrentDecision, false);
    assert.ok(interrupted.checkpointError);
    anchors.recoveryGateProofContinuity.failWrites = false;
    await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpoint(owner);
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(audit.pendingDriftResolutionReceiptCount, 0);
    const snapshot = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpoint(owner);
    assert.equal(snapshot.usableForCurrentDecision, true);
    const receiptEvents = (await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner)).eventCount;
    await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpoint(owner);
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner)).eventCount, receiptEvents);
  });

  test("Batch 205: signing-key cutoff after intent is recorded but before apply prevents stale lifecycle use", async t => {
    const { app, owner } = await currentGate(t, "b205-cutoff");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Prepare renewal before testing a signing-key lifecycle cutoff." });
    await rotateKeyToOld(app, owner);
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      { action: "renew", reason: "Reject lifecycle renewal while its target attestation is stale." }),
    error => error.code === "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_TARGET_STALE");
    const blocked = await app.applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(blocked.status, "recovery_required");
    assert.equal(blocked.checkpointError.code, "RECOVERY_GATE_PROOF_CONTINUITY_LIFECYCLE_KEY_CUTOFF");
    const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuity(owner);
    assert.equal(audit.usableForCurrentDecision, false);
  });

  test("Batch 205: lifecycle routes and public application methods are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle\/prepare/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle\/apply/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/lifecycle\/audit/);
    assert.match(server, /recoveryGateProofContinuityRoot}\/drift\/finalize/);
    const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(appSource, /prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAttestationLifecycle/);
    assert.match(appSource, /finalizeRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityDriftResolution/);
  });
});
