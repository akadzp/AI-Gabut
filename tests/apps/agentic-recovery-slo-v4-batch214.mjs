import test, { describe } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createCurrentRevalidation, setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

async function readyReceipt(t, owner) {
  const prepared = await createCurrentRevalidation(t, owner, {
    revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true,
    recoveryGateProofCheckpoint: true,
    recoveryGateProofContinuityCheckpoint: true,
    recoveryGateProofContinuityLifecycleCheckpoint: true,
    recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true,
    recoveryGateProofContinuityReceiptLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true
  });
  const { app, owner: user } = prepared;
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(user,
    { operationId: `${owner}-batch214-freshness` });
  await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(user);
  const finalization = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(user);
  assert.ok(finalization.finalizationAttestation?.id);
  const seedChallenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(user, {
    action: "renew", reason: "Seed the signed finalization lifecycle receipt for Batch 214 receipt lifecycle tests."
  });
  let seedResult = null;
  for (let attempt = 0; attempt < 16; attempt++) {
    seedResult = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(user,
      seedChallenge.challengeId, { confirmation: seedChallenge.confirmation });
    if (seedResult.complete === true && ["verified_current", "decision_blocked"].includes(seedResult.status)) break;
  }
  assert.equal(seedResult?.complete, true, JSON.stringify({ status: seedResult?.status, phase: seedResult?.phase }));
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpointStatus(user);
  assert.equal(checkpoint.usableForCurrentDecision, true, JSON.stringify(checkpoint));
  return prepared;
}

async function applyReceiptLifecycleUntilComplete(app, owner, challenge, max = 18) {
  let result = null;
  for (let attempt = 0; attempt < max; attempt++) {
    result = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true && ["verified_current", "decision_blocked"].includes(result.status)) return result;
  }
  throw new Error(`receipt lifecycle did not converge: ${JSON.stringify({ status: result?.status, phase: result?.phase,
    audit: result?.audit, checkpointAdvancement: result?.checkpointAdvancement })}`);
}

describe("Agentic AI V4 Batch 214", { concurrency: false }, () => {
  test("Batch 214: receipt renewal supersedes predecessor and advances generation", async t => {
    const { app, owner, anchors } = await readyReceipt(t, "b214-renew");
    const challenge1 = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "Renew the current lifecycle receipt and retain its predecessor binding."
    });
    const first = await applyReceiptLifecycleUntilComplete(app, owner, challenge1);
    assert.ok(first.receiptLifecycleEvent?.id);
    assert.equal(first.audit.status, "verified_current", JSON.stringify(first.audit));
    assert.equal(first.audit.latestLifecycle.action, "renew");
    assert.equal(first.audit.latestLifecycle.replacementReceiptId, first.receiptLifecycleEvent.id);
    const challenge2 = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "Renew the replacement receipt as a second monotonic generation."
    });
    assert.equal(challenge2.receiptLifecycleGeneration, 2);
    assert.equal(challenge2.targetReceiptId, first.receiptLifecycleEvent.id);
    const second = await applyReceiptLifecycleUntilComplete(app, owner, challenge2);
    assert.equal(second.audit.status, "verified_current", JSON.stringify(second.audit));
    assert.equal(second.audit.latestLifecycle.generation, 2);
    assert.notEqual(second.receiptLifecycleEvent.id, first.receiptLifecycleEvent.id);
    assert.equal(second.idempotent, false);
    const replay = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge2.challengeId, { confirmation: challenge2.confirmation });
    assert.equal(replay.idempotent, true);
    const snapshot = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntentFinalization(owner);
    assert.ok(snapshot.eventCount > 0);
    const anchor = [...anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt.records.values()][0];
    assert.ok(anchor?.digest);
    assert.equal((await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner)).status,
      "verified_current");
  });

  test("Batch 214: receipt revocation is terminal and blocks convergence", async t => {
    const { app, owner } = await readyReceipt(t, "b214-revoke");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "revoke", reason: "Revoke the current lifecycle receipt while retaining its signed history."
    });
    const result = await applyReceiptLifecycleUntilComplete(app, owner, challenge);
    assert.equal(result.status, "decision_blocked");
    assert.equal(result.audit.status, "decision_blocked");
    assert.equal(result.audit.latestLifecycle.action, "revoke");
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "A revoked receipt must not be renewed again."
    }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ALREADY_REVOKED");
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergence.status, "decision_blocked", JSON.stringify({ status: convergence.status, blockers: convergence.blockers }));
    assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_REVOKED"));
  });

  test("Batch 214: checkpoint write failure resumes without duplicate lifecycle receipt", async t => {
    const { app, owner, anchors } = await readyReceipt(t, "b214-recovery");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "Exercise recovery after an independent receipt checkpoint write failure."
    });
    const intent = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(intent.phase, "intent");
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt.failWrites = true;
    const interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(interrupted.status, "recovery_required");
    assert.ok(interrupted.event?.id);
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt.failWrites = false;
    const resumed = await applyReceiptLifecycleUntilComplete(app, owner, challenge);
    assert.equal(resumed.audit.status, "verified_current");
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner);
    assert.equal(audit.finalizedCount, 1);
    assert.equal(audit.lifecycleEventCount, 4);
  });

  test("Batch 214: challenge snapshot and confirmation guards prevent stale replay", async t => {
    const { app, owner } = await readyReceipt(t, "b214-replay");
    const challenge1 = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "Prepare the first receipt lifecycle challenge against a stable snapshot."
    });
    const challenge2 = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "Prepare a competing challenge that must become stale after the first intent."
    });
    await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge1.challengeId, { confirmation: challenge1.confirmation });
    await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge2.challengeId, { confirmation: challenge2.confirmation }),
    error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_SNAPSHOT_CHANGED");
  });

  test("Batch 214: routes, lifecycle events, and convergence bindings are registered", async () => {
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["finalization-attestation-lifecycle-receipt/lifecycle/prepare",
      "finalization-attestation-lifecycle-receipt/lifecycle/apply", "finalization-attestation-lifecycle-receipt/lifecycle/audit"])
      assert.ok(server.includes(route), `missing route ${route}`);
    const service = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
    for (const event of ["proof_continuity_finalization_attestation_lifecycle_receipt_lifecycle_intent",
      "proof_continuity_finalization_attestation_lifecycle_receipt_lifecycle_renewed",
      "proof_continuity_finalization_attestation_lifecycle_receipt_lifecycle_revoked",
      "proof_continuity_finalization_attestation_lifecycle_receipt_lifecycle_superseded",
      "proof_continuity_finalization_attestation_lifecycle_receipt_lifecycle_finalized"])
      assert.ok(service.includes(event), `missing event ${event}`);
    const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.match(application, /finalizationAttestationLifecycleReceiptLifecycleAudit/);
    assert.match(application, /RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_REVOKED/);
  });
});
