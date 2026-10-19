import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

async function applyLifecycle(app, owner, challenge, max = 20) {
  let result = null;
  for (let attempt = 0; attempt < max; attempt++) {
    result = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true) return result;
  }
  return result;
}

test("Batch 222: lifecycle receipt renewal supersedes generations and replay reuses the same events", { timeout: 180000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b222-renewal", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true
  });
  const base = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(base.status, "verified_current", JSON.stringify({ status: base.status, audit: base.audit }));
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    { action: "renew", reason: "Renew the current finalization receipt lifecycle for Batch 222." });
  const first = await applyLifecycle(app, owner, challenge);
  assert.equal(first.complete, true, JSON.stringify({ status: first.status, phase: first.phase, audit: first.audit, errors: first.checkpointAdvancement?.errors }));
  assert.equal(first.status, "verified_current");
  assert.equal(first.receiptLifecycleEvent.generation, 1);
  assert.equal(first.supersession.stableBinding.previousReceiptId, base.receipt.id);
  assert.equal(first.supersession.stableBinding.replacementReceiptId, first.receiptLifecycleEvent.id);
  const replay = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(replay.complete, true);
  assert.equal(replay.idempotent, true);
  assert.equal(replay.receiptLifecycleEvent.id, first.receiptLifecycleEvent.id);

  const secondChallenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    { action: "renew", reason: "Renew the second receipt lifecycle generation for Batch 222.", targetReceiptId: first.receiptLifecycleEvent.id });
  const second = await applyLifecycle(app, owner, secondChallenge);
  assert.equal(second.complete, true, JSON.stringify({ status: second.status, audit: second.audit, errors: second.checkpointAdvancement?.errors }));
  assert.equal(second.receiptLifecycleEvent.generation, 2);
  assert.equal(second.supersession.stableBinding.previousReceiptId, first.receiptLifecycleEvent.id);
  assert.equal(second.supersession.stableBinding.replacementReceiptId, second.receiptLifecycleEvent.id);
  assert.equal(second.audit.lifecycleAudit.status, "verified_current");
});

test("Batch 222: revocation is terminal and blocks current-decision use", { timeout: 180000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b222-revocation", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true
  });
  const base = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(base.status, "verified_current", JSON.stringify(base));
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    { action: "revoke", reason: "Revoke the current finalization receipt lifecycle for Batch 222." });
  const revoked = await applyLifecycle(app, owner, challenge);
  assert.equal(revoked.complete, true, JSON.stringify({ status: revoked.status, audit: revoked.audit, errors: revoked.checkpointAdvancement?.errors }));
  assert.equal(revoked.status, "decision_blocked");
  assert.equal(revoked.usableForCurrentDecision, false);
  assert.equal(revoked.audit.lifecycleAudit.status, "decision_blocked");
  await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    { action: "renew", reason: "Attempt renewal after terminal receipt revocation." }), error => /ALREADY_REVOKED/.test(String(error.code || "")));
  const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
  assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_LIFECYCLE_RECEIPT_REVOKED"),
    JSON.stringify(convergence.blockers));
});

test("Batch 222: checkpoint write failure recovers without duplicate lifecycle receipt events", { timeout: 180000 }, async t => {
  const { app, owner, anchors } = await readyReceipt(t, "b222-recovery", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true
  });
  const base = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(base.status, "verified_current", JSON.stringify(base));
  const anchor = anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    { action: "renew", reason: "Validate recovery after an external checkpoint write failure." });
  let phase = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(phase.phase, "intent");
  phase = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(phase.phase, "renewed");
  const replacementId = phase.receiptLifecycleEvent.id;
  phase = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(phase.phase, "superseded");
  anchor.failWrites = true;
  const interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(interrupted.status, "recovery_required");
  assert.equal(interrupted.phase, "finalized");
  anchor.failWrites = false;
  const resumed = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(resumed.complete, true, JSON.stringify({ status: resumed.status, audit: resumed.audit, errors: resumed.checkpointAdvancement?.errors }));
  assert.equal(resumed.receiptLifecycleEvent.id, replacementId);
  assert.equal(resumed.idempotent, true);
  assert.equal(resumed.audit.lifecycleAudit.eventCount, 4);
  assert.equal(resumed.audit.checkpointState.usableForCurrentDecision, true);
});

test("Batch 222: lifecycle API routes are registered", async () => {
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/prepare",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/lifecycle/audit"]) assert.ok(server.includes(route), route);
});
