import test from "node:test";
import assert from "node:assert/strict";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 218: checkpoint write failure after local receipt commit recovers without duplicate receipt", { timeout: 120000 }, async t => {
  const { app, owner, anchors } = await readyReceipt(t, "b218-recovery");
  const before = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt(owner);
  assert.equal(before.receiptCount, 1);
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
    { action: "revoke", reason: "Exercise Batch 218 receipt checkpoint recovery after a local receipt commit." });
  let pending = null;
  for (let attempt = 0; attempt < 10; attempt++) {
    pending = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
      revoke.challengeId, { confirmation: revoke.confirmation });
    if (pending.phase === "finalized_receipt_pending") break;
  }
  assert.equal(pending?.phase, "finalized_receipt_pending", JSON.stringify({ status: pending?.status, phase: pending?.phase }));
  anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt.failWrites = true;
  const interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle(owner,
    revoke.challengeId, { confirmation: revoke.confirmation });
  assert.equal(interrupted.complete, false, JSON.stringify({ status: interrupted.status, checkpointAdvancement: interrupted.checkpointAdvancement }));
  assert.equal(interrupted.audit.receiptAudit.receiptCount, 2);
  assert.equal(interrupted.checkpointAdvancement.complete, false);
  anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt.failWrites = false;
  const recovered = await app.reconcileRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt(owner);
  assert.equal(recovered.complete, true, JSON.stringify(recovered));
  assert.equal(recovered.audit.receiptCount, 2);
  assert.equal(recovered.audit.checkpointState.usableForCurrentDecision, true);
  assert.equal(recovered.audit.checkpointState.sourceCount, 2);
  assert.equal(recovered.audit.status, "decision_blocked");
});
