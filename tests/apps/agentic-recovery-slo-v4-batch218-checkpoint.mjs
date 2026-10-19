import test from "node:test";
import assert from "node:assert/strict";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 218: finalization receipt checkpoint is independent and part of convergence binding", { timeout: 120000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b218-independent");
  const checkpoint = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint(owner);
  assert.equal(checkpoint.status, "verified_current", JSON.stringify(checkpoint));
  assert.equal(checkpoint.checkpointState.enabled, true);
  assert.equal(checkpoint.checkpointState.usableForCurrentDecision, true);
  assert.equal(checkpoint.checkpointState.sourceCount, checkpoint.receiptAudit.receiptCount);
  assert.ok(checkpoint.checkpointState.sourceCount >= 1);
  const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
  assert.ok(convergence.checkpoints.some(item => item.name === "finalization_attestation_lifecycle_receipt_attestation_lifecycle_receipt"));
  assert.ok(convergence.generationBindingDigest);
});
