import test from "node:test";
import assert from "node:assert/strict";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 220: key cutoff makes the previous binding attestation stale until renewal revalidates it", { timeout: 120000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b220-key-cutoff", {
    requireFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation: true
  });
  const first = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(first.status, "verified_current", JSON.stringify(first));

  const rotation = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_old", reason: "Rotate signing key to verify current finalization receipt binding attestation after cutoff." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, rotation.challengeId,
    { confirmation: rotation.confirmation });

  const stale = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(stale.status, "stale", JSON.stringify({ status: stale.status, findings: stale.findings }));
  assert.equal(stale.keyCutoffDetected, true);
  assert.equal(stale.usableForCurrentDecision, false);
  const renewed = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b220-key-cutoff-revalidation" });
  assert.equal(renewed.status, "verified_current", JSON.stringify({ status: renewed.status, audit: renewed.audit }));
  assert.equal(renewed.audit.keyCutoffDetected, false);
  assert.equal(renewed.audit.keyCutoffRevalidated, true);
  assert.equal(renewed.audit.usableForCurrentDecision, true);
  assert.ok(renewed.supersession.stableBinding.keyCutoffDetected);
  const revalidated = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
  assert.ok(!revalidated.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_KEY_CUTOFF_REVALIDATION_REQUIRED"),
    JSON.stringify(revalidated.blockers));
});
