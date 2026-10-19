import test from "node:test";
import assert from "node:assert/strict";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 219: external finalization-receipt checkpoint rollback invalidates binding attestation", { timeout: 120000 }, async t => {
  const { app, owner, anchors } = await readyReceipt(t, "b219-roll");
  const attested = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(attested.status, "verified_current", JSON.stringify(attested));
  const provider = anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt;
  const [scope, current] = [...provider.records.entries()][0];
  assert.ok(current);
  provider.records.set(scope, { ...current, anchorSequence: Math.max(0, current.anchorSequence - 1), digest: "0".repeat(64) });
  const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(audit.rollbackDetected, true, JSON.stringify(audit));
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_CHECKPOINT_ROLLBACK_DETECTED"));
});
