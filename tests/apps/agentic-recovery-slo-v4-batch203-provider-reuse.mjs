import test from "node:test";
import assert from "node:assert/strict";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 203: provider reuse is rejected before proof checkpoint use", async t => {
  const prepared = await setupOwner(t, "b203-proof-provider-reuse", { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true,
    revalidationLifecycleCheckpoint: true, recoveryGateProofCheckpoint: true, enrollRecoveryGateProofCheckpoint: false,
    reuseRecoveryGateProofProvider: true });
  const state = await prepared.app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(prepared.owner);
  assert.equal(state.status, "unhealthy");
  assert.equal(state.usableForCurrentDecision, false);
  assert.ok(state.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_GATE_PROOF_ANCHOR_PROVIDER_REUSED"));
});
