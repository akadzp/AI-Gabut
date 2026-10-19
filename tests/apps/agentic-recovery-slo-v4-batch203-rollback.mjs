import test from "node:test";
import assert from "node:assert/strict";
import { createCurrentRevalidation } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 203: a rolled-back independent proof anchor blocks current-decision use", async t => {
  const { app, owner, anchors } = await createCurrentRevalidation(t, "b203-proof-rollback", { revalidationLifecycleCheckpoint: true,
    requireRevalidationLifecycleFreshnessAttestation: true, recoveryGateProofCheckpoint: true });
  const [scope, enrolledAnchor] = [...anchors.recoveryGateProof.records.entries()][0];
  const gate = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(owner);
  assert.ok(gate.recoveryGateProof?.id);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(owner)).usableForCurrentDecision, true);
  anchors.recoveryGateProof.records.set(scope, enrolledAnchor);
  const rolledBack = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointStatus(owner);
  assert.equal(rolledBack.status, "rollback_suspected");
  assert.equal(rolledBack.usableForCurrentDecision, false);
  const proofAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleRecoveryGateProof(owner);
  assert.equal(proofAudit.usableForCurrentDecision, false);
});
