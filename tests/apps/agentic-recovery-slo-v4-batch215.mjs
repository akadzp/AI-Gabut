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
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint: true
  });
  const { app, owner: user } = prepared;
  await app.attestRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshness(user,
    { operationId: `${owner}-batch215-freshness` });
  await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureRecoveryGate(user);
  const finalization = await app.finalizeRecoverySloCrossDomainRecoveryGateProofContinuityMultiCheckpointRecoveryIntent(user);
  assert.ok(finalization.finalizationAttestation?.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(user,
    { action: "renew", reason: "Seed a signed lifecycle receipt for Batch 215 external-attestation tests." });
  let result = null;
  for (let attempt = 0; attempt < 18; attempt++) {
    result = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycle(user,
      challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true && ["verified_current", "decision_blocked"].includes(result.status)) break;
  }
  assert.equal(result?.complete, true, JSON.stringify({ status: result?.status, phase: result?.phase }));
  const receiptLifecycleChallenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(user, {
    action: "renew", reason: "Seed a finalized receipt-lifecycle generation before Batch 215 attestation checks." });
  let receiptLifecycleResult = null;
  for (let attempt = 0; attempt < 18; attempt++) {
    receiptLifecycleResult = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(user,
      receiptLifecycleChallenge.challengeId, { confirmation: receiptLifecycleChallenge.confirmation });
    if (receiptLifecycleResult.complete === true && ["verified_current", "decision_blocked"].includes(receiptLifecycleResult.status)) break;
  }
  assert.equal(receiptLifecycleResult?.complete, true, JSON.stringify({ status: receiptLifecycleResult?.status, phase: receiptLifecycleResult?.phase }));
  const receiptCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpointStatus(user);
  assert.equal(receiptCheckpoint.usableForCurrentDecision, true, JSON.stringify(receiptCheckpoint));
  const attestationCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestationCheckpointStatus(user);
  assert.equal(attestationCheckpoint.usableForCurrentDecision, true, JSON.stringify(attestationCheckpoint));
  return prepared;
}

async function applyReceiptLifecycle(app, owner, challenge, max = 18) {
  let result = null;
  for (let attempt = 0; attempt < max; attempt++) {
    result = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    if (result.complete === true && ["verified_current", "decision_blocked"].includes(result.status)) return result;
  }
  return result;
}

describe("Agentic AI V4 Batch 215", { concurrency: false }, () => {
  test("Batch 215: receipt-lifecycle external attestation is signed, independently anchored, and idempotent", async t => {
    const { app, owner, anchors } = await readyReceipt(t, "b215-attest");
    const before = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestation(owner);
    assert.equal(before.status, "verified_current", JSON.stringify({ status: before.status, findings: before.findings }));
    assert.equal(before.attestationCount, 1);
    assert.ok(before.latestAttestation?.digest);
    const again = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner);
    assert.equal(again.complete, true, JSON.stringify({ status: again.status, audit: again.audit }));
    assert.equal(again.idempotent, true);
    const after = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestation(owner);
    assert.equal(after.attestationCount, 1);
    assert.equal(after.status, "verified_current");
    const checkpoint = [...anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestation.records.values()][0];
    assert.ok(checkpoint?.digest);
    assert.equal(checkpoint.domain, "cross_domain_finalization_attestation_receipt_lifecycle_attestations");
  });

  test("Batch 215: attestation checkpoint write failure recovers without duplicate attestation", async t => {
    const { app, owner, anchors } = await readyReceipt(t, "b215-recover");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "Exercise interrupted external attestation after receipt renewal." });
    let result = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
      challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(result.phase, "intent");
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestation.failWrites = true;
    let interrupted = null;
    for (let attempt = 0; attempt < 12; attempt++) {
      interrupted = await app.applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner,
        challenge.challengeId, { confirmation: challenge.confirmation });
      if (interrupted.lifecycleReceiptAttestation) break;
    }
    assert.equal(interrupted?.status, "recovery_required", JSON.stringify({ status: interrupted?.status, phase: interrupted?.phase }));
    assert.equal(interrupted?.lifecycleReceiptAttestation?.complete, false);
    await assert.rejects(() => app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "renew", reason: "A new lifecycle operation must wait until the pending attestation is externally anchored." }),
    error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ATTESTATION_CHECKPOINT_NOT_CURRENT");
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestation.failWrites = false;
    const resumed = await applyReceiptLifecycle(app, owner, challenge);
    assert.equal(resumed?.complete, true, JSON.stringify({ status: resumed?.status, phase: resumed?.phase }));
    assert.equal(resumed.status, "verified_current");
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestation(owner);
    assert.equal(audit.status, "verified_current");
    assert.equal(audit.attestationCount, 2);
  });

  test("Batch 215: revocation attestation preserves terminal decision blocking", async t => {
    const { app, owner } = await readyReceipt(t, "b215-revoke");
    const challenge = await app.prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycle(owner, {
      action: "revoke", reason: "Record the terminal revocation and attest its lifecycle receipt." });
    const result = await applyReceiptLifecycle(app, owner, challenge);
    assert.equal(result?.complete, true, JSON.stringify({ status: result?.status, phase: result?.phase }));
    assert.equal(result.status, "decision_blocked");
    const audit = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestation(owner);
    assert.equal(audit.status, "decision_blocked");
    assert.equal(audit.usableForCurrentDecision, false);
    const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
    assert.equal(convergence.status, "decision_blocked");
    assert.ok(convergence.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_REVOKED"));
  });

  test("Batch 215: reused provider is rejected and API routes are registered", async t => {
    await assert.rejects(() => setupOwner(t, "b215-reuse", {
      recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint: true,
      reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationProvider: true
    }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ATTESTATION_ANCHOR_PROVIDER_REUSED");
    const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
    for (const route of ["finalization-attestation-lifecycle-receipt/attest", "finalization-attestation-lifecycle-receipt/attestation/audit",
      "finalization-attestation-lifecycle-receipt-attestation-checkpoint/status",
      "finalization-attestation-lifecycle-receipt-attestation-checkpoint/enrollment/prepare",
      "finalization-attestation-lifecycle-receipt-attestation-checkpoint/enrollment/apply",
      "finalization-attestation-lifecycle-receipt-attestation-checkpoint/reconcile"])
      assert.ok(server.includes(route), `missing route ${route}`);
    const service = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
    assert.ok(service.includes("proof_continuity_finalization_attestation_lifecycle_receipt_lifecycle_attested"));
    const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
    assert.ok(application.includes("RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ATTESTATION_NOT_CURRENT"));
  });
});
