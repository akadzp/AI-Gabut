import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 221: signed binding-attestation receipts anchor supersession generations and replay idempotently", { timeout: 180000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b221-receipt-chain", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true
  });
  const first = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(first.status, "verified_current", JSON.stringify({ status: first.status, audit: first.audit, receiptAudit: first.receiptAudit }));
  assert.ok(first.receipt?.id);
  assert.equal(first.receipt.generation, 1);
  assert.equal(first.receipt.stableBinding.attestationId, first.event.id);
  assert.equal(first.receipt.stableBinding.supersessionEventId, null);
  const firstCheckpoint = await app.getRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpointStatus(owner);
  assert.equal(firstCheckpoint.usableForCurrentDecision, true, JSON.stringify(firstCheckpoint));

  const renewed = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b221-receipt-chain-renewal-1" });
  assert.equal(renewed.status, "verified_current", JSON.stringify({ status: renewed.status, audit: renewed.audit, receiptAudit: renewed.receiptAudit }));
  assert.equal(renewed.event.generation, 2);
  assert.ok(renewed.supersession?.id);
  assert.ok(renewed.receipt?.id);
  assert.equal(renewed.receipt.generation, 2);
  assert.equal(renewed.receipt.stableBinding.previousReceiptId, first.receipt.id);
  assert.equal(renewed.receipt.stableBinding.previousReceiptDigest, first.receipt.digest);
  assert.equal(renewed.receipt.stableBinding.supersessionEventId, renewed.supersession.id);
  assert.equal(renewed.receipt.stableBinding.supersessionEventDigest, renewed.supersession.digest);
  assert.equal(renewed.receiptAudit.status, "verified_current");
  assert.equal(renewed.receiptAudit.receiptAudit.latestReceipt.id, renewed.receipt.id);
  assert.equal(renewed.receiptAudit.checkpointState.usableForCurrentDecision, true);

  const replay = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b221-receipt-chain-renewal-1" });
  assert.equal(replay.event.id, renewed.event.id);
  assert.equal(replay.receipt.id, renewed.receipt.id);
  assert.equal(replay.receiptIdempotent, true);
  assert.equal(replay.receiptAudit.status, "verified_current");
});

test("Batch 221: a committed receipt is reused and its independent checkpoint is reconciled after write failure", { timeout: 180000 }, async t => {
  const { app, owner, anchors } = await readyReceipt(t, "b221-receipt-recovery", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true
  });
  const anchor = anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt;
  anchor.failWrites = true;
  const interrupted = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(interrupted.status, "recovery_required", JSON.stringify({ status: interrupted.status, errors: interrupted.receiptCheckpointAdvancement?.errors }));
  assert.ok(interrupted.receipt?.id, "receipt must remain committed locally after external write failure");
  const receiptId = interrupted.receipt.id;
  const before = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint(owner);
  assert.notEqual(before.checkpointState.usableForCurrentDecision, true);

  anchor.failWrites = false;
  const resumed = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(resumed.status, "verified_current", JSON.stringify({ status: resumed.status, audit: resumed.audit, receiptAudit: resumed.receiptAudit }));
  assert.equal(resumed.receipt.id, receiptId);
  assert.equal(resumed.receiptIdempotent, true);
  assert.equal(resumed.receiptAudit.checkpointState.usableForCurrentDecision, true);
  assert.equal(resumed.receiptAudit.receiptAudit.receiptCount, 1);
});

test("Batch 221: key cutoff is recorded in the receipt chain and current-key renewal restores decision eligibility", { timeout: 180000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b221-key-cutoff", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true,
    requireFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation: true
  });
  const first = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(first.status, "verified_current", JSON.stringify(first));
  const rotation = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_old", reason: "Rotate key to validate Batch 221 receipt-chain cutoff continuity." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, rotation.challengeId,
    { confirmation: rotation.confirmation });
  const stale = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(stale.status, "stale");
  assert.equal(stale.keyCutoffDetected, true);
  assert.equal(stale.usableForCurrentDecision, false);

  const renewed = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b221-key-cutoff-renewal" });
  assert.equal(renewed.status, "verified_current", JSON.stringify({ status: renewed.status, audit: renewed.audit, receiptAudit: renewed.receiptAudit }));
  assert.equal(renewed.supersession.stableBinding.keyCutoffDetected, true);
  assert.equal(renewed.receipt.stableBinding.keyCutoffDetected, true);
  assert.equal(renewed.receipt.stableBinding.previousReceiptId, first.receipt.id);
  assert.equal(renewed.receiptAudit.status, "verified_current");
  assert.equal(renewed.receiptAudit.checkpointState.usableForCurrentDecision, true);
});

test("Batch 221: provider reuse is rejected and lifecycle receipt checkpoint routes are registered", { timeout: 180000 }, async t => {
  await assert.rejects(() => readyReceipt(t, "b221-provider-reuse", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptProvider: true
  }), error => String(error.code || "").endsWith("ANCHOR_PROVIDER_REUSED"));
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/status",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/audit",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/enrollment/prepare",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/enrollment/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/checkpoint/reconcile"]) assert.ok(server.includes(route), route);
});
