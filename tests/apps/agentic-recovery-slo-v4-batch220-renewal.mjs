import test from "node:test";
import assert from "node:assert/strict";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 220: binding-attestation renewal creates a signed supersession chain and replays idempotently", { timeout: 120000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b220-renewal");
  const first = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(first.status, "verified_current", JSON.stringify({ status: first.status, audit: first.audit }));
  assert.equal(first.audit.latestAttestation.generation, 1);

  const renewed = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b220-renewal-operation-1" });
  assert.equal(renewed.status, "verified_current", JSON.stringify({ status: renewed.status, audit: renewed.audit, advancement: renewed.checkpointAdvancement }));
  assert.equal(renewed.event.generation, 2);
  assert.equal(renewed.event.stableBinding.action, "renew");
  assert.ok(renewed.supersession?.id);
  assert.equal(renewed.audit.status, "verified_current");
  assert.equal(renewed.audit.latestSupersession.generation, 2);
  assert.equal(renewed.audit.pendingSupersessionIds.length, 0);

  const replay = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b220-renewal-operation-1" });
  assert.equal(replay.event.id, renewed.event.id);
  assert.equal(replay.idempotent, true);
  assert.equal(replay.supersession.id, renewed.supersession.id);
  assert.equal(replay.audit.status, "verified_current");
});
