import test from "node:test";
import assert from "node:assert/strict";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 219: finalization-receipt checkpoint binding attestation is signed, current, and idempotent", { timeout: 120000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b219-attest");
  const first = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(first.status, "verified_current", JSON.stringify({ status: first.status, audit: first.audit, advancement: first.checkpointAdvancement }));
  assert.equal(first.complete, true);
  assert.equal(first.audit.status, "verified_current");
  assert.ok(first.event?.id);
  assert.ok(first.audit.latestAttestation?.bindingDigest);
  const second = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(second.event.id, first.event.id);
  assert.equal(second.idempotent, true);
  assert.equal(second.audit.status, "verified_current");
});
