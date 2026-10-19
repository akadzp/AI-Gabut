import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 220: interrupted renewal resumes the same operation and routes expose renewal/supersession recovery", { timeout: 120000 }, async t => {
  const { app, owner, anchors } = await readyReceipt(t, "b220-recovery");
  const first = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(first.status, "verified_current", JSON.stringify(first));

  anchors.recoveryGateProofContinuity.failWrites = true;
  const interrupted = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b220-recovery-operation" });
  assert.equal(interrupted.status, "recovery_required", JSON.stringify({ status: interrupted.status, checkpointAdvancement: interrupted.checkpointAdvancement }));
  assert.ok(interrupted.event?.id);
  anchors.recoveryGateProofContinuity.failWrites = false;

  const recovered = await app.renewRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner,
    { operationId: "b220-recovery-operation" });
  assert.equal(recovered.status, "verified_current", JSON.stringify({ status: recovered.status, audit: recovered.audit }));
  assert.equal(recovered.event.id, interrupted.event.id);
  assert.equal(recovered.idempotent, true);
  assert.ok(recovered.supersession?.id);
  assert.equal(recovered.audit.pendingSupersessionIds.length, 0);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.ok(server.includes("finalization-receipt-checkpoint/binding-attestation/renew"));
  assert.ok(server.includes("finalization-receipt-checkpoint/binding-attestation/supersession/finalize"));
  assert.ok(application.includes("AGENTIC_REQUIRE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_KEY_CUTOFF_REVALIDATION"));
  assert.ok(application.includes("RECOVERY_GATE_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_KEY_CUTOFF_REVALIDATION_REQUIRED"));
});
