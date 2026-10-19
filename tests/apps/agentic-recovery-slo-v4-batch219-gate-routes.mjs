import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { readyReceipt } from "./helpers/agentic-recovery-slo-v4-batch218-helpers.mjs";

test("Batch 219: convergence reflects binding attestation and API routes enforce the strict-gate contract", { timeout: 120000 }, async t => {
  const { app, owner } = await readyReceipt(t, "b219-gate");
  const before = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(before.status, "missing");
  const attested = await app.attestRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestation(owner);
  assert.equal(attested.status, "verified_current", JSON.stringify(attested));
  const convergence = await app.auditRecoverySloCrossDomainRecoveryGateProofContinuityConvergence(owner);
  assert.ok(convergence.finalizationReceiptCheckpointBindingAttestation);
  assert.equal(convergence.finalizationReceiptCheckpointBindingAttestation.status, "verified_current");
  assert.ok(!convergence.blockers.some(item => item.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_NOT_CURRENT"
    || item.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_EVIDENCE_UNHEALTHY"), JSON.stringify(convergence.blockers));
  assert.ok(convergence.generationBindingDigest);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.ok(server.includes("finalization-receipt-checkpoint/binding-attestation/attest"));
  assert.ok(server.includes("finalization-receipt-checkpoint/binding-attestation/audit"));
  assert.ok(application.includes("AGENTIC_REQUIRE_RECOVERY_GATE_PROOF_CONTINUITY_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION"));
  assert.ok(application.includes("RECOVERY_GATE_FINALIZATION_RECEIPT_CHECKPOINT_BINDING_ATTESTATION_NOT_CURRENT"));
});
