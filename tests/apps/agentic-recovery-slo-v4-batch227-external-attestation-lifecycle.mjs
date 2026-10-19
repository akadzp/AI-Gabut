import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 227: external-attestation lifecycle starts empty and fails closed without a current attestation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b227-empty", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint: true
  });
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationExternalLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.eventCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationExternalLifecycle(owner,
    { action: "renew", reason: "Renew external attestation before any attestation exists." }),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_EXTERNAL_LIFECYCLE_NOT_CURRENT");
  await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationExternalLifecycle(owner,
    { action: "delete", reason: "Unsupported external attestation lifecycle operation." }),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_EXTERNAL_LIFECYCLE_ACTION_INVALID");
});

test("Batch 227: signed renewal/revocation chain and lifecycle HTTP routes are registered", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_lifecycle_intent",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_lifecycle_renewed",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_lifecycle_revoked",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_lifecycle_superseded",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_lifecycle_finalized",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycle",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_EXTERNAL_ATTESTATION_REVOKED",
    "lifecycleRenewalEventDigest"
  ]) assert.ok(core.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/lifecycle/prepare",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/lifecycle/apply",
    "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/lifecycle/audit"
  ]) assert.ok(server.includes(route), route);
});
