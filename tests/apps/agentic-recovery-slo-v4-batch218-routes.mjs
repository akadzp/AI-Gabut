import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 218: provider reuse is rejected and independent checkpoint routes are registered", async t => {
  await assert.rejects(() => setupOwner(t, "b218-provider-reuse", {
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint: true,
    reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptProvider: true
  }), error => error.code === "RECOVERY_GATE_FINALIZATION_ATTESTATION_LIFECYCLE_RECEIPT_ATTESTATION_LIFECYCLE_RECEIPT_ANCHOR_PROVIDER_REUSED");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "finalization-attestation-lifecycle-receipt-attestation/lifecycle/finalization-receipt-checkpoint/status",
    "finalization-attestation-lifecycle-receipt-attestation/lifecycle/finalization-receipt-checkpoint/audit",
    "finalization-attestation-lifecycle-receipt-attestation/lifecycle/finalization-receipt-checkpoint/enrollment/prepare",
    "finalization-attestation-lifecycle-receipt-attestation/lifecycle/finalization-receipt-checkpoint/enrollment/apply",
    "finalization-attestation-lifecycle-receipt-attestation/lifecycle/finalization-receipt-checkpoint/reconcile"
  ]) assert.ok(server.includes(route), `missing route ${route}`);
});
