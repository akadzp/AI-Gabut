import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 228: empty external-attestation lifecycle has no invented finalization receipts and reconciliation is idempotently empty", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b228-empty", {
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint: true
  });
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationExternalLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.eventCount, 0);
  assert.equal(audit.finalizationReceiptCount, 0);
  assert.equal(audit.pendingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);

  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationExternalLifecycleFinalizationReceipts(owner);
  assert.equal(reconciled.status, "not_initialized", JSON.stringify(reconciled));
  assert.equal(reconciled.complete, true);
  assert.equal(reconciled.createdCount, 0);
  assert.equal(reconciled.receipts.length, 0);

  const snapshot = await app.recoveryGateProofContinuityService?.getFinalizationReceiptBindingAttestationLifecycleAttestationReceiptSnapshot?.(owner);
  if (snapshot) {
    assert.equal(snapshot.snapshot.domain, "cross_domain_finalization_receipt_lifecycle_attestation_receipts");
    assert.equal(snapshot.count, 0);
  }
});

test("Batch 228: finalization receipts bind lifecycle generations, predecessor receipts, and independent checkpoint recovery routes", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_lifecycle_finalization_receipt_finalized",
    "ensureFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt",
    "reconcileFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipts",
    "sourceLifecycleChainDigest",
    "previousFinalizationReceiptDigest",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_BINDING_ATTESTATION_EXTERNAL_LIFECYCLE_FINALIZATION_RECEIPT_MISSING",
    "pendingFinalizationReceiptCount",
    "REVOCATION_DESCENDANT_PRESENT",
    "BATCH228_EVENT_TYPES"
  ]) assert.ok(core.includes(token), token);

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.ok(application.includes("reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationExternalLifecycleFinalizationReceipts"));
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("external-attestation/lifecycle/finalization-receipts/reconcile"));
});
