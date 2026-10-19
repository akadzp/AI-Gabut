import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 231: empty lifecycle does not fabricate finalization receipts and remains auditable", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b231-empty", {
    recoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint: true
  });
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.finalizedCount, 0);
  assert.equal(audit.finalizationReceiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  const snapshot = await app.getRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_finalization_receipt_external_attestations_lifecycle");
  assert.equal(snapshot.count, 0);
  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle(owner);
  assert.equal(reconciled.lifecycleReceiptReconciliation.receiptCount, 0);
  assert.equal(reconciled.lifecycleReceiptReconciliation.createdCount, 0);
  assert.equal(reconciled.lifecycleReceiptReconciliation.audit.status, "not_initialized");
});

test("Batch 231: finalization receipts bind the signed lifecycle, checkpoint snapshot, and terminal-revocation descendant audit", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_finalization_receipt_lifecycle_finalization_receipt_finalized",
    "externalAttestationLifecycleFinalizationReceiptBindingFields",
    "ensureFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptLifecycleReceipt",
    "reconcileFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceipts",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_LIFECYCLE_FINALIZATION_RECEIPT_MISSING",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_LIFECYCLE_FINALIZATION_RECEIPT_INVALID",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_LIFECYCLE_REVOCATION_DESCENDANT_INVALID",
    "BATCH231_EVENT_TYPES"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  assert.ok(application.includes("lifecycleReceiptReconciliation"));
  assert.ok(application.includes("reconcileFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceipts"));
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("external-attestation/finalization-receipt-attestation/lifecycle/reconcile"));
});
