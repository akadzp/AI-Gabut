import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROOT = "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/lifecycle/finalization-receipts";

test("Batch 234: empty lifecycle finalization history is read-only and cannot fabricate receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b234-empty");
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceipts(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.finalizationCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.orphanReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceiptsSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_external_lifecycle_finalization_receipts");
  assert.equal(snapshot.receiptCount, 0);
  assert.deepEqual(snapshot.snapshot.receipts, []);
  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceipts(owner);
  assert.equal(reconciled.status, "not_initialized", JSON.stringify({ status: reconciled.status, audit: reconciled.audit }));
  assert.equal(reconciled.complete, true);
  assert.equal(reconciled.receiptReconciliation.createdCount, 0);
});

test("Batch 234: signed finalization receipts bind lifecycle phases, terminal state, and checkpoint replay", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_lifecycle_finalization_receipt_attestation_finalization_receipt_finalized",
    "BATCH234_EVENT_TYPES",
    "batch234LifecycleFinalizationReceiptBindingFields",
    "ensureFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceipts",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceipts",
    "getFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceiptsSnapshot",
    "RECOVERY_GATE_BATCH234_FINALIZATION_RECEIPT_MISSING",
    "RECOVERY_GATE_BATCH234_RECEIPT_BINDING_INVALID",
    "RECOVERY_GATE_BATCH234_TERMINAL_REVOCATION",
    "lifecycleFinalizationReceipts"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceipts",
    "getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceiptsSnapshot",
    "reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationFinalizationReceipts",
    "externalLifecycleFinalizationReceiptAttestationFinalizationReceiptAudit"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const suffix of ["audit", "snapshot", "reconcile"]) assert.ok(server.includes(`${ROOT}/${suffix}`), suffix);
});
