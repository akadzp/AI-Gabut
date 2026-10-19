import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 232: empty lifecycle finalization-receipt history remains read-only and is never fabricated", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b232-empty");
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceiptSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_finalization_receipt_external_attestation_lifecycle_finalization_receipts");
  assert.equal(snapshot.receiptCount, 0);
  assert.equal(snapshot.attestationCount, 0);
  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt(owner);
  assert.equal(reconciled.status, "not_initialized", JSON.stringify({ status: reconciled.status, audit: reconciled.audit }));
  assert.equal(reconciled.complete, true);
  await assert.rejects(() => app.attestRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt(owner),
    error => error.code === "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_LIFECYCLE_FINALIZATION_RECEIPT_MISSING");
});

test("Batch 232: signed finalization-receipt attestation binds receipt generations and joins independent checkpoint convergence", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_lifecycle_finalization_receipt_attested",
    "BATCH232_EVENT_TYPES",
    "externalLifecycleFinalizationReceiptAttestationBindingFields",
    "attestFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt",
    "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceiptAttestationSnapshot",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_LIFECYCLE_ATTESTATION_CHAIN_INVALID",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_LIFECYCLE_ATTESTATION_MISSING",
    "cross_domain_finalization_receipt_external_attestation_lifecycle_finalization_receipts"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "attestRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt",
    "auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt",
    "reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationLifecycleFinalizationReceipt",
    "externalLifecycleFinalizationReceiptAttestationRequired"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/attest",
    "external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/audit",
    "external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/snapshot",
    "external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/reconcile"
  ]) assert.ok(server.includes(route), route);
});
