import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 237: empty Batch 236 lifecycle history remains read-only and creates no finalization receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b237-empty");
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceipts(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.finalizationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceiptsSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_external_finalization_receipt_attestation_lifecycle_finalization_receipts");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceipts(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  assert.equal(reconciled.receiptCount, 0);
});

test("Batch 237: finalization receipt chain, replay recovery, convergence, and routes are wired", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH237_EVENT_TYPES",
    "batch237LifecycleFinalizationReceiptBindingFields",
    "ensureFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceipts",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceipts",
    "getFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceiptsSnapshot",
    "reconcileFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceipts",
    "RECOVERY_GATE_BATCH237_RECEIPT_CHAIN_INVALID",
    "RECOVERY_GATE_BATCH237_TERMINAL_REVOCATION"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceipts",
    "getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceiptsSnapshot",
    "reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycleFinalizationReceipts",
    "externalFinalizationReceiptAttestationLifecycleFinalizationReceiptAudit"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch237FinalizationReceiptRoot"));
  for (const suffix of ["audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
