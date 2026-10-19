import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROOT = "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/lifecycle/finalization-receipts/external-attestations";

test("Batch 235: empty receipt history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b235-empty");
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationExternalAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const convergence = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(convergence.externalLifecycleFinalizationReceiptAttestationExternalAudit.receiptCount, 0);
  const snapshot = await app.getRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationExternalAttestationsSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_external_lifecycle_finalization_receipt_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationExternalAttestations(owner);
  assert.equal(reconciled.status, "not_initialized", JSON.stringify({ status: reconciled.status, audit: reconciled.audit }));
  assert.equal(reconciled.complete, true);
});

test("Batch 235: finalization receipt attestation bindings and checkpoint routes are wired", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH235_EVENT_TYPES",
    "batch235ExternalAttestationBindingFields",
    "attestExternalLifecycleFinalizationReceiptFinalizationReceipts",
    "auditExternalLifecycleFinalizationReceiptFinalizationReceiptAttestations",
    "getExternalLifecycleFinalizationReceiptFinalizationReceiptAttestationSnapshot",
    "reconcileExternalLifecycleFinalizationReceiptFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH235_EXTERNAL_ATTESTATION_CHAIN_INVALID",
    "RECOVERY_GATE_BATCH235_EXTERNAL_ATTESTATION_MISSING",
    "cross_domain_external_lifecycle_finalization_receipt_attestations"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "attestRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationExternalAttestations",
    "auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationExternalAttestations",
    "reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalLifecycleFinalizationReceiptAttestationExternalAttestations",
    "externalLifecycleFinalizationReceiptAttestationExternalAudit"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch235ExternalAttestationRoot"));
  assert.ok(server.includes(ROOT));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
