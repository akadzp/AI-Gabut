import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 230: empty external-attestation lifecycle remains uninitialized and cannot invent a target", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b230-empty", {
    recoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint: true
  });
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.eventCount, 0);
  assert.equal(audit.finalizedCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_finalization_receipt_external_attestations_lifecycle");
  assert.equal(snapshot.count, 0);
  await assert.rejects(() => app.prepareRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew external receipt after controlled lifecycle review"
  }), error => [
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_LIFECYCLE_NOT_CURRENT",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_LIFECYCLE_TARGET_MISSING"
  ].includes(error.code));
});

test("Batch 230: signed lifecycle chain, key-cutoff revalidation, checkpoint coverage, and authenticated routes are wired", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_finalization_receipt_lifecycle_intent",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_finalization_receipt_lifecycle_renewed",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_finalization_receipt_lifecycle_revoked",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_finalization_receipt_lifecycle_superseded",
    "proof_continuity_finalization_receipt_binding_attestation_lifecycle_external_attestation_finalization_receipt_lifecycle_finalized",
    "prepareFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycle",
    "applyFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycle",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycle",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_LIFECYCLE_TERMINAL_REVOCATION",
    "RECOVERY_GATE_FINALIZATION_RECEIPT_EXTERNAL_ATTESTATION_LIFECYCLE_SUPERSESSION_INVALID",
    "cross_domain_finalization_receipt_external_attestations",
    'domain: "batch229-finalization-receipt-external-attestation"'
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "prepareRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle",
    "applyRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle",
    "auditRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle",
    "reconcileRecoveryGateProofContinuityFinalizationReceiptExternalAttestationLifecycle",
    "externalFinalizationReceiptAttestationLifecycleAudit"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "external-attestation/finalization-receipt-attestation/lifecycle/prepare",
    "external-attestation/finalization-receipt-attestation/lifecycle/apply",
    "external-attestation/finalization-receipt-attestation/lifecycle/audit",
    "external-attestation/finalization-receipt-attestation/lifecycle/snapshot",
    "external-attestation/finalization-receipt-attestation/lifecycle/reconcile"
  ]) assert.ok(server.includes(route), route);
});
