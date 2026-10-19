import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROOT = "finalization-receipt-checkpoint/binding-attestation/lifecycle-receipt/attestation-receipt/external-attestation/finalization-receipt-attestation/lifecycle-finalization-receipt-attestation/lifecycle/finalization-receipts/external-attestations/lifecycle";

test("Batch 236: empty external-attestation history remains read-only and renewal fails closed", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b236-empty");
  const audit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.deepEqual(audit.pendingChallengeIds, []);
  assert.equal(audit.usableForCurrentDecision, true);
  const reconciled = await app.reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  await assert.rejects(app.prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle(owner, {
    action: "renew", reason: "renewal must require a current source attestation"
  }));
});

test("Batch 236: lifecycle events, checkpoint-aware replay, and routes are wired", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH236_EVENT_TYPES",
    "BATCH236_EVENT_TYPES.includes(event.eventType)",
    "getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot",
    "batch236LifecycleBindingFields",
    "prepareFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "applyFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "auditFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "resumeFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "RECOVERY_GATE_BATCH236_REVOCATION_DESCENDANT_INVALID"
  ]) assert.ok(core.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "applyRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "reconcileRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalFinalizationReceiptAttestationLifecycle",
    "externalFinalizationReceiptAttestationExternalLifecycleAudit"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch236ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("batch235ExternalAttestationRoot"));
  assert.ok(server.includes("`${batch235ExternalAttestationRoot}/lifecycle`"));
  for (const suffix of ["prepare", "apply", "audit", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
