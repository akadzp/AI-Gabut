import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations";

test("Batch 246: empty Batch 245 lifecycle-receipt history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b246-empty");
  const audit = await app.auditRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch245_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const attested = await app.attestRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch246ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 246: receipt binding, independent checkpoint snapshot, application API, and owner-scoped routes are registered", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b246-wiring");
  const empty = await app.attestRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(empty.status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH246_ATTESTED_EVENT", "BATCH246_EVENT_TYPES", "batch246ExternalAttestationBindingFields",
    "attestExternalBatch245LifecycleFinalizationReceipts", "auditExternalBatch245LifecycleFinalizationReceiptAttestations",
    "getExternalBatch245LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch245LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH246_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch245_lifecycle_finalization_receipt_external_attestations"
  ]) assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH246_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 246 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch246ExternalLifecycleFinalizationReceiptAttestations",
    "batch246ExternalLifecycleFinalizationReceiptAttestationAudit"]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch246ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes(ROUTE));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
