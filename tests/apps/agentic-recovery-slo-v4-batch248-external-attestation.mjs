import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations";

test("Batch 248: empty Batch 247 lifecycle-receipt history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b248-empty");
  const audit = await app.auditRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch247_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const attested = await app.attestRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch248ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 248: receipt binding, independent checkpoint snapshot, application API, and owner-scoped routes are registered", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b248-wiring");
  const empty = await app.attestRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(empty.status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH248_ATTESTED_EVENT", "BATCH248_EVENT_TYPES", "batch248ExternalAttestationBindingFields",
    "attestExternalBatch247LifecycleFinalizationReceipts", "auditExternalBatch247LifecycleFinalizationReceiptAttestations",
    "getExternalBatch247LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch247LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH248_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch247_lifecycle_finalization_receipt_external_attestations"
  ]) assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH248_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 248 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch248ExternalLifecycleFinalizationReceiptAttestations",
    "batch248ExternalLifecycleFinalizationReceiptAttestationAudit"]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch248ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes(ROUTE));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
