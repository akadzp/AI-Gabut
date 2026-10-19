import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations/lifecycle/finalization-receipts/external-attestations";

test("Batch 254: empty Batch 253 lifecycle-receipt history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b254-empty");
  const audit = await app.auditRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);

  const snapshot = await app.getRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch253_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);

  const reconciled = await app.reconcileRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const attested = await app.attestRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");

  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch254ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 254: source receipt binding, independent checkpoint snapshot, application API, and owner-scoped routes are registered", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b254-wiring");
  const empty = await app.attestRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(empty.status, "not_initialized");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH254_ATTESTED_EVENT", "BATCH254_EVENT_TYPES", "batch254ExternalAttestationBindingFields",
    "attestExternalBatch253LifecycleFinalizationReceipts", "auditExternalBatch253LifecycleFinalizationReceiptAttestations",
    "getExternalBatch253LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch253LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH254_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch253_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH254_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 254 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch254ExternalLifecycleFinalizationReceiptAttestations",
    "batch254ExternalLifecycleFinalizationReceiptAttestationAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch254ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("`${batch253ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"])
    assert.ok(server.includes(`/${suffix}",async`), suffix);
  assert.ok(ROUTE.length > 0);
});


test("Batch 254: inherited Batch 250 attestation writer uses the event type audited by Batch 250", { timeout: 30000 }, async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("async function attestExternalBatch249LifecycleFinalizationReceipts(ownerId)");
  const end = core.indexOf("async function auditExternalBatch249LifecycleFinalizationReceiptAttestations(ownerId)", start);
  assert.ok(start >= 0 && end > start, "Batch 250 writer and auditor are present");
  const writer = core.slice(start, end);
  assert.ok(writer.includes("eventType: BATCH250_ATTESTED_EVENT"), "Batch 250 writer must append the Batch 250 event type");
  assert.ok(!writer.includes("eventType: BATCH248_ATTESTED_EVENT"), "Batch 250 writer must not misclassify events as Batch 248 attestations");
});
