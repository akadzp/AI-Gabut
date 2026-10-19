import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 256: empty Batch 255 lifecycle-receipt history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b256-empty");
  const audit = await app.auditRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);

  const snapshot = await app.getRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch255_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);

  const reconciled = await app.reconcileRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const attested = await app.attestRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");

  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch256ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 256: attestation requires complete current Batch 255 receipts and wires independent checkpoint and owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b256-source-required");
  const result = await app.attestRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH256_ATTESTED_EVENT", "BATCH256_EVENT_TYPES", "batch256ExternalAttestationBindingFields",
    "attestExternalBatch255LifecycleFinalizationReceipts", "auditExternalBatch255LifecycleFinalizationReceiptAttestations",
    "getExternalBatch255LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch255LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH256_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch255_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH256_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 256 events");

  const writerStart = core.indexOf("async function attestExternalBatch255LifecycleFinalizationReceipts(ownerId)");
  const writerEnd = core.indexOf("async function auditExternalBatch255LifecycleFinalizationReceiptAttestations(ownerId)", writerStart);
  assert.ok(writerStart >= 0 && writerEnd > writerStart, "Batch 256 writer and auditor are present");
  const writer = core.slice(writerStart, writerEnd);
  assert.ok(writer.includes("eventType: BATCH256_ATTESTED_EVENT"), "writer must append Batch 256 attestation events");
  assert.ok(writer.includes("BATCH255_RECEIPT_EVENT_TYPES"), "writer must consume Batch 255 finalization receipts");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch256ExternalLifecycleFinalizationReceiptAttestations",
    "batch256ExternalLifecycleFinalizationReceiptAttestationAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch256ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("`${batch255ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch256ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 256: external attestation audit rejects an inherited writer event-type mismatch", { timeout: 30000 }, async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const writerStart = core.indexOf("async function attestExternalBatch255LifecycleFinalizationReceipts(ownerId)");
  const writerEnd = core.indexOf("async function auditExternalBatch255LifecycleFinalizationReceiptAttestations(ownerId)", writerStart);
  const auditStart = writerEnd;
  const auditEnd = core.indexOf("async function getExternalBatch255LifecycleFinalizationReceiptAttestationSnapshot(ownerId)", auditStart);
  assert.ok(writerStart >= 0 && writerEnd > writerStart && auditEnd > auditStart);
  assert.ok(core.slice(writerStart, writerEnd).includes("eventType: BATCH256_ATTESTED_EVENT"));
  assert.ok(core.slice(auditStart, auditEnd).includes("BATCH256_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(!core.slice(writerStart, writerEnd).includes("eventType: BATCH254_ATTESTED_EVENT"));
});
