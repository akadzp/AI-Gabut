import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 258: empty Batch 257 lifecycle-receipt history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b258-empty");
  const audit = await app.auditRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);

  const snapshot = await app.getRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch257_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);

  const reconciled = await app.reconcileRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const attested = await app.attestRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");

  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch258ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
  assert.equal(gate.status, "not_initialized");
});

test("Batch 258: external attestation requires complete current Batch 257 receipts and wires checkpoint-aware owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b258-source-required");
  const result = await app.attestRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH258_ATTESTED_EVENT", "BATCH258_EVENT_TYPES", "batch258ExternalAttestationBindingFields",
    "attestExternalBatch257LifecycleFinalizationReceipts", "auditExternalBatch257LifecycleFinalizationReceiptAttestations",
    "getExternalBatch257LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch257LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH258_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch257_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH258_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 258 events");

  const writerStart = core.indexOf("async function attestExternalBatch257LifecycleFinalizationReceipts(ownerId)");
  const writerEnd = core.indexOf("async function auditExternalBatch257LifecycleFinalizationReceiptAttestations(ownerId)", writerStart);
  assert.ok(writerStart >= 0 && writerEnd > writerStart, "Batch 258 writer and auditor are present");
  const writer = core.slice(writerStart, writerEnd);
  assert.ok(writer.includes("eventType: BATCH258_ATTESTED_EVENT"), "writer must append Batch 258 attestation events");
  assert.ok(writer.includes("BATCH257_RECEIPT_EVENT_TYPES"), "writer must consume Batch 257 finalization receipts");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch258ExternalLifecycleFinalizationReceiptAttestations",
    "batch258ExternalLifecycleFinalizationReceiptAttestationAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch258ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("`${batch257ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch258ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 258: event schema and auditor reject inherited writer event-type mismatches", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const writerStart = core.indexOf("async function attestExternalBatch257LifecycleFinalizationReceipts(ownerId)");
  const writerEnd = core.indexOf("async function auditExternalBatch257LifecycleFinalizationReceiptAttestations(ownerId)", writerStart);
  const auditStart = writerEnd;
  const auditEnd = core.indexOf("async function getExternalBatch257LifecycleFinalizationReceiptAttestationSnapshot(ownerId)", auditStart);
  assert.ok(writerStart >= 0 && writerEnd > writerStart && auditEnd > auditStart);
  assert.ok(core.slice(writerStart, writerEnd).includes("eventType: BATCH258_ATTESTED_EVENT"));
  assert.ok(core.slice(auditStart, auditEnd).includes("BATCH258_EVENT_TYPES.includes(event.eventType)"));
  assert.ok(!core.slice(writerStart, writerEnd).includes("eventType: BATCH256_ATTESTED_EVENT"));

  const validatorStart = core.indexOf("|| BATCH258_EVENT_TYPES.includes(event.eventType) && (");
  const validatorEnd = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", validatorStart);
  assert.ok(validatorStart >= 0 && validatorEnd > validatorStart);
  const validator = core.slice(validatorStart, validatorEnd);
  for (const field of ["attestationGeneration", "finalizationReceiptId", "sourceReceiptChainDigest", "bindingDigest", "previousAttestationDigest"])
    assert.ok(validator.includes(field), field);
});
