import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 312: empty history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b312-empty");
  const audit = await app.auditRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch311_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch312ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 312: attestation and reconciliation do not invent Batch 311 source receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b312-no-source");
  const result = await app.attestRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const audit = await app.auditRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
});

test("Batch 312: service, independent checkpoint inventory, convergence, and owner-scoped routes are wired", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH312_ATTESTED_EVENT", "BATCH312_EVENT_TYPES", "batch312ExternalAttestationBindingFields",
    "attestExternalBatch311LifecycleFinalizationReceipts", "auditExternalBatch311LifecycleFinalizationReceiptAttestations",
    "getExternalBatch311LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch311LifecycleFinalizationReceiptAttestations",
    "BATCH311_RECEIPT_EVENT_TYPES", "BATCH311_FINALIZED_EVENT"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycleSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH312_EVENT_TYPES"), "independent checkpoint inventory includes Batch 312 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch312ExternalLifecycleFinalizationReceiptAttestations",
    "batch312ExternalLifecycleFinalizationReceiptAttestationAudit", "batch312ExternalLifecycleFinalizationReceiptAttestationRequired",
    "batch312ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch312ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("const batch312ExternalLifecycleFinalizationReceiptAttestationRoot = `${batch311ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch312ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 312: ledger schema validates receipt, generation, signature binding, and predecessor chain", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH312_EVENT_TYPES.includes(event.eventType) && (");
  assert.ok(start >= 0, "Batch 312 schema validator branch exists");
  const validator = core.slice(start, start + 2600);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "finalizationReceiptDigest", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest", "signingKeyLifecycleBindingDigest",
    "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
