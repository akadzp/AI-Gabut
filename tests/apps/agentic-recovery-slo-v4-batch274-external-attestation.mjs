import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 274: empty history is read-only and cannot fabricate Batch 273 finalization receipt attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b274-empty");
  const audit = await app.auditRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch273_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch274ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 274: owner-scoped APIs, checkpoint coverage, and source receipt binding are wired", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b274-wiring");
  const audit = await app.auditRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH274_ATTESTED_EVENT", "BATCH274_EVENT_TYPES", "batch274ExternalAttestationBindingFields",
    "attestExternalBatch273LifecycleFinalizationReceipts", "auditExternalBatch273LifecycleFinalizationReceiptAttestations",
    "getExternalBatch273LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch273LifecycleFinalizationReceiptAttestations",
    "batch273FinalizationReceiptPrefixDigest", "RECOVERY_GATE_BATCH274_RECEIPT_BINDING_INVALID",
    "cross_domain_batch273_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH274_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 274 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch274ExternalLifecycleFinalizationReceiptAttestations",
    "batch274ExternalLifecycleFinalizationReceiptAttestationAudit", "batch274ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch274ExternalLifecycleFinalizationReceiptAttestationRoot"));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"])
    assert.ok(server.includes("${batch274ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix), suffix);
});

test("Batch 274: malformed external attestation bindings are rejected by ledger schema validation", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH274_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 274 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest",
    "signingKeyLifecycleBindingDigest", "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
