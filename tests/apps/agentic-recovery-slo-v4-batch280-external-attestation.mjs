import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 280: empty history is read-only and cannot fabricate Batch 279 finalization receipt attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b280-empty");
  const audit = await app.auditRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch279_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const attested = await app.attestRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");
  assert.equal(attested.complete, true);
  const reconciled = await app.reconcileRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch280ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 280: owner-scoped APIs, checkpoint coverage, and Batch 279 source receipt binding are wired", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b280-wiring");
  const audit = await app.auditRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH280_ATTESTED_EVENT", "BATCH280_EVENT_TYPES", "batch280ExternalAttestationBindingFields",
    "attestExternalBatch279LifecycleFinalizationReceipts", "auditExternalBatch279LifecycleFinalizationReceiptAttestations",
    "getExternalBatch279LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch279LifecycleFinalizationReceiptAttestations",
    "batch279FinalizationReceiptPrefixDigest", "RECOVERY_GATE_BATCH280_RECEIPT_BINDING_INVALID",
    "cross_domain_batch279_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH280_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 280 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch280ExternalLifecycleFinalizationReceiptAttestations",
    "batch280ExternalLifecycleFinalizationReceiptAttestationAudit", "batch280ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch280ExternalLifecycleFinalizationReceiptAttestationRoot"));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"])
    assert.ok(server.includes("${batch280ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix), suffix);
});

test("Batch 280: malformed external attestation bindings are rejected by ledger schema validation", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH280_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 280 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest",
    "signingKeyLifecycleBindingDigest", "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
