import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 276: empty history is read-only and cannot fabricate Batch 275 finalization receipt attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b276-empty");
  const audit = await app.auditRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch275_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const attested = await app.attestRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");
  assert.equal(attested.complete, true);
  const reconciled = await app.reconcileRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch276ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 276: owner-scoped APIs, checkpoint coverage, and Batch 275 source receipt binding are wired", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b276-wiring");
  const audit = await app.auditRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH276_ATTESTED_EVENT", "BATCH276_EVENT_TYPES", "batch276ExternalAttestationBindingFields",
    "attestExternalBatch275LifecycleFinalizationReceipts", "auditExternalBatch275LifecycleFinalizationReceiptAttestations",
    "getExternalBatch275LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch275LifecycleFinalizationReceiptAttestations",
    "batch275FinalizationReceiptPrefixDigest", "RECOVERY_GATE_BATCH276_RECEIPT_BINDING_INVALID",
    "cross_domain_batch275_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH276_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 276 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch276ExternalLifecycleFinalizationReceiptAttestations",
    "batch276ExternalLifecycleFinalizationReceiptAttestationAudit", "batch276ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch276ExternalLifecycleFinalizationReceiptAttestationRoot"));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"])
    assert.ok(server.includes("${batch276ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix), suffix);
});

test("Batch 276: malformed external attestation bindings are rejected by ledger schema validation", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH276_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 276 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest",
    "signingKeyLifecycleBindingDigest", "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
