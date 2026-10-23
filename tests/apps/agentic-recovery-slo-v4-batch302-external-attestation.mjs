import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 302: empty history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b302-empty");
  const audit = await app.auditRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch301_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch302ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 302: attestation and reconciliation do not invent a source receipt", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b302-no-source");
  const result = await app.attestRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const audit = await app.auditRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
});

test("Batch 302: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b302-wiring");
  assert.equal((await app.auditRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH302_ATTESTED_EVENT", "BATCH302_EVENT_TYPES", "batch302ExternalAttestationBindingFields",
    "attestExternalBatch301LifecycleFinalizationReceipts", "auditExternalBatch301LifecycleFinalizationReceiptAttestations",
    "getExternalBatch301LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch301LifecycleFinalizationReceiptAttestations",
    "BATCH301_RECEIPT_EVENT_TYPES", "BATCH301_FINALIZED_EVENT"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH302_EVENT_TYPES"), "independent checkpoint inventory includes Batch 302 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch302ExternalLifecycleFinalizationReceiptAttestations",
    "batch302ExternalLifecycleFinalizationReceiptAttestationAudit", "batch302ExternalLifecycleFinalizationReceiptAttestationRequired",
    "batch302ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch302ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("const batch302ExternalLifecycleFinalizationReceiptAttestationRoot = `${batch301ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch302ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 302: ledger schema validates generation, source receipt, signature binding, and predecessor chain", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH302_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 302 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "finalizationReceiptDigest", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest", "signingKeyLifecycleBindingDigest",
    "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
