import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 310: empty history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b310-empty");
  const audit = await app.auditRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch309_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch310ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 310: attestation and reconciliation do not invent Batch 309 source receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b310-no-source");
  const result = await app.attestRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const audit = await app.auditRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
});

test("Batch 310: service, independent checkpoint inventory, convergence, and owner-scoped routes are wired", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH310_ATTESTED_EVENT", "BATCH310_EVENT_TYPES", "batch310ExternalAttestationBindingFields",
    "attestExternalBatch309LifecycleFinalizationReceipts", "auditExternalBatch309LifecycleFinalizationReceiptAttestations",
    "getExternalBatch309LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch309LifecycleFinalizationReceiptAttestations",
    "BATCH309_RECEIPT_EVENT_TYPES", "BATCH309_FINALIZED_EVENT"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationLifecycleSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH310_EVENT_TYPES"), "independent checkpoint inventory includes Batch 310 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch310ExternalLifecycleFinalizationReceiptAttestations",
    "batch310ExternalLifecycleFinalizationReceiptAttestationAudit", "batch310ExternalLifecycleFinalizationReceiptAttestationRequired",
    "batch310ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch310ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("const batch310ExternalLifecycleFinalizationReceiptAttestationRoot = `${batch309ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch310ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 310: ledger schema validates receipt, generation, signature binding, and predecessor chain", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH310_EVENT_TYPES.includes(event.eventType) && (");
  assert.ok(start >= 0, "Batch 310 schema validator branch exists");
  const validator = core.slice(start, start + 2600);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "finalizationReceiptDigest", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest", "signingKeyLifecycleBindingDigest",
    "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
