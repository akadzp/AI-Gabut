import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 298: empty history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b298-empty");
  const audit = await app.auditRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch297_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const result = await app.reconcileRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const attempted = await app.attestRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attempted.status, "not_initialized");
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch298ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 298: no Batch 297 lifecycle receipts means attestation remains a no-op", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b298-no-source");
  const result = await app.attestRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const snapshot = await app.getRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.receiptCount, 0);
  assert.equal(snapshot.attestationCount, 0);
  assert.equal(snapshot.missingAttestationCount, 0);
});

test("Batch 298: service, checkpoint inventory, convergence, and owner-scoped routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b298-wiring");
  assert.equal((await app.auditRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH298_ATTESTED_EVENT", "BATCH298_EVENT_TYPES", "batch298ExternalAttestationBindingFields",
    "attestExternalBatch297LifecycleFinalizationReceipts", "auditExternalBatch297LifecycleFinalizationReceiptAttestations",
    "getExternalBatch297LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch297LifecycleFinalizationReceiptAttestations",
    "BATCH297_RECEIPT_EVENT_TYPES", "batch297FinalizationReceiptPrefixDigest"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH298_EVENT_TYPES"), "independent checkpoint snapshot includes Batch 298 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch298ExternalLifecycleFinalizationReceiptAttestations",
    "batch298ExternalLifecycleFinalizationReceiptAttestationAudit", "batch298ExternalLifecycleFinalizationReceiptAttestationRequired",
    "batch298ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch298ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("const batch298ExternalLifecycleFinalizationReceiptAttestationRoot = `${batch297ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch298ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 298: ledger schema validates external attestation and predecessor bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH298_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 298 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "finalizationReceiptDigest", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest", "signingKeyLifecycleBindingDigest",
    "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
