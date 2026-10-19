import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 266: empty Batch 265 receipt history remains read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b266empty");
  const audit = await app.auditRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch265_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
});

test("Batch 266: external attestation flow is bound to Batch 265 receipts and owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b266source");
  const result = await app.reconcileRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch266ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH266_EVENT_TYPES", "BATCH266_ATTESTED_EVENT", "batch266ExternalAttestationBindingFields",
    "attestExternalBatch265LifecycleFinalizationReceipts", "auditExternalBatch265LifecycleFinalizationReceiptAttestations",
    "getExternalBatch265LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch265LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH266_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch265_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH266_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 266 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch266ExternalLifecycleFinalizationReceiptAttestations",
    "batch266ExternalLifecycleFinalizationReceiptAttestationAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch266ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("`${batch265ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch266ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 266: ledger validation binds attestation to receipt chain, lifecycle finalization, signing key, and predecessor", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const validationStart = core.indexOf("|| BATCH266_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType)", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["finalizationReceiptId", "finalizationReceiptDigest", "sourceReceiptChainDigest", "sourceCheckpointFingerprint",
    "sourceLifecycleAuditDigest", "sourceSigningKeyLifecycleBindingDigest", "signingKeyLifecycleBindingDigest",
    "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
