import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 264: empty Batch 263 receipt history remains read-only and cannot fabricate attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b263-empty");
  const audit = await app.auditRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch263_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
});

test("Batch 264: external attestation requires current Batch 263 receipts and exposes owner-scoped APIs", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b263-source-required");
  const result = await app.reconcileRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH264_EVENT_TYPES", "BATCH264_ATTESTED_EVENT", "batch264ExternalAttestationBindingFields",
    "attestExternalBatch263LifecycleFinalizationReceipts", "auditExternalBatch263LifecycleFinalizationReceiptAttestations",
    "getExternalBatch263LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch263LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH264_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch263_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH264_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 264 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch264ExternalLifecycleFinalizationReceiptAttestations",
    "batch264ExternalLifecycleFinalizationReceiptAttestationAudit"])
    assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch264ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("`${batch263ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch264ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 264: ledger validation binds each attestation to a receipt, chain prefix, signing key, and predecessor", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const validationStart = core.indexOf("|| BATCH264_EVENT_TYPES.includes(event.eventType) && (");
  const validationEnd = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType)", validationStart);
  assert.ok(validationStart >= 0 && validationEnd > validationStart);
  const validator = core.slice(validationStart, validationEnd);
  for (const token of ["finalizationReceiptId", "finalizationReceiptDigest", "sourceReceiptChainDigest", "sourceCheckpointFingerprint",
    "sourceLifecycleAuditDigest", "sourceSigningKeyLifecycleBindingDigest", "signingKeyLifecycleBindingDigest",
    "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
