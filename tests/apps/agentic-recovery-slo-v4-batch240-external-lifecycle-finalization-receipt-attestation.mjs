import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations";

test("Batch 240: empty source history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b240-empty");
  const audit = await app.auditRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch239_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const result = await app.reconcileRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch240ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 240: source receipt binding, checkpoint snapshot, API surface, and fail-closed wiring are registered", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b240-wiring");
  const emptyAttestation = await app.attestRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(emptyAttestation.status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH240_ATTESTED_EVENT", "BATCH240_EVENT_TYPES", "batch240ExternalAttestationBindingFields",
    "attestExternalBatch239LifecycleFinalizationReceipts", "auditExternalBatch239LifecycleFinalizationReceiptAttestations",
    "getExternalBatch239LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch239LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH240_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch239_lifecycle_finalization_receipt_external_attestations"
  ]) assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("const snapshot = { schemaVersion: 1, domain: \"cross_domain_finalization_receipt_external_attestations\"", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH240_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 240 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch240ExternalLifecycleFinalizationReceiptAttestations",
    "batch240ExternalLifecycleFinalizationReceiptAttestationAudit"]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch240ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes(ROUTE));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
