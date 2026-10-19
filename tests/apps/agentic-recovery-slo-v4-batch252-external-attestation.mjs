import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations/lifecycle/finalization-receipts/external-attestations/lifecycle/finalization-receipts/external-attestations";

test("Batch 252: empty Batch 251 lifecycle-receipt history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b252-empty");
  const audit = await app.auditRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);

  const snapshot = await app.getRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch251_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);

  const reconciled = await app.reconcileRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const attested = await app.attestRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");

  const gate = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(gate.batch252ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 252: source receipt binding, independent checkpoint snapshot, application API, and owner-scoped routes are registered", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b252-wiring");
  const empty = await app.attestRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(empty.status, "not_initialized");

  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH252_ATTESTED_EVENT", "BATCH252_EVENT_TYPES", "batch252ExternalAttestationBindingFields",
    "attestExternalBatch251LifecycleFinalizationReceipts", "auditExternalBatch251LifecycleFinalizationReceiptAttestations",
    "getExternalBatch251LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch251LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH252_EXTERNAL_ATTESTATION_CHAIN_INVALID", "cross_domain_batch251_lifecycle_finalization_receipt_external_attestations"
  ]) assert.ok(core.includes(token), token);

  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH252_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 252 events");

  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch252ExternalLifecycleFinalizationReceiptAttestations",
    "batch252ExternalLifecycleFinalizationReceiptAttestationAudit"]) assert.ok(application.includes(token), token);

  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch252ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("`${batch251ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"])
    assert.ok(server.includes(`/${suffix}",async`), suffix);
  assert.ok(ROUTE.length > 0);
});
