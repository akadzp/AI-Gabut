import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

const ROUTE = "/finalization-receipts/external-attestations";

test("Batch 238: empty Batch 237 receipt history remains read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b238-empty");
  const audit = await app.auditRecoveryGateBatch238ExternalFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const convergence = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(convergence.batch238ExternalAttestationAudit.receiptCount, 0);
  assert.equal(convergence.batch238ExternalAttestationAudit.status, "not_initialized");
  const snapshot = await app.getRecoveryGateBatch238ExternalFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch237_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch238ExternalFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized", JSON.stringify({ status: reconciled.status, audit: reconciled.audit }));
  assert.equal(reconciled.complete, true);
  assert.equal(reconciled.attestation?.attestationCount ?? 0, 0);
});

test("Batch 238: external attestations bind Batch 237 receipt generations and converge through the independent checkpoint", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of [
    "BATCH238_EVENT_TYPES",
    "batch238ExternalAttestationBindingFields",
    "attestExternalBatch237LifecycleFinalizationReceipts",
    "auditExternalBatch237LifecycleFinalizationReceiptAttestations",
    "getExternalBatch237LifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileExternalBatch237LifecycleFinalizationReceiptAttestations",
    "RECOVERY_GATE_BATCH238_EXTERNAL_ATTESTATION_CHAIN_INVALID",
    "RECOVERY_GATE_BATCH238_EXTERNAL_ATTESTATION_MISSING",
    "cross_domain_batch237_finalization_receipt_external_attestations"
  ]) assert.ok(core.includes(token), token);
  const checkpointSnapshot = core.slice(core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot"),
    core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields"));
  assert.ok(checkpointSnapshot.includes("BATCH237_EVENT_TYPES"));
  assert.ok(checkpointSnapshot.includes("BATCH238_EVENT_TYPES"));
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of [
    "attestRecoveryGateBatch238ExternalFinalizationReceiptAttestations",
    "auditRecoveryGateBatch238ExternalFinalizationReceiptAttestations",
    "getRecoveryGateBatch238ExternalFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch238ExternalFinalizationReceiptAttestations",
    "batch238ExternalAttestationAudit"
  ]) assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch238ExternalAttestationRoot"));
  assert.ok(server.includes(ROUTE));
  for (const suffix of ["attest", "audit", "snapshot", "reconcile"]) assert.ok(server.includes(`/${suffix}",async`), suffix);
});
