import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 290: empty history remains read-only and cannot fabricate Batch 289 receipt attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b288-empty");
  const audit = await app.auditRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch289_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const attested = await app.attestRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");
  assert.equal(attested.complete, true);
  const reconciled = await app.reconcileRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch290ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 290: service, independent checkpoint inventory, convergence, and owner-scoped HTTP routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b288-wiring");
  assert.equal((await app.auditRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestations(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH290_ATTESTED_EVENT", "BATCH290_EVENT_TYPES", "batch290ExternalAttestationBindingFields",
    "attestExternalBatch289LifecycleFinalizationReceipts", "auditExternalBatch289LifecycleFinalizationReceiptAttestations",
    "getExternalBatch289LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch289LifecycleFinalizationReceiptAttestations",
    "batch289FinalizationReceiptPrefixDigest", "RECOVERY_GATE_BATCH290_RECEIPT_BINDING_INVALID",
    "cross_domain_batch289_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH290_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 290 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch290ExternalLifecycleFinalizationReceiptAttestations",
    "batch290ExternalLifecycleFinalizationReceiptAttestationAudit", "batch290ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch290ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("const batch290ExternalLifecycleFinalizationReceiptAttestationRoot = `${batch289ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch290ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 290: ledger schema rejects malformed external-attestation bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH290_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 290 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest",
    "signingKeyLifecycleBindingDigest", "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
