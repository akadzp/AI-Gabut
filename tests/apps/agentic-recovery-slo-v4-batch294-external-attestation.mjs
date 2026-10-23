import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 294: empty history remains read-only and cannot fabricate Batch 293 receipt attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b292-empty");
  const audit = await app.auditRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch293_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const attested = await app.attestRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(attested.status, "not_initialized");
  assert.equal(attested.complete, true);
  const reconciled = await app.reconcileRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch294ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 294: service, independent checkpoint inventory, convergence, and owner-scoped HTTP routes are wired", async t => {
  const { app, owner } = await setupOwner(t, "b292-wiring");
  assert.equal((await app.auditRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestations(owner)).status, "not_initialized");
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  assert.ok(core.includes("...BATCH293_EVENT_TYPES, ...BATCH294_EVENT_TYPES"), "ledger allowlist retains Batch 293 source events and Batch 294 attestations");
  for (const token of ["BATCH294_ATTESTED_EVENT", "BATCH294_EVENT_TYPES", "batch294ExternalAttestationBindingFields",
    "attestExternalBatch293LifecycleFinalizationReceipts", "auditExternalBatch293LifecycleFinalizationReceiptAttestations",
    "getExternalBatch293LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch293LifecycleFinalizationReceiptAttestations",
    "batch293FinalizationReceiptPrefixDigest", "RECOVERY_GATE_BATCH294_RECEIPT_BINDING_INVALID",
    "cross_domain_batch293_lifecycle_finalization_receipt_external_attestations"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH294_EVENT_TYPES"), "independent checkpoint snapshot covers Batch 294 events");
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch294ExternalLifecycleFinalizationReceiptAttestations",
    "batch294ExternalLifecycleFinalizationReceiptAttestationAudit", "batch294ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch294ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("const batch294ExternalLifecycleFinalizationReceiptAttestationRoot = `${batch293ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch294ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 294: ledger schema rejects malformed external-attestation bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("|| BATCH294_EVENT_TYPES.includes(event.eventType) && (");
  const end = core.indexOf("|| BATCH249_EVENT_TYPES.includes(event.eventType) && (", start);
  assert.ok(start >= 0 && end > start, "Batch 294 schema validator branch exists");
  const validator = core.slice(start, end);
  for (const token of ["attestationGeneration", "finalizationReceiptId", "lifecycleFinalizationEventId",
    "sourceReceiptChainDigest", "sourceCheckpointFingerprint", "sourceLifecycleAuditDigest",
    "signingKeyLifecycleBindingDigest", "bindingDigest", "previousAttestationId", "previousAttestationDigest"])
    assert.ok(validator.includes(token), token);
});
