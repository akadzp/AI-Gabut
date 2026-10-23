import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 287: empty history is read-only and cannot fabricate lifecycle receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b287-empty");
  const audit = await app.auditRecoveryGateBatch287ExternalAttestationLifecycle(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.lifecycleGenerationCount, 0);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.missingFinalizationReceiptCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch287ExternalAttestationLifecycleSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch286_external_attestation_lifecycle");
  assert.deepEqual(snapshot.snapshot.lifecycleEvents, []);
  assert.deepEqual(snapshot.snapshot.finalizationReceipts, []);
  const reconciled = await app.reconcileRecoveryGateBatch287ExternalAttestationLifecycle(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch287ExternalAttestationLifecycleAudit.status, "not_initialized");
});

test("Batch 287: invalid actions and challenge parameters are rejected before any lifecycle mutation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b287-invalid");
  await assert.rejects(() => app.prepareRecoveryGateBatch287ExternalAttestationLifecycle(owner, {
    action: "reactivate", reason: "Attempt to reactivate a revoked attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH287_ACTION_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch287ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "short"
  }), error => error.code === "RECOVERY_GATE_BATCH287_REASON_INVALID");
  await assert.rejects(() => app.prepareRecoveryGateBatch287ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "A valid reason for a lifecycle renewal", ttlMs: 0
  }), error => error.code === "RECOVERY_GATE_BATCH287_TTL_INVALID");
  const audit = await app.auditRecoveryGateBatch287ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 287: source currentness is required before renewal or revocation", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b287-source-gate");
  await assert.rejects(() => app.prepareRecoveryGateBatch287ExternalAttestationLifecycle(owner, {
    action: "renew", reason: "Renew only after a verified current source attestation"
  }), error => error.code === "RECOVERY_GATE_BATCH287_SOURCE_NOT_CURRENT");
  const audit = await app.auditRecoveryGateBatch287ExternalAttestationLifecycle(owner);
  assert.equal(audit.lifecycleEventCount, 0);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 287: service, checkpoint inventory, global convergence, and owner-scoped HTTP routes are wired", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH287_INTENT_EVENT", "BATCH287_RENEWED_EVENT", "BATCH287_REVOKED_EVENT", "BATCH287_SUPERSEDED_EVENT",
    "BATCH287_FINALIZED_EVENT", "BATCH287_RECEIPT_EVENT", "BATCH287_EVENT_TYPES", "BATCH287_CHALLENGE_KIND",
    "prepareBatch287ExternalAttestationLifecycle", "applyBatch287ExternalAttestationLifecycle", "auditBatch287ExternalAttestationLifecycle",
    "getBatch287ExternalAttestationLifecycleSnapshot", "resumeBatch287ExternalAttestationLifecycle", "reconcileBatch287ExternalAttestationLifecycle",
    "auditExternalBatch285LifecycleFinalizationReceiptAttestations", "BATCH285_RECEIPT_EVENT_TYPES",
    "RECOVERY_GATE_BATCH287_RECEIPT_BINDING_INVALID", "cross_domain_batch286_external_attestation_lifecycle"])
    assert.ok(core.includes(token), token);
  const checkpointStart = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const checkpointEnd = core.indexOf("function externalLifecycleFinalizationReceiptAttestationBindingFields", checkpointStart);
  assert.ok(checkpointStart >= 0 && checkpointEnd > checkpointStart
    && core.slice(checkpointStart, checkpointEnd).includes("BATCH287_EVENT_TYPES"), "independent checkpoint inventory includes Batch 287 lifecycle events");
  const schemaStart = core.indexOf("|| BATCH287_EVENT_TYPES.includes(event.eventType) && (");
  const schemaEnd = core.indexOf("|| BATCH246_EVENT_TYPES.includes(event.eventType) && (", schemaStart);
  assert.ok(schemaStart >= 0 && schemaEnd > schemaStart, "Batch 287 ledger schema validation branch exists");
  const schema = core.slice(schemaStart, schemaEnd);
  for (const token of ["externalAttestationLifecycleGeneration", "targetAttestationId", "sourceFinalizationReceiptId", "reasonDigest",
    "signingKeyLifecycleBindingDigest", "replacementAttestationId", "lifecycleFinalizationEventId", "receiptBindingDigest", "previousReceiptDigest"])
    assert.ok(schema.includes(token), token);
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["prepareRecoveryGateBatch287ExternalAttestationLifecycle", "applyRecoveryGateBatch287ExternalAttestationLifecycle",
    "auditRecoveryGateBatch287ExternalAttestationLifecycle", "getRecoveryGateBatch287ExternalAttestationLifecycleSnapshot",
    "reconcileRecoveryGateBatch287ExternalAttestationLifecycle", "batch287ExternalAttestationLifecycleAudit", "batch287ConvergedStatus"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch287ExternalAttestationLifecycleRoot"));
  assert.ok(server.includes("const batch287ExternalAttestationLifecycleRoot = `${batch286ExternalLifecycleFinalizationReceiptAttestationRoot}/lifecycle`"));
  for (const [method, suffix] of [["post", "prepare"], ["post", "apply"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch287ExternalAttestationLifecycleRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});
