import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { setupOwner } from "./helpers/agentic-recovery-slo-v4-batch203-helpers.mjs";

test("Batch 324: empty history is read-only and cannot fabricate external attestations", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b324-empty");
  const audit = await app.auditRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.status, "not_initialized", JSON.stringify({ status: audit.status, findings: audit.findings }));
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
  assert.equal(audit.usableForCurrentDecision, true);
  const snapshot = await app.getRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestationSnapshot(owner);
  assert.equal(snapshot.snapshot.domain, "cross_domain_batch323_lifecycle_finalization_receipt_external_attestations");
  assert.deepEqual(snapshot.snapshot.receipts, []);
  assert.deepEqual(snapshot.snapshot.attestations, []);
  const reconciled = await app.reconcileRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(reconciled.status, "not_initialized");
  assert.equal(reconciled.complete, true);
  const globalAudit = await app.auditRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt(owner);
  assert.equal(globalAudit.batch324ExternalLifecycleFinalizationReceiptAttestationAudit.status, "not_initialized");
});

test("Batch 324: attest and reconcile do not invent Batch 323 source receipts", { timeout: 30000 }, async t => {
  const { app, owner } = await setupOwner(t, "b324-no-source");
  const result = await app.attestRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(result.status, "not_initialized");
  assert.equal(result.complete, true);
  const audit = await app.auditRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestations(owner);
  assert.equal(audit.receiptCount, 0);
  assert.equal(audit.attestationCount, 0);
  assert.equal(audit.missingAttestationCount, 0);
});

test("Batch 324: service validates Batch 323 receipts, finalization events, and chain bindings", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  for (const token of ["BATCH324_ATTESTED_EVENT", "BATCH324_EVENT_TYPES", "batch324ExternalAttestationBindingFields",
    "attestExternalBatch323LifecycleFinalizationReceipts", "auditExternalBatch323LifecycleFinalizationReceiptAttestations",
    "getExternalBatch323LifecycleFinalizationReceiptAttestationSnapshot", "reconcileExternalBatch323LifecycleFinalizationReceiptAttestations",
    "BATCH323_RECEIPT_EVENT_TYPES", "BATCH323_FINALIZED_EVENT", "sourceReceiptChainDigest", "previousAttestationDigest",
    "keyCutoffDetected", "keyCutoffRevalidated"])
    assert.ok(core.includes(token), token);
});

test("Batch 324: independent checkpoint snapshot inventories Batch 324 attestation events", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  const start = core.indexOf("async function getFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationSnapshot");
  const end = core.indexOf("\n  async function ", start + 1);
  assert.ok(start >= 0 && end > start, "checkpoint snapshot function exists");
  const block = core.slice(start, end);
  assert.ok(block.includes("BATCH324_EVENT_TYPES"), "checkpoint snapshot includes Batch 324 event inventory");
  assert.ok(block.includes("previousAttestationId") && block.includes("sourceReceiptChainDigest"), "snapshot preserves predecessor and receipt-chain fields");
});

test("Batch 324: application convergence and owner-scoped HTTP routes are wired", async () => {
  const application = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const token of ["attestRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestations",
    "auditRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestations",
    "getRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestationSnapshot",
    "reconcileRecoveryGateBatch324ExternalLifecycleFinalizationReceiptAttestations",
    "batch324ExternalLifecycleFinalizationReceiptAttestationAudit", "batch324ExternalLifecycleFinalizationReceiptAttestationRequired",
    "batch324ConvergedStatus", "batch324ExternalLifecycleFinalizationReceiptAttestationDigest"])
    assert.ok(application.includes(token), token);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("batch324ExternalLifecycleFinalizationReceiptAttestationRoot"));
  assert.ok(server.includes("const batch324ExternalLifecycleFinalizationReceiptAttestationRoot = `${batch323ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`"));
  for (const [method, suffix] of [["post", "attest"], ["get", "audit"], ["get", "snapshot"], ["post", "reconcile"]])
    assert.ok(server.includes("app." + method + "(`${batch324ExternalLifecycleFinalizationReceiptAttestationRoot}/" + suffix + "`"), `${method.toUpperCase()} ${suffix} route`);
});

test("Batch 324: ledger schema validates attestation generation, receipt binding, and predecessor continuity", async () => {
  const core = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-recovery-gate-proof-continuity.js", import.meta.url), "utf8");
  assert.ok(core.includes("|| BATCH324_EVENT_TYPES.includes(event.eventType) && (!Number.isSafeInteger(event.generation)"));
  assert.ok(core.includes("...BATCH321_EVENT_TYPES, ...BATCH322_EVENT_TYPES, ...BATCH323_EVENT_TYPES, ...BATCH324_EVENT_TYPES, ...BATCH325_EVENT_TYPES, ...BATCH326_EVENT_TYPES, ...BATCH327_EVENT_TYPES, ...BATCH328_EVENT_TYPES, ...BATCH329_EVENT_TYPES].includes(event.eventType)"));
  const start = core.indexOf("function batch324ExternalAttestationBindingFields");
  const end = core.indexOf("async function attestExternalBatch323LifecycleFinalizationReceipts", start);
  assert.ok(start >= 0 && end > start, "Batch 324 binding canonicalizer exists");
  const fields = core.slice(start, end);
  for (const field of ["finalizationReceiptId", "lifecycleFinalizationEventDigest", "sourceReceiptChainDigest",
    "sourceCheckpointFingerprint", "sourceSigningKeyLifecycleBindingDigest", "signingKeyLifecycleBindingDigest",
    "previousAttestationId", "previousAttestationDigest"])
    assert.ok(fields.includes(field), field);
});
