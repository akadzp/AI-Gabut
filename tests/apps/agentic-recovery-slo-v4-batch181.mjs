import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
function anchorProvider(baseUrl) {
  const records = new Map();
  return { baseUrl, records,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
async function setup(root, extra = {}, clock = () => "2026-10-14T00:00:00.000Z") {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock,
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    ...extra });
  return { app, storage, pairs };
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function enrollReceiptCheckpoint(app, owner) {
  return enroll(app, owner,
    "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "Explicitly enroll the decision-gate receipt checkpoint before recovery finalization.");
}
async function enrollFinalizationCheckpoint(app, owner) {
  return enroll(app, owner,
    "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "Enroll the empty recovery-finalization ledger as a verified genesis baseline.");
}
async function activateKey(app, owner, keyId = "finalization_key_old") {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId, reason: "Activate the signing key for current recovery-finalization binding." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}

 test("Batch 181: required finalization-ledger checkpoint fails closed without provider", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b181-required-anchor" }),
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true }),
  /External recovery decision-gate receipt recovery-finalization checkpoint diwajibkan/);
});

test("Batch 181: finalization ledger external checkpoint enrolls genesis, advances after CAS, and binds completed recovery intent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b181-finalization-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b181-receipt-anchor.example");
  const finalizationAnchor = anchorProvider("https://b181-finalization-anchor.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true
  });
  const owner = "b181-finalization-anchor";
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b181-bootstrap" });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b181-receipt-current" });
  const genesis = await enrollFinalizationCheckpoint(app, owner);
  assert.equal(genesis.status, "anchored");
  assert.equal(genesis.historyNotProven, false);
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  assert.ok(recovered.finalizationReceipt.receipt.recoveryIntentDigest);
  assert.ok(recovered.finalizationReceipt.receipt.recoveryIntentId);
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointStatus(owner);
  assert.equal(checkpoint.status, "anchored");
  assert.equal(checkpoint.freshnessStatus, "fresh");
  const ledgerAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(ledgerAudit.status, "healthy");
  assert.equal(ledgerAudit.receiptCount, 1);
  assert.equal(ledgerAudit.usableForCurrentDecision, true);
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationContinuity(owner);
  assert.equal(continuity.status, "healthy");
  assert.equal(continuity.usableForCurrentDecision, true);
});

test("Batch 181: key-lifecycle change makes a previously finalized receipt continuity stale", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b181-key-cutoff-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b181-key-receipt-anchor.example");
  const finalizationAnchor = anchorProvider("https://b181-key-finalization-anchor.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true
  });
  const owner = "b181-key-cutoff";
  await activateKey(app, owner);
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b181-bootstrap" });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b181-attested-receipt" });
  await enrollFinalizationCheckpoint(app, owner);
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
  assert.equal(recovered.status, "recovered");
  const before = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(before.status, "healthy");
  assert.ok(before.latestReceipt.keyLifecycleBindingDigest);
  const rotation = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate key to prove finalization continuity is revalidated." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, rotation.challengeId,
    { confirmation: rotation.confirmation });
  const after = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(after.status, "stale");
  assert.equal(after.usableForCurrentDecision, false);
  assert.ok(after.findings.some(item => item.code === "RECOVERY_FINALIZATION_KEY_LIFECYCLE_BINDING_STALE"));
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationContinuity(owner);
  assert.equal(continuity.usableForCurrentDecision, false);
  assert.ok(["stale", "unhealthy"].includes(continuity.status));
});

test("Batch 181: finalization checkpoint marker crash-recovery uses a completed recovery intent and preserves the anchor", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b181-marker-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b181-marker-receipt-anchor.example");
  const finalizationAnchor = anchorProvider("https://b181-marker-finalization-anchor.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true
  });
  const owner = "b181-marker-recovery";
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b181-marker-source" });
  await enrollFinalizationCheckpoint(app, owner);
  const store = createAgenticStore({ storage });
  const receiptMarkerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const receiptMarker = await store.getEvidence(owner, receiptMarkerId);
  assert.ok(receiptMarker);
  await store.state.delete("evidence", `${owner}--${receiptMarkerId}`, { expectedVersion: receiptMarker._storage?.version });
  const receiptRecovery = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
  assert.equal(receiptRecovery.status, "recovered");
  const markerId = `cross-domain-recovery-decision-gate-receipt-recovery-finalization-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  const externalBefore = await app.getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointStatus(owner);
  assert.equal(externalBefore.status, "anchored");
  assert.equal(externalBefore.sourceCount, 1);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointRecovery(owner);
  assert.equal(inspection.recoverable, true);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.recoveryIntent.status, "completed");
  assert.equal(recovered.checkpoint.status, "anchored");
  assert.equal(recovered.checkpoint.anchorDigest, externalBefore.anchorDigest);
  const markerAfter = await store.getEvidence(owner, markerId);
  assert.ok(markerAfter);
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint(owner);
  assert.equal(continuity.status, "healthy");
});

test("Batch 181: an empty genesis finalization checkpoint can recover its marker without inventing history", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b181-empty-genesis-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const finalizationAnchor = anchorProvider("https://b181-empty-genesis-anchor.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true
  });
  const owner = "b181-empty-genesis";
  const enrolled = await enrollFinalizationCheckpoint(app, owner);
  assert.equal(enrolled.status, "anchored");
  const genesisStatus = await app.getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointStatus(owner);
  assert.equal(genesisStatus.sourceCount, 0);
  assert.equal(genesisStatus.historyNotProven, false);
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-receipt-recovery-finalization-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.checkpoint.status, "anchored");
  assert.equal(recovered.checkpoint.sourceCount, 0);
  assert.equal(recovered.checkpoint.historyNotProven, false);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint(owner)).status, "healthy");
});

test("Batch 181: finalization rejects an unpersisted or mismatched recovery-intent binding", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b181-intent-binding-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b181-intent-receipt-anchor.example");
  const finalizationAnchor = anchorProvider("https://b181-intent-finalization-anchor.example");
  const { app } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true
  });
  const owner = "b181-intent-binding";
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b181-intent-receipt" });
  await enrollFinalizationCheckpoint(app, owner);
  await assert.rejects(() => app.finalizeRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryCAS(owner, {
    recoveryIntent: { id: "missing-intent", ownerId: owner, recoveryIntentDigest: "a".repeat(64), status: "completed" }
  }), error => error.code === "RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_INTENT_NOT_FINALIZED"
    || error.code === "RECOVERY_DECISION_GATE_RECEIPT_RECOVERY_INTENT_BINDING_INVALID");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(audit.receiptCount, 0);
});

test("Batch 181: finalization checkpoint rejects shared provider endpoint and exports recovery APIs", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b181-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const shared = anchorProvider("https://b181-shared-anchor.example");
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: path.join(root, "shared") }),
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: shared,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: shared }), /external anchor provider terpisah/);
  const { app } = await setup(path.join(root, "api"));
  for (const name of [
    "getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointStatus",
    "reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint",
    "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint",
    "inspectRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointRecovery",
    "recoverRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint",
    "auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationContinuity"
  ]) assert.equal(typeof app[name], "function", `${name} must be exported`);
  const server = await fs.readFile(path.resolve("apps/agentic/backend/server.js"), "utf8");
  for (const route of ["/receipts/recovery/finalizations/checkpoint/status", "/receipts/recovery/finalizations/checkpoint/enrollments",
    "/receipts/recovery/finalizations/checkpoint/recovery/inspect", "/receipts/recovery/finalizations/continuity/audit"])
    assert.ok(server.includes(route), `HTTP route ${route} must be registered`);
});
