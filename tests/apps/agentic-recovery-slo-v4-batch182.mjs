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
const recordDigest = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
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
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Explicit receipt checkpoint enrollment for Batch 182.");
}
async function enrollFinalizationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint genesis for Batch 182.");
}
async function enrollReconciliationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation receipt checkpoint genesis for Batch 182.");
}
async function activateKey(app, owner, keyId = "finalization_key_old") {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId, reason: "Activate signing key for Batch 182 finalization attestation." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function createFinalization(app, storage, owner) {
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enrollFinalizationCheckpoint(app, owner);
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  return app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
}

test("Batch 182: required finalization attestation fails closed without an Ed25519 signer registry", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b182-no-signer" }),
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation: true }),
  /Recovery-finalization receipt attestation diwajibkan/);
});

test("Batch 182: required reconciliation checkpoint fails closed without an independent provider", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b182-no-reconciliation-anchor" }),
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: true }),
  /External recovery-finalization reconciliation-receipt checkpoint diwajibkan/);
});

test("Batch 182: finalization receipt is Ed25519-attested and reconciliation receipt is independently anchored", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b182-fa-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b182-receipt-anchor.example");
  const finalizationAnchor = anchorProvider("https://b182-finalization-anchor.example");
  const reconciliationAnchor = anchorProvider("https://b182-reconciliation-anchor.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: reconciliationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation: true
  });
  const owner = "b182-fa";
  await activateKey(app, owner);
  await enrollReconciliationCheckpoint(app, owner);
  const recovered = await createFinalization(app, storage, owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  const finalization = recovered.finalizationReceipt.receipt;
  assert.ok(finalization.attestation);
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation(owner, finalization.id);
  assert.equal(verification.status, "verified_current");
  assert.equal(verification.usableForCurrentDecision, true);
  const reconciliationAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationReceipts(owner);
  assert.equal(reconciliationAudit.status, "healthy");
  assert.ok(reconciliationAudit.receiptCount >= 1);
  assert.equal(reconciliationAudit.usableForCurrentDecision, true);
  assert.equal(reconciliationAudit.checkpointAudit.checkpoint.status, "anchored");
  assert.equal(reconciliationAudit.checkpointAudit.checkpoint.freshnessStatus, "fresh");
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationContinuity(owner);
  assert.equal(continuity.status, "healthy");
  assert.equal(continuity.usableForCurrentDecision, true);
});

test("Batch 182: key rotation preserves historical signature but blocks current use", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b182-key-cutoff-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b182-key-receipt-anchor.example");
  const finalizationAnchor = anchorProvider("https://b182-key-finalization-anchor.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation: true
  });
  const owner = "b182-key-cutoff";
  await activateKey(app, owner);
  const recovered = await createFinalization(app, storage, owner);
  const finalization = recovered.finalizationReceipt.receipt;
  const rotate = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Exercise key-cutoff revalidation for Batch 182." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, rotate.challengeId,
    { confirmation: rotate.confirmation });
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation(owner, finalization.id,
    { checkCurrent: true });
  assert.equal(verification.status, "historically_valid_stale");
  assert.equal(verification.historicallyValid, true);
  assert.equal(verification.usableForCurrentDecision, false);
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(audit.status, "stale");
  assert.equal(audit.usableForCurrentDecision, false);
  const continuity = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationContinuity(owner);
  assert.equal(continuity.usableForCurrentDecision, false);
  const gate = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b182-gate-after-key-cutoff" });
  assert.notEqual(gate.status, "healthy");
  assert.ok(gate.findings.some(item => item.code === "RECOVERY_DECISION_GATE_FINALIZATION_CONTINUITY_NOT_CURRENT"
    || item.code === "RECOVERY_DECISION_GATE_FINALIZATION_CONTINUITY_UNHEALTHY"));
});

test("Batch 182: tampered finalization signature is rejected even when local digests are recomputed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "b182-tamper-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b182-tamper-receipt-anchor.example");
  const finalizationAnchor = anchorProvider("https://b182-tamper-finalization-anchor.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation: true
  });
  const owner = "b182-tamper";
  await activateKey(app, owner);
  const recovered = await createFinalization(app, storage, owner);
  const store = createAgenticStore({ storage });
  const ledgerId = `decision-gate-receipt-recovery-finalizations-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const events = structuredClone(ledger.events);
  events[0].attestation.signature = "A".repeat(86);
  events[0].attestation.digest = recordDigest(events[0].attestation);
  events[0].digest = recordDigest(events[0]);
  const unsignedLedger = { ...ledger, events, headDigest: events[0].digest, eventCount: events.length };
  delete unsignedLedger.digest;
  delete unsignedLedger._storage;
  const candidate = { ...unsignedLedger, digest: recordDigest(unsignedLedger) };
  await store.putEvidence(owner, candidate, { expectedVersion: ledger._storage?.version });
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation(owner, recovered.finalizationReceipt.receipt.id);
  assert.equal(verification.status, "unhealthy");
  assert.equal(verification.reasonCode, "RECOVERY_FINALIZATION_ATTESTATION_SIGNATURE_INVALID");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_FINALIZATION_ATTESTATION_UNHEALTHY"));
});

test("Batch 182: stale finalization checkpoint reconciliation emits an anchored receipt with attestation", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b182-rr-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse("2026-10-14T00:00:00.000Z");
  const clock = () => new Date(now).toISOString();
  const finalizationAnchor = anchorProvider("https://b182-reconcile-target-anchor.example");
  const reconciliationAnchor = anchorProvider("https://b182-reconcile-receipt-anchor.example");
  const { app } = await setup(root, {
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: reconciliationAnchor,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: true
  }, clock);
  const owner = "b182-rr";
  await enrollFinalizationCheckpoint(app, owner);
  await enrollReconciliationCheckpoint(app, owner);
  now += 2 * 86400000;
  await app.reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint(owner);
  const refreshedReceiptCheckpoint = await app.getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointStatus(owner);
  assert.equal(refreshedReceiptCheckpoint.status, "anchored");
  assert.equal(refreshedReceiptCheckpoint.freshnessStatus, "fresh");
  const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpoint(owner);
  assert.equal(reconciled.status, "anchored");
  assert.ok(reconciled.reconciliationReceipt?.receipt);
  assert.equal(reconciled.reconciliationReceipt.receipt.operation, "refresh_stale_checkpoint");
  assert.ok(reconciled.reconciliationReceipt.receipt.attestation);
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAttestation(owner,
    reconciled.reconciliationReceipt.receipt.id);
  assert.equal(verification.status, "verified_current");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.usableForCurrentDecision, true);
});

test("Batch 182: finalization and reconciliation APIs are exported and providers must be independent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b182-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const shared = anchorProvider("https://b182-shared-anchor.example");
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: path.join(root, "shared") }),
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: shared,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: shared }), /external anchor provider terpisah/);
  const { app } = await setup(path.join(root, "api"));
  for (const name of [
    "verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation",
    "auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationReceipts",
    "verifyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAttestation",
    "getRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointStatus",
    "reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint",
    "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpoint"
  ]) assert.equal(typeof app[name], "function", `${name} must be exported`);
  const server = await fs.readFile(path.resolve("apps/agentic/backend/server.js"), "utf8");
  assert.match(server, /recovery\/finalizations\/attestation\/:id\/verify/);
  assert.match(server, /recovery\/finalizations\/reconciliation\/checkpoint\/enrollments/);
});
