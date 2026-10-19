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
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
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
async function setup(root, extra = {}) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock: () => "2026-10-14T00:00:00.000Z",
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    ...extra });
  return { app, storage, pairs };
}
async function seedFinalization(storage, owner, suffix = "one", createdAt = "2026-10-14T00:00:00.000Z") {
  const store = createAgenticStore({ storage });
  const action = "reconcile_policy_binding_audit_checkpoint";
  const planUnsigned = { id: `b178-plan-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-plan", schemaVersion: 1,
    status: "prepared", reason: "Seed a source-bound remediation plan for Batch 178 tests.", createdAt,
    expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString(), stateFingerprint: "d".repeat(64),
    allowedActions: [action], blockedActions: [], auditStatus: "blocked", auditFindingsDigest: "e".repeat(64),
    deletionPerformed: false, compactionPerformed: false };
  const plan = { ...planUnsigned, digest: digestRecord(planUnsigned) };
  await store.putEvidence(owner, plan, { overwrite: false });
  const intentUnsigned = { id: `b178-intent-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-recovery-intent",
    schemaVersion: 1, status: "completed", planId: plan.id, planDigest: plan.digest, stateFingerprint: plan.stateFingerprint,
    action, confirmationDigest: sha256(`EXECUTE CROSS-DOMAIN DRIFT REMEDIATION ${plan.digest.slice(0, 12)}`),
    createdAt, finalizedAt: createdAt, resultAnchorDigest: null };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  const executionUnsigned = { id: `b178-execution-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-execution",
    schemaVersion: 1, planId: plan.id, planDigest: plan.digest, recoveryIntentId: intent.id,
    recoveryIntentDigest: intent.digest, action, status: "completed", resultDigest: "a".repeat(64), createdAt, completedAt: createdAt,
    deletionPerformed: false, compactionPerformed: false };
  const execution = { ...executionUnsigned, digest: digestRecord(executionUnsigned) };
  await store.putEvidence(owner, execution, { overwrite: false });
  const finalizationUnsigned = { id: `b178-finalization-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-finalization",
    schemaVersion: 1, intentId: intent.id, intentDigest: intent.digest, executionId: execution.id, executionDigest: execution.digest,
    checkpointDomain: "cross_domain_drift_remediation_executions", checkpointStatus: "anchored",
    checkpointAnchorDigest: "c".repeat(64), checkpointAnchorSequence: 1, checkpointHistoryNotProven: false,
    usableForCurrentDecision: true, finalizedAt: createdAt, deletionPerformed: false, compactionPerformed: false };
  const finalization = { ...finalizationUnsigned, digest: digestRecord(finalizationUnsigned) };
  await store.putEvidence(owner, finalization, { overwrite: false });
  return { store, plan, intent, execution, finalization };
}
async function revokeReceipt(app, storage, owner, suffix) {
  const seeded = await seedFinalization(storage, owner, suffix);
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Revoke a test receipt to verify Batch 178 recovery-intent anchoring." });
  return app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}


test("Batch 178: required decision-gate receipt anchor fails closed without a provider", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b178-required-anchor" }),
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true }), /decision-gate audit receipt checkpoint diwajibkan/);
});

test("Batch 178: decision-gate receipts bind checkpoint/policy state and the external checkpoint advances one receipt at a time", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-receipt-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b178-receipt-anchor", provider = anchorProvider("https://b178-decision-receipts.example");
  const { app } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true });
  const bootstrap = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "bootstrap-178" });
  assert.equal(bootstrap.status, "blocked");
  assert.equal(bootstrap.decisionGateAuditReceipt.status, "recorded");
  assert.equal((await app.getRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointStatus(owner)).status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the bootstrap decision receipt history before relying on external continuity." });
  const enrolled = await app.applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const first = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "decision-178-1" });
  assert.equal(first.status, "blocked", "pre-enrollment history must not be treated as trusted retroactively");
  assert.equal(first.decisionGateAuditReceipt.status, "recorded");
  const receipt = first.decisionGateAuditReceipt.receipt;
  assert.equal(receipt.schemaVersion, 2);
  assert.equal(receipt.evidenceBindingDigest, sha256(canonical(receipt.evidenceBinding)));
  assert.equal(receipt.receiptCheckpointBindingDigest, sha256(canonical(receipt.evidenceBinding.decisionReceiptCheckpointBinding)));
  assert.equal(receipt.policyStateDigest, receipt.evidenceBinding.decisionEvidenceBinding.policyStateDigest);
  assert.equal(receipt.sourceCheckpointDigest, sha256(canonical(receipt.evidenceBinding.decisionEvidenceBinding.checkpointBindings)));
  assert.ok(receipt.evidenceBinding.decisionEvidenceBinding.checkpointBindings.some(item => Object.hasOwn(item, "currentPolicyDigest")));
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointStatus(owner);
  assert.equal(checkpoint.status, "anchored");
  assert.equal(checkpoint.anchorSequence, 2);
  assert.equal(checkpoint.sourceCount, 2);
  assert.equal(checkpoint.historyNotProven, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.receiptCount, 2);
});

test("Batch 178: explicit requestId replay is idempotent while each independent audit remains append-only", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-replay-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b178-replay", { app } = await setup(root);
  const first = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "stable-audit-request-178" });
  const countAfterFirst = (await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner)).receiptCount;
  const replay = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "stable-audit-request-178" });
  assert.equal(replay.decisionGateAuditReceipt.status, "recorded");
  assert.equal(replay.decisionGateAuditReceipt.idempotent, true);
  assert.equal(replay.decisionGateAuditReceipt.replayDetected, true);
  assert.equal(replay.decisionGateAuditReceipt.receipt.id, first.decisionGateAuditReceipt.receipt.id);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner)).receiptCount, countAfterFirst);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner)).receiptCount, countAfterFirst + 1);
});

test("Batch 178: reused requestId with changed evidence is rejected instead of overwriting or duplicating a receipt", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-request-conflict-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b178-request-conflict", { app, storage } = await setup(root);
  const first = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "conflict-request-178" });
  const seeded = await seedFinalization(storage, owner, "conflict-state");
  await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const replay = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "conflict-request-178" });
  assert.equal(replay.status, "unhealthy");
  assert.equal(replay.decisionGateAuditReceipt.status, "conflict");
  assert.ok(replay.findings.some(item => item.code === "CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_NOT_RECORDED"));
  assert.ok(first.decisionGateAuditReceipt.receipt);
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.receipts.filter(item => item.requestId === "conflict-request-178").length, 1);
});

test("Batch 178: attestation recovery-intent checkpoint marker can be recovered only from the exact external anchor", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-att-intent-marker-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b178-att-intent-marker", provider = anchorProvider("https://b178-att-intent.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: provider,
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: true });
  await revokeReceipt(app, storage, owner, "marker-source");
  const enrollment = await app.prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    { reason: "Enroll attestation recovery-intent history before marker-recovery testing." });
  await app.applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    enrollment.challengeId, { confirmation: enrollment.confirmation });
  const store = createAgenticStore({ storage });
  const markerId = `cas-finalization-attestation-recovery-intent-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  assert.equal(inspection.recoverable, true);
  const recovered = await app.recoverRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.inspection.checkpoint.status, "anchored");
  assert.equal(recovered.inspection.checkpoint.anchorDigest, inspection.plan.anchorDigest);
});

test("Batch 178: decision-receipt checkpoint marker recovery does not append new evidence while the marker is missing", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-receipt-marker-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b178-receipt-marker", provider = anchorProvider("https://b178-receipt-marker.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true });
  const bootstrap = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "bootstrap-marker-178" });
  assert.equal(bootstrap.status, "blocked");
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the bootstrap receipt before testing marker recovery." });
  await app.applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    enrollment.challengeId, { confirmation: enrollment.confirmation });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "anchored-receipt-178" });
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  const countBefore = (await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false })).receiptCount;
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const blocked = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "do-not-append-while-marker-missing" });
  assert.equal(blocked.status, "unhealthy");
  assert.equal(blocked.decisionGateAuditReceipt.status, "blocked");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false })).receiptCount, countBefore);
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.inspection.checkpoint.status, "anchored");
});


test("Batch 178: invalid requestId values are rejected before an audit receipt can be written", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-invalid-request-id-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app } = await setup(root);
  await assert.rejects(() => app.auditRecoverySloCrossDomainCheckpointFreshnessReplay("b178-invalid-request-id", { requestId: "not allowed" }),
    error => error.code === "CROSS_DOMAIN_RECOVERY_DECISION_GATE_REQUEST_ID_INVALID");
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts("b178-invalid-request-id", { includeCheckpoint: false });
  assert.equal(audit.receiptCount, 0);
});

test("Batch 178: external decision-receipt checkpoint rollback blocks further receipt writes", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-receipt-rollback-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b178-receipt-rollback", provider = anchorProvider("https://b178-receipt-rollback.example");
  const { app } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "bootstrap-rollback-178" });
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the bootstrap receipt before rollback testing." });
  await app.applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    enrollment.challengeId, { confirmation: enrollment.confirmation });
  const scope = `agentic-v4-cross_domain_recovery_decision_gate_audit_receipts-${sha256(owner).slice(0, 32)}`;
  const baseline = structuredClone(provider.records.get(scope));
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "receipt-after-enrollment-178" });
  const advanced = structuredClone(provider.records.get(scope));
  assert.ok(advanced.anchorSequence > baseline.anchorSequence);
  const countBefore = (await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false })).receiptCount;
  provider.records.set(scope, baseline);
  const blocked = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "receipt-rollback-attempt-178" });
  assert.equal(blocked.status, "unhealthy");
  assert.equal(blocked.decisionGateAuditReceipt.status, "blocked");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false })).receiptCount, countBefore);
  assert.equal(provider.records.get(scope).digest, baseline.digest);
});

test("Batch 178: new recovery checkpoint API methods are exported", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b178-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app } = await setup(root);
  for (const name of [
    "getRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointStatus",
    "reconcileRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpoint",
    "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpoint",
    "inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointRecovery",
    "recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpoint",
    "inspectRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointRecovery",
    "recoverRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint"
  ]) assert.equal(typeof app[name], "function", `${name} must be exported`);
  const routes = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of [
    "/api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/status",
    "/api/agentic/recovery-audit/cross-domain/checkpoints/freshness-replay/receipts/checkpoint/recovery/inspect",
    "/api/agentic/recovery-audit/cross-domain/checkpoints/attestation-recovery-intents/recovery/inspect"
  ]) assert.ok(routes.includes(route), `authenticated route ${route} must exist`);
});
