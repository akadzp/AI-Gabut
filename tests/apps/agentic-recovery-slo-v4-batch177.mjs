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
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    ...extra });
  return { app, storage, pairs };
}
async function seedFinalization(storage, owner, suffix = "one", createdAt = "2026-10-13T00:00:00.000Z") {
  const store = createAgenticStore({ storage });
  const action = "reconcile_policy_binding_audit_checkpoint";
  const planUnsigned = { id: `b177-plan-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-plan", schemaVersion: 1,
    status: "prepared", reason: "Seed a source-bound remediation plan for Batch 177 tests.", createdAt,
    expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString(), stateFingerprint: "d".repeat(64),
    allowedActions: [action], blockedActions: [], auditStatus: "blocked", auditFindingsDigest: "e".repeat(64),
    deletionPerformed: false, compactionPerformed: false };
  const plan = { ...planUnsigned, digest: digestRecord(planUnsigned) };
  await store.putEvidence(owner, plan, { overwrite: false });
  const intentUnsigned = { id: `b177-intent-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-recovery-intent",
    schemaVersion: 1, status: "completed", planId: plan.id, planDigest: plan.digest, stateFingerprint: plan.stateFingerprint,
    action, confirmationDigest: sha256(`EXECUTE CROSS-DOMAIN DRIFT REMEDIATION ${plan.digest.slice(0, 12)}`),
    createdAt, finalizedAt: createdAt, resultAnchorDigest: null };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  const executionUnsigned = { id: `b177-execution-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-execution",
    schemaVersion: 1, planId: plan.id, planDigest: plan.digest, recoveryIntentId: intent.id,
    recoveryIntentDigest: intent.digest, action, status: "completed", resultDigest: "a".repeat(64), createdAt, completedAt: createdAt,
    deletionPerformed: false, compactionPerformed: false };
  const execution = { ...executionUnsigned, digest: digestRecord(executionUnsigned) };
  await store.putEvidence(owner, execution, { overwrite: false });
  const finalizationUnsigned = { id: `b177-finalization-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-finalization",
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
    { reason: "Revoke a test receipt to verify Batch 177 recovery-intent anchoring." });
  return app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enroll(app, owner, methodPrefix, reason) {
  const challenge = await app[`prepareRecoverySloCrossDomain${methodPrefix}CheckpointEnrollment`](owner, { reason });
  return app[`applyRecoverySloCrossDomain${methodPrefix}CheckpointEnrollment`](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}

test("Batch 177: required attestation recovery-intent anchor fails closed without a provider", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b177-required-anchor" }),
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: true }),
  /attestation recovery-intent checkpoint diwajibkan/);
});

test("Batch 177: lifecycle recovery intents are externally anchored as immutable bindings and preserve bootstrap history state", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b177-intent-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b177-intent-anchor", provider = anchorProvider("https://b177-intent-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: provider,
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: true });
  await revokeReceipt(app, storage, owner, "before-enrollment");
  const initial = await app.getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointStatus(owner);
  assert.ok(["not_initialized", "enrollment_required"].includes(initial.status));
  const challenge = await app.prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    { reason: "Enroll the existing attestation recovery-intent history before relying on its continuity." });
  const enrolled = await app.applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const afterEnrollment = await app.getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointStatus(owner);
  assert.equal(afterEnrollment.status, "anchored");
  assert.equal(afterEnrollment.freshnessStatus, "fresh");
  assert.equal(afterEnrollment.historyNotProven, true);
  await revokeReceipt(app, storage, owner, "after-enrollment");
  const afterSecond = await app.getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointStatus(owner);
  assert.equal(afterSecond.status, "anchored");
  assert.equal(afterSecond.anchorSequence, afterEnrollment.anchorSequence + 1);
  const audit = await app.auditRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.usableForCurrentDecision, false);
  assert.equal(audit.sourceCount, 2);
});

test("Batch 177: recovery-intent checkpoint rejects a multi-event gap instead of reconciling it silently", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b177-gap-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const storage = createStorage({ root });
  const local = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z" });
  const owner = "b177-gap", provider = anchorProvider("https://b177-gap.example");
  await revokeReceipt(local, storage, owner, "gap-base");
  const anchored = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: provider });
  const challenge = await anchored.prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    { reason: "Enroll a baseline before intentionally testing a multi-event continuity gap." });
  const enrolled = await anchored.applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(enrolled.status, "anchored");
  await revokeReceipt(local, storage, owner, "gap-one");
  await revokeReceipt(local, storage, owner, "gap-two");
  await assert.rejects(() => anchored.reconcileRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint(owner),
    error => error.code === "CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_RECOVERY_INTENT_GAP_UNPROVEN");
});

test("Batch 177: central recovery-intent checkpoint rejects multi-event gaps", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b177-global-gap-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const storage = createStorage({ root }), owner = "b177-global-gap";
  const local = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z" });
  await revokeReceipt(local, storage, owner, "global-base");
  const provider = anchorProvider("https://b177-global-intent-ledger.example");
  const anchored = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainRecoveryIntentLedgerAnchor: provider });
  const challenge = await anchored.prepareRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment(owner,
    { reason: "Enroll the central recovery-intent ledger before a controlled gap test." });
  const enrolled = await anchored.applyRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(enrolled.status, "anchored");
  await revokeReceipt(local, storage, owner, "global-gap-one");
  await revokeReceipt(local, storage, owner, "global-gap-two");
  await assert.rejects(() => anchored.reconcileRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint(owner),
    error => error.code === "CROSS_DOMAIN_RECOVERY_INTENT_LEDGER_GAP_UNPROVEN");
});

test("Batch 177: recovery-decision gate emits an append-only receipt bound to inspected evidence", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b177-gate-receipt-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b177-gate-receipt", { app } = await setup(root);
  const first = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.ok(first.decisionGateAuditReceipt?.receipt);
  assert.equal(first.decisionGateAuditReceipt.status, "recorded");
  assert.equal(first.decisionGateAuditReceipt.receipt.evidenceBindingDigest,
    sha256(canonical(first.decisionGateAuditReceipt.receipt.evidenceBinding)));
  assert.equal(first.decisionGateAuditReceipt.receipt.decisionStatus, first.status);
  const second = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.ok(second.decisionGateAuditReceipt?.receipt);
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.receiptCount, 2);
  assert.equal(audit.latestReceipt.sequence, 2);
  assert.equal(audit.receipts[1].id, second.decisionGateAuditReceipt.receipt.id);
  assert.equal(audit.ledgerIntegrityVerified, true);
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 177: decision gate fails closed when its audit-receipt ledger is tampered", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b177-gate-tamper-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b177-gate-tamper", { app, storage } = await setup(root);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  const store = createAgenticStore({ storage });
  const ledgerId = `cross-domain-recovery-decision-gate-audit-receipts-${sha256(owner).slice(0, 40)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  assert.ok(ledger);
  const tamperedUnsigned = { ...ledger, headDigest: "0".repeat(64) };
  delete tamperedUnsigned.digest;
  await store.putEvidence(owner, { ...tamperedUnsigned, digest: digestRecord(tamperedUnsigned) }, { expectedVersion: ledger._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner);
  assert.equal(audit.status, "unhealthy");
  const gate = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.equal(gate.status, "unhealthy");
  assert.equal(gate.usableForCurrentDecision, false);
  assert.ok(gate.findings.some(item => item.code === "CROSS_DOMAIN_RECOVERY_DECISION_GATE_AUDIT_RECEIPT_NOT_RECORDED"));
});

test("Batch 177: new recovery-intent checkpoint and audit-receipt API routes are exported", async () => {
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointStatus",
    "reconcileRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint",
    "prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment",
    "auditRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint",
    "auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts"])
    assert.match(server + await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8"), new RegExp(`application\\.${name}\\b`));
  assert.match(server, /checkpoints\/attestation-recovery-intents\/enrollment-challenges/);
  assert.match(server, /freshness-replay\/receipts\/audit/);
});

test("Batch 177: attestation recovery-intent checkpoint rollback is rejected without rewriting the external history", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b177-rollback-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b177-rollback", provider = anchorProvider("https://b177-rollback.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: provider });
  await revokeReceipt(app, storage, owner, "rollback-base");
  const challenge = await app.prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    { reason: "Enroll a valid baseline before simulating external checkpoint rollback." });
  await app.applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  const scope = `agentic-v4-cross_domain_cas_finalization_receipt_lifecycle_attestation_recovery_intents-${sha256(owner).slice(0, 32)}`;
  const baseline = structuredClone(provider.records.get(scope));
  await revokeReceipt(app, storage, owner, "rollback-next");
  const advanced = structuredClone(provider.records.get(scope));
  assert.ok(advanced.anchorSequence > baseline.anchorSequence);
  provider.records.set(scope, baseline);
  const status = await app.getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointStatus(owner);
  assert.ok(["rollback_suspected", "unhealthy"].includes(status.status));
  await assert.rejects(() => app.reconcileRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint(owner),
    error => /ROLLBACK|RECONCILIATION_BLOCKED/.test(error.code || ""));
  assert.equal(provider.records.get(scope).digest, baseline.digest);
});

test("Batch 177: checkpoint-marker recovery intent is externally anchored before marker recovery executes", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b177-marker-intent-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b177-mia";
  const attestationProvider = anchorProvider("https://b177-marker-attestation.example");
  const intentProvider = anchorProvider("https://b177-marker-intent.example");
  const { app, storage } = await setup(root, {
    recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: attestationProvider,
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: true,
    recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: intentProvider,
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentAnchor: true
  });
  await revokeReceipt(app, storage, owner, "marker-intent");
  const attestationEnrollment = await app.prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointEnrollment(owner,
    { reason: "Enroll attestation evidence before a controlled marker recovery test." });
  await app.applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointEnrollment(owner,
    attestationEnrollment.challengeId, { confirmation: attestationEnrollment.confirmation });
  const intentEnrollment = await app.prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    { reason: "Enroll the existing recovery-intent history before exercising marker recovery." });
  await app.applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointEnrollment(owner,
    intentEnrollment.challengeId, { confirmation: intentEnrollment.confirmation });
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-cas-finalization-receipt-lifecycle-attestation-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const recovered = await app.recoverRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.attestationRecoveryIntentCheckpoint.status, "anchored");
  const status = await app.getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpointStatus(owner);
  assert.equal(status.status, "anchored");
  assert.equal(status.sourceCount, 2);
  const sourceAudit = await app.auditRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationRecoveryIntentCheckpoint(owner);
  assert.equal(sourceAudit.sourceCount, 2);
  assert.equal(sourceAudit.usableForCurrentDecision, false);
});
