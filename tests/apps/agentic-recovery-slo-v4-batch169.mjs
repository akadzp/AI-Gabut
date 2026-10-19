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
function anchorProvider(baseUrl) {
  const records = new Map(); let forceConflict = false;
  return { baseUrl, setForceConflict(value) { forceConflict = Boolean(value); },
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      if (forceConflict) return { applied: false };
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
function signer(pair) { return payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url"); }
async function setupAnchoredReceiptCheckpoint(root, owner, extra = {}) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const keyTransitionProvider = anchorProvider(`https://${owner}.key-transition-anchor.example`);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock,
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: keyTransitionProvider, requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true,
    ...extra });
  const rotation = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate to the next trusted key before enrolling a recoverable receipt checkpoint." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotation.challengeId, { confirmation: rotation.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the receipt checkpoint so recovery intent history can be attested." });
  await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  return { app, storage, owner, clock, advance: milliseconds => { nowMs += milliseconds; } };
}
async function createReceiptForRetentionReview(app, owner) {
  const bundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  return app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, bundle);
}
async function prepareAgedReceiptLedger(root, owner, lifecycleProvider = null) {
  const receiptAnchor = anchorProvider(`https://${owner}.verification-receipt-anchor.example`);
  const setup = await setupAnchoredReceiptCheckpoint(root, owner, {
    recoverySloCrossDomainLeaseExportVerificationReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainLeaseExportVerificationReceiptAnchor: true,
    ...(lifecycleProvider ? { recoverySloCrossDomainRetentionApprovalLifecycleAnchor: lifecycleProvider } : {})
  });
  await createReceiptForRetentionReview(setup.app, owner);
  const enrollment = await setup.app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the verification-receipt ledger before retaining signed audit receipts." });
  await setup.app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await createReceiptForRetentionReview(setup.app, owner);
  setup.advance(91 * 86400000);
  await setup.app.reconcileRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpoint(owner);
  const audit = await setup.app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  assert.equal(audit.rawRetentionReviewDue, true);
  assert.equal(audit.receiptCount, 2);
  return { ...setup, receiptAnchor, audit };
}

async function prepareRetentionApproval(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner,
    { decision: "retain", reason: "Retain the aged verification receipt set after a source-bound governance review." });
  const applied = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.ok(applied.approval?.id);
  return applied.approval;
}

test("Batch 169: policy-binding verification receipts bind checkpoint, policy and approval-chain state; tampering is detected", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b169-policy-receipt-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b169-policy-receipt";
  const { app, storage } = await prepareAgedReceiptLedger(root, owner);
  const created = await app.createRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner,
    "cross_domain_lease_export_verification_receipts");
  assert.equal(created.status, "verified_historical_only");
  assert.equal(created.usableForCurrentDecision, false);
  const verified = await app.verifyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner, created.receipt.id);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.current, false);
  assert.equal(verified.usableForCurrentDecision, false);
  const store = createAgenticStore({ storage });
  await store.mutateEvidence(owner, created.receipt.id, current => ({ value: { ...current,
    binding: { ...current.binding, currentPolicyDigest: "f".repeat(64) } } }));
  const tampered = await app.verifyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner, created.receipt.id);
  assert.equal(tampered.status, "unhealthy");
  assert.equal(tampered.historicallyValid, false);
  const audit = await app.auditRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipts(owner);
  assert.equal(audit.status, "unhealthy");
});

test("Batch 169: retention approval lifecycle events are externally anchored one event at a time without deleting evidence", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b169-retention-lifecycle-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b169-retention-lifecycle";
  const lifecycleProvider = anchorProvider(`https://${owner}.retention-lifecycle-anchor.example`);
  const { app, storage } = await prepareAgedReceiptLedger(root, owner, lifecycleProvider);
  const approval = await prepareRetentionApproval(app, owner);
  const enrollment = await app.prepareRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner,
    { reason: "Explicitly enroll the existing receipt-retention lifecycle before anchoring future transitions." });
  const enrolled = await app.applyRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const before = await app.getRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointStatus(owner);
  assert.equal(before.status, "anchored");
  const revokeChallenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner,
    approval.id, { reason: "Revoke the prior approval before creating a replacement lifecycle decision." });
  assert.equal(revokeChallenge.challengeId != null, true);
  const afterPrepare = await app.getRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointStatus(owner);
  assert.equal(afterPrepare.status, "anchored");
  assert.equal(afterPrepare.anchorSequence, before.anchorSequence + 1);
  const revoked = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner,
    revokeChallenge.challengeId, { confirmation: revokeChallenge.confirmation });
  assert.equal(revoked.status, "revoked");
  const afterApply = await app.getRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointStatus(owner);
  assert.equal(afterApply.status, "anchored");
  assert.equal(afterApply.anchorSequence, afterPrepare.anchorSequence + 1);
  const audit = await app.auditRecoverySloCrossDomainRetentionApprovalLifecycleCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  const evidence = await createAgenticStore({ storage }).listEvidence(owner);
  assert.ok(evidence.some(item => item.id === approval.id));
  assert.ok(evidence.some(item => item.id === revoked.revocation.id));
  assert.equal(revoked.deletionPerformed, false);
  assert.equal(revoked.compactionPerformed, false);
});

test("Batch 169: remediation plan is snapshot-bound, whitelisted, replay-safe and fails closed when state changes", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b169-remediation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b169-remediation";
  const lifecycleProvider = anchorProvider(`https://${owner}.retention-lifecycle-anchor.example`);
  const { app } = await prepareAgedReceiptLedger(root, owner, lifecycleProvider);
  const approval = await prepareRetentionApproval(app, owner);
  const enrollment = await app.prepareRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll retention approval lifecycle records before testing guarded drift remediation." });
  await app.applyRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  lifecycleProvider.setForceConflict(true);
  const revokeChallenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner,
    approval.id, { reason: "Prepare a revocation challenge while simulating an external checkpoint CAS conflict." });
  assert.ok(revokeChallenge.challengeId);
  assert.equal((await app.getRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointStatus(owner)).status, "behind_local");
  const stalePlan = await app.prepareRecoverySloCrossDomainDriftRemediationPlan(owner,
    { reason: "Bind the first remediation attempt to the exact cross-ledger state before checking stale-plan rejection." });
  assert.ok(stalePlan.allowedActions.includes("reconcile_retention_approval_lifecycle_checkpoint"));
  await app.createRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner,
    "cross_domain_lease_export_verification_receipts");
  await assert.rejects(() => app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, stalePlan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: stalePlan.confirmation }),
    error => error?.code === "CROSS_DOMAIN_DRIFT_REMEDIATION_PLAN_STALE");
  const plan = await app.prepareRecoverySloCrossDomainDriftRemediationPlan(owner,
    { reason: "Reconcile a single provable lifecycle event after the external provider becomes available." });
  assert.ok(plan.allowedActions.includes("reconcile_retention_approval_lifecycle_checkpoint"));
  lifecycleProvider.setForceConflict(false);
  const executed = await app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation });
  assert.equal(executed.status, "completed");
  assert.equal(executed.result.status, "anchored");
  const replay = await app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation });
  assert.equal(replay.idempotent, true);
  await assert.rejects(() => app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_recovery_intent_ledger_checkpoint", confirmation: plan.confirmation }),
    error => error?.code === "CROSS_DOMAIN_DRIFT_REMEDIATION_REPLAY_CONFLICT");
});

test("Batch 169: local-only drift remediation exposes no automatic repair and rejects unapproved actions", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b169-local-only-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z" });
  const owner = "b169-local-only";
  const plan = await app.prepareRecoverySloCrossDomainDriftRemediationPlan(owner,
    { reason: "Inspect local-only cross-ledger drift without granting mutation authority." });
  assert.deepEqual(plan.allowedActions, []);
  assert.ok(plan.blockedActions.length >= 1);
  await assert.rejects(() => app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "delete_evidence", confirmation: plan.confirmation }),
    error => error?.code === "CROSS_DOMAIN_DRIFT_REMEDIATION_ACTION_BLOCKED");
  const audit = await app.auditRecoverySloCrossDomainRecoveryLedgerConsistency(owner);
  assert.equal(audit.deletionPerformed, false);
  assert.equal(audit.compactionPerformed, false);
});

test("Batch 169: lifecycle checkpoint, policy-binding receipt and remediation APIs are exposed in HTTP routes", async () => {
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["createRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt",
    "verifyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt", "auditRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipts",
    "getRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointStatus", "reconcileRecoverySloCrossDomainRetentionApprovalLifecycleCheckpoint",
    "prepareRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment", "applyRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment",
    "auditRecoverySloCrossDomainRetentionApprovalLifecycleCheckpoint", "prepareRecoverySloCrossDomainDriftRemediationPlan",
    "executeRecoverySloCrossDomainDriftRemediationPlan"]) assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /cross-domain\/drift-remediation\/plans/);
  assert.match(server, /cross-domain\/checkpoints\/policy-binding-verification-receipts/);
  assert.match(server, /cross-domain\/retention-approval-lifecycle\/checkpoint\/enrollment-challenges/);
});
