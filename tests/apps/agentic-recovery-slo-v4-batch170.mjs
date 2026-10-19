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
async function prepareAgedReceiptLedger(root, owner, lifecycleProvider, executionProvider = null) {
  const receiptAnchor = anchorProvider(`https://${owner}.verification-receipt-anchor.example`);
  const setup = await setupAnchoredReceiptCheckpoint(root, owner, {
    recoverySloCrossDomainLeaseExportVerificationReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainLeaseExportVerificationReceiptAnchor: true,
    ...(lifecycleProvider ? { recoverySloCrossDomainRetentionApprovalLifecycleAnchor: lifecycleProvider } : {}),
    ...(executionProvider ? { recoverySloCrossDomainDriftRemediationExecutionAnchor: executionProvider,
      requireRecoverySloCrossDomainDriftRemediationExecutionAnchor: true } : {})
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
  return applied.approval;
}

test("Batch 170: policy-binding receipt revocation and replacement are append-only, challenge-bound and replay-safe", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b170-policy-lifecycle-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b170-policy-lifecycle";
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z" });
  const created = await app.createRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner,
    "cross_domain_lease_export_verification_receipts");
  const revocation = await app.prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation(owner, created.receipt.id,
    { reason: "Revoke the prior policy-binding receipt before issuing its replacement." });
  const revoked = await app.applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation(owner, revocation.challengeId,
    { confirmation: revocation.confirmation });
  assert.equal(revoked.status, "revoked");
  assert.equal((await app.verifyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner, created.receipt.id)).status, "revoked");
  const replacement = await app.prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptReplacement(owner, created.receipt.id,
    { reason: "Replace the revoked policy-binding receipt with a newly evaluated record." });
  const replaced = await app.applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptReplacement(owner, replacement.challengeId,
    { confirmation: replacement.confirmation });
  assert.equal(replaced.status, "replaced");
  assert.ok(replaced.replacementReceipt.id);
  assert.equal((await app.verifyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner, created.receipt.id)).status, "superseded");
  assert.equal((await app.verifyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner, replaced.replacementReceipt.id)).historicallyValid, true);
  const replay = await app.applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptReplacement(owner, replacement.challengeId,
    { confirmation: replacement.confirmation });
  assert.equal(replay.idempotent, true);
  assert.equal(replay.replacement.id, replaced.replacement.id);
  const evidence = await createAgenticStore({ storage: createStorage({ root }) }).listEvidence(owner);
  assert.ok(evidence.some(row => row.id === created.receipt.id));
  assert.equal(revoked.deletionPerformed, false);
  assert.equal(replaced.deletionPerformed, false);
  assert.equal(replaced.compactionPerformed, false);
});

test("Batch 170: policy-binding receipt lifecycle external checkpoint anchors revocation and replacement events one at a time", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b170-policy-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b170-policy-anchor";
  const lifecycleProvider = anchorProvider(`https://${owner}.policy-binding-lifecycle-anchor.example`);
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainPolicyBindingReceiptLifecycleAnchor: lifecycleProvider,
    requireRecoverySloCrossDomainPolicyBindingReceiptLifecycleAnchor: true });
  const created = await app.createRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner,
    "cross_domain_lease_export_verification_receipts");
  const revocation = await app.prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation(owner, created.receipt.id,
    { reason: "Revoke this receipt after explicitly enrolling the lifecycle checkpoint." });
  const enrollment = await app.prepareRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the policy-binding receipt lifecycle before anchoring revocation events." });
  const enrolled = await app.applyRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const revoked = await app.applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation(owner, revocation.challengeId,
    { confirmation: revocation.confirmation });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.lifecycleCheckpoint.status, "anchored");
  const beforeReplacement = await app.getRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointStatus(owner);
  const replacement = await app.prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptReplacement(owner, created.receipt.id,
    { reason: "Replace the revoked receipt while preserving lifecycle checkpoint continuity." });
  assert.equal(replacement.lifecycleCheckpoint.status, "anchored");
  const replaced = await app.applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptReplacement(owner, replacement.challengeId,
    { confirmation: replacement.confirmation });
  assert.equal(replaced.status, "replaced");
  assert.equal(replaced.lifecycleCheckpoint.status, "anchored");
  const after = await app.getRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointStatus(owner);
  assert.equal(after.anchorSequence, beforeReplacement.anchorSequence + 2);
  const audit = await app.auditRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.deletionPerformed, false);
});

test("Batch 170: remediation execution persists intent before action and recovers after checkpoint enrollment", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b170-remediation-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b170-rem";
  const lifecycleProvider = anchorProvider(`https://${owner}.retention-lifecycle-anchor.example`);
  const executionProvider = anchorProvider(`https://${owner}.remediation-execution-anchor.example`);
  const { app, storage } = await prepareAgedReceiptLedger(root, owner, lifecycleProvider, executionProvider);
  const approval = await prepareRetentionApproval(app, owner);
  const lifecycleEnrollment = await app.prepareRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll retention approval lifecycle records before remediation recovery testing." });
  await app.applyRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner, lifecycleEnrollment.challengeId,
    { confirmation: lifecycleEnrollment.confirmation });
  lifecycleProvider.setForceConflict(true);
  const revokeChallenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner, approval.id,
    { reason: "Prepare a single provable lifecycle gap while simulating a temporary CAS conflict." });
  assert.equal((await app.getRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointStatus(owner)).status, "behind_local");
  const plan = await app.prepareRecoverySloCrossDomainDriftRemediationPlan(owner,
    { reason: "Bind remediation to the exact cross-ledger state and recover its durable execution intent." });
  assert.ok(plan.allowedActions.includes("reconcile_retention_approval_lifecycle_checkpoint"));
  await assert.rejects(() => app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation }),
    error => error?.code === "CROSS_DOMAIN_DRIFT_REMEDIATION_EXECUTION_CHECKPOINT_REQUIRED");
  const pending = await app.inspectRecoverySloCrossDomainDriftRemediationRecovery(owner, plan.planId);
  assert.equal(pending.status, "recovery_required");
  assert.equal(pending.pendingCount, 1);
  const executionEnrollment = await app.prepareRecoverySloCrossDomainDriftRemediationExecutionCheckpointEnrollment(owner,
    { reason: "Enroll the persisted remediation intent before executing its authorized action." });
  const enrolled = await app.applyRecoverySloCrossDomainDriftRemediationExecutionCheckpointEnrollment(owner, executionEnrollment.challengeId,
    { confirmation: executionEnrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  lifecycleProvider.setForceConflict(false);
  const recovered = await app.recoverRecoverySloCrossDomainDriftRemediationExecution(owner, plan.planId);
  assert.equal(recovered.status, "completed");
  assert.equal(recovered.result.status, "anchored");
  assert.equal(recovered.checkpointStatus, "anchored");
  assert.equal(recovered.usableForCurrentDecision, false);
  const checkpoint = await app.getRecoverySloCrossDomainDriftRemediationExecutionCheckpointStatus(owner);
  assert.equal(checkpoint.status, "anchored");
  assert.equal(checkpoint.sourceCount, 2);
  const audit = await app.auditRecoverySloCrossDomainDriftRemediationExecutionCheckpoint(owner);
  assert.equal(audit.status, "healthy");
  const replay = await app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation });
  assert.equal(replay.idempotent, true);
  const evidence = await createAgenticStore({ storage }).listEvidence(owner);
  assert.ok(evidence.some(row => row.kind === "recovery-slo-cross-domain-drift-remediation-finalization"));
  assert.ok(evidence.some(row => row.kind === "recovery-slo-cross-domain-drift-remediation-recovery-intent"));
  assert.ok(evidence.some(row => row.id === revokeChallenge.challengeId));
});

test("Batch 170: corrupted remediation execution receipts and lifecycle records fail closed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b170-integrity-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b170-integrity";
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z" });
  const receipt = await app.createRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner,
    "cross_domain_lease_export_verification_receipts");
  const revocation = await app.prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Create a revocation challenge for lifecycle-integrity verification." });
  const revoked = await app.applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation(owner, revocation.challengeId,
    { confirmation: revocation.confirmation });
  const store = createAgenticStore({ storage: createStorage({ root }) });
  await store.mutateEvidence(owner, revoked.revocation.id, current => ({ value: { ...current, receiptDigest: "f".repeat(64) } }));
  const verification = await app.verifyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner, receipt.receipt.id);
  assert.equal(verification.status, "unhealthy");
  assert.equal(verification.usableForCurrentDecision, false);
});


test("Batch 170: recovery finalizes a persisted execution receipt after an external CAS conflict", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b170-execution-cas-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b170-cas";
  const lifecycleProvider = anchorProvider(`https://${owner}.retention-lifecycle-anchor.example`);
  const executionProvider = anchorProvider(`https://${owner}.remediation-execution-anchor.example`);
  const { app } = await prepareAgedReceiptLedger(root, owner, lifecycleProvider, executionProvider);
  const approval = await prepareRetentionApproval(app, owner);
  const lifecycleEnrollment = await app.prepareRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll retention approval lifecycle before testing execution-receipt CAS recovery." });
  await app.applyRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner, lifecycleEnrollment.challengeId,
    { confirmation: lifecycleEnrollment.confirmation });
  lifecycleProvider.setForceConflict(true);
  await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner, approval.id,
    { reason: "Create a single-event lifecycle gap for the recovery execution CAS test." });
  const plan = await app.prepareRecoverySloCrossDomainDriftRemediationPlan(owner,
    { reason: "Bind execution recovery to a single provable lifecycle checkpoint transition." });
  assert.ok(plan.allowedActions.includes("reconcile_retention_approval_lifecycle_checkpoint"));
  await assert.rejects(() => app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation }),
    error => error?.code === "CROSS_DOMAIN_DRIFT_REMEDIATION_EXECUTION_CHECKPOINT_REQUIRED");
  const enrollment = await app.prepareRecoverySloCrossDomainDriftRemediationExecutionCheckpointEnrollment(owner,
    { reason: "Enroll the persisted intent before simulating execution-receipt CAS conflict." });
  await app.applyRecoverySloCrossDomainDriftRemediationExecutionCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  lifecycleProvider.setForceConflict(false);
  executionProvider.setForceConflict(true);
  const first = await app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation });
  assert.equal(first.status, "completed_with_blockers");
  assert.equal(first.recoveryRequired, true);
  assert.equal(first.checkpointStatus, "external_checkpoint_pending");
  const pending = await app.inspectRecoverySloCrossDomainDriftRemediationRecovery(owner, plan.planId);
  assert.equal(pending.status, "recovery_required");
  executionProvider.setForceConflict(false);
  const recovered = await app.recoverRecoverySloCrossDomainDriftRemediationExecution(owner, plan.planId);
  assert.equal(recovered.status, "completed");
  assert.equal(recovered.checkpointStatus, "anchored");
  assert.ok(recovered.finalization.id);
  const audit = await app.auditRecoverySloCrossDomainDriftRemediationExecutionCheckpoint(owner);
  assert.equal(audit.status, "healthy");
});

test("Batch 170: new lifecycle and crash-recovery APIs are exposed through HTTP routes", async () => {
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["recoverRecoverySloCrossDomainDriftRemediationExecution", "inspectRecoverySloCrossDomainDriftRemediationRecovery",
    "getRecoverySloCrossDomainDriftRemediationExecutionCheckpointStatus", "prepareRecoverySloCrossDomainDriftRemediationExecutionCheckpointEnrollment",
    "auditRecoverySloCrossDomainDriftRemediationExecutionCheckpoint", "prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation",
    "applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation",
    "prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptReplacement",
    "applyRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptReplacement",
    "getRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointStatus",
    "prepareRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointEnrollment",
    "auditRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpoint"]) assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /drift-remediation\/plans\/:id\/recover/);
  assert.match(server, /policy-binding-verification-receipts\/:id\/revocation-challenges/);
  assert.match(server, /policy-binding-verification-receipts\/:id\/replacement-challenges/);
  assert.match(server, /policy-binding-receipt-lifecycle\/checkpoint\/enrollment-challenges/);
});
