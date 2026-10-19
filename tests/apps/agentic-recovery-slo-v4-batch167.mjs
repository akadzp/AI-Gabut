import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";
import { createRecoverySloCrossDomainGovernanceHardeningService } from "../../apps/agentic/backend/recovery-slo-cross-domain-governance-hardening.js";

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
function makeReceipt(ownerId, domain, suffix, createdAt = "2026-10-08T00:00:00.000Z") {
  const unsigned = { id: `receipt-${suffix}`, ownerId, kind: "recovery-slo-cross-domain-provider-baseline-transition-receipt", schemaVersion: 1,
    domain, revision: 1, previousReceiptDigest: null, transitionChallengeId: `transition-${suffix}`,
    sourceReportDigest: suffix.padEnd(64, suffix).slice(0, 64), historyNotProven: false, createdAt };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function manifestContext(suffix = "a") {
  const hex = char => char.repeat(64);
  return { guardrails: { status: "healthy", compactionEligible: true, blockers: [], receiptAuditStatus: "healthy", baselineAuditStatus: "healthy",
    receiptCount: 2, receiptHeads: { alpha: { id: `receipt-alpha-${suffix}`, digest: hex(suffix), revision: suffix.charCodeAt(0) },
      beta: { id: `receipt-beta-${suffix}`, digest: hex(String.fromCharCode(suffix.charCodeAt(0) + 1)), revision: suffix.charCodeAt(0) } } },
    checkpointStatus: { status: "anchored", anchorSequence: 2, anchorDigest: hex("c"), policyBindingStatus: "current",
      anchoredPolicyDigest: hex("d"), currentPolicyDigest: hex("d"), sourceDigest: hex("e"), sourceCount: 2 } };
}
async function createSupersession(governance, owner, suffix, reason) {
  const context = manifestContext(suffix);
  const manifest = await governance.createProviderBaselineReceiptCompactionManifest(owner, context);
  const challenge = await governance.prepareProviderBaselineReceiptCompactionManifestApproval(owner, manifest.manifest.id,
    { ...context, reason: `Approve manifest ${suffix} for review while preserving retained evidence.` });
  const approval = await governance.applyProviderBaselineReceiptCompactionManifestApproval(owner, challenge.challengeId,
    { ...context, confirmation: challenge.confirmation });
  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3,
    anchorDigest: "f".repeat(64), sourceDigest: "a".repeat(64) };
  await governance.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(owner, approval.approval.id,
    { verifyManifest: (targetOwnerId, manifestId) => governance.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context), reason });
}
async function seedGapFixture(root, owner, extraAppOptions = {}) {
  const storage = createStorage({ root }), store = createAgenticStore({ storage });
  await store.putEvidence(owner, makeReceipt(owner, "alpha", "a"), { overwrite: false });
  await store.putEvidence(owner, makeReceipt(owner, "beta", "b"), { overwrite: false });
  const governance = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => "2026-10-13T00:00:00.000Z" });
  const context = manifestContext();
  const manifest = await governance.createProviderBaselineReceiptCompactionManifest(owner, context);
  const challenge = await governance.prepareProviderBaselineReceiptCompactionManifestApproval(owner, manifest.manifest.id,
    { ...context, reason: "Approve initial manifest for review and preserve the baseline receipt history." });
  const approval = await governance.applyProviderBaselineReceiptCompactionManifestApproval(owner, challenge.challengeId,
    { ...context, confirmation: challenge.confirmation });
  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3,
    anchorDigest: "f".repeat(64), sourceDigest: "a".repeat(64) };
  await governance.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(owner, approval.approval.id,
    { verifyManifest: (targetOwnerId, manifestId) => governance.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context),
      reason: "Record initial supersession after the source checkpoint became stale." });
  const provider = anchorProvider("https://b166-gap-ledger.example");
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainManifestApprovalLedgerAnchor: provider, ...extraAppOptions });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner,
    { reason: "Enroll the initial manifest ledger snapshot before testing approved gap finalization." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await createSupersession(governance, owner, "x", "Record supersession x and preserve the manifest approval audit history.");
  await createSupersession(governance, owner, "y", "Record supersession y and preserve the manifest approval audit history.");
  return { app, storage, owner, provider };
}
async function setupAnchoredReceiptCheckpoint(root, owner, extra = {}) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const provider = anchorProvider(`https://${owner}.receipt-anchor.example`);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock,
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: provider, requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true,
    ...extra });
  const rotation = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate to the next trusted key before enrolling a recoverable receipt checkpoint." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotation.challengeId, { confirmation: rotation.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the receipt checkpoint so recovery intent history can be attested." });
  await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  return { app, storage, owner, advance: milliseconds => { nowMs += milliseconds; } };
}
async function removeCheckpointMarker(storage, owner, markerKindPart) {
  const store = createAgenticStore({ storage });
  const marker = (await store.listEvidence(owner)).find(item => item.kind?.includes(markerKindPart) && item.kind.endsWith("-marker"));
  assert.ok(marker, `marker ${markerKindPart} exists`);
  await store.mutateEvidence(owner, marker.id, () => ({ delete: true }));
  assert.equal(await store.getEvidence(owner, marker.id), null);
}


test("Batch 167: recovery-intent ledger is externally anchored, resumes after enrollment, and advances one intent at a time", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b167-intent-ledger-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const lifecycleAnchor = anchorProvider("https://b167-lifecycle-anchor.example");
  const intentAnchor = anchorProvider("https://b167-recovery-intent-ledger.example");
  const { app, storage, owner } = await setupAnchoredReceiptCheckpoint(root, "b167-intent-owner", {
    recoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: lifecycleAnchor,
    requireRecoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: true,
    recoverySloCrossDomainRecoveryIntentLedgerAnchor: intentAnchor,
    requireRecoverySloCrossDomainRecoveryIntentLedgerAnchor: true
  });
  const attestation = await app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner,
    { reason: "Create a lifecycle attestation before testing recovery-intent ledger anchoring." });
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, attestation.attestation.id,
    { reason: "Create a lifecycle transition to exercise durable checkpoint recovery intent." });
  await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, revoke.challengeId, { confirmation: revoke.confirmation });
  const lifecycleEnrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll lifecycle events before removing the local checkpoint marker." });
  await app.applyRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner, lifecycleEnrollment.challengeId,
    { confirmation: lifecycleEnrollment.confirmation });
  await removeCheckpointMarker(storage, owner, "cross-domain-recovery-intent-attestation-lifecycle-checkpoint");
  await assert.rejects(() => app.recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner),
    error => error?.code === "CROSS_DOMAIN_RECOVERY_INTENT_LEDGER_CHECKPOINT_NOT_CURRENT");
  const pendingAudit = await app.auditRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint(owner);
  assert.equal(pendingAudit.status, "external_checkpoint_pending");
  assert.equal(pendingAudit.sourceCount, 2);
  const intentEnrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment(owner,
    { reason: "Enroll the recovery-intent ledger after preserving the prepared recovery operation." });
  const enrolled = await app.applyRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment(owner, intentEnrollment.challengeId,
    { confirmation: intentEnrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.recoveryIntentLedgerCheckpoint.status, "anchored");
  assert.equal(recovered.recoveryIntent.status, "completed");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.checkpoint.status, "anchored");
  const beforeSequence = audit.checkpoint.anchorSequence;
  const nextAttestation = await app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner,
    { reason: "Create a second lifecycle attestation to test a subsequent recovery-intent ledger append." });
  const nextRevoke = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, nextAttestation.attestation.id,
    { reason: "Advance lifecycle source once before testing a second recovery-intent anchor event." });
  await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, nextRevoke.challengeId, { confirmation: nextRevoke.confirmation });
  await removeCheckpointMarker(storage, owner, "cross-domain-recovery-intent-attestation-lifecycle-checkpoint");
  const second = await app.recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner);
  assert.equal(second.status, "recovered");
  assert.equal(second.recoveryIntentLedgerCheckpoint.status, "anchored");
  assert.equal(second.recoveryIntentLedgerCheckpoint.anchorSequence, beforeSequence + 1);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint(owner)).checkpoint.status, "anchored");
});

test("Batch 167: finalization recovery resolves an interrupted replay but rejects marker rollback after completion", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b167-finalization-replay-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const finalizationAnchor = anchorProvider("https://b167-finalization-anchor.example");
  const { app, storage, owner } = await seedGapFixture(root, "b167-finalization-owner", {
    recoverySloCrossDomainManifestApprovalLedgerGapFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationAnchor: true
  });
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner,
    { reason: "Approve the unique manifest-ledger gap before exercising replay-safe finalization recovery." });
  const approval = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  await app.finalizeRecoverySloCrossDomainManifestApprovalLedgerGap(owner, approval.approval.id);
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointEnrollment(owner,
    { reason: "Enroll the finalization receipt history before simulating a marker interruption." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await removeCheckpointMarker(storage, owner, "cross-domain-manifest-approval-ledger-gap-finalization-checkpoint");
  const first = await app.recoverRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpoint(owner);
  assert.equal(first.status, "recovered");
  const replay = await app.recoverRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpoint(owner);
  assert.equal(replay.status, "already_recovered");
  assert.equal(replay.idempotent, true);
  await removeCheckpointMarker(storage, owner, "cross-domain-manifest-approval-ledger-gap-finalization-checkpoint");
  await assert.rejects(() => app.recoverRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpoint(owner),
    error => error?.code === "MANIFEST_GAP_FINALIZATION_RECOVERY_ROLLBACK_DETECTED");
});

async function createReceiptForRetentionReview(app, owner) {
  const bundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  return app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, bundle);
}

async function prepareAgedReceiptLedger(root, owner) {
  const receiptAnchor = anchorProvider(`https://${owner}.verification-receipt-anchor.example`);
  const setup = await setupAnchoredReceiptCheckpoint(root, owner, {
    recoverySloCrossDomainLeaseExportVerificationReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainLeaseExportVerificationReceiptAnchor: true
  });
  const first = await createReceiptForRetentionReview(setup.app, owner);
  const enrollment = await setup.app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the verification-receipt ledger before retaining signed audit receipts." });
  await setup.app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await createReceiptForRetentionReview(setup.app, owner);
  const staleBundle = await setup.app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  setup.advance(91 * 86400000);
  await setup.app.reconcileRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpoint(owner);
  const audit = await setup.app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  assert.equal(audit.rawRetentionReviewDue, true);
  assert.equal(audit.receiptCount, 2);
  return { ...setup, receiptAnchor, first, audit, staleBundle };
}

test("Batch 167: receipt retention approval binds exact source, targets, policy, and checkpoint without deleting evidence", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b167-retention-approval-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b167-retain";
  const { app } = await prepareAgedReceiptLedger(root, owner);
  const challenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner,
    { decision: "retain", reason: "Retain the reviewed verification receipts and preserve their signed audit history." });
  assert.equal(challenge.reviewedReceiptCount, 2);
  const applied = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(applied.status, "reviewed_retain");
  assert.equal(applied.current, true);
  assert.equal(applied.deletionPerformed, false);
  assert.equal(applied.compactionPerformed, false);
  const replay = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
  const audit = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  assert.equal(audit.rawRetentionReviewDue, true);
  assert.equal(audit.retentionReviewDue, false);
  assert.equal(audit.reviewedDueReceiptCount, 2);
  assert.equal(audit.receiptRetentionReviewAudit.currentApprovalCount, 1);
  assert.equal(audit.deletionPerformed, false);
  assert.equal(audit.compactionPerformed, false);
  assert.equal(audit.receiptCount, 2);
  assert.equal(audit.usableForCurrentDecision, false, "initial checkpoint enrollment remains history-unproven");
});

test("Batch 167: receipt retention challenge rejects source drift and API routes are exposed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b167-retention-stale-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b167-stale";
  const { app, staleBundle } = await prepareAgedReceiptLedger(root, owner);
  const challenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner,
    { decision: "retain", reason: "Bind the retention review to the current receipt snapshot and checkpoint." });
  await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, staleBundle);
  await assert.rejects(() => app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => error?.code === "CROSS_DOMAIN_VERIFICATION_RECEIPT_RETENTION_CHALLENGE_STALE");
  const audit = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  assert.equal(audit.rawRetentionReviewDue, true);
  assert.equal(audit.retentionReviewDue, true);
  assert.equal(audit.deletionPerformed, false);
  for (const name of ["getRecoverySloCrossDomainRecoveryIntentLedgerCheckpointStatus", "reconcileRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint",
    "prepareRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment", "applyRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment",
    "auditRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint", "prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview",
    "applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview", "auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviews"])
    assert.equal(typeof app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-intent-ledger\/checkpoint\/enrollment-challenges/);
  assert.match(server, /verification-receipts\/ledger\/retention-review-challenges/);
  assert.match(server, /verification-receipts\/ledger\/retention-reviews\/audit/);
});
