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
  const records = new Map();
  return { baseUrl,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
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
async function seedGapFixture(root, owner) {
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
  const provider = anchorProvider("https://b163-gap-ledger.example");
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z", recoverySloCrossDomainManifestApprovalLedgerAnchor: provider });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner,
    { reason: "Enroll the initial manifest ledger snapshot before testing explicit gap approval." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await createSupersession(governance, owner, "x", "Record supersession x and preserve the manifest approval audit history.");
  await createSupersession(governance, owner, "y", "Record supersession y and preserve the manifest approval audit history.");
  return { app, governance, owner };
}

async function setupAnchoredReceiptCheckpoint(root, owner) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const provider = anchorProvider(`https://${owner}.example`);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const advance = milliseconds => { nowMs += milliseconds; };
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: provider, requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true });
  const rotation = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate to the next trusted key before enrolling a recoverable receipt checkpoint." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotation.challengeId, { confirmation: rotation.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the receipt checkpoint so recovery intent history can be attested." });
  await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  return { app, owner, oldPair, nextPair, advance };
}

test("Batch 163: finalized recovery-intent history can be signed, verified, and audited against the current checkpoint", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b163-recovery-attestation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app, owner, advance } = await setupAnchoredReceiptCheckpoint(root, "b163-recovery-owner");
  const created = await app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner,
    { reason: "Attest the finalized recovery intent history and bind it to the current external receipt checkpoint." });
  assert.equal(created.status, "signed_history_unproven");
  assert.equal(created.usableForCurrentDecision, false);
  const verified = await app.verifyRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, created.attestation.id);
  assert.equal(verified.status, "history_unproven");
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.current, true);
  assert.equal(verified.usableForCurrentDecision, false);
  const tampered = structuredClone(created.attestation); tampered.reason = "tampered reason";
  const invalid = await app.verifyRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, tampered);
  assert.equal(invalid.status, "unhealthy");
  assert.equal(invalid.signatureValid, false);
  const audit = await app.auditRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestations(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.currentCount, 1);
  const rotateBack = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_old",
    { reason: "Rotate away from the attestation key to verify historical key-cutoff behavior." });
  advance(1000);
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotateBack.challengeId, { confirmation: rotateBack.confirmation });
  await app.reconcileRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);
  const revokeNext = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation(owner, "key_next",
    { reason: "Revoke the retired attestation key after its signed historical evidence was retained." });
  advance(1000);
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation(owner, revokeNext.challengeId, { confirmation: revokeNext.confirmation });
  await app.reconcileRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);
  const historical = await app.verifyRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, created.attestation.id);
  assert.equal(historical.historicallyValid, true);
  assert.equal(historical.current, false);
  assert.equal(historical.usableForCurrentDecision, false);
});

test("Batch 163: multi-event gap approval is bound to candidate/source/policy digests and never advances the checkpoint", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b163-gap-approval-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app, owner, governance } = await seedGapFixture(root, "b163-gap-owner");
  const diagnostics = await app.diagnoseRecoverySloCrossDomainManifestApprovalLedgerCheckpointGaps(owner);
  assert.equal(diagnostics.status, "multi_event_gap_proven");
  assert.equal(diagnostics.checkpointFreshnessStatus, "fresh");
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner,
    { reason: "Approve review of this uniquely proven multi-event gap without automatic checkpoint advancement." });
  const applied = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(applied.status, "approved_for_review");
  assert.equal(applied.checkpointAdvanced, false);
  assert.equal(applied.automaticReconciliationAllowed, false);
  const retry = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(retry.idempotent, true);
  const checkpoint = await app.getRecoverySloCrossDomainManifestApprovalLedgerCheckpointStatus(owner);
  assert.equal(checkpoint.status, "behind_local");
  const audit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerGapApprovals(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.approvals[0].current, true);
  const staleChallenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner,
    { reason: "Prepare a second approval challenge to prove source changes invalidate the prepared approval." });
  await createSupersession(governance, owner, "z", "Record a later supersession so the previously approved gap snapshot becomes stale.");
  await assert.rejects(() => app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, staleChallenge.challengeId,
    { confirmation: staleChallenge.confirmation }), error => error.code === "MANIFEST_APPROVAL_LEDGER_GAP_APPROVAL_STALE");
  const staleAudit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerGapApprovals(owner);
  assert.equal(staleAudit.status, "stale");
  assert.equal(staleAudit.approvals[0].current, false);
  const staleRetry = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(staleRetry.idempotent, true);
  assert.equal(staleRetry.status, "approved_but_stale");
  assert.equal(staleRetry.usableForCurrentDecision, false);
});

test("Batch 163: signed-export verification receipts are signed, checkpoint-bound, tamper-evident, and auditable", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b163-export-receipt-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app, owner, advance } = await setupAnchoredReceiptCheckpoint(root, "b163-export-owner");
  const bundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const recorded = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, bundle);
  assert.equal(recorded.status, "recorded");
  assert.equal(recorded.verification.signatureValid, true);
  assert.equal(recorded.receipt.kind, "recovery-slo-cross-domain-revalidation-lease-signed-export-verification-receipt");
  const verified = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipt(owner, recorded.receipt.id);
  assert.equal(verified.status, "current");
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.usableForCurrentDecision, false);
  const tampered = structuredClone(recorded.receipt); tampered.verificationSummary.status = "unhealthy";
  const invalid = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipt(owner, tampered);
  assert.equal(invalid.status, "unhealthy");
  const audit = await app.auditRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.receiptCount, 1);
  assert.equal(audit.usableCount, 0);
  const rotateBack = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_old",
    { reason: "Rotate the receipt signing key to verify historical receipt cutoff and checkpoint invalidation." });
  advance(1000);
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotateBack.challengeId, { confirmation: rotateBack.confirmation });
  await app.reconcileRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);
  const historical = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipt(owner, recorded.receipt.id);
  assert.equal(historical.historicallyValid, true);
  assert.equal(historical.current, false);
  assert.equal(historical.usableForCurrentDecision, false);
  const staleAudit = await app.auditRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipts(owner);
  assert.equal(staleAudit.status, "stale");
});

test("Batch 163: new recovery attestation, gap approval, and verification receipt APIs/routes are exposed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b163-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of ["createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation",
    "verifyRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation",
    "auditRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestations",
    "prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval", "applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval",
    "auditRecoverySloCrossDomainManifestApprovalLedgerGapApprovals",
    "verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport",
    "verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipt",
    "auditRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipts"]) assert.equal(typeof app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-intents\/attestations\/audit/);
  assert.match(server, /manifest-approval-ledger\/checkpoint\/gap-approval-challenges/);
  assert.match(server, /verification-receipts\/audit/);
});
