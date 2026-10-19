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
  const provider = anchorProvider("https://b165-gap-ledger.example");
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z", recoverySloCrossDomainManifestApprovalLedgerAnchor: provider, ...extraAppOptions });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner,
    { reason: "Enroll the initial manifest ledger snapshot before testing approved gap finalization." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await createSupersession(governance, owner, "x", "Record supersession x and preserve the manifest approval audit history.");
  await createSupersession(governance, owner, "y", "Record supersession y and preserve the manifest approval audit history.");
  return { app, governance, owner, provider };
}
async function setupAnchoredReceiptCheckpoint(root, owner, extra = {}) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const provider = anchorProvider(`https://${owner}.receipt-anchor.example`);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
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
  return { app, owner, advance: milliseconds => { nowMs += milliseconds; } };
}
async function createAttestation(app, owner, reason) {
  return app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, { reason });
}

 test("Batch 165: attestation lifecycle is externally anchored and subsequent revocation advances one event at a time", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b165-lifecycle-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const lifecycleAnchor = anchorProvider("https://b165-lifecycle-anchor.example");
  const { app, owner } = await setupAnchoredReceiptCheckpoint(root, "b165-lifecycle-owner", {
    recoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: lifecycleAnchor,
    requireRecoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: true
  });
  const first = await createAttestation(app, owner, "Create an attestation for the lifecycle external checkpoint test.");
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, first.attestation.id,
    { reason: "Revoke the first attestation to establish a checkpointable lifecycle event." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, revoke.challengeId, { confirmation: revoke.confirmation });
  assert.equal(revoked.externalLifecycleCheckpoint.status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the first lifecycle event while preserving unproven pre-enrollment history." });
  await app.applyRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const second = await createAttestation(app, owner, "Create a second attestation for a later lifecycle checkpoint transition.");
  const revokeSecond = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, second.attestation.id,
    { reason: "Revoke the second attestation to test single-event lifecycle checkpoint advancement." });
  const revokedSecond = await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, revokeSecond.challengeId,
    { confirmation: revokeSecond.confirmation });
  assert.equal(revokedSecond.externalLifecycleCheckpoint.status, "anchored");
  assert.equal(revokedSecond.externalLifecycleCheckpoint.anchorSequence, 2);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner)).status, "history_unproven");
});

test("Batch 165: gap finalization receipts have an independent external checkpoint", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b165-finalization-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const finalizationAnchor = anchorProvider("https://b165-finalization-anchor.example");
  const { app, owner } = await seedGapFixture(root, "b165-finalization-owner", {
    recoverySloCrossDomainManifestApprovalLedgerGapFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationAnchor: true
  });
  const diagnostics = await app.diagnoseRecoverySloCrossDomainManifestApprovalLedgerCheckpointGaps(owner);
  assert.equal(diagnostics.status, "multi_event_gap_proven");
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner,
    { reason: "Approve the uniquely proven gap before recording its finalization receipt." });
  const approval = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const result = await app.finalizeRecoverySloCrossDomainManifestApprovalLedgerGap(owner, approval.approval.id);
  assert.equal(result.finalizationReceiptCheckpoint.status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointEnrollment(owner,
    { reason: "Enroll the finalized multi-event approval receipt history explicitly." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const status = await app.getRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointStatus(owner);
  assert.equal(status.status, "anchored");
  assert.equal(status.historyNotProven, true);
  assert.equal((await app.auditRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpoint(owner)).status, "history_unproven");
});

test("Batch 165: verification receipt recovery intents recover after enrollment and gap diagnostics report no gap", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b165-receipt-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b165-verification-receipts.example");
  const { app, owner } = await setupAnchoredReceiptCheckpoint(root, "b165-receipt-owner", {
    recoverySloCrossDomainLeaseExportVerificationReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainLeaseExportVerificationReceiptAnchor: true
  });
  const firstBundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const first = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, firstBundle);
  assert.equal(first.recoveryIntent.status, "awaiting_enrollment");
  const enrollment = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the initial signed verification receipt ledger before adding another receipt." });
  await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const secondBundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const second = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, secondBundle);
  assert.equal(second.recoveryIntent.status, "completed");
  const recovered = await app.recoverRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerIntents(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.intentAudit.pendingCount, 0);
  assert.equal(recovered.intentAudit.completedCount, 2);
  assert.equal(recovered.gapDiagnostics.status, "no_gap");
  assert.equal((await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptRecoveryIntents(owner)).status, "healthy");
  receiptAnchor.setForceConflict(true);
  const thirdBundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const third = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, thirdBundle);
  assert.equal(third.recoveryIntent.status, "checkpoint_pending");
  const gap = await app.diagnoseRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerGaps(owner);
  assert.equal(gap.status, "single_receipt_gap_proven");
  assert.equal(gap.uniqueContinuityProof, true);
  receiptAnchor.setForceConflict(false);
  const crashRecovered = await app.recoverRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerIntents(owner);
  assert.equal(crashRecovered.status, "recovered");
  assert.equal(crashRecovered.intentAudit.pendingCount, 0);
  assert.equal(crashRecovered.gapDiagnostics.status, "no_gap");
});

test("Batch 165: a prepared receipt intent without a persisted receipt is safely finalized as abandoned", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b165-abandoned-intent-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const storage = createStorage({ root }), store = createAgenticStore({ storage });
  const app = createAgenticApplication({ storage }), owner = "b165-abandoned-owner";
  const unsigned = { id: "slvri-b165-simulated-crash", ownerId: owner, sequence: 1, receiptId: "missing-receipt",
    expectedReceiptDigest: "a".repeat(64), expectedReceiptSequence: 1, expectedPreviousReceiptDigest: null,
    expectedExportDigest: "b".repeat(64), createdAt: "2026-10-13T00:00:00.000Z" };
  const intentUnsigned = { ...unsigned, kind: "recovery-slo-cross-domain-revalidation-lease-verification-receipt-checkpoint-recovery-intent",
    schemaVersion: 1, previousEventDigest: null, status: "prepared", updatedAt: unsigned.createdAt };
  intentUnsigned.intentEventDigest = sha256(canonical(unsigned));
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  assert.equal((await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptRecoveryIntents(owner)).pendingCount, 1);
  const result = await app.recoverRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerIntents(owner);
  assert.equal(result.results[0].status, "abandoned");
  assert.equal(result.intentAudit.pendingCount, 0);
  assert.equal(result.intentAudit.abandonedCount, 1);
});

test("Batch 165: new checkpoint, recovery, and diagnostics APIs are exposed in application and HTTP routes", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b165-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of ["getRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointStatus",
    "reconcileRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint", "auditRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint",
    "getRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointStatus", "auditRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpoint",
    "auditRecoverySloCrossDomainLeaseExportVerificationReceiptRecoveryIntents", "recoverRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerIntents",
    "diagnoseRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerGaps"]) assert.equal(typeof app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /attestation-lifecycle\/checkpoint\/enrollment-challenges/);
  assert.match(server, /gap-finalizations\/external-checkpoint\/enrollment-challenges/);
  assert.match(server, /verification-receipts\/recovery-intents\/recover/);
  assert.match(server, /verification-receipts\/ledger\/gap-diagnostics/);
});
