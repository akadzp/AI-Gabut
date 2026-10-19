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
  const provider = anchorProvider("https://b164-gap-ledger.example");
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
  const advance = milliseconds => { nowMs += milliseconds; };
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
  return { app, owner, oldPair, nextPair, advance };
}

async function createAttestation(app, owner, reason) {
  return app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, { reason });
}

test("Batch 164: recovery-intent attestation revocation and renewal are challenge-bound, append-only, and replay-safe", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b164-attestation-lifecycle-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app, owner } = await setupAnchoredReceiptCheckpoint(root, "b164-attestation-owner");
  const first = await createAttestation(app, owner, "Create first recovery attestation for a controlled renewal lifecycle test.");
  const second = await createAttestation(app, owner, "Create second recovery attestation for a controlled revocation lifecycle test.");
  const renewal = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRenewal(owner, first.attestation.id,
    { reason: "Renew the recovery attestation after revalidating its current checkpoint binding." });
  await assert.rejects(() => app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner,
    { reason: renewal.reason || "Attempt a direct renewal bypass without the internal approval capability.",
      supersedesAttestationId: first.attestation.id, renewalChallengeId: renewal.challengeId }),
    error => error.code === "CROSS_DOMAIN_KEY_TRANSITION_RECEIPT_RECOVERY_ATTESTATION_RENEWAL_BINDING_INVALID");
  const renewed = await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRenewal(owner, renewal.challengeId,
    { confirmation: renewal.confirmation });
  assert.equal(renewed.status, "renewed");
  const renewalRetry = await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRenewal(owner, renewal.challengeId,
    { confirmation: renewal.confirmation });
  assert.equal(renewalRetry.idempotent, true);
  const oldVerification = await app.verifyRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, first.attestation.id);
  assert.equal(oldVerification.status, "superseded");
  assert.equal(oldVerification.usableForCurrentDecision, false);
  const newVerification = await app.verifyRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, renewed.attestation.id);
  assert.equal(newVerification.historicallyValid, true);
  assert.equal(newVerification.current, true);
  assert.equal(newVerification.usableForCurrentDecision, false); // enrollment history remains explicitly unproven
  const revocation = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, second.attestation.id,
    { reason: "Revoke the second attestation while retaining its signed historical evidence." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, revocation.challengeId,
    { confirmation: revocation.confirmation });
  assert.equal(revoked.status, "revoked");
  assert.equal((await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, revocation.challengeId,
    { confirmation: revocation.confirmation })).idempotent, true);
  const revokedVerification = await app.verifyRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner, second.attestation.id);
  assert.equal(revokedVerification.status, "revoked");
  assert.equal(revokedVerification.historicallyValid, true);
  assert.equal(revokedVerification.usableForCurrentDecision, false);
  const lifecycle = await app.auditRecoverySloCrossDomainRecoveryIntentAttestationLifecycle(owner);
  assert.equal(lifecycle.status, "healthy");
  assert.equal(lifecycle.eventCount, 2);
});

test("Batch 164: approved multi-event gap is finalized through external-anchor CAS and finalization is idempotent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b164-gap-finalize-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app, owner, provider } = await seedGapFixture(root, "b164-gap-owner");
  const diagnostics = await app.diagnoseRecoverySloCrossDomainManifestApprovalLedgerCheckpointGaps(owner);
  assert.equal(diagnostics.status, "multi_event_gap_proven");
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner,
    { reason: "Approve the uniquely proven multi-event gap for explicit external checkpoint finalization." });
  const approved = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(approved.status, "approved_for_review");
  provider.setForceConflict(true);
  await assert.rejects(() => app.finalizeRecoverySloCrossDomainManifestApprovalLedgerGap(owner, approved.approval.id),
    error => error.code === "EXTERNAL_SNAPSHOT_CHECKPOINT_CAS_CONFLICT");
  provider.setForceConflict(false);
  const finalized = await app.finalizeRecoverySloCrossDomainManifestApprovalLedgerGap(owner, approved.approval.id);
  assert.equal(finalized.checkpointAdvanced, true);
  assert.equal(finalized.externalCheckpoint.status, "anchored");
  assert.equal(finalized.finalization.previousAnchorSequence, diagnostics.anchorSequence);
  assert.equal(finalized.finalization.resultAnchorSequence, diagnostics.anchorSequence + 1);
  assert.equal(finalized.finalization.candidateEventIds.length, diagnostics.gapCount);
  const retry = await app.finalizeRecoverySloCrossDomainManifestApprovalLedgerGap(owner, approved.approval.id);
  assert.equal(retry.idempotent, true);
  const audit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerGapFinalizations(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.finalizationCount, 1);
  assert.equal(audit.currentCount, 1);
  assert.equal(audit.finalizations[0].usableForCurrentDecision, false); // initial enrollment remains history-unproven
});

test("Batch 164: a multi-event gap approval is rejected if its source changes before CAS finalization", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b164-gap-stale-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app, governance, owner, provider } = await seedGapFixture(root, "b164-gap-stale-owner");
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner,
    { reason: "Approve the current multi-event gap but require a fresh source before finalization." });
  const approval = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  await createSupersession(governance, owner, "z", "Append a later supersession to invalidate the prepared multi-event gap approval.");
  const before = await app.getRecoverySloCrossDomainManifestApprovalLedgerCheckpointStatus(owner);
  await assert.rejects(() => app.finalizeRecoverySloCrossDomainManifestApprovalLedgerGap(owner, approval.approval.id),
    error => error.code === "MANIFEST_APPROVAL_LEDGER_GAP_FINALIZATION_STALE");
  const after = await app.getRecoverySloCrossDomainManifestApprovalLedgerCheckpointStatus(owner);
  assert.equal(after.anchorDigest, before.anchorDigest);
  assert.equal(after.anchorSequence, before.anchorSequence);
});

test("Batch 164: signed verification receipts form a digest-linked ledger and external checkpoint advances one receipt at a time", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b164-receipt-ledger-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b164-verification-receipts.example");
  const { app, owner } = await setupAnchoredReceiptCheckpoint(root, "b164-receipt-owner", {
    recoverySloCrossDomainLeaseExportVerificationReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainLeaseExportVerificationReceiptAnchor: true
  });
  const firstBundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const first = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, firstBundle);
  assert.equal(first.receipt.receiptLedgerSequence, 1);
  assert.equal(first.receipt.previousReceiptDigest, null);
  assert.equal(first.externalCheckpoint.status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the signed verification receipt ledger after retaining the first receipt." });
  await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const secondBundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const second = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, secondBundle);
  assert.equal(second.receipt.receiptLedgerSequence, 2);
  assert.equal(second.receipt.previousReceiptDigest, first.receipt.digest);
  assert.equal(second.externalCheckpoint.status, "anchored");
  assert.equal(second.externalCheckpoint.anchorSequence, 2);
  const ledger = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerContinuity(owner);
  assert.equal(ledger.status, "history_unproven");
  assert.equal(ledger.receiptCount, 2);
  assert.equal(ledger.findings.length, 0);
  const checkpointAudit = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpoint(owner);
  assert.equal(checkpointAudit.status, "history_unproven");
  const tampered = structuredClone(second.receipt); tampered.previousReceiptDigest = "f".repeat(64);
  assert.equal((await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventVerificationReceipt(owner, tampered)).status, "unhealthy");
});

test("Batch 164: new lifecycle, approved-gap finalization, and receipt-checkpoint APIs/routes are exposed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b164-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of ["prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation", "applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation",
    "prepareRecoverySloCrossDomainRecoveryIntentAttestationRenewal", "applyRecoverySloCrossDomainRecoveryIntentAttestationRenewal",
    "auditRecoverySloCrossDomainRecoveryIntentAttestationLifecycle", "finalizeRecoverySloCrossDomainManifestApprovalLedgerGap",
    "auditRecoverySloCrossDomainManifestApprovalLedgerGapFinalizations", "getRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointStatus",
    "reconcileRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpoint", "auditRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpoint",
    "auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerContinuity"]) assert.equal(typeof app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /attestation-revocation-challenges/);
  assert.match(server, /attestation-renewal-challenges/);
  assert.match(server, /gap-approvals\/:approvalId\/finalize/);
  assert.match(server, /verification-receipts\/checkpoint\/enrollment-challenges/);
});
