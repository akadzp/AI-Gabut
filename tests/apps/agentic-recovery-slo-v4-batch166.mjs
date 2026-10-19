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

 test("Batch 166: lifecycle checkpoint marker recovery is intent-bound, idempotent, and fail-closed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b166-lifecycle-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const lifecycleAnchor = anchorProvider("https://b166-lifecycle-anchor.example");
  const { app, storage, owner } = await setupAnchoredReceiptCheckpoint(root, "b166-lifecycle-owner", {
    recoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: lifecycleAnchor,
    requireRecoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: true
  });
  const attestation = await app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner,
    { reason: "Create an attestation before testing crash recovery for the lifecycle checkpoint marker." });
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, attestation.attestation.id,
    { reason: "Revoke the attestation to create a checkpointable lifecycle event for recovery." });
  await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, revoke.challengeId, { confirmation: revoke.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the lifecycle event before simulating a local marker-write interruption." });
  await app.applyRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await removeCheckpointMarker(storage, owner, "cross-domain-recovery-intent-attestation-lifecycle-checkpoint");
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  assert.equal(inspection.recoverable, true);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.checkpoint.status, "anchored");
  assert.equal(recovered.recoveryIntent.status, "completed");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointRecoveryIntents(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.completedCount, 1);
  const again = await app.recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner);
  assert.equal(again.status, "not_required");
  lifecycleAnchor.setForceConflict(true);
  const nextAttestation = await app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner,
    { reason: "Create a second attestation to verify recovery refuses an advanced source snapshot." });
  const nextRevoke = await app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, nextAttestation.attestation.id,
    { reason: "Create a second lifecycle event while the external checkpoint provider rejects writes." });
  await app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, nextRevoke.challengeId, { confirmation: nextRevoke.confirmation });
  const advanced = await app.inspectRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointRecovery(owner);
  assert.equal(advanced.status, "source_advanced");
  assert.equal(advanced.recoverable, false);
  await assert.rejects(() => app.recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner),
    error => error?.code === "CROSS_DOMAIN_RECOVERY_ATTESTATION_LIFECYCLE_RECOVERY_BLOCKED");
});

test("Batch 166: finalization checkpoint recovery verifies approval, challenge, and finalization receipt bindings", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b166-finalization-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const finalizationAnchor = anchorProvider("https://b166-finalization-anchor.example");
  const { app, storage, owner } = await seedGapFixture(root, "b166-finalization-owner", {
    recoverySloCrossDomainManifestApprovalLedgerGapFinalizationAnchor: finalizationAnchor,
    requireRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationAnchor: true
  });
  const diagnostics = await app.diagnoseRecoverySloCrossDomainManifestApprovalLedgerCheckpointGaps(owner);
  assert.equal(diagnostics.status, "multi_event_gap_proven");
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner,
    { reason: "Approve the uniquely proven gap before testing approval-bound finalization receipt recovery." });
  const approval = await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapApproval(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  await app.finalizeRecoverySloCrossDomainManifestApprovalLedgerGap(owner, approval.approval.id);
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointEnrollment(owner,
    { reason: "Enroll the finalization receipt history before simulating a local marker interruption." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await removeCheckpointMarker(storage, owner, "cross-domain-manifest-approval-ledger-gap-finalization-checkpoint");
  const inspection = await app.inspectRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  assert.equal(inspection.recoverable, true);
  assert.ok(inspection.latestFinalization.approvalId);
  const recovered = await app.recoverRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.checkpoint.status, "anchored");
  const audit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointRecoveryIntents(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.completedCount, 1);
});

test("Batch 166: verification receipt policy and retention audit is read-only and blocks stale or unproven use", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b166-receipt-retention-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const receiptAnchor = anchorProvider("https://b166-verification-receipts.example");
  const { app, owner, advance } = await setupAnchoredReceiptCheckpoint(root, "b166-receipt-owner", {
    recoverySloCrossDomainLeaseExportVerificationReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainLeaseExportVerificationReceiptAnchor: true
  });
  const firstBundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const first = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, firstBundle);
  assert.equal(first.recoveryIntent.status, "awaiting_enrollment");
  const enrollment = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the signed verification receipt ledger before evaluating its policy and retention state." });
  await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const secondBundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  const second = await app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, secondBundle);
  assert.equal(second.recoveryIntent.status, "completed");
  const audit = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  assert.equal(audit.receiptCount, 2);
  assert.equal(audit.deletionPerformed, false);
  assert.equal(audit.compactionPerformed, false);
  assert.ok(audit.policyBindingAudit);
  assert.ok(audit.receipts.every(item => item.policyBindingCurrent));
  assert.ok(["history_unproven", "healthy"].includes(audit.status));
  advance(91 * 86400000);
  const aged = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  assert.equal(aged.retentionReviewDue, true);
  assert.equal(aged.deletionPerformed, false);
  assert.equal(aged.usableForCurrentDecision, false);
});

test("Batch 166: new recovery and retention audit APIs/routes are exposed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b166-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of ["inspectRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointRecovery",
    "recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint",
    "auditRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointRecoveryIntents",
    "inspectRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointRecovery",
    "recoverRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpoint",
    "auditRecoverySloCrossDomainManifestApprovalLedgerGapFinalizationCheckpointRecoveryIntents",
    "auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention"]) assert.equal(typeof app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /attestation-lifecycle\/checkpoint\/recovery\/recover/);
  assert.match(server, /gap-finalizations\/external-checkpoint\/recovery\/recover/);
  assert.match(server, /verification-receipts\/ledger\/policy-retention\/audit/);
});
