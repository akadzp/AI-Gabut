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
  return { app, storage, owner, clock, advance: milliseconds => { nowMs += milliseconds; } };
}
async function removeCheckpointMarker(storage, owner, markerKindPart) {
  const store = createAgenticStore({ storage });
  const marker = (await store.listEvidence(owner)).find(item => item.kind?.includes(markerKindPart) && item.kind.endsWith("-marker"));
  assert.ok(marker, `marker ${markerKindPart} exists`);
  await store.mutateEvidence(owner, marker.id, () => ({ delete: true }));
  assert.equal(await store.getEvidence(owner, marker.id), null);
}



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


test("Batch 168: recovery-intent checkpoint recovery is inspectable and fails closed for an unproven local-only state", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b168-intent-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z" });
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentLedgerCheckpointRecovery("b168-local-only");
  assert.equal(inspection.recoverable, false);
  assert.equal(inspection.mutationAllowed, false);
  await assert.rejects(() => app.recoverRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint("b168-local-only"),
    error => error?.code === "CROSS_DOMAIN_RECOVERY_INTENT_LEDGER_RECOVERY_BLOCKED");
  const audit = await app.auditRecoverySloCrossDomainRecoveryLedgerConsistency("b168-local-only");
  assert.ok(["local_only", "blocked", "healthy"].includes(audit.status));
  assert.equal(audit.mutationAllowed, false);
  assert.equal(audit.deletionPerformed, false);
});

test("Batch 168: recovery-intent ledger policy drift is inspectable and cannot be silently repaired", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b168-policy-drift-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b168-policy-drift";
  const intentAnchor = anchorProvider("https://b168-policy-drift-intent-anchor.example");
  const lifecycleAnchor = anchorProvider("https://b168-policy-drift-lifecycle-anchor.example");
  const setup = await setupAnchoredReceiptCheckpoint(root, owner, {
    recoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: lifecycleAnchor,
    requireRecoverySloCrossDomainRecoveryIntentAttestationLifecycleAnchor: true,
    recoverySloCrossDomainRecoveryIntentLedgerAnchor: intentAnchor,
    requireRecoverySloCrossDomainRecoveryIntentLedgerAnchor: false
  });
  const attestation = await setup.app.createRecoverySloCrossDomainAttestationKeyTransitionReceiptRecoveryIntentAttestation(owner,
    { reason: "Create an attestation so lifecycle checkpoint recovery produces a durable intent." });
  const revoke = await setup.app.prepareRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, attestation.attestation.id,
    { reason: "Revoke the attestation to create a lifecycle event for recovery-intent ledger enrollment." });
  await setup.app.applyRecoverySloCrossDomainRecoveryIntentAttestationRevocation(owner, revoke.challengeId, { confirmation: revoke.confirmation });
  const enrollment = await setup.app.prepareRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll lifecycle history before simulating a checkpoint marker interruption." });
  await setup.app.applyRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await removeCheckpointMarker(setup.storage, owner, "cross-domain-recovery-intent-attestation-lifecycle-checkpoint");
  const recovered = await setup.app.recoverRecoverySloCrossDomainRecoveryIntentAttestationLifecycleCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  const ledgerEnrollment = await setup.app.prepareRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment(owner,
    { reason: "Anchor the recovered intent history before testing policy-drift recovery safeguards." });
  await setup.app.applyRecoverySloCrossDomainRecoveryIntentLedgerCheckpointEnrollment(owner, ledgerEnrollment.challengeId,
    { confirmation: ledgerEnrollment.confirmation });
  const driftedApp = createAgenticApplication({ storage: setup.storage, clock: setup.clock,
    recoverySloCrossDomainRecoveryIntentLedgerAnchor: intentAnchor,
    recoverySloCrossDomainSnapshotAnchorMaxAgeMs: 172800000 });
  const inspection = await driftedApp.inspectRecoverySloCrossDomainRecoveryIntentLedgerCheckpointRecovery(owner);
  assert.equal(inspection.status, "policy_drift");
  assert.equal(inspection.recoverable, false);
  assert.equal(inspection.requiredAction, "explicit_policy_binding_required");
  await assert.rejects(() => driftedApp.recoverRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint(owner),
    error => error?.code === "CROSS_DOMAIN_RECOVERY_INTENT_LEDGER_POLICY_DRIFT_RECOVERY_BLOCKED");
});

test("Batch 168: retention approval revocation is append-only and a replacement must bind the valid revocation", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b168-retention-revoke-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b168-revoke";
  const { app, storage } = await prepareAgedReceiptLedger(root, owner);
  const initialChallenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner,
    { decision: "retain", reason: "Approve the current aged receipt set while preserving the signed audit history." });
  const initial = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner, initialChallenge.challengeId,
    { confirmation: initialChallenge.confirmation });
  assert.equal(initial.status, "reviewed_retain");
  const revocationChallenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner,
    initial.approval.id, { reason: "Revoke this retention decision because it is being superseded by a fresh review." });
  const revoked = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner,
    revocationChallenge.challengeId, { confirmation: revocationChallenge.confirmation });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.usableForCurrentDecision, false);
  const revokedAudit = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  const priorState = revokedAudit.receiptRetentionReviewAudit.approvals.find(item => item.id === initial.approval.id);
  assert.equal(priorState.revoked, true);
  assert.equal(priorState.current, false);
  const replacementChallenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewReplacement(owner,
    initial.approval.id, { decision: "escalate", reason: "Escalate the receipt retention review after revoking the earlier decision." });
  const replacement = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner,
    replacementChallenge.challengeId, { confirmation: replacementChallenge.confirmation });
  assert.equal(replacement.status, "reviewed_escalate");
  assert.equal(replacement.approval.replacesApprovalId, initial.approval.id);
  assert.equal(replacement.approval.replacesRevocationId, revoked.revocation.id);
  const after = await app.auditRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerPolicyRetention(owner);
  assert.equal(after.receiptRetentionReviewAudit.approvals.find(item => item.id === initial.approval.id).current, false);
  assert.equal(after.receiptRetentionReviewAudit.approvals.find(item => item.id === replacement.approval.id).current, true);
  const evidence = await createAgenticStore({ storage }).listEvidence(owner);
  assert.equal(evidence.filter(item => item.kind === "recovery-slo-cross-domain-revalidation-lease-verification-receipt-retention-review-approval").length, 2);
  assert.equal(evidence.filter(item => item.kind === "recovery-slo-cross-domain-revalidation-lease-verification-receipt-retention-review-revocation").length, 1);
  assert.equal(after.deletionPerformed, false);
  assert.equal(after.compactionPerformed, false);
});

test("Batch 168: cross-ledger consistency audit exposes all checkpoint domains and detects orphaned approval references", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b168-cross-ledger-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z" });
  const owner = "b168-cross-ledger";
  const audit = await app.auditRecoverySloCrossDomainRecoveryLedgerConsistency(owner);
  assert.ok(audit.components.recoveryIntentLedger);
  assert.ok(audit.components.attestationLifecycle);
  assert.ok(audit.components.manifestGapFinalization);
  assert.ok(audit.components.verificationReceiptCheckpoint);
  assert.ok(audit.components.receiptRetention);
  assert.ok(audit.components.manifestApprovalLedger);
  assert.equal(audit.readOnly, true);
  assert.equal(audit.mutationAllowed, false);
  const store = createAgenticStore({ storage });
  const orphan = { id: "b168-orphan-approval", ownerId: owner,
    kind: "recovery-slo-cross-domain-revalidation-lease-verification-receipt-retention-review-approval", schemaVersion: 1,
    status: "completed", decision: "retain", reviewedReceiptRefs: [{ id: "missing-receipt", digest: "a".repeat(64) }],
    createdAt: "2026-10-13T00:00:00.000Z", deletionPerformed: false, compactionPerformed: false };
  const { createHash } = await import("node:crypto");
  const canonical = value => value === null || typeof value !== "object" ? JSON.stringify(value)
    : Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
      : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  orphan.digest = createHash("sha256").update(canonical(orphan)).digest("hex");
  await store.putEvidence(owner, orphan, { overwrite: false });
  const after = await app.auditRecoverySloCrossDomainRecoveryLedgerConsistency(owner);
  assert.equal(after.status, "unhealthy");
  assert.ok(after.findings.some(item => item.code === "CROSS_DOMAIN_LEDGER_RETENTION_APPROVAL_ORPHANED_RECEIPT"));
});

test("Batch 168: policy drift and rollback recovery APIs are fail-closed and HTTP routes are wired", async () => {
  const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["inspectRecoverySloCrossDomainRecoveryIntentLedgerCheckpointRecovery",
    "recoverRecoverySloCrossDomainRecoveryIntentLedgerCheckpoint", "auditRecoverySloCrossDomainRecoveryLedgerConsistency",
    "prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation",
    "applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation",
    "prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewReplacement"])
    assert.match(appSource, new RegExp(`${name}:`), name);
  assert.match(server, /recovery-intent-ledger\/checkpoint\/recovery\/inspect/);
  assert.match(server, /cross-domain\/ledger-consistency\/audit/);
  assert.match(server, /retention-review-revocation-challenges/);
  assert.match(server, /replacement-challenges/);
});
