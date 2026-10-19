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
  return { baseUrl, async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) { const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true }; } };
}
function makeReceipt(ownerId, domain, suffix, createdAt = "2026-10-08T00:00:00.000Z") {
  const unsigned = { id: `receipt-${suffix}`, ownerId, kind: "recovery-slo-cross-domain-provider-baseline-transition-receipt", schemaVersion: 1,
    domain, revision: 1, previousReceiptDigest: null, transitionChallengeId: `transition-${suffix}`,
    sourceReportDigest: suffix.padEnd(64, suffix).slice(0, 64), historyNotProven: false, createdAt };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function manifestContext() {
  return { guardrails: { status: "healthy", compactionEligible: true, blockers: [], receiptAuditStatus: "healthy", baselineAuditStatus: "healthy",
    receiptCount: 2, receiptHeads: { alpha: { id: "receipt-a", digest: "a".repeat(64), revision: 1 }, beta: { id: "receipt-b", digest: "b".repeat(64), revision: 1 } } },
    checkpointStatus: { status: "anchored", anchorSequence: 2, anchorDigest: "c".repeat(64), policyBindingStatus: "current",
      anchoredPolicyDigest: "d".repeat(64), currentPolicyDigest: "d".repeat(64), sourceDigest: "e".repeat(64), sourceCount: 2 } };
}
async function seedOverdueManifestLedger(root) {
  const storage = createStorage({ root }), store = createAgenticStore({ storage }), owner = "owner-b160-ledger";
  const createdAt = "2026-10-08T00:00:00.000Z";
  await store.putEvidence(owner, makeReceipt(owner, "alpha", "a", createdAt), { overwrite: false });
  await store.putEvidence(owner, makeReceipt(owner, "beta", "b", createdAt), { overwrite: false });
  const governance = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => createdAt });
  const context = manifestContext();
  const manifest = await governance.createProviderBaselineReceiptCompactionManifest(owner, context);
  const challenge = await governance.prepareProviderBaselineReceiptCompactionManifestApproval(owner, manifest.manifest.id,
    { ...context, reason: "Approve this receipt manifest for review only without compacting retained evidence." });
  const approval = await governance.applyProviderBaselineReceiptCompactionManifestApproval(owner, challenge.challengeId,
    { ...context, confirmation: challenge.confirmation });
  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3, anchorDigest: "f".repeat(64) };
  await governance.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(owner, approval.approval.id,
    { verifyManifest: (targetOwnerId, manifestId) => governance.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context),
      reason: "Record supersession after the source checkpoint moved behind the local baseline state." });
  return { storage, store, owner };
}

test("Batch 160: registry-transition receipts bind key fingerprints and export integrity", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b160-key-receipts-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519"), changedPair = generateKeyPairSync("ed25519");
  const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const options = { storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) } };
  const app = createAgenticApplication(options), owner = "owner-b160-key";
  const challenge = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate to a trusted key and retain an explicit registry transition receipt." });
  const result = await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.ok(result.transitionReceipt);
  assert.equal(result.transitionReceipt.lifecycleEventDigest, result.event.eventDigest);
  const audit = await app.auditRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.receiptCount, 1);
  const bundle = await app.exportRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceipts(owner);
  assert.equal((await app.verifyRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceiptExport(owner, bundle)).status, "verified");
  const tampered = structuredClone(bundle); tampered.receipts[0].targetKeyFingerprint = "f".repeat(64);
  assert.equal((await app.verifyRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceiptExport(owner, tampered)).status, "unhealthy");
  const changed = createAgenticApplication({ ...options, recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: {
    key_old: oldPair.publicKey, key_next: changedPair.publicKey } });
  const drift = await changed.auditRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceipts(owner);
  assert.equal(drift.status, "registry_rotation_unproven");
  assert.ok(drift.findings.some(item => item.code === "POLICY_BINDING_ATTESTATION_KEY_REGISTRY_ROTATION_UNPROVEN"));
});

test("Batch 160: manifest-ledger retention approval can be revoked and replaced only through bound evidence", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b160-retention-revocation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const seeded = await seedOverdueManifestLedger(root);
  const provider = anchorProvider("https://b160-manifest-ledger-anchor.example");
  const app = createAgenticApplication({ storage: seeded.storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainManifestApprovalLedgerAnchor: provider, recoverySloCrossDomainSnapshotAnchorRetentionDays: 1 });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner,
    { reason: "Enroll the manifest approval ledger before testing approval revocation." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner, enrollment.challengeId, { confirmation: enrollment.confirmation });
  const firstChallenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner,
    { decision: "retain", reason: "Retain the overdue supersession evidence after digest review." });
  const first = await app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner, firstChallenge.challengeId,
    { confirmation: firstChallenge.confirmation });
  assert.equal(first.usableForCurrentDecision, true);
  const revokeChallenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReviewRevocation(seeded.owner, first.approval.id,
    { reason: "Revoke this retention approval because the review decision needs replacement." });
  const revoked = await app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReviewRevocation(seeded.owner, revokeChallenge.challengeId,
    { confirmation: revokeChallenge.confirmation });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.usableForCurrentDecision, false);
  const afterRevoke = await app.auditRecoverySloCrossDomainManifestApprovalLedgerRetentionReviews(seeded.owner);
  const priorState = afterRevoke.approvalStates.find(item => item.id === first.approval.id);
  assert.equal(priorState.revoked, true);
  assert.equal(priorState.current, false);
  assert.equal(afterRevoke.revocationCount, 1);
  const replacementChallenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner,
    { decision: "escalate", reason: "Replace the revoked retain decision with an explicit escalation review.", replacesApprovalId: first.approval.id });
  const replacement = await app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner, replacementChallenge.challengeId,
    { confirmation: replacementChallenge.confirmation });
  assert.equal(replacement.approval.decision, "escalate");
  assert.equal(replacement.approval.replacesApprovalId, first.approval.id);
  const finalAudit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerRetentionReviews(seeded.owner);
  assert.equal(finalAudit.status, "healthy");
  assert.equal(finalAudit.approvalStates.find(item => item.id === first.approval.id).replacedByApprovalId, replacement.approval.id);
  assert.equal(finalAudit.approvalStates.find(item => item.id === replacement.approval.id).current, true);
  await assert.rejects(() => app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReviewRevocation(seeded.owner, first.approval.id,
    { reason: "Attempt to revoke the same approval a second time." }), error => error.code === "MANIFEST_APPROVAL_LEDGER_RETENTION_REVOCATION_TARGET_INVALID"
      || error.code === "MANIFEST_APPROVAL_LEDGER_RETENTION_ALREADY_REVOKED");
});

test("Batch 160: lease audit-event export excludes secrets and detects tampering", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b160-lease-export-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const store = createAgenticStore({ storage: createStorage({ root }) });
  const service = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => new Date().toISOString() });
  const owner = "owner-b160-lease";
  const result = await service.runLeasedRevalidation(owner, "approval-export", async ({ fencingToken }) => ({ status: "current", fencingToken }), { leaseMs: 1500 });
  assert.equal(result.status, "current");
  const bundle = await service.exportRevalidationLeaseAuditEvents(owner);
  assert.equal(bundle.rawLeaseTokensExcluded, true);
  const storedLease = (await store.listEvidence(owner)).find(row => row?.kind === "recovery-slo-cross-domain-retention-review-revalidation-lease");
  assert.ok(storedLease?.leaseToken === null, "lease should be terminal after the worker returns");
  const containsRawTokenField = value => Array.isArray(value) ? value.some(containsRawTokenField)
    : value && typeof value === "object" ? Object.entries(value).some(([key, item]) => key === "leaseToken" || containsRawTokenField(item)) : false;
  assert.equal(containsRawTokenField(bundle), false);
  assert.equal((await service.verifyRevalidationLeaseAuditEventExport(owner, bundle)).status, "verified");
  const tampered = structuredClone(bundle); tampered.leases[0].events[0].reason = "tampered reason";
  const verified = await service.verifyRevalidationLeaseAuditEventExport(owner, tampered);
  assert.equal(verified.status, "unhealthy");
  assert.ok(verified.findings.some(item => item.code === "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_DIGEST_INVALID"));
});

test("Batch 160: public APIs and HTTP routes expose receipt, revocation/replacement, and lease export integrity", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b160-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of [
    "auditRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceipts",
    "recoverRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceipts",
    "exportRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceipts",
    "verifyRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycleTransitionReceiptExport",
    "prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReviewRevocation",
    "applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReviewRevocation",
    "exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents",
    "verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport"
  ]) assert.equal(typeof app[name], "function", name);
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /key-lifecycle\/transition-receipts\/export/);
  assert.match(serverSource, /manifest-approval-ledger\/retention-review\/approvals\/:approvalId\/revocation-challenges/);
  assert.match(serverSource, /revalidation-leases\/events\/verify-export/);
});
