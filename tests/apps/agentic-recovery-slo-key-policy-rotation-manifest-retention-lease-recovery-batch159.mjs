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
    async compareAndSet(scope, expectedDigest, candidate) {
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
function makeReceipt(ownerId, domain, suffix, createdAt = "2026-10-10T00:00:00.000Z") {
  const unsigned = { id: `receipt-${suffix}`, ownerId, kind: "recovery-slo-cross-domain-provider-baseline-transition-receipt",
    schemaVersion: 1, domain, revision: 1, previousReceiptDigest: null, transitionChallengeId: `transition-${suffix}`,
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
  const storage = createStorage({ root }), store = createAgenticStore({ storage }), owner = "owner-b159-ledger";
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

test("Batch 159: key-lifecycle checkpoint classifies registry and policy drift without auto-advancing it", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b159-key-policy-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519"), changedPair = generateKeyPairSync("ed25519");
  const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const provider = anchorProvider("https://b159-key-lifecycle-anchor.example");
  const options = { storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyLifecycleAnchor: provider, requireRecoverySloCrossDomainAttestationKeyLifecycleAnchor: true };
  const app = createAgenticApplication(options), owner = "owner-b159-key-policy";
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the trusted signing-key registry before testing lifecycle policy drift." });
  await app.applyRecoverySloCrossDomainAttestationKeyLifecycleCheckpointEnrollment(owner, enrollment.challengeId, { confirmation: enrollment.confirmation });
  const changedRegistry = createAgenticApplication({ ...options, recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: {
    key_old: oldPair.publicKey, key_next: changedPair.publicKey } });
  const audit = await changedRegistry.auditRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint(owner);
  assert.equal(audit.status, "registry_rotation_unproven");
  assert.ok(audit.findings.some(item => item.code === "CROSS_DOMAIN_KEY_LIFECYCLE_REGISTRY_ROTATION_UNPROVEN"));
  await assert.rejects(() => changedRegistry.reconcileRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint(owner), error =>
    error.code === "CROSS_DOMAIN_KEY_LIFECYCLE_CONTINUITY_UNPROVEN" && /registry.*berubah tanpa event lifecycle/i.test(error.message));
  const changedPolicy = createAgenticApplication({ ...options, recoverySloCrossDomainSnapshotAnchorRetentionDays: 91 });
  const policyAudit = await changedPolicy.auditRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint(owner);
  assert.equal(policyAudit.status, "policy_binding_required");
  assert.equal(policyAudit.usableForCurrentDecision, false);
});

test("Batch 159: manifest-ledger retention approval binds overdue event digests and anchors the decision", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b159-ledger-review-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const seeded = await seedOverdueManifestLedger(root);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const provider = anchorProvider("https://b159-manifest-ledger-anchor.example");
  const app = createAgenticApplication({ storage: seeded.storage, clock: () => new Date(nowMs).toISOString(),
    recoverySloCrossDomainManifestApprovalLedgerAnchor: provider, recoverySloCrossDomainSnapshotAnchorRetentionDays: 1 });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner,
    { reason: "Enroll the overdue manifest-approval ledger before retention decision review." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner, enrollment.challengeId, { confirmation: enrollment.confirmation });
  const before = await app.auditRecoverySloCrossDomainManifestApprovalLedgerFreshnessRetention(seeded.owner);
  assert.equal(before.status, "retention_review_due");
  assert.equal(before.retentionReviewDue, true);
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner,
    { decision: "retain", reason: "Retain the overdue ledger evidence after digest and checkpoint revalidation." });
  assert.equal(challenge.reviewedEventCount, 1);
  const applied = await app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(applied.status, "reviewed_retain");
  assert.equal(applied.usableForCurrentDecision, true);
  assert.equal(applied.externalCheckpoint.status, "anchored");
  const after = await app.auditRecoverySloCrossDomainManifestApprovalLedgerFreshnessRetention(seeded.owner);
  assert.equal(after.status, "history_unproven", "initial enrollment does not prove pre-enrollment ledger history");
  assert.equal(after.retentionReviewDue, false);
  assert.equal(after.retainedEventCount, 1);
  assert.equal(after.retentionReviewApprovalAudit.status, "healthy");
  const replay = await app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
  assert.equal(replay.approval.id, applied.approval.id);
  assert.equal((await app.auditRecoverySloCrossDomainManifestApprovalLedgerCheckpoint(seeded.owner)).status, "history_unproven");
});

test("Batch 159: retention-review challenge is rejected when its bound source snapshot changes", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b159-ledger-stale-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const seeded = await seedOverdueManifestLedger(root);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const provider = anchorProvider("https://b159-manifest-ledger-stale-anchor.example");
  const app = createAgenticApplication({ storage: seeded.storage, clock: () => new Date(nowMs).toISOString(),
    recoverySloCrossDomainManifestApprovalLedgerAnchor: provider, recoverySloCrossDomainSnapshotAnchorRetentionDays: 1 });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner,
    { reason: "Enroll the overdue manifest ledger before testing stale review challenge rejection." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner, enrollment.challengeId, { confirmation: enrollment.confirmation });
  const challenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner,
    { decision: "retain", reason: "Prepare a retention review bound to the exact source snapshot digest." });
  const store = createAgenticStore({ storage: seeded.storage });
  const rows = await store.listEvidence(seeded.owner);
  const target = rows.find(item => item.kind === "recovery-slo-cross-domain-provider-baseline-receipt-compaction-manifest-approval-supersession");
  const changedUnsigned = { ...target, createdAt: "2026-10-09T00:00:00.000Z" };
  delete changedUnsigned.digest;
  changedUnsigned.eventDigest = sha256(canonical(Object.fromEntries(Object.entries(changedUnsigned).filter(([key]) => !["_storage", "digest", "eventDigest"].includes(key)))));
  changedUnsigned.digest = digestRecord(changedUnsigned);
  await store.putEvidence(seeded.owner, changedUnsigned, { expectedVersion: target._storage?.version });
  await assert.rejects(() => app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => ["MANIFEST_APPROVAL_LEDGER_RETENTION_SOURCE_UNTRUSTED", "MANIFEST_APPROVAL_LEDGER_RETENTION_CHALLENGE_STALE"].includes(error.code));
});

test("Batch 159: lease recovery is idempotent by request ID and exposes durable recovery metrics", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b159-lease-idempotent-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const storage = createStorage({ root }), store = createAgenticStore({ storage });
  const ownerId = "owner-b159-lease", approvalId = "approval-b159-lease", token = "lease-token-b159";
  const leaseKind = "recovery-slo-cross-domain-retention-review-revalidation-lease";
  const leaseId = `${leaseKind}-${sha256(`${ownerId}\0${approvalId}`).slice(0, 36)}`;
  const acquiredAt = new Date(nowMs).toISOString(), leaseExpiresAt = new Date(nowMs + 1000).toISOString();
  const eventBody = { sequence: 1, action: "acquired", previousEventDigest: null, previousRecordDigest: null, at: acquiredAt,
    fencingToken: 1, leaseTokenDigest: sha256(token), leaseExpiresAt, reason: "Lease acquired for bounded revalidation" };
  const event = { ...eventBody, eventDigest: sha256(canonical(eventBody)) };
  const unsigned = { id: leaseId, ownerId, kind: leaseKind, schemaVersion: 2, approvalId, status: "active", leaseToken: token,
    fencingToken: 1, leaseExpiresAt, createdAt: acquiredAt, updatedAt: acquiredAt, previousRecordDigest: null,
    events: [event], headEventDigest: event.eventDigest };
  await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { overwrite: false });
  const service = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => new Date(nowMs).toISOString() });
  nowMs += 2000;
  const first = await service.recoverRevalidationLease(ownerId, approvalId, { recoveryRequestId: "recovery-request-159" });
  assert.equal(first.status, "recovered");
  assert.equal(first.recovered, true);
  assert.equal(first.idempotent, false);
  const afterFirst = await store.getEvidence(ownerId, leaseId);
  const second = await service.recoverRevalidationLease(ownerId, approvalId, { recoveryRequestId: "recovery-request-159" });
  assert.equal(second.status, "recovered");
  assert.equal(second.idempotent, true);
  assert.equal(second.recoveryEventDigest, first.recoveryEventDigest);
  assert.equal((await store.getEvidence(ownerId, leaseId)).events.length, afterFirst.events.length);
  const audit = await service.auditRevalidationLeases(ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.recoveryEventCount, 1);
  assert.equal(audit.recoveredLeaseCount, 1);
  assert.equal(audit.recoveryRequestIdCount, 1);
  assert.equal(audit.lastRecoveredAt, first.lastRecoveredAt);
});

test("Batch 159: public APIs and HTTP routes expose retention approval and recovery observability", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b159-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of ["prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReview", "applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReview",
    "auditRecoverySloCrossDomainManifestApprovalLedgerRetentionReviews", "auditRecoverySloCrossDomainRetentionReviewRevalidationLeases",
    "recoverRecoverySloCrossDomainRetentionReviewRevalidationLease"]) assert.equal(typeof app[name], "function", name);
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /manifest-approval-ledger\/retention-review\/challenges/);
  assert.match(serverSource, /manifest-approval-ledger\/retention-review\/audit/);
  assert.match(serverSource, /recoverRecoverySloCrossDomainRetentionReviewRevalidationLease\(q\.agentic\.user\.id,q\.params\.id,q\.body\|\|\{\}\)/);
});
