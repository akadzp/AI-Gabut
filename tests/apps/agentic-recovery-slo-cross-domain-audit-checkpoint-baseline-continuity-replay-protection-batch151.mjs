import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
function provider(identity) {
  const records = new Map();
  return { providerIdentity: identity, baseUrl: identity, records,
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId || candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision !== (current ? current.revision + 1 : 1) || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        throw Object.assign(new Error("anchor contract violation"), { code: "ANCHOR_CONTRACT_VIOLATION" });
      }
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b151-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.intentAnchor ?? options.intentAnchor ?? provider("https://intent-default-b151.example"),
    recoverySloRootTrustBaselineProofRevocationAnchor: overrides.revocationAnchor ?? options.revocationAnchor ?? provider("https://revocation-default-b151.example"),
    recoverySloCrossDomainSnapshotAuditAnchor: overrides.auditAnchor ?? options.auditAnchor ?? null,
    requireRecoverySloCrossDomainSnapshotAuditAnchor: overrides.requireAuditAnchor ?? options.requireAuditAnchor ?? false,
    recoverySloCrossDomainProviderBaselineAnchor: overrides.baselineAnchor ?? options.baselineAnchor ?? null,
    requireRecoverySloCrossDomainProviderBaselineAnchor: overrides.requireBaselineAnchor ?? options.requireBaselineAnchor ?? false,
    recoverySloCrossDomainRetentionReviewAnchor: overrides.reviewAnchor ?? options.reviewAnchor ?? null,
    requireRecoverySloCrossDomainRetentionReviewAnchor: overrides.requireReviewAnchor ?? options.requireReviewAnchor ?? false,
    recoverySloCrossDomainSnapshotAnchorMaxAgeMs: 86400000,
    recoverySloCrossDomainSnapshotAnchorFutureSkewMs: 60000,
    recoverySloCrossDomainSnapshotAnchorRetentionDays: overrides.retentionDays ?? options.retentionDays ?? 90,
    recoverySloCrossDomainSnapshotAuditSigner: overrides.signer ?? options.signer ?? null,
    recoverySloCrossDomainSnapshotAuditKeyId: overrides.keyId ?? options.keyId ?? null,
    recoverySloCrossDomainSnapshotAuditPublicKeys: overrides.publicKeys ?? options.publicKeys ?? null,
    requireRecoverySloCrossDomainSnapshotAuditAttestation: overrides.requireAuditAttestation ?? options.requireAuditAttestation ?? false });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b151", now: clock, advance: ms => { nowMs += ms; } };
}
async function runConformance(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, { domain,
    reason: "Run a disposable provider conformance probe before anchoring lifecycle continuity evidence." });
  return app.runRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function acceptBaseline(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainProviderIdentityBaseline(ownerId, { domain,
    reason: "Accept the latest conformant provider identity as the next lifecycle baseline revision." });
  return app.applyRecoverySloCrossDomainProviderIdentityBaseline(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function seedOverdueChallenge(root, ownerId, id = "expired-challenge-b151") {
  const store = createAgenticStore({ storage: createStorage({ root }) });
  const unsigned = { id, ownerId, kind: "retention-decision-gate-recovery-intent-checkpoint-enrollment-challenge", schemaVersion: 1,
    status: "prepared", domain: "retention_decision_gate_recovery_intent", createdAt: "2026-10-01T00:00:00.000Z",
    expiresAt: "2026-10-01T00:10:00.000Z", reason: "Historical expired checkpoint enrollment challenge for a non-destructive retention review." };
  await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { overwrite: false });
  return { store, id };
}

 test("Batch 151: audit-attestation checkpoint requires explicit enrollment and advances after new attestations", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-attestation-anchor-b151.example");
  const f = await fixture(t, { auditAnchor, signer, keyId: "audit-key-151", publicKeys: { "audit-key-151": pair.publicKey }, requireAuditAnchor: true });
  const first = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Attest the first cross-domain governance snapshot before explicit external checkpoint enrollment." });
  assert.equal(first.status, "signed_pending_external_checkpoint");
  assert.equal(first.externalCheckpoint.status, "enrollment_required");
  const challenge = await f.app.prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the verified audit-attestation history at the independently operated external checkpoint." });
  const enrolled = await f.app.applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(enrolled.status, "anchored");
  const verified = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, first.attestation.attestationId);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.usableForCurrentDecision, true);
  const second = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Capture a later governance snapshot and append its digest to the established external checkpoint chain." });
  assert.equal(second.status, "signed");
  assert.equal(second.externalCheckpoint.status, "anchored");
  assert.equal((await f.app.getRecoverySloCrossDomainSnapshotAuditCheckpointStatus(f.ownerId)).anchorSequence, 2);
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAuditCheckpoint(f.ownerId)).status, "healthy");
});

test("Batch 151: provider-baseline lifecycle checkpoint binds baseline revisions and blocks rotation while checkpoint is pending", async t => {
  const intent = provider("https://intent-baseline-chain-b151.example"), baselineAnchor = provider("https://baseline-lifecycle-anchor-b151.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const first = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  assert.equal(first.status, "accepted_pending_external_checkpoint");
  const enrollment = await f.app.prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the accepted provider-baseline lifecycle before permitting any subsequent baseline rotation." });
  assert.equal((await f.app.applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment(f.ownerId, enrollment.challengeId,
    { confirmation: enrollment.confirmation })).status, "anchored");
  intent.providerIdentity = "https://intent-baseline-chain-rotated-b151.example";
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).status, "drift_detected");
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const rotated = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  assert.equal(rotated.status, "accepted");
  assert.equal(rotated.baseline.revision, 2);
  assert.equal(rotated.externalCheckpoint.status, "anchored");
  assert.equal(rotated.externalCheckpoint.anchorSequence, 2);
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).status, "healthy");
});

test("Batch 151: retention-review decisions use a deterministic replay guard and concurrent applies create one approval", async t => {
  const reviewAnchor = provider("https://retention-review-anchor-b151.example");
  const f = await fixture(t, { reviewAnchor, requireReviewAnchor: true, retentionDays: 1 });
  const { store, id } = await seedOverdueChallenge(f.root, f.ownerId, "expired-review-replay-b151");
  f.advance(3 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [id], decision: "retain",
    reason: "Retain this overdue record while preserving a one-time decision receipt against concurrent replay." });
  const results = await Promise.all([
    f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation })
  ]);
  assert.ok(results.every(result => ["approved_pending_external_checkpoint", "approved"].includes(result.status)));
  const rows = await store.listEvidence(f.ownerId);
  const approvals = rows.filter(row => row.kind === "recovery-slo-cross-domain-retention-review-approval");
  const guards = rows.filter(row => row.kind === "recovery-slo-cross-domain-retention-review-replay-guard");
  assert.equal(approvals.length, 1);
  assert.equal(guards.length, 1);
  assert.equal(guards[0].status, "completed");
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviews(f.ownerId)).status, "external_checkpoint_pending");
  await assert.rejects(() => f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [id], decision: "escalate",
    reason: "A second decision must wait until the first retention-review decision is externally checkpointed." }),
    error => error?.code === "CROSS_DOMAIN_RETENTION_REVIEW_CHECKPOINT_NOT_CURRENT");
  const repeated = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(repeated.idempotent, true);
  assert.equal((await store.listEvidence(f.ownerId)).filter(row => row.kind === "recovery-slo-cross-domain-retention-review-approval").length, 1);
  const enrollment = await f.app.prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the single finalized retention-review decision before accepting further review decisions." });
  assert.equal((await f.app.applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, enrollment.challengeId,
    { confirmation: enrollment.confirmation })).status, "anchored");
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviewCheckpoint(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviews(f.ownerId)).status, "healthy");
});

test("Batch 151: replay-guard tampering makes retention-review audit unhealthy", async t => {
  const f = await fixture(t, { retentionDays: 1 });
  const { store, id } = await seedOverdueChallenge(f.root, f.ownerId, "expired-review-tamper-b151");
  f.advance(3 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [id], decision: "escalate",
    reason: "Escalate this overdue evidence and retain an immutable replay-protected decision receipt." });
  await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  const guard = (await store.listEvidence(f.ownerId)).find(row => row.kind === "recovery-slo-cross-domain-retention-review-replay-guard");
  await store.putEvidence(f.ownerId, { ...guard, decision: "retain" }, { expectedVersion: guard._storage?.version });
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviews(f.ownerId)).status, "unhealthy");
});

test("Batch 151: required external checkpoint providers fail closed and checkpoint APIs/routes are exposed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b151-required-"));
  try {
    assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloCrossDomainSnapshotAuditAnchor: true }),
      /External cross-domain audit-attestation checkpoint diwajibkan/);
    assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloCrossDomainProviderBaselineAnchor: true }),
      /External provider-baseline lifecycle checkpoint diwajibkan/);
    assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloCrossDomainRetentionReviewAnchor: true }),
      /External retention-review decision checkpoint diwajibkan/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
  const f = await fixture(t);
  for (const name of ["getRecoverySloCrossDomainSnapshotAuditCheckpointStatus", "reconcileRecoverySloCrossDomainSnapshotAuditCheckpoint",
    "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "auditRecoverySloCrossDomainSnapshotAuditCheckpoint", "getRecoverySloCrossDomainProviderBaselineCheckpointStatus",
    "reconcileRecoverySloCrossDomainProviderBaselineCheckpoint", "prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment",
    "applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment", "auditRecoverySloCrossDomainProviderBaselineCheckpoint",
    "getRecoverySloCrossDomainRetentionReviewCheckpointStatus", "reconcileRecoverySloCrossDomainRetentionReviewCheckpoint",
    "prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment", "applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment",
    "auditRecoverySloCrossDomainRetentionReviewCheckpoint"]) assert.equal(typeof f.app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["snapshot-checkpoints/audit-attestations/anchor/status", "provider-baselines/checkpoint/status",
    "retention-reviews/checkpoint/status", "enrollment-challenges/:id/apply"]) assert.ok(server.includes(route), route);
});


test("Batch 151: provider-baseline checkpoint refuses same-count history rewrite instead of accepting a false continuity step", async t => {
  const intent = provider("https://intent-baseline-tamper-b151.example"), baselineAnchor = provider("https://baseline-anchor-tamper-b151.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const enrollment = await f.app.prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the provider-baseline lifecycle history before testing continuity enforcement." });
  await f.app.applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const challenge = (await store.listEvidence(f.ownerId)).find(row => row.kind === "recovery-slo-cross-domain-provider-identity-baseline-challenge" && row.status === "completed");
  const altered = { ...challenge, reason: "Rewritten lifecycle reason with a recomputed local digest to simulate a same-count history rewrite." };
  delete altered.digest;
  altered.digest = digestRecord(altered);
  await store.putEvidence(f.ownerId, altered, { expectedVersion: challenge._storage?.version });
  assert.equal((await f.app.getRecoverySloCrossDomainProviderBaselineCheckpointStatus(f.ownerId)).status, "behind_local");
  await assert.rejects(() => f.app.reconcileRecoverySloCrossDomainProviderBaselineCheckpoint(f.ownerId),
    error => error?.code === "CROSS_DOMAIN_PROVIDER_BASELINE_CONTINUITY_UNPROVEN");
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderBaselineCheckpoint(f.ownerId)).status, "external_checkpoint_pending");
});

test("Batch 151: audit-attestation checkpoint rollback makes historical attestation unusable for current decisions", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-anchor-rollback-b151.example");
  const f = await fixture(t, { auditAnchor, signer, keyId: "audit-key-151-rb", publicKeys: { "audit-key-151-rb": pair.publicKey } });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Create a signed audit attestation for external checkpoint rollback enforcement." });
  const enrollment = await f.app.prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the signed audit-attestation history before testing rollback detection." });
  await f.app.applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  auditAnchor.records.clear();
  const verified = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.usableForCurrentDecision, false);
  assert.equal(verified.externalCheckpoint.status, "rollback_suspected");
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAuditCheckpoint(f.ownerId)).status, "unhealthy");
});

test("Batch 151: checkpoint trust domains reject reuse of the same provider instance", t => {
  const root = fs.mkdtemp(path.join(os.tmpdir(), "agentic-b151-provider-collision-"));
  return root.then(async directory => {
    try {
      const shared = provider("https://shared-checkpoint-b151.example");
      assert.throws(() => createAgenticApplication({ storage: createStorage({ root: directory }),
        recoverySloCrossDomainSnapshotAuditAnchor: shared, recoverySloCrossDomainProviderBaselineAnchor: shared }),
        /external anchor provider terpisah/);
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
  });
});
