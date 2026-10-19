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
  return { providerIdentity: identity, baseUrl: identity, records, failWrites: false,
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (this.failWrites) throw Object.assign(new Error("temporary provider outage"), { code: "PROVIDER_TEMPORARY_OUTAGE" });
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b152-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.intentAnchor ?? options.intentAnchor ?? provider("https://intent-default-b152.example"),
    recoverySloRootTrustBaselineProofRevocationAnchor: overrides.revocationAnchor ?? options.revocationAnchor ?? provider("https://revocation-default-b152.example"),
    recoverySloCrossDomainSnapshotAuditAnchor: overrides.auditAnchor ?? options.auditAnchor ?? null,
    requireRecoverySloCrossDomainSnapshotAuditAnchor: overrides.requireAuditAnchor ?? options.requireAuditAnchor ?? false,
    recoverySloCrossDomainProviderBaselineAnchor: overrides.baselineAnchor ?? options.baselineAnchor ?? null,
    requireRecoverySloCrossDomainProviderBaselineAnchor: overrides.requireBaselineAnchor ?? options.requireBaselineAnchor ?? false,
    recoverySloCrossDomainRetentionReviewAnchor: overrides.reviewAnchor ?? options.reviewAnchor ?? null,
    requireRecoverySloCrossDomainRetentionReviewAnchor: overrides.requireReviewAnchor ?? options.requireReviewAnchor ?? false,
    recoverySloCrossDomainSnapshotAnchorMaxAgeMs: overrides.maxAgeMs ?? options.maxAgeMs ?? 86400000,
    recoverySloCrossDomainSnapshotAnchorFutureSkewMs: overrides.futureSkewMs ?? options.futureSkewMs ?? 60000,
    recoverySloCrossDomainSnapshotAnchorRetentionDays: overrides.retentionDays ?? options.retentionDays ?? 90,
    recoverySloCrossDomainSnapshotAuditSigner: overrides.signer ?? options.signer ?? null,
    recoverySloCrossDomainSnapshotAuditKeyId: overrides.keyId ?? options.keyId ?? null,
    recoverySloCrossDomainSnapshotAuditPublicKeys: overrides.publicKeys ?? options.publicKeys ?? null,
    requireRecoverySloCrossDomainSnapshotAuditAttestation: overrides.requireAuditAttestation ?? options.requireAuditAttestation ?? false });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b152", now: clock, advance: ms => { nowMs += ms; } };
}
async function runConformance(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, { domain,
    reason: "Run a disposable provider conformance probe before anchoring lifecycle continuity evidence." });
  return app.runRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function acceptBaseline(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainProviderIdentityBaseline(ownerId, { domain,
    reason: "Accept the latest conformant provider identity as the next replay-resistant baseline revision." });
  return app.applyRecoverySloCrossDomainProviderIdentityBaseline(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function seedOverdueChallenge(root, ownerId, id) {
  const store = createAgenticStore({ storage: createStorage({ root }) });
  const unsigned = { id, ownerId, kind: "retention-decision-gate-recovery-intent-checkpoint-enrollment-challenge", schemaVersion: 1,
    status: "applied", domain: "retention_decision_gate_recovery_intent", createdAt: "2026-10-01T00:00:00.000Z",
    expiresAt: "2026-10-01T00:10:00.000Z", reason: "Historical expired checkpoint enrollment challenge retained for a non-destructive review." };
  await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { overwrite: false });
  return { store, id };
}

 test("Batch 152: audit-attestation checkpoint freshness is enforced and a stale but intact anchor can be refreshed", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-freshness-b152.example");
  const f = await fixture(t, { auditAnchor, signer, keyId: "audit-key-152", publicKeys: { "audit-key-152": pair.publicKey },
    requireAuditAnchor: true, maxAgeMs: 60000 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Create a signed audit attestation to verify freshness enforcement on its external checkpoint." });
  const enrollment = await f.app.prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the verified audit-attestation history before checking checkpoint freshness." });
  await f.app.applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal((await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId)).usableForCurrentDecision, true);
  f.advance(60001);
  const stale = await f.app.getRecoverySloCrossDomainSnapshotAuditCheckpointStatus(f.ownerId);
  assert.equal(stale.status, "anchored");
  assert.equal(stale.freshnessStatus, "stale");
  const historical = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId);
  assert.equal(historical.historicallyValid, true);
  assert.equal(historical.usableForCurrentDecision, false);
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAuditAttestations(f.ownerId)).status, "external_checkpoint_pending");
  const refreshed = await f.app.reconcileRecoverySloCrossDomainSnapshotAuditCheckpoint(f.ownerId);
  assert.equal(refreshed.status, "anchored");
  assert.equal(refreshed.refreshed, true);
  assert.equal(refreshed.anchorSequence, 2);
  const current = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId);
  assert.equal(current.historicallyValid, true);
  assert.equal(current.usableForCurrentDecision, true);
});

test("Batch 152: overdue audit attestation requires a retained review decision and its external checkpoint", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-retention-b152.example"), reviewAnchor = provider("https://review-retention-b152.example");
  const f = await fixture(t, { auditAnchor, reviewAnchor, signer, keyId: "audit-key-152-retention", publicKeys: { "audit-key-152-retention": pair.publicKey },
    requireAuditAnchor: true, requireReviewAnchor: true, maxAgeMs: 30 * 86400000, retentionDays: 1 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Create a signed attestation to exercise explicit retention review before trusted reuse." });
  const enrollment = await f.app.prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the audit attestation before evaluating its retention policy." });
  await f.app.applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  f.advance(3 * 86400000);
  const overdue = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId);
  assert.equal(overdue.historicallyValid, true);
  assert.equal(overdue.retentionStatus, "retention_overdue_review");
  assert.equal(overdue.usableForCurrentDecision, false);
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAuditAttestations(f.ownerId)).status, "retention_review_required");
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [created.attestation.attestationId], decision: "retain",
    reason: "Retain this audit attestation after an explicit policy review and preserve the approval evidence." });
  const approved = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(approved.status, "approved_pending_external_checkpoint");
  const stillPending = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId);
  assert.equal(stillPending.usableForCurrentDecision, false);
  const reviewEnrollment = await f.app.prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the retention-review decision before allowing the reviewed attestation to be used again." });
  assert.equal((await f.app.applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, reviewEnrollment.challengeId,
    { confirmation: reviewEnrollment.confirmation })).status, "anchored");
  const retained = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId);
  assert.equal(retained.retentionStatus, "retention_reviewed_retain");
  assert.equal(retained.usableForCurrentDecision, true);
});

test("Batch 152: provider baseline transitions carry digest-linked receipts and reject receipt tampering", async t => {
  const intent = provider("https://intent-receipts-b152.example");
  const f = await fixture(t, { intentAnchor: intent });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const first = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  assert.equal(first.status, "accepted");
  assert.ok(first.transitionReceipt);
  assert.equal(first.transitionReceipt.revision, 1);
  assert.equal(first.transitionReceipt.previousReceiptDigest, null);
  assert.equal(first.transitionReceipt.historyNotProven, true);
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).status, "healthy");
  intent.providerIdentity = "https://intent-receipts-rotated-b152.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const second = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  assert.equal(second.transitionReceipt.revision, 2);
  assert.equal(second.transitionReceipt.previousReceiptDigest, first.transitionReceipt.digest);
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).transitionReceiptCount, 2);
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const receipt = await store.getEvidence(f.ownerId, first.transitionReceipt.id);
  const altered = { ...receipt, issuedAt: "2026-10-12T00:01:00.000Z" };
  delete altered.digest;
  altered.digest = digestRecord(altered);
  await store.putEvidence(f.ownerId, altered, { expectedVersion: receipt._storage?.version });
  const audit = await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code.includes("TRANSITION_RECEIPT")));
});

test("Batch 152: retention-review external reconciliation advances only one provable approval after a provider outage", async t => {
  const reviewAnchor = provider("https://review-reconcile-b152.example");
  const f = await fixture(t, { reviewAnchor, requireReviewAnchor: true, maxAgeMs: 30 * 86400000, retentionDays: 1 });
  const { id: firstId } = await seedOverdueChallenge(f.root, f.ownerId, "overdue-review-first-b152");
  f.advance(3 * 86400000);
  const firstChallenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [firstId], decision: "retain",
    reason: "Retain the first overdue record and anchor its one-time decision before the next review." });
  const firstResult = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, firstChallenge.challengeId,
    { confirmation: firstChallenge.confirmation });
  assert.equal(firstResult.status, "approved_pending_external_checkpoint");
  const enrollment = await f.app.prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the first finalized decision before accepting another retention review." });
  await f.app.applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  const { id: secondId } = await seedOverdueChallenge(f.root, f.ownerId, "overdue-review-second-b152");
  const secondChallenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [secondId], decision: "escalate",
    reason: "Escalate the second overdue record and require external reconciliation of the exact new decision." });
  reviewAnchor.failWrites = true;
  const pending = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, secondChallenge.challengeId,
    { confirmation: secondChallenge.confirmation });
  assert.equal(pending.status, "approved_pending_external_checkpoint");
  assert.equal((await f.app.getRecoverySloCrossDomainRetentionReviewCheckpointStatus(f.ownerId)).status, "behind_local");
  reviewAnchor.failWrites = false;
  const reconciled = await f.app.reconcileRecoverySloCrossDomainRetentionReviewCheckpoint(f.ownerId);
  assert.equal(reconciled.status, "anchored");
  assert.equal(reconciled.anchorSequence, 2);
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviews(f.ownerId)).status, "healthy");
  const { id: thirdId } = await seedOverdueChallenge(f.root, f.ownerId, "overdue-review-third-b152");
  const thirdChallenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [thirdId], decision: "retain",
    reason: "Ensure the next decision is allowed only after the second decision checkpoint is current." });
  assert.ok(thirdChallenge.challengeId);
});

test("Batch 152: retention-review reconciliation refuses multi-decision jumps and same-count rewrites", async t => {
  const reviewAnchor = provider("https://review-continuity-b152.example");
  const f = await fixture(t, { reviewAnchor, requireReviewAnchor: true, maxAgeMs: 30 * 86400000, retentionDays: 1 });
  const { id } = await seedOverdueChallenge(f.root, f.ownerId, "overdue-review-tamper-b152");
  f.advance(3 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [id], decision: "retain",
    reason: "Anchor a single review decision before verifying tamper-resistant reconciliation." });
  await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  const enrollment = await f.app.prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the single decision so subsequent changes require continuity proof." });
  await f.app.applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const approval = (await store.listEvidence(f.ownerId)).find(row => row.kind === "recovery-slo-cross-domain-retention-review-approval");
  const altered = { ...approval, reason: "Rewritten review reason with recomputed local digest to simulate same-count history mutation." };
  delete altered.digest;
  altered.digest = digestRecord(altered);
  await store.putEvidence(f.ownerId, altered, { expectedVersion: approval._storage?.version });
  await assert.rejects(() => f.app.reconcileRecoverySloCrossDomainRetentionReviewCheckpoint(f.ownerId), error =>
    ["EXTERNAL_SNAPSHOT_CHECKPOINT_RECONCILIATION_BLOCKED", "CROSS_DOMAIN_RETENTION_REVIEW_CONTINUITY_UNPROVEN"].includes(error?.code));
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviewCheckpoint(f.ownerId)).status, "unhealthy");
});

test("Batch 152: excessive future checkpoint timestamps are untrusted and cannot be refreshed over", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-future-skew-b152.example");
  const f = await fixture(t, { auditAnchor, signer, keyId: "audit-key-152-future", publicKeys: { "audit-key-152-future": pair.publicKey },
    requireAuditAnchor: true, maxAgeMs: 60000, futureSkewMs: 60000 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Create a signed attestation before checking strict future timestamp skew enforcement." });
  const enrollment = await f.app.prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, {
    reason: "Enroll the audit history before simulating a local clock that trails the checkpoint." });
  await f.app.applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  f.advance(-120001);
  const status = await f.app.getRecoverySloCrossDomainSnapshotAuditCheckpointStatus(f.ownerId);
  assert.equal(status.freshnessStatus, "future_skew_exceeded");
  assert.equal(status.usableForCurrentDecision, false);
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAuditAttestations(f.ownerId)).status, "unhealthy");
  assert.equal((await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId)).usableForCurrentDecision, false);
  await assert.rejects(() => f.app.reconcileRecoverySloCrossDomainSnapshotAuditCheckpoint(f.ownerId), error =>
    error?.code === "CROSS_DOMAIN_AUDIT_CHECKPOINT_FRESHNESS_UNTRUSTED");
});

test("Batch 152: transition-receipt audit API and authenticated HTTP route are exposed", async t => {
  const f = await fixture(t);
  assert.equal(typeof f.app.auditRecoverySloCrossDomainProviderBaselineTransitionReceipts, "function");
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderBaselineTransitionReceipts(f.ownerId)).status, "not_initialized");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("provider-baselines/transition-receipts/audit"));
  assert.ok(server.includes("application.auditRecoverySloCrossDomainProviderBaselineTransitionReceipts(q.agentic.user.id)"));
});

test("Batch 152: replaying a legacy baseline transition without a receipt stays idempotent and marks history unproven", async t => {
  const intent = provider("https://intent-legacy-receipt-b152.example");
  const f = await fixture(t, { intentAnchor: intent });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const accepted = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const challenge = (await store.listEvidence(f.ownerId)).find(row => row.kind === "recovery-slo-cross-domain-provider-identity-baseline-challenge"
    && row.id === accepted.baseline.sourceChallengeId);
  const receipt = await store.getEvidence(f.ownerId, accepted.transitionReceipt.id);
  assert.ok(challenge && receipt);
  await store.state.delete("evidence", `${f.ownerId}--${receipt.id}`);
  const legacy = { ...challenge };
  delete legacy.transitionReceiptId;
  delete legacy.transitionReceiptDigest;
  delete legacy.preparedChallengeDigest;
  delete legacy.digest;
  legacy.digest = digestRecord(legacy);
  await store.putEvidence(f.ownerId, legacy, { expectedVersion: challenge._storage?.version });
  const replayed = await f.app.applyRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, challenge.id, { confirmation: "legacy-replay" });
  assert.equal(replayed.idempotent, true);
  assert.equal(replayed.legacyTransitionReceiptMissing, true);
  assert.equal(replayed.historyNotProven, true);
  assert.equal(replayed.baseline.digest, accepted.baseline.digest);
});
