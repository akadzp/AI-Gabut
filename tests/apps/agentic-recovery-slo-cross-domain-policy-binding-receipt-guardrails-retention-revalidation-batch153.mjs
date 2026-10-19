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
        || candidate.revision !== (current ? current.revision + 1 : 1) || candidate.previousAnchorDigest !== (current?.digest ?? null))
        throw Object.assign(new Error("anchor contract violation"), { code: "ANCHOR_CONTRACT_VIOLATION" });
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b153-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.intentAnchor ?? options.intentAnchor ?? provider("https://intent-default-b153.example"),
    recoverySloRootTrustBaselineProofRevocationAnchor: overrides.revocationAnchor ?? options.revocationAnchor ?? provider("https://revocation-default-b153.example"),
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
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b153", now: clock, advance: ms => { nowMs += ms; } };
}
async function runConformance(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, { domain,
    reason: "Run an isolated conformance probe before binding the checkpoint policy to the external trust anchor." });
  return app.runRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function acceptBaseline(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainProviderIdentityBaseline(ownerId, { domain,
    reason: "Accept the latest conformant provider identity as the next replay-resistant baseline revision." });
  return app.applyRecoverySloCrossDomainProviderIdentityBaseline(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function enrollCheckpoint(app, ownerId, prepareName, applyName, reason) {
  const challenge = await app[prepareName](ownerId, { reason });
  return app[applyName](ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}

 test("Batch 153: checkpoint freshness policy digest is anchored and policy drift requires explicit challenge binding", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-policy-b153.example");
  const f = await fixture(t, { auditAnchor, requireAuditAnchor: true, signer, keyId: "audit-policy-b153", publicKeys: { "audit-policy-b153": pair.publicKey }, maxAgeMs: 60000, retentionDays: 90 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Create a signed audit attestation before binding its checkpoint to the active freshness policy." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the audit checkpoint with its initial freshness policy digest.");
  let status = await f.app.getRecoverySloCrossDomainSnapshotAuditCheckpointStatus(f.ownerId);
  assert.equal(status.status, "anchored");
  assert.equal(status.policyBindingStatus, "current");
  assert.match(status.anchoredPolicyDigest, /^[a-f0-9]{64}$/);
  assert.equal((await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId)).usableForCurrentDecision, true);

  const changed = f.build({ maxAgeMs: 120000 });
  status = await changed.getRecoverySloCrossDomainSnapshotAuditCheckpointStatus(f.ownerId);
  assert.equal(status.status, "policy_drift");
  assert.equal(status.freshnessStatus, "policy_drift");
  assert.equal(status.usableForCurrentDecision, false);
  await assert.rejects(() => changed.reconcileRecoverySloCrossDomainSnapshotAuditCheckpoint(f.ownerId), error =>
    error?.code === "EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_DRIFT");
  const challenge = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId,
    "cross_domain_snapshot_audit_attestation", { reason: "Approve the updated freshness limits after reviewing their operational effect." });
  assert.equal(challenge.previousPolicyDigest, status.anchoredPolicyDigest);
  const applied = await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId,
    "cross_domain_snapshot_audit_attestation", challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(applied.status, "anchored");
  assert.equal(applied.anchorSequence, status.anchorSequence + 1);
  status = await changed.getRecoverySloCrossDomainSnapshotAuditCheckpointStatus(f.ownerId);
  assert.equal(status.status, "anchored");
  assert.equal(status.policyBindingStatus, "current");
  assert.notEqual(status.anchoredPolicyDigest, challenge.previousPolicyDigest);
  const replayed = await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId,
    "cross_domain_snapshot_audit_attestation", challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(replayed.idempotent, true);
});

test("Batch 153: policy binding challenge becomes stale when the source snapshot changes", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-policy-stale-b153.example");
  const f = await fixture(t, { auditAnchor, requireAuditAnchor: true, signer, keyId: "audit-policy-stale-b153",
    publicKeys: { "audit-policy-stale-b153": pair.publicKey }, maxAgeMs: 60000 });
  await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Create a signed attestation before testing policy challenge source snapshot binding." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the source snapshot before preparing a policy rebinding challenge.");
  const changed = f.build({ maxAgeMs: 120000 });
  const challenge = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId,
    "cross_domain_snapshot_audit_attestation", { reason: "Prepare a policy rebinding challenge bound to the current source snapshot." });
  await changed.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Add another signed audit record to invalidate the previous policy binding challenge snapshot." });
  await assert.rejects(() => changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId,
    "cross_domain_snapshot_audit_attestation", challenge.challengeId, { confirmation: challenge.confirmation }), error =>
    ["EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_CHALLENGE_STALE", "EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_CONTINUITY_UNPROVEN"].includes(error?.code));
});

test("Batch 153: provider baseline receipt compaction guardrails require healthy receipts and an aligned external checkpoint", async t => {
  const intent = provider("https://intent-baseline-guard-b153.example");
  const baselineAnchor = provider("https://baseline-guard-b153.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const first = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  assert.equal(first.status, "accepted_pending_external_checkpoint");
  let guardrails = await f.app.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails(f.ownerId);
  assert.equal(guardrails.compactionEligible, false);
  assert.ok(guardrails.blockers.includes("external_checkpoint_not_current"));
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment",
    "applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment", "Enroll the first baseline receipt chain before considering compaction.");
  intent.providerIdentity = "https://intent-baseline-guard-rotated-b153.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const second = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  assert.equal(second.status, "accepted");
  guardrails = await f.app.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails(f.ownerId);
  assert.equal(guardrails.status, "eligible");
  assert.equal(guardrails.compactionEligible, true);
  assert.equal(guardrails.compactionPerformed, false);
  assert.equal(guardrails.automaticCompactionAllowed, false);
  assert.ok(guardrails.requiredPreservations.includes("historyNotProven flags"));
  const changed = f.build({ maxAgeMs: 120000 });
  const drift = await changed.getRecoverySloCrossDomainProviderBaselineCheckpointStatus(f.ownerId);
  assert.equal(drift.status, "policy_drift");
  guardrails = await changed.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails(f.ownerId);
  assert.equal(guardrails.compactionEligible, false);
  assert.ok(guardrails.blockers.includes("external_checkpoint_not_current"));
  const policyChallenge = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId,
    "cross_domain_provider_baseline", { reason: "Approve the updated checkpoint freshness policy for the baseline receipt chain." });
  await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_provider_baseline",
    policyChallenge.challengeId, { confirmation: policyChallenge.confirmation });
  guardrails = await changed.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails(f.ownerId);
  assert.equal(guardrails.compactionEligible, true);
});

test("Batch 153: pending baseline transition exposes receipt recovery and blocks compaction", async t => {
  const intent = provider("https://intent-recovery-b153.example");
  const baselineAnchor = provider("https://baseline-recovery-b153.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const accepted = await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment",
    "applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment", "Enroll the baseline receipt chain before simulating interrupted finalization.");
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const challenge = await store.getEvidence(f.ownerId, accepted.baseline.sourceChallengeId);
  const receipt = await store.getEvidence(f.ownerId, accepted.transitionReceipt.id);
  const prepared = { ...challenge, status: "prepared" };
  delete prepared.digest; prepared.digest = digestRecord(prepared);
  await store.putEvidence(f.ownerId, prepared, { expectedVersion: challenge._storage?.version });
  const guardrails = await f.app.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails(f.ownerId);
  assert.equal(guardrails.compactionEligible, false);
  assert.ok(guardrails.blockers.includes("pending_transition_requires_recovery"));
  assert.ok(guardrails.recoveryCandidates.some(item => item.challengeId === prepared.id && item.receiptId === receipt.id && item.recoveryAllowed));
});

async function seedOverdueChallenge(root, ownerId, id) {
  const store = createAgenticStore({ storage: createStorage({ root }) });
  const unsigned = { id, ownerId, kind: "retention-decision-gate-recovery-intent-checkpoint-enrollment-challenge", schemaVersion: 1,
    status: "applied", domain: "retention_decision_gate_recovery_intent", createdAt: "2026-10-01T00:00:00.000Z",
    expiresAt: "2026-10-01T00:10:00.000Z", reason: "Historical expired checkpoint enrollment challenge retained for a non-destructive review." };
  await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { overwrite: false });
  return { store, id };
}

test("Batch 153: retention decision revalidation requires current targets, replay proof, and the external checkpoint", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-retention-revalidate-b153.example");
  const reviewAnchor = provider("https://review-retention-revalidate-b153.example");
  const f = await fixture(t, { auditAnchor, reviewAnchor, requireAuditAnchor: true, requireReviewAnchor: true, signer,
    keyId: "audit-retention-revalidate-b153", publicKeys: { "audit-retention-revalidate-b153": pair.publicKey }, maxAgeMs: 30 * 86400000, retentionDays: 1 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Create a signed attestation to exercise decision revalidation after an explicit retention review." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the audit attestation source before testing review evidence revalidation.");
  f.advance(3 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [created.attestation.attestationId], decision: "retain",
    reason: "Retain the overdue attestation only after revalidating its digest and replay-protected approval." });
  const approvalResult = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(approvalResult.status, "approved_pending_external_checkpoint");
  const pendingValidation = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, approvalResult.approval.id);
  assert.equal(pendingValidation.usableForCurrentDecision, false);
  assert.equal(pendingValidation.status, "external_checkpoint_pending");
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment",
    "applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment", "Enroll the retention approval before allowing reviewed evidence to be used.");
  const approval = approvalResult.approval;
  const valid = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, approval.id);
  assert.equal(valid.status, "current");
  assert.equal(valid.historicallyValid, true);
  assert.equal(valid.replayProtected, true);
  assert.equal(valid.targetsCurrent, true);
  assert.equal(valid.usableForCurrentDecision, true);
  const changedPolicy = f.build({ retentionDays: 2 });
  const policyPending = await changedPolicy.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, approval.id);
  assert.equal(policyPending.usableForCurrentDecision, false);
  assert.equal(policyPending.status, "external_checkpoint_pending");
  const policyChallenge = await changedPolicy.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId,
    "cross_domain_retention_review", { reason: "Approve the revised retention-review checkpoint policy after checking the policy diff." });
  await changedPolicy.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_retention_review",
    policyChallenge.challengeId, { confirmation: policyChallenge.confirmation });
  assert.equal((await changedPolicy.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, approval.id)).usableForCurrentDecision, true);

  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const record = await store.getEvidence(f.ownerId, created.attestation.attestationId);
  const altered = { ...record, reason: "Changed source record after approval to prove revalidation refuses stale target evidence." };
  delete altered.digest; altered.digest = digestRecord(altered);
  await store.putEvidence(f.ownerId, altered, { expectedVersion: record._storage?.version });
  const stale = await changedPolicy.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, approval.id);
  assert.equal(stale.usableForCurrentDecision, false);
  assert.equal(stale.targetsCurrent, false);
  assert.ok(stale.findings.some(item => item.code === "CROSS_DOMAIN_RETENTION_TARGET_EVIDENCE_STALE"));
});

test("Batch 153: policy-binding, receipt guardrail, and retention revalidation APIs are exposed", async t => {
  const f = await fixture(t);
  assert.equal(typeof f.app.prepareRecoverySloCrossDomainCheckpointPolicyBinding, "function");
  assert.equal(typeof f.app.applyRecoverySloCrossDomainCheckpointPolicyBinding, "function");
  assert.equal(typeof f.app.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails, "function");
  assert.equal(typeof f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision, "function");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("checkpoints/:domain/policy-binding/challenges"));
  assert.ok(server.includes("provider-baselines/transition-receipts/compaction-guardrails"));
  assert.ok(server.includes("retention-reviews/:id/revalidate"));
});
