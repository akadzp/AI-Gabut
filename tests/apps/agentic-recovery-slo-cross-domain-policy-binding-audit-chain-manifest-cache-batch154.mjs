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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b154-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.intentAnchor ?? options.intentAnchor ?? provider("https://intent-default-b154.example"),
    recoverySloRootTrustBaselineProofRevocationAnchor: overrides.revocationAnchor ?? options.revocationAnchor ?? provider("https://revocation-default-b154.example"),
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
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b154", now: clock, advance: ms => { nowMs += ms; } };
}
async function enrollCheckpoint(app, ownerId, prepareName, applyName, reason) {
  const challenge = await app[prepareName](ownerId, { reason });
  return app[applyName](ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function runConformance(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, { domain,
    reason: "Run a disposable provider conformance probe before accepting a new identity baseline." });
  return app.runRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function acceptBaseline(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainProviderIdentityBaseline(ownerId, { domain,
    reason: "Accept a freshly conformant provider identity as a replay-resistant baseline transition." });
  return app.applyRecoverySloCrossDomainProviderIdentityBaseline(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}

 test("Batch 154: policy-binding approvals produce a verifiable per-domain audit chain", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const anchor = provider("https://audit-policy-chain-b154.example");
  const f = await fixture(t, { auditAnchor: anchor, requireAuditAnchor: true, signer, keyId: "audit-policy-chain-b154",
    publicKeys: { "audit-policy-chain-b154": pair.publicKey }, maxAgeMs: 60000 });
  await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, { reason: "Create a signed audit record before the explicit policy-binding transition." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the original policy-bound checkpoint before testing its approval chain.");
  const changed = f.build({ maxAgeMs: 120000 });
  const challenge = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation",
    { reason: "Approve the changed freshness policy after reviewing the checkpoint continuity and policy diff." });
  await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation", challenge.challengeId,
    { confirmation: challenge.confirmation });
  const audit = await changed.auditRecoverySloCrossDomainCheckpointPolicyBindingApprovalChain(f.ownerId);
  assert.equal(audit.status, "healthy");
  const domain = audit.domains.find(item => item.domain === "cross_domain_snapshot_audit_attestation");
  assert.equal(domain.eventCount, 1);
  assert.equal(domain.eventHead.sequence, 1);
  assert.equal(domain.historyNotProven, false);
  assert.equal(domain.findings.length, 0);
});

test("Batch 154: policy-binding event tampering is detected and cannot be treated as trusted history", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const anchor = provider("https://audit-policy-tamper-b154.example");
  const f = await fixture(t, { auditAnchor: anchor, requireAuditAnchor: true, signer, keyId: "audit-policy-tamper-b154",
    publicKeys: { "audit-policy-tamper-b154": pair.publicKey }, maxAgeMs: 60000 });
  await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, { reason: "Create a signed audit record before tamper detection is exercised." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the original checkpoint before the policy-binding event is created.");
  const changed = f.build({ maxAgeMs: 120000 });
  const challenge = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation",
    { reason: "Approve a revised checkpoint freshness policy with a bound audit event." });
  await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation", challenge.challengeId,
    { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const rows = await store.listEvidence(f.ownerId);
  const event = rows.find(row => row.ownerId === f.ownerId && row.kind === "cross-domain-snapshot-audit-attestation-checkpoint-policy-binding-event");
  assert.ok(event);
  const altered = { ...event, reason: "tampered policy approval event" };
  delete altered.digest; altered.digest = digestRecord(altered);
  await store.putEvidence(f.ownerId, altered, { expectedVersion: event._storage?.version });
  const audit = await changed.auditRecoverySloCrossDomainCheckpointPolicyBindingApprovalChain(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_EVENT_CHALLENGE_MISMATCH"));
});

test("Batch 154: legacy policy-binding approvals without events remain explicitly history-unproven", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const f = await fixture(t, { signer, keyId: "audit-policy-legacy-b154", publicKeys: { "audit-policy-legacy-b154": pair.publicKey } });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const unsigned = { id: "legacy-policy-binding-challenge-b154", ownerId: f.ownerId,
    kind: "cross-domain-snapshot-audit-attestation-checkpoint-policy-binding-challenge", schemaVersion: 1,
    status: "applied", domain: "cross_domain_snapshot_audit_attestation", expectedAnchorDigest: "a".repeat(64),
    expectedAnchorSequence: 1, expectedSourceDigest: "b".repeat(64), expectedSourceCount: 1,
    previousPolicyDigest: null, targetPolicyDigest: "c".repeat(64), reason: "Historical policy approval created before audit-chain events were introduced.",
    createdAt: "2026-10-01T00:00:00.000Z", expiresAt: "2026-10-01T00:10:00.000Z", appliedAt: "2026-10-01T00:01:00.000Z",
    resultAnchorDigest: "d".repeat(64) };
  await store.putEvidence(f.ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { overwrite: false });
  const audit = await f.app.auditRecoverySloCrossDomainCheckpointPolicyBindingApprovalChain(f.ownerId);
  assert.equal(audit.status, "history_unproven");
  assert.ok(audit.findings.some(item => item.code === "EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_HISTORY_UNPROVEN"));
});

test("Batch 154: baseline receipt compaction manifest preserves heads, sequence ranges, and unproven-history flags without compacting", async t => {
  const intent = provider("https://intent-manifest-b154.example"), baselineAnchor = provider("https://baseline-manifest-b154.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment",
    "applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment", "Enroll the baseline receipt chain before creating a manifest draft.");
  intent.providerIdentity = "https://intent-manifest-rotated-b154.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const guardrails = await f.app.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails(f.ownerId);
  assert.equal(guardrails.compactionEligible, true);
  const created = await f.app.createRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest(f.ownerId);
  assert.equal(created.status, "ready_for_review");
  assert.equal(created.manifest.compactionPerformed, false);
  assert.equal(created.manifest.automaticCompactionAllowed, false);
  assert.equal(created.manifest.receiptCount, 2);
  assert.ok(created.manifest.receiptHeads.retention_decision_gate_recovery_intent);
  assert.ok(created.manifest.sequenceRanges.retention_decision_gate_recovery_intent);
  assert.ok(Array.isArray(created.manifest.historyNotProvenDomains));
  const verified = await f.app.verifyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest(f.ownerId, created.manifest.id);
  assert.equal(verified.valid, true);
  assert.equal(verified.current, true);
  assert.equal(verified.compactionPerformed, false);
});

test("Batch 154: receipt compaction manifest becomes stale when source receipts or checkpoint change", async t => {
  const intent = provider("https://intent-manifest-stale-b154.example"), baselineAnchor = provider("https://baseline-manifest-stale-b154.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment",
    "applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment", "Enroll the baseline receipt chain before testing manifest invalidation.");
  intent.providerIdentity = "https://intent-manifest-stale-rotated-b154.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const created = await f.app.createRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest(f.ownerId);
  assert.equal(created.status, "ready_for_review");
  intent.providerIdentity = "https://intent-manifest-stale-rotated-again-b154.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const verified = await f.app.verifyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest(f.ownerId, created.manifest.id);
  assert.equal(verified.valid, true);
  assert.equal(verified.current, false);
  assert.ok(verified.findings.some(item => item.code === "CROSS_DOMAIN_RECEIPT_MANIFEST_SOURCE_CHANGED"));
});

test("Batch 154: retention decision revalidation cache hits only while evidence, checkpoint, and policy fingerprint remain stable", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-cache-b154.example"), reviewAnchor = provider("https://review-cache-b154.example");
  const f = await fixture(t, { auditAnchor, reviewAnchor, requireAuditAnchor: true, requireReviewAnchor: true, signer,
    keyId: "audit-cache-b154", publicKeys: { "audit-cache-b154": pair.publicKey }, maxAgeMs: 30 * 86400000, retentionDays: 1 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId,
    { reason: "Create a signed audit record before measuring decision-cache invalidation." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the audit checkpoint before preparing a retention review.");
  f.advance(3 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [created.attestation.attestationId], decision: "retain",
    reason: "Retain the overdue attestation only after validating its target digest and replay guard." });
  const applied = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment",
    "applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment", "Enroll the review decision checkpoint before caching a current result.");
  const first = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(first.usableForCurrentDecision, true);
  assert.equal(first.cacheHit, false);
  const second = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(second.usableForCurrentDecision, true);
  assert.equal(second.cacheHit, true);
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const target = await store.getEvidence(f.ownerId, created.attestation.attestationId);
  const altered = { ...target, reason: "The target changed after the prior decision cache entry was computed." };
  delete altered.digest; altered.digest = digestRecord(altered);
  await store.putEvidence(f.ownerId, altered, { expectedVersion: target._storage?.version });
  const third = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(third.cacheHit, false);
  assert.equal(third.usableForCurrentDecision, false);
  assert.equal(third.targetsCurrent, false);
  const cacheAudit = await f.app.auditRecoverySloCrossDomainRetentionDecisionRevalidationCache(f.ownerId);
  assert.ok(cacheAudit.stats.invalidations >= 1);
});

test("Batch 154: new governance hardening APIs and routes are exposed", async t => {
  const f = await fixture(t);
  assert.equal(typeof f.app.auditRecoverySloCrossDomainCheckpointPolicyBindingApprovalChain, "function");
  assert.equal(typeof f.app.createRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest, "function");
  assert.equal(typeof f.app.verifyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest, "function");
  assert.equal(typeof f.app.auditRecoverySloCrossDomainRetentionDecisionRevalidationCache, "function");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("cross-domain/checkpoints/policy-binding/audit-chain"));
  assert.ok(server.includes("provider-baselines/transition-receipts/compaction-manifests"));
  assert.ok(server.includes("retention-reviews/revalidation-cache"));
});

test("Batch 154: revalidation cache is invalidated when the external checkpoint and policy binding advance", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-cache-policy-b154.example"), reviewAnchor = provider("https://review-cache-policy-b154.example");
  const f = await fixture(t, { auditAnchor, reviewAnchor, requireAuditAnchor: true, requireReviewAnchor: true, signer,
    keyId: "audit-cache-policy-b154", publicKeys: { "audit-cache-policy-b154": pair.publicKey }, maxAgeMs: 20 * 86400000, retentionDays: 1 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId,
    { reason: "Create a signed audit record before testing cache invalidation from checkpoint policy rotation." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the audit checkpoint before preparing the policy-cache test.");
  f.advance(3 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [created.attestation.attestationId], decision: "retain",
    reason: "Retain the overdue attestation only after validating its target and replay protection." });
  const applied = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment",
    "applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment", "Enroll the retention decision checkpoint before caching the current decision.");
  const first = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(first.usableForCurrentDecision, true);
  const second = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(second.cacheHit, true);
  const changedPolicyApp = f.build({ maxAgeMs: 25 * 86400000 });
  const binding = await changedPolicyApp.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_retention_review",
    { reason: "Approve the new checkpoint freshness policy after reviewing the changed age limit." });
  await changedPolicyApp.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_retention_review", binding.challengeId,
    { confirmation: binding.confirmation });
  const after = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(after.cacheHit, false);
  assert.equal(after.usableForCurrentDecision, false);
  assert.equal(after.status, "external_checkpoint_pending");
  const cacheAudit = await f.app.auditRecoverySloCrossDomainRetentionDecisionRevalidationCache(f.ownerId);
  assert.ok(cacheAudit.stats.invalidations >= 1);
});
