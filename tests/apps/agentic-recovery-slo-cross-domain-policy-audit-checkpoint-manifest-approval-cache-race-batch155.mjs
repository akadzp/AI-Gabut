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
    async read(ownerId) { if (typeof this.onRead === "function") await this.onRead(ownerId); return structuredClone(records.get(ownerId) ?? null); },
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b155-"));
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
    requireRecoverySloCrossDomainSnapshotAuditAttestation: overrides.requireAuditAttestation ?? options.requireAuditAttestation ?? false,
    recoverySloCrossDomainPolicyBindingAuditAnchor: overrides.policyAuditAnchor ?? options.policyAuditAnchor ?? null,
    requireRecoverySloCrossDomainPolicyBindingAuditAnchor: overrides.requirePolicyAuditAnchor ?? options.requirePolicyAuditAnchor ?? false });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b155", now: clock, advance: ms => { nowMs += ms; } };
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


test("Batch 155: policy-binding audit chain is externally checkpointed and advances only one provable event", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-domain-b155.example"), chainAnchor = provider("https://policy-chain-b155.example");
  const f = await fixture(t, { auditAnchor, policyAuditAnchor: chainAnchor, requireAuditAnchor: true, requirePolicyAuditAnchor: true,
    signer, keyId: "audit-chain-b155", publicKeys: { "audit-chain-b155": pair.publicKey }, maxAgeMs: 60000 });
  const attestation = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId,
    { reason: "Create signed evidence before exercising external policy-chain anchoring." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the audit-attestation checkpoint before changing its policy.");
  const changed = f.build({ maxAgeMs: 120000 });
  const challenge = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation",
    { reason: "Approve a policy change and verify its audit event is externally anchored." });
  const applied = await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation", challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(applied.status, "policy_binding_audit_checkpoint_pending");
  assert.equal(applied.usableForCurrentDecision, false);
  const enrollment = await changed.prepareRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment(f.ownerId,
    { reason: "Explicitly enroll the complete current policy-binding audit chain." });
  const enrolled = await changed.applyRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment(f.ownerId, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  let state = await changed.getRecoverySloCrossDomainPolicyBindingAuditCheckpointStatus(f.ownerId);
  assert.equal(state.status, "anchored");
  assert.equal(state.anchorSequence, 1);
  assert.equal(state.historyNotProven, true);
  const changedAgain = f.build({ maxAgeMs: 120000, futureSkewMs: 120000 });
  const secondChallenge = await changedAgain.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation",
    { reason: "Approve a second policy change after validating the previous anchor." });
  const secondApplied = await changedAgain.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation", secondChallenge.challengeId,
    { confirmation: secondChallenge.confirmation });
  assert.equal(secondApplied.policyBindingAuditCheckpoint.status, "anchored");
  state = await changedAgain.getRecoverySloCrossDomainPolicyBindingAuditCheckpointStatus(f.ownerId);
  assert.equal(state.status, "anchored");
  assert.equal(state.anchorSequence, 2);
  const audit = await changedAgain.auditRecoverySloCrossDomainPolicyBindingAuditCheckpoint(f.ownerId);
  assert.equal(audit.status, "history_unproven");
  assert.equal(attestation.status, "signed_pending_external_checkpoint");
});

test("Batch 155: policy-binding audit checkpoint advances monotonically after a single provable event", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-jump-b155.example"), chainAnchor = provider("https://policy-chain-jump-b155.example");
  const f = await fixture(t, { auditAnchor, policyAuditAnchor: chainAnchor, requireAuditAnchor: true, requirePolicyAuditAnchor: true,
    signer, keyId: "audit-jump-b155", publicKeys: { "audit-jump-b155": pair.publicKey }, maxAgeMs: 60000 });
  await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId,
    { reason: "Create signed evidence before testing checkpoint continuity boundaries." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the source checkpoint before the first policy transition.");
  const changed = f.build({ maxAgeMs: 120000 });
  const first = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation",
    { reason: "Approve a first policy transition before external audit-chain enrollment." });
  await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation", first.challengeId,
    { confirmation: first.confirmation });
  const enrollment = await changed.prepareRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment(f.ownerId,
    { reason: "Enroll the first valid policy-binding audit event." });
  await changed.applyRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment(f.ownerId, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const next = f.build({ maxAgeMs: 180000 });
  const second = await next.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation",
    { reason: "Approve the second transition and verify monotonic checkpoint advancement." });
  await next.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation", second.challengeId,
    { confirmation: second.confirmation });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const rows = await store.listEvidence(f.ownerId);
  const events = rows.filter(row => row.ownerId === f.ownerId && row.kind.endsWith("-policy-binding-event"));
  assert.equal(events.length, 2);
  const status = await next.getRecoverySloCrossDomainPolicyBindingAuditCheckpointStatus(f.ownerId);
  assert.equal(status.status, "anchored");
  assert.equal(status.anchorSequence, 2);
});

test("Batch 155: external policy-binding audit checkpoint detects tampering in a retained event", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-tamper-b155.example"), chainAnchor = provider("https://policy-chain-tamper-b155.example");
  const f = await fixture(t, { auditAnchor, policyAuditAnchor: chainAnchor, requireAuditAnchor: true, requirePolicyAuditAnchor: true,
    signer, keyId: "audit-tamper-b155", publicKeys: { "audit-tamper-b155": pair.publicKey }, maxAgeMs: 60000 });
  await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId,
    { reason: "Create signed evidence before anchoring the policy audit event." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the source checkpoint before the policy transition.");
  const changed = f.build({ maxAgeMs: 120000 });
  const challenge = await changed.prepareRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation",
    { reason: "Approve the policy change before tamper detection is tested." });
  await changed.applyRecoverySloCrossDomainCheckpointPolicyBinding(f.ownerId, "cross_domain_snapshot_audit_attestation", challenge.challengeId,
    { confirmation: challenge.confirmation });
  const enrollment = await changed.prepareRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment(f.ownerId,
    { reason: "Enroll the policy audit chain before modifying a retained event." });
  await changed.applyRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment(f.ownerId, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const rows = await store.listEvidence(f.ownerId);
  const event = rows.find(row => row.ownerId === f.ownerId && row.kind.endsWith("-policy-binding-event"));
  assert.ok(event);
  const altered = { ...event, reason: "Tampered event reason despite a recomputed local digest." };
  delete altered.digest; altered.digest = digestRecord(altered);
  await store.putEvidence(f.ownerId, altered, { expectedVersion: event._storage?.version });
  const status = await changed.getRecoverySloCrossDomainPolicyBindingAuditCheckpointStatus(f.ownerId);
  assert.equal(status.status, "unhealthy");
  const audit = await changed.auditRecoverySloCrossDomainPolicyBindingAuditCheckpoint(f.ownerId);
  assert.equal(audit.status, "unhealthy");
});

test("Batch 155: compaction manifest approval is explicit, idempotent, and never executes compaction", async t => {
  const intent = provider("https://intent-manifest-approval-b155.example"), baselineAnchor = provider("https://baseline-manifest-approval-b155.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment",
    "applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment", "Enroll baseline receipt history before creating the manifest.");
  intent.providerIdentity = "https://intent-manifest-approval-rotated-b155.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const manifest = await f.app.createRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest(f.ownerId);
  assert.equal(manifest.status, "ready_for_review");
  const challenge = await f.app.prepareRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApproval(f.ownerId, manifest.manifest.id,
    { reason: "Approve this current manifest for controlled review without deleting any receipt." });
  const applied = await f.app.applyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApproval(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(applied.status, "approved_for_review");
  assert.equal(applied.compactionPerformed, false);
  assert.equal(applied.automaticCompactionAllowed, false);
  const replay = await f.app.applyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApproval(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
  const audit = await f.app.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApprovals(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.approvalCount, 1);
  assert.equal(audit.compactionPerformed, false);
});

test("Batch 155: manifest approval challenge is rejected when receipt source changes after preparation", async t => {
  const intent = provider("https://intent-manifest-stale-approval-b155.example"), baselineAnchor = provider("https://baseline-manifest-stale-approval-b155.example");
  const f = await fixture(t, { intentAnchor: intent, baselineAnchor, requireBaselineAnchor: true });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainProviderBaselineCheckpointEnrollment",
    "applyRecoverySloCrossDomainProviderBaselineCheckpointEnrollment", "Enroll baseline receipt history before creating a stale-approval test manifest.");
  intent.providerIdentity = "https://intent-manifest-stale-approval-rotated-b155.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const manifest = await f.app.createRecoverySloCrossDomainProviderBaselineReceiptCompactionManifest(f.ownerId);
  const challenge = await f.app.prepareRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApproval(f.ownerId, manifest.manifest.id,
    { reason: "Prepare a manifest approval challenge before changing its source receipts." });
  intent.providerIdentity = "https://intent-manifest-stale-approval-rotated-again-b155.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await acceptBaseline(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  await assert.rejects(() => f.app.applyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApproval(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation }), error => error.code === "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_STALE");
});

test("Batch 155: cache entries expire at checkpoint freshness deadline even when digests are unchanged", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-cache-freshness-b155.example"), reviewAnchor = provider("https://review-cache-freshness-b155.example");
  const f = await fixture(t, { auditAnchor, reviewAnchor, requireAuditAnchor: true, requireReviewAnchor: true, signer,
    keyId: "audit-cache-freshness-b155", publicKeys: { "audit-cache-freshness-b155": pair.publicKey }, maxAgeMs: 5 * 86400000, retentionDays: 1 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId,
    { reason: "Create a signed audit record to test cache expiry against checkpoint freshness." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the audit checkpoint before aging the attestation.");
  f.advance(2 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [created.attestation.attestationId], decision: "retain",
    reason: "Retain the overdue attestation only after validating its current digest and replay guard." });
  const applied = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment",
    "applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment", "Enroll the retention decision checkpoint before measuring freshness-bound cache lifetime.");
  const first = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(first.usableForCurrentDecision, true);
  const second = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(second.cacheHit, true);
  f.advance(6 * 86400000);
  const expired = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(expired.cacheHit, false);
  assert.equal(expired.usableForCurrentDecision, false);
  assert.equal(expired.status, "external_checkpoint_pending");
});

test("Batch 155: source mutation during cache fingerprint capture is reported as a revalidation race", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const auditAnchor = provider("https://audit-cache-race-b155.example"), reviewAnchor = provider("https://review-cache-race-b155.example");
  const f = await fixture(t, { auditAnchor, reviewAnchor, requireAuditAnchor: true, requireReviewAnchor: true, signer,
    keyId: "audit-cache-race-b155", publicKeys: { "audit-cache-race-b155": pair.publicKey }, maxAgeMs: 30 * 86400000, retentionDays: 1 });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId,
    { reason: "Create a signed audit record before injecting a deterministic source race." });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment",
    "applyRecoverySloCrossDomainSnapshotAuditCheckpointEnrollment", "Enroll the audit checkpoint before the race test.");
  f.advance(2 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [created.attestation.attestationId], decision: "retain",
    reason: "Approve the overdue attestation before injecting a concurrent evidence update." });
  const applied = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  await enrollCheckpoint(f.app, f.ownerId, "prepareRecoverySloCrossDomainRetentionReviewCheckpointEnrollment",
    "applyRecoverySloCrossDomainRetentionReviewCheckpointEnrollment", "Enroll the decision checkpoint before injecting a race.");
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  let mutated = false;
  reviewAnchor.onRead = async () => {
    if (mutated) return;
    mutated = true;
    reviewAnchor.onRead = null;
    const target = await store.getEvidence(f.ownerId, created.attestation.attestationId);
    const altered = { ...target, reason: "Concurrent source mutation injected while checkpoint fingerprinting was in progress." };
    delete altered.digest; altered.digest = digestRecord(altered);
    await store.putEvidence(f.ownerId, altered, { expectedVersion: target._storage?.version });
  };
  const result = await f.app.revalidateRecoverySloCrossDomainRetentionReviewDecision(f.ownerId, applied.approval.id);
  assert.equal(mutated, true);
  assert.equal(result.status, "revalidation_race_detected");
  assert.equal(result.revalidationRaceDetected, true);
  assert.equal(result.usableForCurrentDecision, false);
  assert.ok(result.findings.some(item => item.code === "CROSS_DOMAIN_RETENTION_REVALIDATION_SOURCE_CHANGED_DURING_CHECK"));
});

test("Batch 155: new external audit-chain and manifest approval APIs are exposed", async t => {
  const f = await fixture(t);
  for (const name of ["getRecoverySloCrossDomainPolicyBindingAuditCheckpointStatus", "reconcileRecoverySloCrossDomainPolicyBindingAuditCheckpoint",
    "prepareRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment", "applyRecoverySloCrossDomainPolicyBindingAuditCheckpointEnrollment",
    "auditRecoverySloCrossDomainPolicyBindingAuditCheckpoint", "prepareRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApproval",
    "applyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApproval", "auditRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApprovals"])
    assert.equal(typeof f.app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.ok(server.includes("policy-binding-audit-checkpoint/enrollment-challenges"));
  assert.ok(server.includes("compaction-manifests/:id/approval-challenges"));
  assert.ok(server.includes("compaction-manifests/approvals/audit"));
});
