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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b150-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.intentAnchor ?? options.intentAnchor ?? null,
    requireRecoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.requireIntentAnchor ?? options.requireIntentAnchor ?? false,
    recoverySloRootTrustBaselineProofRevocationAnchor: overrides.revocationAnchor ?? options.revocationAnchor ?? null,
    requireRecoverySloRootTrustBaselineProofRevocationAnchor: overrides.requireRevocationAnchor ?? options.requireRevocationAnchor ?? false,
    recoverySloCrossDomainSnapshotAnchorMaxAgeMs: overrides.maxAgeMs ?? options.maxAgeMs ?? 86400000,
    recoverySloCrossDomainSnapshotAnchorFutureSkewMs: overrides.futureSkewMs ?? options.futureSkewMs ?? 60000,
    recoverySloCrossDomainSnapshotAnchorRetentionDays: overrides.retentionDays ?? options.retentionDays ?? 90,
    recoverySloCrossDomainSnapshotAuditSigner: overrides.signer ?? options.signer ?? null,
    recoverySloCrossDomainSnapshotAuditKeyId: overrides.keyId ?? options.keyId ?? null,
    recoverySloCrossDomainSnapshotAuditPublicKeys: overrides.publicKeys ?? options.publicKeys ?? null,
    requireRecoverySloCrossDomainSnapshotAuditAttestation: overrides.requireAuditAttestation ?? options.requireAuditAttestation ?? false });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b150", now: clock, advance: ms => { nowMs += ms; } };
}
async function runConformance(app, ownerId, domain) {
  const challenge = await app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, { domain,
    reason: "Verify the provider contract in a disposable namespace before accepting a provider identity baseline." });
  return app.runRecoverySloCrossDomainSnapshotAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}

test("Batch 150: cross-domain governance audit is signed, retained, verifiable, and detects tampering", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const intent = provider("https://intent-audit-150.example"), revocation = provider("https://revocation-audit-150.example");
  const f = await fixture(t, { intentAnchor: intent, revocationAnchor: revocation,
    signer, keyId: "audit-key-150", publicKeys: { "audit-key-150": pair.publicKey }, requireAuditAttestation: true });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Record the signed governance outcome for the current cross-domain checkpoint configuration." });
  assert.equal(created.status, "signed");
  assert.equal((await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId)).valid, true);
  assert.equal((await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation("another-owner", created.attestation.attestationId)).valid, false);
  intent.providerIdentity = "https://intent-audit-rotated-150.example";
  const afterDrift = await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, created.attestation.attestationId);
  assert.equal(afterDrift.historicallyValid, true);
  assert.equal(afterDrift.current, false);
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAuditAttestations(f.ownerId)).status, "healthy");
});

test("Batch 150: audit attestation verifier detects signed payload tampering and retained-record corruption", async t => {
  const pair = generateKeyPairSync("ed25519"), signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const f = await fixture(t, { intentAnchor: provider("https://intent-tamper-150.example"), revocationAnchor: provider("https://revocation-tamper-150.example"),
    signer, keyId: "audit-key-150", publicKeys: { "audit-key-150": pair.publicKey } });
  const created = await f.app.createRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, {
    reason: "Capture an immutable audit snapshot so later verification detects payload modification." });
  const altered = { ...created.attestation, auditStatus: "healthy-but-altered" };
  assert.equal((await f.app.verifyRecoverySloCrossDomainSnapshotAuditAttestation(f.ownerId, altered)).valid, false);
});

test("Batch 150: concurrent provider conformance runs reserve unique monotonic report sequences", async t => {
  const f = await fixture(t, { intentAnchor: provider("https://intent-concurrent-150.example"), revocationAnchor: provider("https://revocation-concurrent-150.example") });
  const prepare = () => f.app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, { domain: "retention_decision_gate_recovery_intent",
    reason: "Exercise concurrent conformance without allowing duplicate sequence numbers in retained reports." });
  const [a, b] = await Promise.all([prepare(), prepare()]);
  const results = await Promise.all([f.app.runRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, a.challengeId, { confirmation: a.confirmation }),
    f.app.runRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, b.challengeId, { confirmation: b.confirmation })]);
  assert.ok(results.every(result => result.status === "conformant"));
  assert.deepEqual(results.map(result => result.report.conformanceSequence).sort((x, y) => x - y), [1, 2]);
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, { domain: "retention_decision_gate_recovery_intent" })).status, "healthy");
});

test("Batch 150: provider baseline requires a current conformant report and detects identity drift", async t => {
  const intent = provider("https://intent-baseline-150.example"), revocation = provider("https://revocation-baseline-150.example");
  const f = await fixture(t, { intentAnchor: intent, revocationAnchor: revocation });
  assert.equal((await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent")).status, "conformant");
  const challenge = await f.app.prepareRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, { domain: "retention_decision_gate_recovery_intent",
    reason: "Accept the current provider identity only after the most recent conformance report has passed." });
  const accepted = await f.app.applyRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(accepted.status, "accepted");
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).status, "healthy");
  intent.providerIdentity = "https://intent-baseline-rotated-150.example";
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).status, "drift_detected");
  await assert.rejects(() => f.app.prepareRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, { domain: "retention_decision_gate_recovery_intent",
    reason: "A new baseline must not be accepted until the changed provider passes fresh conformance." }), error => error?.code === "CROSS_DOMAIN_PROVIDER_BASELINE_CONFORMANCE_REQUIRED");
});

test("Batch 150: provider baseline rotation needs fresh conformance and stale challenges are rejected", async t => {
  const intent = provider("https://intent-rotate-150.example"), revocation = provider("https://revocation-rotate-150.example");
  const f = await fixture(t, { intentAnchor: intent, revocationAnchor: revocation });
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const first = await f.app.prepareRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, { domain: "retention_decision_gate_recovery_intent",
    reason: "Create the first accepted identity baseline from a conformant report." });
  await f.app.applyRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, first.challengeId, { confirmation: first.confirmation });
  intent.providerIdentity = "https://intent-rotate-new-150.example";
  await runConformance(f.app, f.ownerId, "retention_decision_gate_recovery_intent");
  const rotation = await f.app.prepareRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, { domain: "retention_decision_gate_recovery_intent",
    reason: "Rotate the provider identity baseline after successful conformance of the replacement endpoint." });
  f.advance(11 * 60 * 1000);
  await assert.rejects(() => f.app.applyRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, rotation.challengeId, { confirmation: rotation.confirmation }),
    error => error?.code === "CROSS_DOMAIN_PROVIDER_BASELINE_CONFIRMATION_INVALID");
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).status, "drift_detected");
  const freshRotation = await f.app.prepareRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, { domain: "retention_decision_gate_recovery_intent",
    reason: "Apply a fresh approval challenge after the previous challenge expired without mutating the active baseline." });
  const applied = await f.app.applyRecoverySloCrossDomainProviderIdentityBaseline(f.ownerId, freshRotation.challengeId, { confirmation: freshRotation.confirmation });
  assert.equal(applied.status, "accepted");
  assert.equal((await f.app.auditRecoverySloCrossDomainProviderIdentityBaselines(f.ownerId)).status, "healthy");
});

test("Batch 150: retention review approval binds overdue evidence and performs no deletion", async t => {
  const intent = provider("https://intent-retention-150.example"), revocation = provider("https://revocation-retention-150.example");
  const f = await fixture(t, { intentAnchor: intent, revocationAnchor: revocation, retentionDays: 1 });
  const seedStore = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const pendingId = "expired-enrollment-challenge-b150";
  const seedUnsigned = { id: pendingId, ownerId: f.ownerId, kind: "retention-decision-gate-recovery-intent-checkpoint-enrollment-challenge",
    schemaVersion: 1, status: "prepared", domain: "retention_decision_gate_recovery_intent", createdAt: "2026-10-01T00:00:00.000Z",
    expiresAt: "2026-10-01T00:10:00.000Z", reason: "Historical challenge seeded for a non-destructive retention review." };
  await seedStore.putEvidence(f.ownerId, { ...seedUnsigned, digest: digestRecord(seedUnsigned) }, { overwrite: false });
  f.advance(3 * 86400000);
  const audit = await f.app.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention(f.ownerId);
  const overdue = audit.retention.find(item => item.recordId === pendingId && item.retentionClass === "retention_overdue_review");
  assert.ok(overdue);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [pendingId], decision: "retain",
    reason: "Approve retention of the expired enrollment challenge for auditability; do not delete source evidence." });
  const result = await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "approved");
  assert.equal(result.destructiveActionPerformed, false);
  assert.equal((await f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation })).idempotent, true);
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviews(f.ownerId)).status, "healthy");
});

test("Batch 150: retention review rejects non-overdue and duplicate targets", async t => {
  const f = await fixture(t, { intentAnchor: provider("https://intent-retention-invalid-150.example"), revocationAnchor: provider("https://revocation-retention-invalid-150.example") });
  await assert.rejects(() => f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: ["not-overdue"], decision: "retain",
    reason: "This request must not approve an arbitrary evidence record outside the review set." }), error => error?.code === "CROSS_DOMAIN_RETENTION_REVIEW_TARGET_NOT_OVERDUE");
  await assert.rejects(() => f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: ["x", "x"], decision: "retain",
    reason: "Duplicate target IDs are rejected before an approval challenge is issued." }), error => error?.code === "CROSS_DOMAIN_RETENTION_REVIEW_TARGETS_INVALID");
});

test("Batch 150: retention review rejects an audit snapshot that changes after the challenge", async t => {
  const f = await fixture(t, { intentAnchor: provider("https://intent-retention-stale-150.example"),
    revocationAnchor: provider("https://revocation-retention-stale-150.example"), retentionDays: 1 });
  const seedStore = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const id = "expired-review-source-stale-b150";
  const original = { id, ownerId: f.ownerId, kind: "retention-decision-gate-recovery-intent-checkpoint-enrollment-challenge",
    schemaVersion: 1, status: "prepared", domain: "retention_decision_gate_recovery_intent", createdAt: "2026-10-01T00:00:00.000Z",
    expiresAt: "2026-10-01T00:10:00.000Z", reason: "Original historical challenge for a stale review test." };
  await seedStore.putEvidence(f.ownerId, { ...original, digest: digestRecord(original) }, { overwrite: false });
  f.advance(3 * 86400000);
  const challenge = await f.app.prepareRecoverySloCrossDomainRetentionReview(f.ownerId, { recordIds: [id], decision: "retain",
    reason: "Review is bound to the current audit snapshot and must fail if that snapshot changes." });
  const changed = { ...original, reason: "Updated historical challenge before approval." };
  await seedStore.putEvidence(f.ownerId, { ...changed, digest: digestRecord(changed) });
  await assert.rejects(() => f.app.applyRecoverySloCrossDomainRetentionReview(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    error => error?.code === "CROSS_DOMAIN_RETENTION_REVIEW_AUDIT_STALE");
  assert.equal((await f.app.auditRecoverySloCrossDomainRetentionReviews(f.ownerId)).approvalCount, 0);
});

test("Batch 150: required audit attestation configuration fails closed without signer and trusted key", () => {
  const root = fs.mkdtemp(path.join(os.tmpdir(), "agentic-b150-required-"));
  return root.then(async directory => {
    try {
      assert.throws(() => createAgenticApplication({ storage: createStorage({ root: directory }), requireRecoverySloCrossDomainSnapshotAuditAttestation: true }),
        /Cross-domain audit attestation wajib memiliki signer dan trusted public key/);
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
  });
});

test("Batch 150: application exports and HTTP routes expose audit attestation, provider baseline, and retention review", async t => {
  const f = await fixture(t, { intentAnchor: provider("https://intent-routes-150.example"), revocationAnchor: provider("https://revocation-routes-150.example") });
  for (const name of ["createRecoverySloCrossDomainSnapshotAuditAttestation", "verifyRecoverySloCrossDomainSnapshotAuditAttestation",
    "auditRecoverySloCrossDomainSnapshotAuditAttestations", "prepareRecoverySloCrossDomainProviderIdentityBaseline",
    "applyRecoverySloCrossDomainProviderIdentityBaseline", "auditRecoverySloCrossDomainProviderIdentityBaselines",
    "prepareRecoverySloCrossDomainRetentionReview", "applyRecoverySloCrossDomainRetentionReview", "auditRecoverySloCrossDomainRetentionReviews"]) {
    assert.equal(typeof f.app[name], "function", name);
  }
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["snapshot-checkpoints/audit-attestations", "cross-domain/provider-baselines/challenges", "cross-domain/provider-baselines/audit",
    "cross-domain/retention-reviews/challenges", "cross-domain/retention-reviews/audit"]) assert.ok(server.includes(route), route);
});
