import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const hasCode = code => error => error?.code === code;
function keyPair(keyId) { const pair = generateKeyPairSync("ed25519"); return { keyId, publicKey: pair.publicKey, privateKey: pair.privateKey }; }
function signPayload(key, payload) { return sign(null, Buffer.from(canonical(payload), "utf8"), key.privateKey).toString("base64url"); }
function provider(identity, { rejectCas = false } = {}) {
  const records = new Map();
  return { providerIdentity: identity, records, rejectCas,
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if (this.rejectCas) return { applied: false, anchor: structuredClone(current) };
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId || candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision !== (current ? current.revision + 1 : 1)
        || candidate.previousAnchorDigest !== (current?.digest ?? null)) throw Object.assign(new Error("anchor contract violation"), { code: "ANCHOR_CONTRACT_VIOLATION" });
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b145-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const storage = createStorage({ root });
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRootRecoveryTrustAnchor: overrides.rootAnchor ?? options.rootAnchor ?? null,
    recoverySloRetentionDecisionGateAnchor: overrides.decisionAnchor ?? options.decisionAnchor ?? null,
    recoverySloRootTrustBaselineLifecycleAnchor: overrides.lifecycleAnchor ?? options.lifecycleAnchor ?? null,
    recoverySloRetentionReconciliationSigner: overrides.reconciliationSigner ?? options.reconciliationSigner ?? null,
    recoverySloRetentionReconciliationKeyId: overrides.reconciliationKeyId ?? options.reconciliationKeyId ?? null,
    recoverySloRetentionReconciliationPublicKeys: overrides.reconciliationPublicKeys ?? options.reconciliationPublicKeys ?? null,
    recoverySloRootTrustConformanceBaselineSigner: overrides.baselineSigner ?? options.baselineSigner ?? null,
    recoverySloRootTrustConformanceBaselineKeyId: overrides.baselineKeyId ?? options.baselineKeyId ?? null,
    recoverySloRootTrustConformanceBaselinePublicKeys: overrides.baselinePublicKeys ?? options.baselinePublicKeys ?? null,
    recoverySloRetentionReconciliationAttestationMaxAgeMs: overrides.maxAgeMs ?? options.maxAgeMs ?? 86400000,
    recoverySloRetentionReconciliationAttestationFutureSkewMs: overrides.futureSkewMs ?? options.futureSkewMs ?? 60000 });
  return { app: build(), build, storage, root, ownerId: options.ownerId || "owner-b145", now: clock,
    advance: (ms = 1000) => { nowMs += ms; } };
}
async function runRootConformance(app, ownerId) {
  const challenge = await app.prepareRecoverySloRootRecoveryTrustAnchorConformance(ownerId, {
    reason: "Validate root-recovery anchor behavior before baseline lifecycle checkpointing." });
  const result = await app.runRecoverySloRootRecoveryTrustAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  return { challenge, result };
}
async function enrollBaseline(f, signing) {
  const source = await runRootConformance(f.app, f.ownerId);
  const challenge = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: source.challenge.challengeId,
    reason: "Enroll the initial root-trust baseline to exercise external lifecycle checkpointing." });
  return f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}

test("Batch 145: decision-gate anchor conformance probes a disposable namespace and retains a verifiable report", async t => {
  const anchor = provider("https://decision-gate-conformance-145.example"), f = await fixture(t, { decisionAnchor: anchor });
  const challenge = await f.app.prepareRecoverySloRetentionDecisionGateAnchorConformance(f.ownerId, {
    reason: "Validate decision-gate anchor CAS behavior before relying on external audit checkpoints." });
  assert.equal(challenge.writesToProductionNamespace, false);
  const result = await f.app.runRecoverySloRetentionDecisionGateAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "conformant");
  assert.equal(result.report.writesToProductionNamespace, false);
  assert.equal(result.report.checks.every(item => item.passed), true);
  assert.equal((await f.app.auditRecoverySloRetentionDecisionGateAnchorConformance(f.ownerId)).status, "healthy");
  const replay = await f.app.runRecoverySloRetentionDecisionGateAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
});

test("Batch 145: a nonconformant decision-gate provider is reported and never auto-repaired", async t => {
  const anchor = provider("https://decision-gate-nonconformant-145.example", { rejectCas: true }), f = await fixture(t, { decisionAnchor: anchor });
  const challenge = await f.app.prepareRecoverySloRetentionDecisionGateAnchorConformance(f.ownerId, {
    reason: "Detect an anchor provider that rejects even genesis CAS writes in its disposable namespace." });
  const result = await f.app.runRecoverySloRetentionDecisionGateAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "nonconformant");
  assert.equal(result.report.findings.length > 0, true);
  assert.equal(anchor.records.size, 0);
  assert.equal((await f.app.auditRecoverySloRetentionDecisionGateAnchorConformance(f.ownerId)).status, "healthy");
});

test("Batch 145: decision-gate anchor recovery after CAS outage requires explicit enrollment and preserves unproven history", async t => {
  const anchor = provider("https://decision-gate-recovery-145.example", { rejectCas: true });
  const signing = keyPair("decision-gate-recovery-145");
  const f = await fixture(t, { decisionAnchor: anchor, reconciliationSigner: async payload => signPayload(signing, payload),
    reconciliationKeyId: signing.keyId, reconciliationPublicKeys: { [signing.keyId]: signing.publicKey } });
  const issued = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Create a signed reconciliation snapshot before testing decision-gate anchor recovery." });
  await assert.rejects(f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, {
    decision: "must-remain-blocked", expectedAuditDigest: issued.attestation.snapshot.auditDigest
  }), hasCode("RETENTION_DECISION_GATE_EXTERNAL_ANCHOR_FAILED"));
  assert.equal((await f.app.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId)).status, "enrollment_required");
  anchor.rejectCas = false;
  const challenge = await f.app.prepareRecoverySloRetentionDecisionGateAnchorEnrollment(f.ownerId, {
    reason: "Explicitly recover local decision-gate evidence after the external anchor provider becomes available." });
  const result = await f.app.applyRecoverySloRetentionDecisionGateAnchorEnrollment(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "enrolled");
  assert.equal(result.historyNotProven, true);
  assert.equal((await f.app.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId)).status, "anchored");
  assert.equal((await f.app.auditRecoverySloRetentionReconciliationDecisionGateEvidence(f.ownerId)).status, "healthy");
});

test("Batch 145: root-trust baseline lifecycle checkpoint failure is explicit and recoverable only after provider recovery", async t => {
  const rootAnchor = provider("https://root-anchor-145.example");
  const lifecycleAnchor = provider("https://baseline-lifecycle-anchor-145.example", { rejectCas: true });
  const signing = keyPair("baseline-lifecycle-145");
  const f = await fixture(t, { rootAnchor, lifecycleAnchor, baselineSigner: async payload => signPayload(signing, payload),
    baselineKeyId: signing.keyId, baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  const source = await runRootConformance(f.app, f.ownerId);
  const challenge = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: source.challenge.challengeId,
    reason: "Create a baseline lifecycle event while the external checkpoint provider is temporarily rejecting writes." });
  await assert.rejects(f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("ROOT_TRUST_BASELINE_LIFECYCLE_EXTERNAL_ANCHOR_FAILED"));
  const gatedBaseline = await f.app.getRecoverySloRootTrustConformanceCurrentBaseline(f.ownerId);
  assert.equal(gatedBaseline.status, "external_anchor_untrusted");
  assert.equal(gatedBaseline.localBaselineStatus, "current");
  assert.equal((await f.app.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(f.ownerId)).status, "anchor_pending");
  lifecycleAnchor.rejectCas = false;
  const reconciled = await f.app.reconcileRecoverySloRootTrustBaselineLifecycleAnchor(f.ownerId);
  assert.equal(reconciled.status, "anchored");
  assert.equal(reconciled.historyNotProven, true);
  assert.equal((await f.app.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(f.ownerId)).status, "anchored");
  const nextSource = await runRootConformance(f.app, f.ownerId);
  const nextChallenge = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: nextSource.challenge.challengeId,
    reason: "Advance an already anchored baseline lifecycle to prove external checkpoint continuity across rotations." });
  const next = await f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, nextChallenge.challengeId, { confirmation: nextChallenge.confirmation });
  assert.equal(next.externalAnchor.status, "anchored");
  assert.equal(next.externalAnchor.anchorSequence, 2);
  assert.equal((await f.app.getRecoverySloRootTrustConformanceCurrentBaseline(f.ownerId)).status, "current");
});

test("Batch 145: legacy baseline lifecycle history requires explicit enrollment and preserves unproven history", async t => {
  const rootAnchor = provider("https://root-anchor-legacy-145.example"), signing = keyPair("baseline-lifecycle-legacy-145");
  const f = await fixture(t, { rootAnchor, baselineSigner: async payload => signPayload(signing, payload), baselineKeyId: signing.keyId,
    baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  await enrollBaseline(f, signing);
  const secondSource = await runRootConformance(f.app, f.ownerId);
  const secondChallenge = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: secondSource.challenge.challengeId,
    reason: "Create a second baseline lifecycle event before the external checkpoint is configured." });
  await f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, secondChallenge.challengeId, { confirmation: secondChallenge.confirmation });
  const lifecycleAnchor = provider("https://baseline-lifecycle-legacy-145.example");
  const configured = f.build({ lifecycleAnchor, baselineSigner: async payload => signPayload(signing, payload), baselineKeyId: signing.keyId,
    baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  assert.equal((await configured.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(f.ownerId)).status, "enrollment_required");
  const enrollment = await configured.prepareRecoverySloRootTrustBaselineLifecycleAnchorEnrollment(f.ownerId, {
    reason: "Explicitly anchor legacy baseline lifecycle history without claiming proof before enrollment." });
  const result = await configured.applyRecoverySloRootTrustBaselineLifecycleAnchorEnrollment(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal(result.status, "enrolled");
  assert.equal(result.anchored, 2);
  assert.equal(result.historyNotProven, true);
  assert.equal((await configured.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(f.ownerId)).status, "anchored");
});

test("Batch 145: baseline lifecycle anchor detects a remote rollback and refuses implicit re-enrollment", async t => {
  const rootAnchor = provider("https://root-anchor-rollback-145.example"), lifecycleAnchor = provider("https://baseline-lifecycle-rollback-145.example");
  const signing = keyPair("baseline-lifecycle-rollback-145");
  const f = await fixture(t, { rootAnchor, lifecycleAnchor, baselineSigner: async payload => signPayload(signing, payload),
    baselineKeyId: signing.keyId, baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  await enrollBaseline(f, signing);
  const scope = [...lifecycleAnchor.records.keys()][0];
  assert.ok(scope);
  lifecycleAnchor.records.delete(scope);
  assert.equal((await f.app.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(f.ownerId)).status, "rollback_suspected");
  await assert.rejects(f.app.anchorPendingRecoverySloRootTrustBaselineLifecycle(f.ownerId), hasCode("ROOT_TRUST_BASELINE_LIFECYCLE_ROLLBACK_SUSPECTED"));
});

test("Batch 145: freshness policy drift audit detects runtime policy changes against signed retained attestations", async t => {
  const signing = keyPair("freshness-policy-drift-145");
  const f = await fixture(t, { reconciliationSigner: async payload => signPayload(signing, payload), reconciliationKeyId: signing.keyId,
    reconciliationPublicKeys: { [signing.keyId]: signing.publicKey }, maxAgeMs: 60000, futureSkewMs: 1000 });
  const issued = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Create a signed reconciliation attestation to establish its issuance freshness policy." });
  assert.equal((await f.app.auditRecoverySloRetentionFreshnessPolicyDrift(f.ownerId)).status, "healthy");
  const changed = f.build({ reconciliationSigner: async payload => signPayload(signing, payload), reconciliationKeyId: signing.keyId,
    reconciliationPublicKeys: { [signing.keyId]: signing.publicKey }, maxAgeMs: 120000, futureSkewMs: 2000 });
  const audit = await changed.auditRecoverySloRetentionFreshnessPolicyDrift(f.ownerId);
  assert.equal(audit.status, "drift_detected");
  assert.equal(audit.policyDriftCount, 1);
  assert.equal(audit.mismatches[0].attestationDigest, issued.attestation.attestationDigest);
  assert.equal(audit.currentPolicy.maxAgeMs, 120000);
});

test("Batch 145: APIs and HTTP routes expose conformance, lifecycle checkpoint recovery, and freshness policy drift audit", async t => {
  const f = await fixture(t);
  for (const name of ["prepareRecoverySloRetentionDecisionGateAnchorConformance", "runRecoverySloRetentionDecisionGateAnchorConformance",
    "auditRecoverySloRetentionDecisionGateAnchorConformance", "getRecoverySloRootTrustBaselineLifecycleAnchorStatus",
    "anchorPendingRecoverySloRootTrustBaselineLifecycle", "reconcileRecoverySloRootTrustBaselineLifecycleAnchor",
    "prepareRecoverySloRootTrustBaselineLifecycleAnchorEnrollment", "applyRecoverySloRootTrustBaselineLifecycleAnchorEnrollment",
    "auditRecoverySloRetentionFreshnessPolicyDrift", "getRecoverySloRetentionFreshnessPolicy"]) {
    assert.equal(typeof f.app[name], "function", `${name} should exist`);
  }
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /decision-gate\/anchor\/conformance\/challenges/);
  assert.match(server, /baseline-lifecycle\/anchor\/reconcile/);
  assert.match(server, /freshness-policy-drift\/audit/);
});
