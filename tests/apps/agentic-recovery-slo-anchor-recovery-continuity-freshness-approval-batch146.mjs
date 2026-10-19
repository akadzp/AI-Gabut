import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createRecoverySloRetentionDecisionGateAnchorRecoveryAttestationService } from "../../apps/agentic/backend/recovery-slo-retention-decision-gate-anchor-recovery-attestation.js";
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
        || candidate.revision !== (current ? current.revision + 1 : 1) || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        throw Object.assign(new Error("anchor contract violation"), { code: "ANCHOR_CONTRACT_VIOLATION" });
      }
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b146-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
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
    recoverySloRetentionReconciliationAttestationFutureSkewMs: overrides.futureSkewMs ?? options.futureSkewMs ?? 60000,
    recoverySloRetentionDecisionGateRecoverySigner: overrides.recoverySigner ?? options.recoverySigner ?? null,
    recoverySloRetentionDecisionGateRecoveryKeyId: overrides.recoveryKeyId ?? options.recoveryKeyId ?? null,
    recoverySloRetentionDecisionGateRecoveryPublicKeys: overrides.recoveryPublicKeys ?? options.recoveryPublicKeys ?? null,
    requireRecoverySloRetentionDecisionGateRecoveryAttestation: overrides.requireRecoveryAttestation ?? options.requireRecoveryAttestation ?? false });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b146", now: clock, advance: ms => { nowMs += ms; } };
}
async function runRootConformance(app, ownerId) {
  const challenge = await app.prepareRecoverySloRootRecoveryTrustAnchorConformance(ownerId, {
    reason: "Validate root-recovery anchor behavior before baseline continuity proof generation." });
  return app.runRecoverySloRootRecoveryTrustAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function enrollBaseline(f, key) {
  const source = await f.app.prepareRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, {
    reason: "Create a root-trust provider conformance report before baseline lifecycle enrollment." });
  await f.app.runRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, source.challengeId, { confirmation: source.confirmation });
  const challenge = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: source.challengeId,
    reason: "Enroll the baseline lifecycle before creating a checkpoint continuity proof." });
  return f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}

test("Batch 146: freshness-policy change approval is challenge-bound, one-time, and deployment-aware", async t => {
  const f = await fixture(t, { maxAgeMs: 86400000, futureSkewMs: 60000 });
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalStatus(f.ownerId)).status, "not_initialized");
  const challenge = await f.app.prepareRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, {
    targetPolicy: { maxAgeMs: 120000, futureSkewMs: 5000 }, reason: "Tighten attestation freshness limits after review of decision risk and deployment requirements." });
  await assert.rejects(f.app.applyRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, challenge.challengeId, { confirmation: "wrong" }),
    hasCode("RETENTION_FRESHNESS_POLICY_APPROVAL_CHALLENGE_INVALID"));
  const result = await f.app.applyRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "approved_deployment_pending");
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalStatus(f.ownerId)).status, "deployment_pending");
  await assert.rejects(f.app.prepareRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, {
    targetPolicy: { maxAgeMs: 180000, futureSkewMs: 5000 }, reason: "Try to supersede an approved policy before deployment has aligned runtime settings." }),
    hasCode("RETENTION_FRESHNESS_POLICY_DEPLOYMENT_PENDING"));
  const aligned = f.build({ maxAgeMs: 120000, futureSkewMs: 5000 });
  assert.equal((await aligned.getRecoverySloRetentionFreshnessPolicyApprovalStatus(f.ownerId)).status, "aligned");
  assert.equal((await aligned.auditRecoverySloRetentionFreshnessPolicyApprovals(f.ownerId)).status, "healthy");
  await assert.rejects(aligned.applyRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("RETENTION_FRESHNESS_POLICY_APPROVAL_CHALLENGE_INVALID"));
});

test("Batch 146: freshness-policy approval rejects stale runtime policy and out-of-range changes", async t => {
  const f = await fixture(t, { maxAgeMs: 86400000, futureSkewMs: 60000 });
  const challenge = await f.app.prepareRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, {
    targetPolicy: { maxAgeMs: 300000, futureSkewMs: 10000 }, reason: "Prepare a controlled policy change that must fail if runtime configuration drifts before approval." });
  const changed = f.build({ maxAgeMs: 172800000, futureSkewMs: 60000 });
  await assert.rejects(changed.applyRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("RETENTION_FRESHNESS_POLICY_APPROVAL_STALE"));
  await assert.rejects(f.app.prepareRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, {
    targetPolicy: { maxAgeMs: 1000, futureSkewMs: 0 }, reason: "Reject an unsafe target freshness age that is below the supported lower bound." }),
    hasCode("RETENTION_FRESHNESS_POLICY_APPROVAL_POLICY_INVALID"));
  await assert.rejects(f.app.applyRecoverySloRetentionFreshnessPolicyChangeApproval("different-owner", challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("RETENTION_FRESHNESS_POLICY_APPROVAL_CHALLENGE_INVALID"));
  const expiring = await f.app.prepareRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, {
    targetPolicy: { maxAgeMs: 600000, futureSkewMs: 15000 }, reason: "Verify that freshness policy approval challenges expire before any late configuration change is applied." });
  f.advance(11 * 60 * 1000);
  await assert.rejects(f.app.applyRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, expiring.challengeId, { confirmation: expiring.confirmation }),
    hasCode("RETENTION_FRESHNESS_POLICY_APPROVAL_CHALLENGE_INVALID"));
});

test("Batch 146: freshness-policy approval event chain detects stored state tampering", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, {
    targetPolicy: { maxAgeMs: 3600000, futureSkewMs: 30000 }, reason: "Approve a policy revision so the persistent event chain can be audited for tampering." });
  await f.app.applyRecoverySloRetentionFreshnessPolicyChangeApproval(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal((await f.app.auditRecoverySloRetentionFreshnessPolicyApprovals(f.ownerId)).status, "deployment_pending");
  const rows = await f.app.store.listEvidence(f.ownerId);
  const state = rows.find(row => row.kind === "recovery-slo-retention-freshness-policy-approval-state");
  assert.ok(state);
  await f.app.store.putEvidence(f.ownerId, { ...state, approvedPolicy: { ...state.approvedPolicy, maxAgeMs: 777777 } }, { expectedVersion: state._storage?.version });
  assert.equal((await f.app.auditRecoverySloRetentionFreshnessPolicyApprovals(f.ownerId)).status, "unhealthy");
});

test("Batch 146: root-trust baseline continuity proof requires a healthy, current external checkpoint", async t => {
  const rootAnchor = provider("https://root-anchor-continuity-146.example");
  const lifecycleAnchor = provider("https://baseline-lifecycle-continuity-146.example");
  const signing = keyPair("baseline-continuity-146");
  const f = await fixture(t, { rootAnchor, lifecycleAnchor, baselineSigner: async payload => signPayload(signing, payload), baselineKeyId: signing.keyId,
    baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  await enrollBaseline(f, signing);
  assert.equal((await f.app.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(f.ownerId)).status, "anchored");
  const created = await f.app.createRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, {
    reason: "Capture a retained continuity proof for the externally anchored baseline lifecycle and active baseline." });
  assert.equal(created.status, "proof_created");
  const verified = await f.app.verifyRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, created.proof);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.current, true);
  assert.equal((await f.app.auditRecoverySloRootTrustBaselineCheckpointContinuityProofs(f.ownerId)).status, "healthy");
});

test("Batch 146: continuity proof refuses a local-only lifecycle without an independently anchored checkpoint", async t => {
  const rootAnchor = provider("https://root-anchor-local-only-146.example"), signing = keyPair("baseline-local-only-146");
  const f = await fixture(t, { rootAnchor, baselineSigner: async payload => signPayload(signing, payload), baselineKeyId: signing.keyId,
    baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  await enrollBaseline(f, signing);
  assert.equal((await f.app.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(f.ownerId)).status, "local_only");
  await assert.rejects(f.app.createRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, {
    reason: "Refuse to issue a continuity proof when no independent external checkpoint is configured." }),
    hasCode("ROOT_TRUST_BASELINE_CONTINUITY_NOT_PROVABLE"));
});

test("Batch 146: continuity proof remains historical after baseline advances but is no longer current", async t => {
  const rootAnchor = provider("https://root-anchor-advance-146.example"), lifecycleAnchor = provider("https://baseline-lifecycle-advance-146.example");
  const signing = keyPair("baseline-advance-146");
  const f = await fixture(t, { rootAnchor, lifecycleAnchor, baselineSigner: async payload => signPayload(signing, payload), baselineKeyId: signing.keyId,
    baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  await enrollBaseline(f, signing);
  const created = await f.app.createRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, {
    reason: "Preserve the first checkpoint continuity state before advancing the baseline lifecycle." });
  const source = await f.app.prepareRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, {
    reason: "Revalidate the provider before rotating the baseline after a retained continuity proof." });
  await f.app.runRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, source.challengeId, { confirmation: source.confirmation });
  const rotation = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: source.challengeId,
    reason: "Advance the baseline after recording the prior checkpoint continuity proof." });
  await f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, rotation.challengeId, { confirmation: rotation.confirmation });
  const verified = await f.app.verifyRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, created.proof);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.current, false);
});

test("Batch 146: decision-gate recovery attestation signs only a provable behind-local recovery and detects later supersession", async t => {
  const signing = keyPair("decision-gate-recovery-146");
  let state = { status: "behind_local", total: 4, anchorSequence: 3, anchorDigest: "a".repeat(64), historyNotProven: false };
  let reconcileCalls = 0, failSigningOnce = true;
  const anchorService = {
    async getRecoverySloRetentionDecisionGateAnchorStatus() { return structuredClone(state); },
    async reconcileRecoverySloRetentionDecisionGateAnchor() { reconcileCalls++; state = { status: "anchored", total: 4, anchorSequence: 4, anchorDigest: "b".repeat(64), historyNotProven: false }; return { status: "anchored", anchored: 1 }; }
  };
  const records = [];
  const retainedEvidenceService = {
    async retainRecoverySloAnchorEvidence(ownerId, { artifactType, sourceId, payload, retentionDays }) {
      const unsigned = { id: `retained-${records.length + 1}`, ownerId, kind: "mock-retained-evidence", schemaVersion: 1, artifactType, sourceId,
        payload, payloadDigest: sha256(canonical(payload)), retentionDays, status: "retained", capturedAt: "2026-10-12T00:00:00.000Z",
        expiresAt: "2036-10-09T00:00:00.000Z", tombstone: null };
      const record = { ...unsigned, digest: sha256(canonical(unsigned)) };
      records.push(record); return structuredClone(record);
    },
    async listRecoverySloRetainedAnchorEvidence(ownerId) { return { items: records.filter(item => item.ownerId === ownerId).map(item => structuredClone(item)) }; }
  };
  const localRecords = new Map();
  const store = {
    async listEvidence(ownerId) { return [...localRecords.values()].filter(item => item.ownerId === ownerId).map(item => structuredClone(item)); },
    async getEvidence(ownerId, id) { const item = localRecords.get(id); return item?.ownerId === ownerId ? structuredClone(item) : null; },
    async putEvidence(ownerId, item, options = {}) {
      const current = localRecords.get(item.id);
      if (current && options.expectedVersion != null && current._storage?.version !== options.expectedVersion) throw new Error("version conflict");
      if (!current && options.overwrite === false && options.expectedVersion != null) throw new Error("missing version");
      const next = { ...structuredClone(item), _storage: { version: (current?._storage?.version || 0) + 1 } };
      localRecords.set(item.id, next); return structuredClone(next);
    }
  };
  const service = createRecoverySloRetentionDecisionGateAnchorRecoveryAttestationService({ store, anchorService, retainedEvidenceService,
    signer: async payload => { if (failSigningOnce) { failSigningOnce = false; throw new Error("temporary signer outage"); } return signPayload(signing, payload); },
    keyId: signing.keyId, publicKeys: { [signing.keyId]: signing.publicKey }, required: true,
    clock: () => "2026-10-12T00:00:00.000Z" });
  const reason = "Attest a continuity-proven decision-gate anchor recovery after a temporary external provider outage.";
  await assert.rejects(service.recoverAndAttestRecoverySloRetentionDecisionGateAnchor("owner-b146-attest", { reason }),
    hasCode("RETENTION_DECISION_GATE_RECOVERY_SIGNER_FAILED"));
  const result = await service.recoverAndAttestRecoverySloRetentionDecisionGateAnchor("owner-b146-attest", { reason });
  assert.equal(reconcileCalls, 1);
  assert.equal(result.status, "recovered_and_attested");
  const verified = await service.verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation("owner-b146-attest", result.attestation);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.current, true);
  const replay = await service.recoverAndAttestRecoverySloRetentionDecisionGateAnchor("owner-b146-attest", { reason });
  assert.equal(replay.idempotent, true);
  state = { ...state, anchorSequence: 5, anchorDigest: "c".repeat(64) };
  const superseded = await service.verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation("owner-b146-attest", result.attestation);
  assert.equal(superseded.historicallyValid, true);
  assert.equal(superseded.current, false);
  const tampered = await service.verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation("owner-b146-attest", { ...result.attestation, reason: "changed" });
  assert.equal(tampered.historicallyValid, false);
  await assert.rejects(service.recoverAndAttestRecoverySloRetentionDecisionGateAnchor("owner-b146-attest", {
    reason: "Reject an attempted recovery attestation when the anchor is not in a provably recoverable state." }), hasCode("RETENTION_DECISION_GATE_RECOVERY_NOT_PROVABLE"));
});

test("Batch 146: application recovery flow signs and retains an attestation only after a behind-local anchor is reconciled", async t => {
  const decisionAnchor = provider("https://decision-anchor-integrated-146.example");
  const reconciliationSigning = keyPair("reconciliation-146"), recoverySigning = keyPair("decision-recovery-146");
  const f = await fixture(t, { decisionAnchor,
    reconciliationSigner: async payload => signPayload(reconciliationSigning, payload), reconciliationKeyId: reconciliationSigning.keyId,
    reconciliationPublicKeys: { [reconciliationSigning.keyId]: reconciliationSigning.publicKey },
    recoverySigner: async payload => signPayload(recoverySigning, payload), recoveryKeyId: recoverySigning.keyId,
    recoveryPublicKeys: { [recoverySigning.keyId]: recoverySigning.publicKey } });
  const issued = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Create a signed reconciliation snapshot before exercising the integrated recovery attestation flow." });
  await f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, {
    decision: "initial-allowed-decision", expectedAuditDigest: issued.attestation.snapshot.auditDigest });
  decisionAnchor.rejectCas = true;
  await assert.rejects(f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, {
    decision: "blocked-during-anchor-outage", expectedAuditDigest: issued.attestation.snapshot.auditDigest }),
    hasCode("RETENTION_DECISION_GATE_EXTERNAL_ANCHOR_FAILED"));
  assert.equal((await f.app.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId)).status, "behind_local");
  decisionAnchor.rejectCas = false;
  const recovered = await f.app.recoverAndAttestRecoverySloRetentionDecisionGateAnchor(f.ownerId, {
    reason: "Record a signed recovery attestation after the external anchor provider resumes correct compare-and-set behavior." });
  assert.equal(recovered.status, "recovered_and_attested");
  const verified = await f.app.verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation(f.ownerId, recovered.attestation);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.current, true);
  assert.equal((await f.app.auditRecoverySloRetentionDecisionGateAnchorRecoveryAttestations(f.ownerId)).status, "healthy");
});

test("Batch 146: application APIs and HTTP routes expose recovery attestation, continuity proofs, and freshness approvals", async t => {
  const f = await fixture(t);
  for (const name of ["recoverAndAttestRecoverySloRetentionDecisionGateAnchor", "verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation",
    "auditRecoverySloRetentionDecisionGateAnchorRecoveryAttestations", "createRecoverySloRootTrustBaselineCheckpointContinuityProof",
    "verifyRecoverySloRootTrustBaselineCheckpointContinuityProof", "auditRecoverySloRootTrustBaselineCheckpointContinuityProofs",
    "getRecoverySloRetentionFreshnessPolicyApprovalStatus", "prepareRecoverySloRetentionFreshnessPolicyChangeApproval",
    "applyRecoverySloRetentionFreshnessPolicyChangeApproval", "auditRecoverySloRetentionFreshnessPolicyApprovals"]) {
    assert.equal(typeof f.app[name], "function", `${name} should exist`);
  }
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /decision-gate\/anchor\/recovery\/attest/);
  assert.match(server, /baseline-lifecycle\/checkpoint-continuity\/proofs/);
  assert.match(server, /freshness-policy\/approvals\/challenges/);
});
