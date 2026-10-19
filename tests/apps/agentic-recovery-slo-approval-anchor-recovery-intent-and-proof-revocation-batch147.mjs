import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createRecoverySloRetentionDecisionGateRecoveryIntentContinuityService } from "../../apps/agentic/backend/recovery-slo-retention-decision-gate-recovery-intent-continuity.js";
import { createRecoverySloRetentionDecisionGateAnchorRecoveryAttestationService } from "../../apps/agentic/backend/recovery-slo-retention-decision-gate-anchor-recovery-attestation.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b147-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRetentionFreshnessPolicyApprovalAnchor: overrides.approvalAnchor ?? options.approvalAnchor ?? null,
    requireRecoverySloRetentionFreshnessPolicyApprovalAnchor: overrides.requireApprovalAnchor ?? options.requireApprovalAnchor ?? false,
    recoverySloRootRecoveryTrustAnchor: overrides.rootAnchor ?? options.rootAnchor ?? null,
    recoverySloRootTrustBaselineLifecycleAnchor: overrides.lifecycleAnchor ?? options.lifecycleAnchor ?? null,
    recoverySloRootTrustConformanceBaselineSigner: overrides.baselineSigner ?? options.baselineSigner ?? null,
    recoverySloRootTrustConformanceBaselineKeyId: overrides.baselineKeyId ?? options.baselineKeyId ?? null,
    recoverySloRootTrustConformanceBaselinePublicKeys: overrides.baselinePublicKeys ?? options.baselinePublicKeys ?? null,
    recoverySloRetentionReconciliationAttestationMaxAgeMs: overrides.maxAgeMs ?? options.maxAgeMs ?? 86400000,
    recoverySloRetentionReconciliationAttestationFutureSkewMs: overrides.futureSkewMs ?? options.futureSkewMs ?? 60000,
    recoverySloRetentionDecisionGateRecoverySigner: overrides.recoverySigner ?? options.recoverySigner ?? null,
    recoverySloRetentionDecisionGateRecoveryKeyId: overrides.recoveryKeyId ?? options.recoveryKeyId ?? null,
    recoverySloRetentionDecisionGateRecoveryPublicKeys: overrides.recoveryPublicKeys ?? options.recoveryPublicKeys ?? null,
    requireRecoverySloRetentionDecisionGateRecoveryAttestation: overrides.requireRecoveryAttestation ?? options.requireRecoveryAttestation ?? false });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b147", now: clock, advance: ms => { nowMs += ms; } };
}
async function approvePolicy(app, ownerId, targetPolicy, reason = "Approve a controlled freshness policy change after evaluating current decision risk and operational impact.") {
  const challenge = await app.prepareRecoverySloRetentionFreshnessPolicyChangeApproval(ownerId, { targetPolicy, reason });
  return { challenge, result: await app.applyRecoverySloRetentionFreshnessPolicyChangeApproval(ownerId, challenge.challengeId, { confirmation: challenge.confirmation }) };
}
async function enrollBaseline(f, key) {
  const source = await f.app.prepareRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, {
    reason: "Create a root-trust provider conformance report before baseline lifecycle enrollment." });
  await f.app.runRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, source.challengeId, { confirmation: source.confirmation });
  const challenge = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: source.challengeId,
    reason: "Enroll the baseline lifecycle before creating a checkpoint continuity proof." });
  return f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}

test("Batch 147: freshness-policy approvals are externally checkpointed and advance monotonically", async t => {
  const anchor = provider("https://freshness-approval-anchor-147.example");
  const f = await fixture(t, { approvalAnchor: anchor });
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId)).status, "not_initialized");
  const { result } = await approvePolicy(f.app, f.ownerId, { maxAgeMs: 3600000, futureSkewMs: 30000 });
  assert.equal(result.externalAnchor.status, "anchored");
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId)).anchorSequence, 1);
  assert.equal((await f.app.auditRecoverySloRetentionFreshnessPolicyApprovalAnchor(f.ownerId)).status, "deployment_pending");
  const aligned = f.build({ approvalAnchor: anchor, maxAgeMs: 3600000, futureSkewMs: 30000 });
  await approvePolicy(aligned, f.ownerId, { maxAgeMs: 1800000, futureSkewMs: 15000 });
  const status = await aligned.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId);
  assert.equal(status.status, "anchored");
  assert.equal(status.anchorSequence, 2);
  assert.equal(status.historyNotProven, true);
});

test("Batch 147: failed external CAS leaves approval pending and can be safely reconciled", async t => {
  const anchor = provider("https://freshness-approval-cas-147.example", { rejectCas: true });
  const f = await fixture(t, { approvalAnchor: anchor });
  await assert.rejects(approvePolicy(f.app, f.ownerId, { maxAgeMs: 7200000, futureSkewMs: 45000 }), hasCode("RETENTION_FRESHNESS_POLICY_ANCHOR_CAS_CONFLICT"));
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId)).status, "anchor_pending");
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalStatus(f.ownerId)).status, "external_anchor_pending");
  anchor.rejectCas = false;
  const reconciled = await f.app.reconcileRecoverySloRetentionFreshnessPolicyApprovalAnchor(f.ownerId);
  assert.equal(reconciled.status, "anchored");
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId)).anchorSequence, 1);
});

test("Batch 147: missing external approval anchor after enrollment is treated as rollback", async t => {
  const anchor = provider("https://freshness-approval-rollback-147.example");
  const f = await fixture(t, { approvalAnchor: anchor });
  await approvePolicy(f.app, f.ownerId, { maxAgeMs: 7200000, futureSkewMs: 45000 });
  const key = [...anchor.records.keys()][0];
  anchor.records.delete(key);
  assert.equal((await f.app.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId)).status, "rollback_suspected");
  assert.equal((await f.app.auditRecoverySloRetentionFreshnessPolicyApprovalAnchor(f.ownerId)).status, "unhealthy");
});

test("Batch 147: pre-existing multi-revision approval history requires explicit enrollment and remains history-unproven", async t => {
  const f = await fixture(t);
  await approvePolicy(f.app, f.ownerId, { maxAgeMs: 3600000, futureSkewMs: 30000 });
  const aligned = f.build({ maxAgeMs: 3600000, futureSkewMs: 30000 });
  await approvePolicy(aligned, f.ownerId, { maxAgeMs: 1800000, futureSkewMs: 15000 });
  const anchor = provider("https://freshness-approval-enroll-147.example");
  const anchoredApp = f.build({ approvalAnchor: anchor, maxAgeMs: 1800000, futureSkewMs: 15000 });
  assert.equal((await anchoredApp.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId)).status, "enrollment_required");
  const challenge = await anchoredApp.prepareRecoverySloRetentionFreshnessPolicyApprovalAnchorEnrollment(f.ownerId, {
    reason: "Enroll the already approved local policy history into an independent external checkpoint after review." });
  const result = await anchoredApp.applyRecoverySloRetentionFreshnessPolicyApprovalAnchorEnrollment(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "enrolled");
  assert.equal(result.historyNotProven, true);
  assert.equal((await anchoredApp.getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus(f.ownerId)).status, "anchored");
});

test("Batch 147: recovery-intent continuity audit detects invalid digests and reports recoverable interruptions", async () => {
  const ownerId = "owner-intent-b147", at = "2026-10-12T00:00:00.000Z";
  const eventUnsigned = { sequence: 1, phase: "prepared", stateStatus: "prepared", at, previousTransitionDigest: null };
  const transitionHistory = [{ ...eventUnsigned, transitionDigest: sha256(canonical(eventUnsigned)) }];
  const intentUnsigned = { id: "intent-b147", ownerId, kind: "recovery-slo-retention-decision-gate-anchor-recovery-intent", schemaVersion: 1,
    status: "prepared", reason: "Recover a previously interrupted decision-gate anchor operation safely.", createdAt: at,
    before: { status: "behind_local", total: 4, anchorSequence: 3, anchorDigest: "a".repeat(64), historyNotProven: false }, transitionHistory };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  const rows = [intent];
  const store = { async listEvidence(owner) { return owner === ownerId ? structuredClone(rows) : []; } };
  const anchorService = { async getRecoverySloRetentionDecisionGateAnchorStatus() { return { status: "anchored", total: 5, anchorSequence: 5, anchorDigest: "b".repeat(64), findings: [] }; } };
  const attestationService = { async verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation() { return { historicallyValid: true, findings: [] }; } };
  const service = createRecoverySloRetentionDecisionGateRecoveryIntentContinuityService({ store, anchorService, attestationService });
  const healthy = await service.auditRecoverySloRetentionDecisionGateRecoveryIntentContinuity(ownerId);
  assert.equal(healthy.status, "recoverable");
  assert.equal(healthy.recoverableInterruptions, 1);
  assert.equal(healthy.historyNotProven, false);
  rows[0] = { ...rows[0], reason: "tampered" };
  assert.equal((await service.auditRecoverySloRetentionDecisionGateRecoveryIntentContinuity(ownerId)).status, "unhealthy");
  const changedTransition = { ...intent, transitionHistory: [{ ...intent.transitionHistory[0], phase: "completed" }] };
  delete changedTransition.digest;
  changedTransition.digest = digestRecord(changedTransition);
  rows[0] = changedTransition;
  const chainTamper = await service.auditRecoverySloRetentionDecisionGateRecoveryIntentContinuity(ownerId);
  assert.equal(chainTamper.status, "unhealthy");
  assert.ok(chainTamper.findings.some(item => item.code === "RETENTION_DECISION_GATE_RECOVERY_INTENT_TRANSITION_CHAIN_INVALID"));
});

test("Batch 147: real recovery flow records a hash-linked intent transition history that audits cleanly", async () => {
  const ownerId = "owner-recovery-transition-b147", signing = keyPair("recovery-transition-b147");
  const values = new Map(), retained = [];
  const store = {
    async listEvidence(owner) { return [...values.values()].filter(item => item.ownerId === owner).map(item => structuredClone(item)); },
    async getEvidence(owner, id) { const item = values.get(id); return item?.ownerId === owner ? structuredClone(item) : null; },
    async putEvidence(owner, item, options = {}) {
      const current = values.get(item.id);
      if (current && options.expectedVersion != null && current._storage?.version !== options.expectedVersion) throw new Error("version conflict");
      if (!current && options.overwrite === false && values.has(item.id)) throw new Error("exists");
      const saved = { ...structuredClone(item), ownerId: owner, _storage: { version: (current?._storage?.version || 0) + 1 } };
      values.set(item.id, saved); return structuredClone(saved);
    }
  };
  let anchor = { status: "behind_local", total: 2, anchorSequence: 1, anchorDigest: "a".repeat(64), historyNotProven: false, findings: [] };
  const anchorService = { async getRecoverySloRetentionDecisionGateAnchorStatus() { return structuredClone(anchor); },
    async reconcileRecoverySloRetentionDecisionGateAnchor() { anchor = { status: "anchored", total: 2, anchorSequence: 2, anchorDigest: "b".repeat(64), historyNotProven: false, findings: [] }; return { status: "anchored", anchored: 1 }; } };
  const retainedEvidenceService = {
    async retainRecoverySloAnchorEvidence(owner, { artifactType, sourceId, payload, retentionDays }) {
      const capturedAt = "2026-10-12T00:00:00.000Z", unsigned = { id: `retained-${retained.length + 1}`, ownerId: owner,
        kind: "recovery-slo-anchor-evidence-retention-record", schemaVersion: 1, artifactType, sourceId, capturedAt,
        expiresAt: "2036-10-09T00:00:00.000Z", retentionDays, status: "retained", payloadDigest: sha256(canonical(payload)), payload, tombstone: null };
      const record = { ...unsigned, digest: digestRecord(unsigned) }; retained.push(record); return structuredClone(record);
    },
    async listRecoverySloRetainedAnchorEvidence(owner) { return { items: retained.filter(item => item.ownerId === owner).map(item => structuredClone(item)) }; },
    async auditRecoverySloRetainedAnchorEvidence() { return { status: "healthy", findings: [] }; }
  };
  const service = createRecoverySloRetentionDecisionGateAnchorRecoveryAttestationService({ store, anchorService, retainedEvidenceService,
    signer: async payload => signPayload(signing, payload), keyId: signing.keyId, publicKeys: { [signing.keyId]: signing.publicKey }, required: true,
    clock: () => "2026-10-12T00:00:00.000Z" });
  const result = await service.recoverAndAttestRecoverySloRetentionDecisionGateAnchor(ownerId, {
    reason: "Recover and attest the provably behind-local checkpoint while preserving each durable intent transition." });
  assert.equal(result.status, "recovered_and_attested");
  const continuity = createRecoverySloRetentionDecisionGateRecoveryIntentContinuityService({ store, anchorService, attestationService: service });
  const audit = await continuity.auditRecoverySloRetentionDecisionGateRecoveryIntentContinuity(ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.completed, 1);
  assert.equal(audit.validAttestations, 1);
  assert.equal(audit.historyNotProven, false);
  const intent = (await store.listEvidence(ownerId)).find(item => item.kind === "recovery-slo-retention-decision-gate-anchor-recovery-intent");
  assert.deepEqual(intent.transitionHistory.map(item => item.phase), ["prepared", "anchor_reconciled", "attestation_draft_persisted", "completed"]);
});

test("Batch 147: baseline continuity proof revocation requires a proven source-trust failure and disables trusted use", async t => {
  const rootAnchor = provider("https://root-anchor-revocation-147.example");
  const lifecycleAnchor = provider("https://baseline-lifecycle-revocation-147.example");
  const signing = keyPair("baseline-revocation-147");
  const f = await fixture(t, { rootAnchor, lifecycleAnchor, baselineSigner: async payload => signPayload(signing, payload),
    baselineKeyId: signing.keyId, baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  await enrollBaseline(f, signing);
  const created = await f.app.createRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, {
    reason: "Capture a retained baseline continuity proof before testing the source trust revocation policy." });
  await assert.rejects(f.app.prepareRecoverySloRootTrustBaselineContinuityProofRevocation(f.ownerId, {
    proof: created.proof, reason: "Attempt revocation while all source continuity evidence remains healthy and trusted." }),
    hasCode("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_SOURCE_STILL_TRUSTED"));
  const rows = await f.app.store.listEvidence(f.ownerId);
  const lifecycleRecord = rows.find(row => row?.kind === "recovery-slo-anchor-evidence-retention-record" && row.artifactType === "root_trust_conformance_baseline_lifecycle");
  assert.ok(lifecycleRecord);
  await f.app.store.putEvidence(f.ownerId, { ...lifecycleRecord, payload: { ...lifecycleRecord.payload, baselineDigest: "f".repeat(64) } },
    { expectedVersion: lifecycleRecord._storage?.version });
  const challenge = await f.app.prepareRecoverySloRootTrustBaselineContinuityProofRevocation(f.ownerId, {
    proof: created.proof, reason: "Revoke the proof because lifecycle source evidence now has a verified integrity conflict." });
  const result = await f.app.applyRecoverySloRootTrustBaselineContinuityProofRevocation(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "revoked");
  const verified = await f.app.verifyRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, created.proof);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.revoked, true);
  assert.equal(verified.valid, false);
  assert.equal(verified.usableAsTrustedEvidence, false);
  assert.equal((await f.app.auditRecoverySloRootTrustBaselineContinuityProofRevocations(f.ownerId)).status, "healthy");
  const rowsAfterRevocation = await f.app.store.listEvidence(f.ownerId);
  const revocationState = rowsAfterRevocation.find(row => row?.kind === "root-trust-baseline-continuity-proof-revocation-state");
  assert.ok(revocationState);
  await f.app.store.putEvidence(f.ownerId, { ...revocationState, status: "not_revoked" }, { expectedVersion: revocationState._storage?.version });
  assert.equal((await f.app.verifyRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, created.proof)).revocationStatus, "unhealthy");
  assert.equal((await f.app.auditRecoverySloRootTrustBaselineContinuityProofRevocations(f.ownerId)).status, "unhealthy");
});

test("Batch 147: revocation challenge rejects replay and source-state changes", async t => {
  const rootAnchor = provider("https://root-anchor-revocation-replay-147.example");
  const lifecycleAnchor = provider("https://baseline-lifecycle-revocation-replay-147.example");
  const signing = keyPair("baseline-revocation-replay-147");
  const f = await fixture(t, { rootAnchor, lifecycleAnchor, baselineSigner: async payload => signPayload(signing, payload),
    baselineKeyId: signing.keyId, baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  await enrollBaseline(f, signing);
  const created = await f.app.createRecoverySloRootTrustBaselineCheckpointContinuityProof(f.ownerId, {
    reason: "Capture a retained proof to verify challenge invalidation and replay protection after source changes." });
  const rows = await f.app.store.listEvidence(f.ownerId);
  const lifecycleRecord = rows.find(row => row?.kind === "recovery-slo-anchor-evidence-retention-record" && row.artifactType === "root_trust_conformance_baseline_lifecycle");
  await f.app.store.putEvidence(f.ownerId, { ...lifecycleRecord, payload: { ...lifecycleRecord.payload, baselineDigest: "e".repeat(64) } },
    { expectedVersion: lifecycleRecord._storage?.version });
  const challenge = await f.app.prepareRecoverySloRootTrustBaselineContinuityProofRevocation(f.ownerId, {
    proof: created.proof, reason: "Prepare a revocation challenge that must become stale when source evidence changes again." });
  const currentRows = await f.app.store.listEvidence(f.ownerId);
  const changed = currentRows.find(row => row.id === lifecycleRecord.id);
  await f.app.store.putEvidence(f.ownerId, { ...changed, payload: { ...changed.payload, baselineDigest: "d".repeat(64) } },
    { expectedVersion: changed._storage?.version });
  await assert.rejects(f.app.applyRecoverySloRootTrustBaselineContinuityProofRevocation(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_SOURCE_CHANGED"));
});

test("Batch 147: application exports and HTTP routes expose approval anchoring, recovery continuity, and proof revocation", async t => {
  const f = await fixture(t);
  assert.throws(() => f.build({ requireApprovalAnchor: true }), /External freshness-policy approval anchor diwajibkan/);
  for (const name of ["getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus", "anchorPendingRecoverySloRetentionFreshnessPolicyApprovals",
    "reconcileRecoverySloRetentionFreshnessPolicyApprovalAnchor", "prepareRecoverySloRetentionFreshnessPolicyApprovalAnchorEnrollment",
    "applyRecoverySloRetentionFreshnessPolicyApprovalAnchorEnrollment", "auditRecoverySloRetentionFreshnessPolicyApprovalAnchor",
    "auditRecoverySloRetentionDecisionGateRecoveryIntentContinuity", "prepareRecoverySloRootTrustBaselineContinuityProofRevocation",
    "applyRecoverySloRootTrustBaselineContinuityProofRevocation", "auditRecoverySloRootTrustBaselineContinuityProofRevocations"]) {
    assert.equal(typeof f.app[name], "function", name);
  }
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /freshness-policy\/approval-anchor\/status/);
  assert.match(server, /recovery-intents\/continuity\/audit/);
  assert.match(server, /checkpoint-continuity\/revocation-challenges/);
});
