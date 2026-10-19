import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createRecoverySloExternalSnapshotCheckpointService } from "../../apps/agentic/backend/recovery-slo-external-snapshot-checkpoint.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
const hasCode = code => error => error?.code === code;
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b148-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const build = (overrides = {}) => createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRetentionFreshnessPolicyApprovalAnchor: overrides.approvalAnchor ?? options.approvalAnchor ?? null,
    requireRecoverySloRetentionFreshnessPolicyApprovalAnchor: overrides.requireApprovalAnchor ?? options.requireApprovalAnchor ?? false,
    recoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.intentAnchor ?? options.intentAnchor ?? null,
    requireRecoverySloRetentionDecisionGateRecoveryIntentAnchor: overrides.requireIntentAnchor ?? options.requireIntentAnchor ?? false,
    recoverySloRootTrustBaselineProofRevocationAnchor: overrides.revocationAnchor ?? options.revocationAnchor ?? null,
    requireRecoverySloRootTrustBaselineProofRevocationAnchor: overrides.requireRevocationAnchor ?? options.requireRevocationAnchor ?? false });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b148", now: clock, advance: ms => { nowMs += ms; } };
}
function memoryStore() {
  const values = new Map(); let version = 0;
  return { values,
    async getEvidence(ownerId, id) { const item = values.get(id); return item?.ownerId === ownerId ? structuredClone(item) : null; },
    async listEvidence(ownerId) { return [...values.values()].filter(item => item.ownerId === ownerId).map(item => structuredClone(item)); },
    async putEvidence(ownerId, item, options = {}) {
      const current = values.get(item.id);
      if (current && options.expectedVersion != null && current._storage?.version !== options.expectedVersion) throw new Error("version conflict");
      if (!current && options.overwrite === false && values.has(item.id)) throw new Error("exists");
      const saved = { ...structuredClone(item), ownerId, _storage: { version: ++version } };
      values.set(item.id, saved); return structuredClone(saved);
    }
  };
}
function sourceState() { return { count: 1, status: "healthy", historyNotProven: false, snapshot: { revision: 1, entries: [{ id: "evt-1", digest: "a".repeat(64) }] } }; }

test("Batch 148: freshness-policy approval anchor conformance validates CAS and retains an idempotent report", async t => {
  const anchor = provider("https://freshness-approval-conformance-148.example");
  const f = await fixture(t, { approvalAnchor: anchor });
  const challenge = await f.app.prepareRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance(f.ownerId, {
    reason: "Verify external freshness approval checkpoint CAS and isolation behavior before production reliance." });
  assert.equal(challenge.writesToProductionNamespace, false);
  const result = await f.app.runRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "conformant");
  assert.equal(result.report.writesToProductionNamespace, false);
  assert.ok(result.report.checks.every(item => item.passed));
  assert.equal((await f.app.runRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation })).idempotent, true);
  assert.equal((await f.app.auditRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance(f.ownerId)).status, "healthy");
});

test("Batch 148: freshness-policy approval anchor conformance reports stale-CAS providers as nonconformant", async t => {
  const anchor = provider("https://freshness-approval-bad-cas-148.example", { rejectCas: true });
  const f = await fixture(t, { approvalAnchor: anchor });
  const challenge = await f.app.prepareRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance(f.ownerId, {
    reason: "Detect an external provider that rejects even valid genesis CAS writes and fail closed." });
  const result = await f.app.runRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "nonconformant");
  assert.ok(result.report.findings.length > 0);
  assert.equal(anchor.records.size, 0);
  assert.equal((await f.app.auditRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance(f.ownerId)).status, "healthy");
});

test("Batch 148: generic snapshot checkpoint requires explicit enrollment and advances monotonically", async t => {
  const store = memoryStore(), anchor = provider("https://intent-checkpoint-148.example");
  let source = sourceState();
  const service = createRecoverySloExternalSnapshotCheckpointService({ store, provider: anchor, domain: "recovery_intent_test",
    kind: "recovery-intent-test-checkpoint", sourceReader: async ownerId => ownerId === "owner-a" ? source : { status: "not_initialized", count: 0, snapshot: { revision: 0, entries: [] } }, clock: () => "2026-10-12T00:00:00.000Z" });
  assert.equal((await service.getExternalSnapshotCheckpointStatus("owner-a")).status, "enrollment_required");
  const enrollment = await service.prepareExternalSnapshotCheckpointEnrollment("owner-a", { reason: "Enroll the existing recovery-intent snapshot after its local integrity audit has passed." });
  const enrolled = await service.applyExternalSnapshotCheckpointEnrollment("owner-a", enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  assert.equal((await service.getExternalSnapshotCheckpointStatus("owner-a")).status, "anchored");
  source = { ...source, count: 2, snapshot: { revision: 2, entries: [...source.snapshot.entries, { id: "evt-2", digest: "b".repeat(64) }] } };
  assert.equal((await service.getExternalSnapshotCheckpointStatus("owner-a")).status, "behind_local");
  const advanced = await service.reconcileExternalSnapshotCheckpoint("owner-a");
  assert.equal(advanced.anchorSequence, 2);
  assert.equal((await service.getExternalSnapshotCheckpointStatus("owner-a")).status, "anchored");
  assert.equal((await service.getExternalSnapshotCheckpointStatus("owner-b")).status, "not_initialized");
});

test("Batch 148: snapshot checkpoint fails closed on rollback and does not enroll over a missing enrolled anchor", async t => {
  const store = memoryStore(), anchor = provider("https://revocation-checkpoint-rollback-148.example");
  const source = sourceState();
  const service = createRecoverySloExternalSnapshotCheckpointService({ store, provider: anchor, domain: "proof_revocation_test",
    kind: "proof-revocation-test-checkpoint", sourceReader: async () => source, clock: () => "2026-10-12T00:00:00.000Z" });
  const challenge = await service.prepareExternalSnapshotCheckpointEnrollment("owner-a", { reason: "Enroll a previously audited proof revocation state into its external checkpoint." });
  await service.applyExternalSnapshotCheckpointEnrollment("owner-a", challenge.challengeId, { confirmation: challenge.confirmation });
  const scope = [...anchor.records.keys()][0]; anchor.records.delete(scope);
  assert.equal((await service.getExternalSnapshotCheckpointStatus("owner-a")).status, "rollback_suspected");
  await assert.rejects(service.reconcileExternalSnapshotCheckpoint("owner-a"), hasCode("EXTERNAL_SNAPSHOT_CHECKPOINT_RECONCILIATION_BLOCKED"));
  await assert.rejects(service.prepareExternalSnapshotCheckpointEnrollment("owner-a", { reason: "Attempt to recreate a missing anchor after enrollment and conceal rollback." }),
    hasCode("EXTERNAL_SNAPSHOT_CHECKPOINT_ENROLLMENT_BLOCKED"));
});

test("Batch 148: interrupted external CAS can be reconciled without rewriting local snapshot history", async t => {
  const store = memoryStore(), anchor = provider("https://intent-checkpoint-retry-148.example");
  let source = sourceState();
  const service = createRecoverySloExternalSnapshotCheckpointService({ store, provider: anchor, domain: "recovery_intent_retry",
    kind: "recovery-intent-retry-checkpoint", sourceReader: async () => source, clock: () => "2026-10-12T00:00:00.000Z" });
  const enrollment = await service.prepareExternalSnapshotCheckpointEnrollment("owner-a", { reason: "Enroll the original recovery snapshot before testing recoverable provider failure." });
  await service.applyExternalSnapshotCheckpointEnrollment("owner-a", enrollment.challengeId, { confirmation: enrollment.confirmation });
  source = { ...source, count: 2, snapshot: { revision: 2, entries: [...source.snapshot.entries, { id: "evt-2", digest: "c".repeat(64) }] } };
  anchor.rejectCas = true;
  await assert.rejects(service.reconcileExternalSnapshotCheckpoint("owner-a"), hasCode("EXTERNAL_SNAPSHOT_CHECKPOINT_CAS_CONFLICT"));
  assert.equal((await service.getExternalSnapshotCheckpointStatus("owner-a")).status, "behind_local");
  anchor.rejectCas = false;
  assert.equal((await service.reconcileExternalSnapshotCheckpoint("owner-a")).status, "anchored");
  assert.equal((await service.auditExternalSnapshotCheckpoint("owner-a")).status, "healthy");
});

test("Batch 148: application wires independent recovery-intent and proof-revocation checkpoint domains", async t => {
  const intentAnchor = provider("https://recovery-intent-domain-148.example");
  const revocationAnchor = provider("https://proof-revocation-domain-148.example");
  const f = await fixture(t, { intentAnchor, revocationAnchor });
  assert.equal((await f.app.getRecoverySloRetentionDecisionGateRecoveryIntentCheckpointStatus(f.ownerId)).status, "not_initialized");
  assert.equal((await f.app.getRecoverySloRootTrustBaselineProofRevocationCheckpointStatus(f.ownerId)).status, "not_initialized");
  for (const name of ["prepareRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance", "runRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance",
    "auditRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance", "reconcileRecoverySloRetentionDecisionGateRecoveryIntentCheckpoint",
    "prepareRecoverySloRetentionDecisionGateRecoveryIntentCheckpointEnrollment", "auditRecoverySloRetentionDecisionGateRecoveryIntentCheckpoint",
    "reconcileRecoverySloRootTrustBaselineProofRevocationCheckpoint", "prepareRecoverySloRootTrustBaselineProofRevocationCheckpointEnrollment",
    "auditRecoverySloRootTrustBaselineProofRevocationCheckpoint"]) assert.equal(typeof f.app[name], "function", name);
  const unconfigured = await fixture(t);
  assert.throws(() => unconfigured.build({ requireIntentAnchor: true }), /External recovery-intent checkpoint diwajibkan/);
  assert.throws(() => unconfigured.build({ requireRevocationAnchor: true }), /External proof-revocation checkpoint diwajibkan/);
});

test("Batch 148: application exposes conformance and both checkpoint enrollment/reconciliation HTTP routes", async t => {
  const f = await fixture(t);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["freshness-policy/approval-anchor/conformance/challenges", "decision-gate/recovery-intents/checkpoint/status",
    "decision-gate/recovery-intents/checkpoint/enrollments", "root-trust/baseline-continuity/revocation-checkpoint/status",
    "root-trust/baseline-continuity/revocation-checkpoint/enrollments"]) assert.ok(server.includes(route), route);
  assert.equal(typeof f.app.auditRecoverySloRetentionDecisionGateRecoveryIntentContinuity, "function");
  assert.equal(typeof f.app.auditRecoverySloRootTrustBaselineContinuityProofRevocations, "function");
});
