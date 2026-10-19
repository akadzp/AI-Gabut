import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createRecoverySloExternalSnapshotCheckpointService } from "../../apps/agentic/backend/recovery-slo-external-snapshot-checkpoint.js";
import { createRecoverySloCrossDomainSnapshotAnchorGovernanceService } from "../../apps/agentic/backend/recovery-slo-cross-domain-snapshot-anchor-governance.js";
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
  return { providerIdentity: identity, baseUrl: identity, records, rejectCas,
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
function sourceState() { return { count: 1, status: "healthy", historyNotProven: false,
  snapshot: { revision: 1, entries: [{ id: "evt-1", digest: "a".repeat(64) }] } }; }
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b149-"));
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
    recoverySloCrossDomainSnapshotAnchorRetentionDays: overrides.retentionDays ?? options.retentionDays ?? 90 });
  return { app: build(), build, root, ownerId: options.ownerId || "owner-b149", now: clock, advance: ms => { nowMs += ms; } };
}

test("Batch 149: recovery-intent and revocation providers pass isolated disposable-namespace conformance", async t => {
  const intentAnchor = provider("https://intent-anchor-149.example");
  const revocationAnchor = provider("https://revocation-anchor-149.example");
  const f = await fixture(t, { intentAnchor, revocationAnchor });
  for (const domain of ["retention_decision_gate_recovery_intent", "root_trust_baseline_proof_revocation"]) {
    const challenge = await f.app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, {
      domain, reason: "Validate isolated CAS semantics before relying on this snapshot checkpoint provider." });
    assert.equal(challenge.writesToProductionNamespace, false);
    const result = await f.app.runRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
    assert.equal(result.status, "conformant");
    assert.ok(result.report.checks.every(check => check.passed));
    assert.equal(result.report.writesToProductionNamespace, false);
    assert.equal((await f.app.runRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation })).idempotent, true);
  }
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAnchorIndependence(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAnchorGovernance(f.ownerId)).status, "healthy");
});

test("Batch 149: a provider that fails CAS is nonconformant and report tampering is detected", async t => {
  const bad = provider("https://bad-anchor-149.example", { rejectCas: true });
  const f = await fixture(t, { intentAnchor: bad, revocationAnchor: provider("https://other-anchor-149.example") });
  const challenge = await f.app.prepareRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, {
    domain: "retention_decision_gate_recovery_intent", reason: "Detect a provider that refuses valid genesis CAS and do not trust its behavior." });
  const result = await f.app.runRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "nonconformant");
  assert.ok(result.report.findings.length > 0);
  assert.equal(bad.records.size, 0);
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAnchorConformance(f.ownerId)).status, "nonconformant");
  assert.equal((await f.app.auditRecoverySloCrossDomainSnapshotAnchorGovernance(f.ownerId)).status, "unhealthy");
});

test("Batch 149: identity collisions across distinct provider objects are reported without claiming infrastructure independence", async () => {
  const store = memoryStore(), first = provider("https://same-anchor-149.example"), second = provider("https://same-anchor-149.example/");
  const governance = createRecoverySloCrossDomainSnapshotAnchorGovernanceService({ store, clock: () => "2026-10-12T00:00:00.000Z",
    domains: [{ domain: "recovery_intent_test", provider: first }, { domain: "proof_revocation_test", provider: second }] });
  const audit = await governance.auditRecoverySloCrossDomainSnapshotAnchorIndependence("owner-a");
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "CROSS_DOMAIN_PROVIDER_IDENTITY_COLLISION"));
  assert.equal(audit.infrastructureIndependenceProven, false);
});


test("Batch 149: retained conformance report tampering is detected", async () => {
  const store = memoryStore(), intent = provider("https://intent-report-149.example"), revocation = provider("https://revocation-report-149.example");
  const governance = createRecoverySloCrossDomainSnapshotAnchorGovernanceService({ store, clock: () => "2026-10-12T00:00:00.000Z",
    domains: [{ domain: "recovery_intent_test", provider: intent }, { domain: "proof_revocation_test", provider: revocation }] });
  const challenge = await governance.prepareRecoverySloCrossDomainSnapshotAnchorConformance("owner-a", { domain: "recovery_intent_test",
    reason: "Verify the report record remains bound to its completed conformance challenge and provider identity." });
  await governance.runRecoverySloCrossDomainSnapshotAnchorConformance("owner-a", challenge.challengeId, { confirmation: challenge.confirmation });
  const retained = [...store.values.values()].find(item => item.kind === "recovery-slo-cross-domain-snapshot-anchor-conformance-report");
  store.values.set(retained.id, { ...retained, reportDigest: "f".repeat(64) });
  const audit = await governance.auditRecoverySloCrossDomainSnapshotAnchorConformance("owner-a");
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "CROSS_DOMAIN_SNAPSHOT_CONFORMANCE_RETENTION_INVALID"));
});

test("Batch 149: checkpoint freshness and retention audit flags stale anchors and old unused enrollment challenges", async () => {
  const store = memoryStore(), anchor = provider("https://intent-checkpoint-freshness-149.example");
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z"), source = sourceState();
  const clock = () => new Date(nowMs).toISOString();
  const checkpoint = createRecoverySloExternalSnapshotCheckpointService({ store, provider: anchor, domain: "recovery_intent_test",
    kind: "recovery-intent-test-checkpoint", sourceReader: async () => source, clock });
  const domains = [{ domain: "recovery_intent_test", provider: anchor, service: checkpoint, kind: "recovery-intent-test-checkpoint", required: true }];
  const governance = createRecoverySloCrossDomainSnapshotAnchorGovernanceService({ store, domains, clock, maxAgeMs: 86400000, futureSkewMs: 60000, retentionDays: 1 });
  const enrollment = await checkpoint.prepareExternalSnapshotCheckpointEnrollment("owner-a", { reason: "Enroll the existing snapshot after source integrity checks are complete." });
  await checkpoint.applyExternalSnapshotCheckpointEnrollment("owner-a", enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal((await governance.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention("owner-a")).status, "healthy");
  nowMs += 3 * 86400000;
  const stale = await governance.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention("owner-a");
  assert.equal(stale.status, "degraded");
  assert.equal(stale.checkpoints[0].freshnessStatus, "stale");
  assert.ok(stale.retention.some(item => item.retentionClass === "retention_overdue_review"));
  const marker = [...store.values.values()].find(item => item.kind === "recovery-intent-test-checkpoint-marker");
  store.values.set(marker.id, { ...marker, snapshotDigest: "f".repeat(64) });
  const tampered = await governance.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention("owner-a");
  assert.equal(tampered.status, "unhealthy");
  assert.ok(tampered.findings.some(item => item.code === "CROSS_DOMAIN_CHECKPOINT_LOCAL_RECORD_TAMPERED"));
});


test("Batch 149: future checkpoint timestamps outside the configured skew fail the governance audit", async () => {
  const store = memoryStore(), anchor = provider("https://future-anchor-149.example");
  const service = { async getExternalSnapshotCheckpointStatus() { return { status: "anchored", anchorSequence: 1,
    anchorDigest: "a".repeat(64), anchorAnchoredAt: "2026-10-12T00:02:00.000Z", findings: [] }; } };
  const governance = createRecoverySloCrossDomainSnapshotAnchorGovernanceService({ store, clock: () => "2026-10-12T00:00:00.000Z",
    maxAgeMs: 86400000, futureSkewMs: 60000, retentionDays: 90,
    domains: [{ domain: "recovery_intent_test", provider: anchor, service, kind: "recovery-intent-test-checkpoint", required: true }] });
  const audit = await governance.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention("owner-a");
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.checkpoints[0].freshnessStatus, "future_skew_exceeded");
});

test("Batch 149: application exposes cross-domain governance APIs, routes, and bounded policy validation", async t => {
  const f = await fixture(t, { intentAnchor: provider("https://intent-api-149.example"), revocationAnchor: provider("https://revocation-api-149.example") });
  for (const name of ["auditRecoverySloCrossDomainSnapshotAnchorIndependence", "prepareRecoverySloCrossDomainSnapshotAnchorConformance",
    "runRecoverySloCrossDomainSnapshotAnchorConformance", "auditRecoverySloCrossDomainSnapshotAnchorConformance",
    "auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention", "auditRecoverySloCrossDomainSnapshotAnchorGovernance"]) {
    assert.equal(typeof f.app[name], "function", name);
  }
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["cross-domain/snapshot-anchors/independence/audit", "cross-domain/snapshot-anchors/conformance/challenges",
    "cross-domain/snapshot-checkpoints/freshness-retention/audit", "cross-domain/snapshot-checkpoints/governance/audit"]) assert.ok(server.includes(route), route);
  assert.throws(() => f.build({ maxAgeMs: 100 }), /AGENTIC_CROSS_DOMAIN_SNAPSHOT_CHECKPOINT_MAX_AGE_MS/);
  assert.throws(() => f.build({ retentionDays: 0 }), /AGENTIC_CROSS_DOMAIN_SNAPSHOT_CHECKPOINT_RETENTION_DAYS/);
});
