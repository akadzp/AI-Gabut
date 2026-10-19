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
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
const signature = (payload, privateKey) => sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64url");
const hasCode = code => error => error?.code === code;

function createAnchorProvider() {
  const anchors = new Map();
  const provider = {
    failReads: false,
    failWrites: false,
    async read(ownerId) {
      if (provider.failReads) throw Object.assign(new Error("anchor read unavailable"), { code: "ANCHOR_READ_DOWN" });
      const value = anchors.get(ownerId);
      return value ? structuredClone(value) : null;
    },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (provider.failWrites) throw Object.assign(new Error("anchor write unavailable"), { code: "ANCHOR_WRITE_DOWN" });
      const current = anchors.get(ownerId) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: current ? structuredClone(current) : null };
      if (!current) {
        if (candidate.anchorSequence !== 1 || candidate.previousAnchorDigest !== null) return { applied: false, anchor: null };
      } else if (candidate.anchorSequence !== current.anchorSequence + 1 || candidate.previousAnchorDigest !== current.digest
        || candidate.revision <= current.revision) return { applied: false, anchor: structuredClone(current) };
      anchors.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    },
    replace(ownerId, value) { anchors.set(ownerId, structuredClone(value)); }
  };
  return provider;
}

async function setup(t, { ownerId = "owner-b118", provider = createAnchorProvider(), root = null } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b118-anchor-health-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const first = generateKeyPairSync("ed25519");
  const app = createAgenticApplication({ storage: createStorage({ root: storageRoot }), clock: () => new Date(time).toISOString(),
    integrityAttestationPublicKeys: { root1: first.publicKey }, attestationTrustAnchor: provider });
  return { app, ownerId, root: storageRoot, provider, first, advance: ms => { time += ms; } };
}

async function makeChallenge(fixture, keyId = "next1") {
  const next = generateKeyPairSync("ed25519");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId, publicKey: next.publicKey });
  return { next, challenge, input: {
    authorizations: [{ keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) }],
    proofOfPossession: signature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: challenge.payload }, next.privateKey)
  } };
}

async function journals(fixture) {
  return (await fixture.app.store.listEvidence(fixture.ownerId)).filter(item => item.kind === "recovery-reconciliation-attestation-trust-transition-journal");
}

test("Batch 118: read-only cross-store audit reports a completed transition as healthy", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreJournal(fixture.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.counts.completed, 1);
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.findings.length, 0);
  assert.equal(audit.mutationAllowed, false);
  assert.equal(audit.readOnly, true);
});

test("Batch 118: cross-store audit detects a tampered journal without rewriting it", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  const record = (await journals(fixture))[0];
  await fixture.app.store.putEvidence(fixture.ownerId, { ...record, snapshot: { ...record.snapshot, anchorStatus: "tampered" } }, { expectedVersion: record._storage.version });
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreJournal(fixture.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "CROSS_STORE_JOURNAL_INTEGRITY_FAILED"));
  assert.equal((await journals(fixture))[0].snapshot.anchorStatus, "tampered");
});

test("Batch 118: audit detects a cross-store anchor lag after a committed transition", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  fixture.provider.failWrites = true;
  const applied = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  assert.equal(applied.crossStoreStatus, "anchor_pending");
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreJournal(fixture.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.counts.anchor_pending, 1);
  assert.ok(audit.findings.some(item => item.code === "CROSS_STORE_EXTERNAL_ANCHOR_BEHIND_REGISTRY" || item.code === "CROSS_STORE_EXTERNAL_ANCHOR_UNAVAILABLE"));
});

test("Batch 118: anchor health records a bounded telemetry sample for a healthy provider", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  const health = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth(fixture.ownerId);
  assert.equal(health.status, "healthy");
  assert.equal(health.anchorStatus, "anchored");
  assert.equal(health.telemetryPersistenceStatus, "stored");
  assert.equal(health.mutationAllowed, false);
  const telemetry = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId);
  assert.equal(telemetry.status, "healthy");
  assert.equal(telemetry.total, 1);
  assert.equal(telemetry.items[0].status, "healthy");
  assert.ok(telemetry.items[0].latencyMs >= 0);
  assert.match(telemetry.items[0].sampleHash, /^[a-f0-9]{64}$/);
});

test("Batch 118: anchor read outage is reported and captured as unavailable telemetry", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  fixture.provider.failReads = true;
  const health = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth(fixture.ownerId);
  assert.equal(health.status, "unavailable");
  assert.equal(health.anchorStatus, "unavailable");
  const telemetry = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId);
  assert.equal(telemetry.items[0].status, "unavailable");
  assert.equal(telemetry.items[0].errorCode, "ANCHOR_READ_DOWN");
});

test("Batch 118: missing provider is explicit and never claims rollback protection", async t => {
  const fixture = await setup(t, { provider: null });
  const health = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth(fixture.ownerId);
  assert.equal(health.status, "not_configured");
  assert.equal(health.rollbackProtectionEnabled, false);
  assert.equal(health.anchorStatus, "not_configured");
  const telemetry = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId);
  assert.equal(telemetry.items[0].status, "not_configured");
});

test("Batch 118: telemetry integrity failure is reported and corrupt history is not overwritten", async t => {
  const fixture = await setup(t);
  await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth(fixture.ownerId);
  const id = (await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId)).items[0];
  const record = await fixture.app.store.getEvidence(fixture.ownerId, `ledger-integrity-trust-anchor-health-${digest(canonical({ domain: "agentic-v4-trust-anchor-health", ownerId: fixture.ownerId })).slice(0, 32)}`);
  await fixture.app.store.putEvidence(fixture.ownerId, { ...record, snapshot: { ...record.snapshot,
    samples: record.snapshot.samples.map((sample, index) => index === 0 ? { ...sample, latencyMs: sample.latencyMs + 1 } : sample) } }, { expectedVersion: record._storage.version });
  const health = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth(fixture.ownerId);
  assert.equal(health.telemetryPersistenceStatus, "invalid_or_unavailable");
  const telemetry = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId);
  assert.equal(telemetry.status, "unhealthy");
  assert.equal(telemetry.items.length, 0);
  assert.equal((await fixture.app.store.getEvidence(fixture.ownerId, record.id)).snapshot.samples[0].latencyMs, id.latencyMs + 1);
});

test("Batch 118: concurrent health polls preserve unique monotonic sequence numbers", async t => {
  const fixture = await setup(t);
  const results = await Promise.all(Array.from({ length: 6 }, () => fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth(fixture.ownerId)));
  assert.ok(results.every(item => ["healthy", "degraded"].includes(item.status)));
  const telemetry = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId, { limit: 10 });
  assert.equal(telemetry.total, 6);
  assert.deepEqual(telemetry.items.map(item => item.sequence).sort((a, b) => a - b), [1, 2, 3, 4, 5, 6]);
});

test("Batch 118: telemetry listing is owner-scoped, bounded, and read-only", async t => {
  const fixture = await setup(t);
  await Promise.all([1, 2, 3].map(() => fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth(fixture.ownerId)));
  const before = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId);
  const limited = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId, { limit: 2 });
  const other = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry("other-owner");
  const after = await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(fixture.ownerId);
  assert.equal(limited.items.length, 2);
  assert.equal(limited.truncated, true);
  assert.equal(other.total, 0);
  assert.equal(after.total, before.total);
  assert.equal(after.readOnly, true);
});

test("Batch 118: cross-store audit and health route mappings are exposed", async t => {
  const fixture = await setup(t);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.equal(typeof fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreJournal, "function");
  assert.equal(typeof fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealth, "function");
  assert.equal(typeof fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry, "function");
  assert.match(source, /attestation-trust\/cross-store-recovery\/audit/);
  assert.match(source, /attestation-trust\/anchor\/health/);
  assert.match(source, /attestation-trust\/anchor\/health\/telemetry/);
});

test("Batch 118: cross-store audit is bounded and explicitly refuses mutation authority", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreJournal(fixture.ownerId, { limit: 1, findingLimit: 1 });
  assert.equal(audit.checked, 1);
  assert.equal(audit.truncated, false);
  assert.equal(audit.readOnly, true);
  assert.equal(audit.automaticRepairAllowed, false);
  assert.equal(audit.mutationAllowed, false);
});
