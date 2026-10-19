import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import { runExternalTrustAnchorProviderConformance } from "../../apps/agentic/backend/external-trust-anchor-conformance.js";

const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
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
    remove(ownerId) { anchors.delete(ownerId); },
    replace(ownerId, value) { anchors.set(ownerId, structuredClone(value)); }
  };
  return provider;
}

async function setup(t, { ownerId = "owner-b117", provider = createAnchorProvider(), storage = null, root = null } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b117-anchor-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const first = generateKeyPairSync("ed25519");
  const app = createAgenticApplication({ storage: storage || createStorage({ root: storageRoot }),
    clock: () => new Date(time).toISOString(), integrityAttestationPublicKeys: { root1: first.publicKey }, attestationTrustAnchor: provider });
  return { app, ownerId, root: storageRoot, provider, first, now: () => new Date(time).toISOString(), advance: ms => { time += ms; } };
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

async function journalRecords(fixture) {
  return (await fixture.app.store.listEvidence(fixture.ownerId))
    .filter(item => item.kind === "recovery-reconciliation-attestation-trust-transition-journal");
}

test("Batch 117: provider conformance probe passes a monotonic compare-and-set implementation", async () => {
  const provider = createAnchorProvider();
  const report = await runExternalTrustAnchorProviderConformance(provider, { allowWrites: true });
  assert.equal(report.conformant, true);
  assert.deepEqual(report.findings, []);
  assert.equal(report.writesPerformed, 3);
  assert.equal(report.checks.length, 8);
});

test("Batch 117: provider conformance probe rejects an implementation that overwrites stale CAS requests", async () => {
  const anchors = new Map();
  const provider = {
    async read(ownerId) { return anchors.has(ownerId) ? structuredClone(anchors.get(ownerId)) : null; },
    async compareAndSet(ownerId, _expectedDigest, candidate) {
      anchors.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
  const report = await runExternalTrustAnchorProviderConformance(provider, {
    ownerId: "__agentic_v4_conformance__bad-cas-0001", allowWrites: true
  });
  assert.equal(report.conformant, false);
  assert.ok(report.findings.includes("CONFORMANCE_STALE_CREATE_IS_REJECTED_WITHOUT_OVERWRITE"));
});

test("Batch 117: conformance probe requires explicit write permission and a disposable namespace", async () => {
  const provider = createAnchorProvider();
  await assert.rejects(() => runExternalTrustAnchorProviderConformance(provider), /allowWrites:true/);
  await assert.rejects(() => runExternalTrustAnchorProviderConformance(provider, { ownerId: "real-production-owner", allowWrites: true }), /disposable/);
});

test("Batch 117: a successful trust rotation leaves a completed durable cross-store journal", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  const result = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, input);
  assert.equal(result.crossStoreStatus, "completed");
  assert.match(result.crossStoreOperationId, /^ledger-integrity-trust-transition-journal-/);
  const records = await journalRecords(fixture);
  assert.equal(records.length, 1);
  assert.equal(records[0].snapshot.status, "completed");
  assert.deepEqual(records[0].snapshot.history.map(item => item.status), ["prepared", "local_committed", "challenge_applied", "completed"]);
});

test("Batch 117: anchor-write failure is journaled and recovery completes without replaying the local transition", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  fixture.provider.failWrites = true;
  const applied = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  assert.equal(applied.crossStoreStatus, "anchor_pending");
  assert.equal((await journalRecords(fixture))[0].snapshot.status, "anchor_pending");
  fixture.provider.failWrites = false;
  const recoveryRuns = await Promise.all([
    fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreTransitions(fixture.ownerId),
    fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreTransitions(fixture.ownerId)
  ]);
  assert.ok(recoveryRuns.every(item => item.status !== "degraded"));
  assert.ok(recoveryRuns.some(item => item.recovered === 1));
  assert.equal((await journalRecords(fixture))[0].snapshot.status, "completed");
  const trust = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  assert.equal(trust.revision, 1);
  assert.equal((await fixture.provider.read(fixture.ownerId)).revision, 1);
});

test("Batch 117: recovery repairs the challenge/journal gap after local commit without a second rotation", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b117-crash-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const baseStorage = createStorage({ root });
  let failChallengeWrite = false;
  let failed = false;
  const storage = {
    read: baseStorage.read, write: baseStorage.write, remove: baseStorage.remove, list: baseStorage.list,
    atomicUpdate: async (key, updater) => {
      if (failChallengeWrite && !failed && key.includes("ledger-integrity-trust-challenge-")) {
        failed = true;
        throw Object.assign(new Error("simulated crash before challenge status write"), { code: "SIMULATED_CRASH" });
      }
      return baseStorage.atomicUpdate(key, updater);
    }
  };
  const fixture = await setup(t, { root, storage });
  const { challenge, input } = await makeChallenge(fixture);
  failChallengeWrite = true;
  await assert.rejects(() => fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, input), hasCode("SIMULATED_CRASH"));
  assert.equal((await journalRecords(fixture))[0].snapshot.status, "local_committed");
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId)).revision, 1);
  failChallengeWrite = false;
  const recovery = await fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreTransitions(fixture.ownerId);
  assert.equal(recovery.status, "recovered");
  assert.equal((await journalRecords(fixture))[0].snapshot.status, "completed");
  const trust = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  assert.equal(trust.revision, 1);
  const challengeRecord = await fixture.app.store.getEvidence(fixture.ownerId, challenge.id);
  assert.equal(challengeRecord.snapshot.status, "applied");
});

test("Batch 117: a stale prepared journal is reported but never automatically aborted", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b117-prepared-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const baseStorage = createStorage({ root });
  let failPolicyWrite = false;
  let failed = false;
  const storage = {
    read: baseStorage.read, write: baseStorage.write, remove: baseStorage.remove, list: baseStorage.list,
    atomicUpdate: async (key, updater) => {
      if (failPolicyWrite && !failed && key.includes("ledger-integrity-trust-policy-")) {
        failed = true;
        throw Object.assign(new Error("simulated pre-commit failure"), { code: "SIMULATED_PRECOMMIT" });
      }
      return baseStorage.atomicUpdate(key, updater);
    }
  };
  const fixture = await setup(t, { root, storage });
  const { challenge, input } = await makeChallenge(fixture);
  failPolicyWrite = true;
  await assert.rejects(() => fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, input), hasCode("SIMULATED_PRECOMMIT"));
  assert.equal((await journalRecords(fixture))[0].snapshot.status, "prepared");
  fixture.advance(60_000);
  const recovery = await fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreTransitions(fixture.ownerId, { staleAfterMs: 1000 });
  assert.equal(recovery.outcomes[0].status, "awaiting_local_commit");
  assert.equal(recovery.outcomes[0].stale, true);
  assert.equal(recovery.outcomes[0].automaticAbortAllowed, false);
  assert.equal((await journalRecords(fixture))[0].snapshot.status, "prepared");
  failPolicyWrite = false;
  const applied = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  assert.equal(applied.crossStoreStatus, "completed");
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId)).revision, 1);
});

test("Batch 117: cross-store recovery status is read-only, bounded, and owner-scoped", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  const status = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreRecoveryStatus(fixture.ownerId, { limit: 1 });
  assert.equal(status.status, "healthy");
  assert.equal(status.total, 1);
  assert.equal(status.items.length, 1);
  assert.equal(status.mutationAllowed, false);
  const other = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreRecoveryStatus("other-owner");
  assert.equal(other.total, 0);
  assert.equal(other.status, "empty");
});

test("Batch 117: corrupted journal is reported and cannot authorize automatic recovery", async t => {
  const fixture = await setup(t);
  const { challenge, input } = await makeChallenge(fixture);
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
  const record = (await journalRecords(fixture))[0];
  const tampered = { ...record, snapshot: { ...record.snapshot, anchorStatus: "tampered" } };
  await fixture.app.store.putEvidence(fixture.ownerId, tampered, { expectedVersion: record._storage.version });
  const status = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreRecoveryStatus(fixture.ownerId);
  assert.equal(status.status, "degraded");
  assert.equal(status.counts.invalid, 1);
  const recovery = await fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreTransitions(fixture.ownerId);
  assert.equal(recovery.status, "degraded");
  assert.equal(recovery.blocked, 1);
});

test("Batch 117: application boundary and authenticated HTTP route mappings expose cross-store recovery", async t => {
  const fixture = await setup(t);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.equal(typeof fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreRecoveryStatus, "function");
  assert.equal(typeof fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerAttestationTrustCrossStoreTransitions, "function");
  assert.match(source, /attestation-trust\/cross-store-recovery"/);
  assert.match(source, /attestation-trust\/cross-store-recovery\/recover/);
});
