import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import { createHttpExternalTrustAnchorProvider } from "../../apps/agentic/backend/external-trust-anchor-client.js";

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
      } else {
        if (candidate.anchorSequence !== current.anchorSequence + 1 || candidate.previousAnchorDigest !== current.digest
          || candidate.revision <= current.revision) return { applied: false, anchor: structuredClone(current) };
      }
      anchors.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    },
    remove(ownerId) { anchors.delete(ownerId); },
    replace(ownerId, value) { anchors.set(ownerId, structuredClone(value)); }
  };
  return provider;
}

async function setup(t, { ownerId = "owner-b116", provider = createAnchorProvider(), keys = null, root = null } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b116-anchor-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const first = keys?.root1 || generateKeyPairSync("ed25519");
  const keyMap = keys?.map || { root1: first.publicKey };
  const app = createAgenticApplication({ storage: createStorage({ root: storageRoot }),
    clock: () => new Date(time).toISOString(), integrityAttestationPublicKeys: keyMap, attestationTrustAnchor: provider });
  return { app, ownerId, root: storageRoot, provider, first, now: () => new Date(time).toISOString(), advance: ms => { time += ms; } };
}

async function rotate(fixture, keyId = "next1") {
  const next = generateKeyPairSync("ed25519");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId, publicKey: next.publicKey });
  const authorizations = [{ keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) }];
  const proofOfPossession = signature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: challenge.payload }, next.privateKey);
  const result = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, { authorizations, proofOfPossession });
  return { next, challenge, result };
}

async function trustRecord(fixture) {
  const id = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-reconciliation-attestation-trust-policy")?.id;
  return id ? fixture.app.store.getEvidence(fixture.ownerId, id) : null;
}

test("Batch 116: genesis is externally anchored before trust transitions and rotations advance the anchor", async t => {
  const fixture = await setup(t);
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus(fixture.ownerId)).status, "missing");
  const { result } = await rotate(fixture);
  assert.equal(result.status, "applied");
  assert.equal(result.externalAnchorStatus, "anchored");
  assert.equal(result.externalAnchorRevision, 1);
  const status = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus(fixture.ownerId);
  assert.equal(status.status, "anchored");
  assert.equal(status.anchorRevision, 1);
  assert.equal(status.rollbackProtectionEnabled, true);
});

test("Batch 116: reconciliation bootstraps genesis idempotently", async t => {
  const fixture = await setup(t);
  const first = await fixture.app.reconcileRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId);
  const second = await fixture.app.reconcileRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId);
  assert.equal(first.status, "healthy");
  assert.equal(second.status, "healthy");
  assert.equal(second.anchorStatus.anchorSequence, 1);
  assert.equal((await fixture.provider.read(fixture.ownerId)).revision, 0);
});

test("Batch 116: a locally rolled-back registry is detected and trust changes fail closed", async t => {
  const fixture = await setup(t);
  const before = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  const original = await trustRecord(fixture);
  await rotate(fixture);
  const current = await trustRecord(fixture);
  await fixture.app.store.putEvidence(fixture.ownerId, { ...current, snapshot: structuredClone(original.snapshot), digest: digest(canonical(original.snapshot)) },
    { expectedVersion: current._storage.version });
  const status = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus(fixture.ownerId);
  assert.equal(status.status, "rollback_detected");
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "ATTESTATION_TRUST_EXTERNAL_ANCHOR_ROLLBACK_DETECTED"));
  await assert.rejects(() => fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "next2", publicKey: generateKeyPairSync("ed25519").publicKey }),
  hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ROLLBACK_DETECTED"));
  assert.equal(before.revision, 0);
});

test("Batch 116: rollback detection blocks the mutation callback before it can run", async t => {
  const fixture = await setup(t);
  await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  const original = await trustRecord(fixture);
  await rotate(fixture);
  const current = await trustRecord(fixture);
  await fixture.app.store.putEvidence(fixture.ownerId, { ...current, snapshot: structuredClone(original.snapshot), digest: digest(canonical(original.snapshot)) },
    { expectedVersion: current._storage.version });
  let invoked = false;
  await assert.rejects(() => fixture.app.runApprovedRecoveryReconciliationMutation(
    fixture.ownerId, "nonexistent-approval", "action-1", {}, async () => { invoked = true; return { ok: true }; }),
  hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ROLLBACK_DETECTED"));
  assert.equal(invoked, false);
});

test("Batch 116: a same-revision anchor digest conflict is not repaired automatically", async t => {
  const fixture = await setup(t);
  await rotate(fixture);
  const anchor = await fixture.provider.read(fixture.ownerId);
  const altered = { ...anchor, trustDigest: digest("different valid-looking trust snapshot") };
  delete altered.digest;
  altered.digest = digest(canonical(altered));
  fixture.provider.replace(fixture.ownerId, altered);
  const status = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus(fixture.ownerId);
  assert.equal(status.status, "mismatch");
  const reconciliation = await fixture.app.reconcileRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId);
  assert.equal(reconciliation.status, "blocked");
  assert.equal((await fixture.provider.read(fixture.ownerId)).trustDigest, altered.trustDigest);
});

test("Batch 116: an unavailable external anchor blocks new trust authorization", async t => {
  const fixture = await setup(t);
  await rotate(fixture);
  fixture.provider.failReads = true;
  await assert.rejects(() => fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "next2", publicKey: generateKeyPairSync("ed25519").publicKey }),
  hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_UNAVAILABLE"));
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.mutationAllowed, false);
  assert.ok(audit.findings.some(item => item.code === "ATTESTATION_TRUST_EXTERNAL_ANCHOR_UNAVAILABLE"));
});

test("Batch 116: a failed post-transition anchor write leaves a detectable gap that can be reconciled", async t => {
  const fixture = await setup(t);
  const next = generateKeyPairSync("ed25519");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "next1", publicKey: next.publicKey });
  fixture.provider.failWrites = true;
  const result = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, {
    authorizations: [{ keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) }],
    proofOfPossession: signature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: challenge.payload }, next.privateKey)
  });
  assert.equal(result.externalAnchorStatus, "unavailable");
  assert.equal(result.mutationAllowed, false);
  fixture.provider.failWrites = false;
  const before = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId);
  assert.equal(before.externalAnchor.status, "behind_registry");
  assert.equal(before.mutationAllowed, false);
  const recovered = await fixture.app.reconcileRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId);
  assert.equal(recovered.status, "reconciled");
  assert.equal(recovered.anchorStatus.anchorRevision, 1);
});

test("Batch 116: a non-genesis registry with no anchor requires quorum enrollment", async t => {
  const fixture = await setup(t);
  const { next } = await rotate(fixture);
  fixture.provider.remove(fixture.ownerId);
  const status = await fixture.app.reconcileRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId);
  assert.equal(status.status, "enrollment_required");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorEnrollmentChallenge(fixture.ownerId);
  const authorizations = [
    { keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) },
    { keyId: "next1", signature: signature(challenge.payload, next.privateKey) }
  ];
  const result = await fixture.app.initializeRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId, challenge.id, { authorizations });
  assert.equal(result.status, "anchored");
  assert.equal(result.revision, 1);
  assert.equal((await fixture.provider.read(fixture.ownerId)).reason, "quorum_enrollment");
});

test("Batch 116: anchor enrollment rejects stale challenges and insufficient quorum", async t => {
  const fixture = await setup(t);
  const { next } = await rotate(fixture);
  fixture.provider.remove(fixture.ownerId);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorEnrollmentChallenge(fixture.ownerId);
  await assert.rejects(() => fixture.app.initializeRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId, challenge.id, {
    authorizations: [{ keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) }]
  }), hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_QUORUM_NOT_MET"));
  const record = await trustRecord(fixture);
  const snapshot = structuredClone(record.snapshot);
  snapshot.bootstrapDigest = digest("tampered bootstrap baseline");
  const tampered = { ...record, snapshot, digest: digest(canonical(snapshot)) };
  await fixture.app.store.putEvidence(fixture.ownerId, tampered, { expectedVersion: record._storage.version });
  await assert.rejects(() => fixture.app.initializeRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor(fixture.ownerId, challenge.id, {
    authorizations: [
      { keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) },
      { keyId: "next1", signature: signature(challenge.payload, next.privateKey) }
    ]
  }), hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CONTEXT_STALE"));
});

test("Batch 116: trust anchor is owner-scoped and persists across application restart", async t => {
  const provider = createAnchorProvider();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b116-restart-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const first = generateKeyPairSync("ed25519");
  const fixture = await setup(t, { ownerId: "owner-b116-a", provider, keys: { root1: first, map: { root1: first.publicKey } }, root });
  await rotate(fixture);
  const other = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus("owner-b116-b");
  assert.equal(other.status, "missing");
  const restarted = createAgenticApplication({ storage: createStorage({ root }),
    integrityAttestationPublicKeys: { root1: first.publicKey }, attestationTrustAnchor: provider });
  const status = await restarted.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus("owner-b116-a");
  assert.equal(status.status, "anchored");
  assert.equal(status.anchorRevision, 1);
});

test("Batch 116: HTTP routes and application boundary expose anchor inspection, reconciliation, and enrollment", async t => {
  const fixture = await setup(t);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(source, /attestation-trust\/anchor"/);
  assert.match(source, /attestation-trust\/anchor\/reconcile/);
  assert.match(source, /attestation-trust\/anchor\/enrollment-challenges/);
  assert.match(source, /enrollment-challenges\/:id\/apply/);
  assert.equal(typeof fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus, "function");
  assert.equal(typeof fixture.app.reconcileRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor, "function");
  assert.equal(typeof fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorEnrollmentChallenge, "function");
  assert.equal(typeof fixture.app.initializeRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchor, "function");
});

test("Batch 116: without an external provider the service explicitly reports rollback protection as disabled", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b116-no-anchor-"));
  try {
    const app = createAgenticApplication({ storage: createStorage({ root }), integrityAttestationPublicKeys: {} });
    const status = await app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustAnchorStatus("owner-no-anchor");
    assert.equal(status.status, "not_configured");
    assert.equal(status.rollbackProtectionEnabled, false);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});


test("Batch 116: HTTP anchor adapter requires TLS outside loopback and a bearer token", () => {
  assert.throws(() => createHttpExternalTrustAnchorProvider({ baseUrl: "http://anchor.example", token: "secret", fetchImpl: async () => ({}) }),
    /HTTPS/);
  assert.throws(() => createHttpExternalTrustAnchorProvider({ baseUrl: "https://anchor.example", token: "" }), /bearer token/);
});

test("Batch 116: HTTP anchor adapter uses owner-scoped reads and reports a missing remote anchor", async () => {
  let seen;
  const provider = createHttpExternalTrustAnchorProvider({ baseUrl: "https://anchor.example/api", token: "test-token", fetchImpl: async (url, options) => {
    seen = { url, options };
    return { status: 404, ok: false, json: async () => ({}) };
  } });
  assert.equal(await provider.read("owner/116"), null);
  assert.match(seen.url, /owner%2F116$/);
  assert.equal(seen.options.method, "GET");
  assert.equal(seen.options.headers.Authorization, "Bearer test-token");
  assert.equal(seen.options.redirect, "error");
  assert.equal(seen.options.cache, "no-store");
});

test("Batch 116: HTTP anchor adapter uses conditional CAS headers and surfaces conflicts", async () => {
  let seen;
  const provider = createHttpExternalTrustAnchorProvider({ baseUrl: "https://anchor.example", token: "test-token", fetchImpl: async (url, options) => {
    seen = { url, options };
    return { status: 412, ok: false, json: async () => ({ anchor: { digest: "a".repeat(64), revision: 4 } }) };
  } });
  const result = await provider.compareAndSet("owner-b116", "b".repeat(64), {
    ownerId: "owner-b116", anchorSequence: 5, revision: 5, digest: "c".repeat(64)
  });
  assert.equal(seen.options.method, "PUT");
  assert.equal(seen.options.headers["If-Match"], `"${"b".repeat(64)}"`);
  assert.equal(result.applied, false);
  assert.equal(result.anchor.revision, 4);
});
