import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const digest = value => createHash("sha256").update(value).digest("hex");
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const hasCode = code => error => error?.code === code;
const signature = (payload, privateKey) => sign(null, Buffer.from(canonical(payload)), privateKey).toString("base64url");

async function setup(t, ownerId = "owner-b115", keys = null, root = null) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b115-trust-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root: storageRoot }),
    clock: () => new Date(time).toISOString(), integrityAttestationPublicKeys: keys || {} });
  return { app, ownerId, root: storageRoot, now: () => new Date(time).toISOString(), advance: ms => { time += ms; } };
}

async function makeCriticalQuarantine(t, ownerId = "owner-b115") {
  const first = generateKeyPairSync("ed25519");
  const fixture = await setup(t, ownerId, { auditor1: first.publicKey });
  const work = await fixture.app.createWork(ownerId, { objective: "Batch 115 trust rotation fixture" });
  await fixture.app.transitionWork(ownerId, work.id, "ready");
  await fixture.app.transitionWork(ownerId, work.id, "running");
  const evidence = await fixture.app.captureRecoveryAuditEvidence(ownerId);
  const plan = await fixture.app.planRecoveryReconciliation(ownerId, evidence.id);
  const action = plan.plan.actions.find(item => item.issueRef && item.operation !== "rerun_audit");
  assert.ok(action);
  const revalidation = await fixture.app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const mutationIntent = { actionId: action.id, operation: action.operation, issueCode: action.issueCode,
    target: action.target, change: { decision: "reviewed", ticket: "OPS-115-1" } };
  const approval = await fixture.app.approveRecoveryReconciliationAction(ownerId, plan.id, revalidation.id, action.id, mutationIntent, { ttlMs: 60_000 });
  await assert.rejects(() => fixture.app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent,
    async () => { const error = new Error("unknown mutation result"); error.code = "TEST_UNKNOWN_OUTCOME"; throw error; }), hasCode("TEST_UNKNOWN_OUTCOME"));
  await fixture.app.captureRecoveryReconciliationMutationOutcomeEvidence(ownerId, approval.id, {
    outcome: "applied", evidenceRef: "evidence://ops/b115/txn", evidenceDigest: digest("applied"),
    verificationMethod: "transaction_log", attemptQuiescent: true, quiescenceEvidenceRef: "process://b115/terminal",
    quiescenceEvidenceDigest: digest("quiescent"), quiescenceMethod: "provider_terminal_status",
    observedAt: fixture.now(), summary: "Outcome verified by provider" });
  const ledger = (await fixture.app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  const saved = await fixture.app.store.getEvidence(ownerId, ledger.id);
  const damaged = { ...saved, snapshot: { ...saved.snapshot, entries: saved.snapshot.entries.map((entry, index) => index === 0 ? { ...entry, outcome: "not_applied" } : entry) } };
  await fixture.app.store.putEvidence(ownerId, damaged, { expectedVersion: saved._storage.version });
  const recovery = await fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(recovery.status, "blocked_tamper_or_non_appendable_gap");
  const current = await fixture.app.store.getEvidence(ownerId, ledger.id);
  await fixture.app.store.putEvidence(ownerId, saved, { expectedVersion: current._storage.version });
  const policy = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId);
  assert.equal(policy.activeIncident.level, "critical");
  assert.equal((await fixture.app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId)).status, "healthy");
  return { ...fixture, first, incidentId: policy.activeIncident.id };
}

async function rotateKey(fixture, keyId = "auditor2") {
  const second = generateKeyPairSync("ed25519");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId, publicKey: second.publicKey });
  const auth = signature(challenge.payload, fixture.first.privateKey);
  const proofPayload = { domain: "agentic-v4-attestation-trust-proof-of-possession", payload: challenge.payload };
  const result = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, { authorizations: [{ keyId: "auditor1", signature: auth }], proofOfPossession: signature(proofPayload, second.privateKey) });
  return { second, challenge, result };
}

async function revokeKey(fixture, keyId, keysToSign) {
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "revoke", keyId, reason: "Scheduled trust rotation after key replacement" });
  const authorizations = keysToSign.map(item => ({ keyId: item.keyId, signature: signature(challenge.payload, item.privateKey) }));
  const result = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, { authorizations });
  return { challenge, result };
}

async function makeAttestation(fixture, keyId = "auditor1", privateKey = fixture.first.privateKey) {
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    fixture.ownerId, fixture.incidentId, { keyId });
  const verified = await fixture.app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation(
    fixture.ownerId, challenge.id, signature(challenge.payload, privateKey));
  return { challenge, verified };
}

test("Batch 115: trust policy bootstraps owner-scoped configured public keys without exposing private material", async t => {
  const first = generateKeyPairSync("ed25519");
  const fixture = await setup(t, "owner-b115-a", { auditor1: first.publicKey });
  const policy = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  assert.equal(policy.revision, 0);
  assert.equal(policy.activeKeyCount, 1);
  assert.equal(policy.keys[0].keyId, "auditor1");
  assert.equal("publicKeyPem" in policy.keys[0], false);
  const otherOwner = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy("owner-b115-b");
  assert.equal(otherOwner.activeKeyCount, 1);
  assert.equal(otherOwner.revision, 0);
});

test("Batch 115: pre-Batch-115 attestations remain inspectable but cannot authorize a new clearance", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    fixture.ownerId, fixture.incidentId, { keyId: "auditor1" });
  const record = await fixture.app.store.getEvidence(fixture.ownerId, challenge.id);
  const snapshot = structuredClone(record.snapshot);
  delete snapshot.payload.trustRevision;
  delete snapshot.payload.trustDigest;
  const legacy = { ...record, snapshot, digest: digest(canonical(snapshot)) };
  await fixture.app.store.putEvidence(fixture.ownerId, legacy, { expectedVersion: record._storage.version });
  const retrieved = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestation(fixture.ownerId, challenge.id);
  assert.equal(retrieved.status, "issued");
  await assert.rejects(() => fixture.app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation(
    fixture.ownerId, challenge.id, signature(snapshot.payload, fixture.first.privateKey)),
    hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_TRUST_REVOKED_OR_STALE"));
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId);
  assert.ok(audit.findings.some(item => item.code === "ATTESTATION_MISSING_TRUST_BINDING"));
});

test("Batch 115: key rotation requires an existing-key signature and new-key proof of possession", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const { second, result } = await rotateKey(fixture);
  assert.equal(result.status, "applied");
  assert.equal(result.revision, 1);
  assert.equal(result.activeKeyCount, 2);
  const policy = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  assert.deepEqual(policy.keys.map(item => item.keyId).sort(), ["auditor1", "auditor2"]);
  assert.equal((await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId)).status, "healthy");
  assert.ok(second.privateKey);
});

test("Batch 115: rotation without quorum or with invalid proof is rejected without changing trust revision", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const second = generateKeyPairSync("ed25519");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "auditor2", publicKey: second.publicKey });
  await assert.rejects(() => fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, { authorizations: [], proofOfPossession: signature({ domain: "x", payload: challenge.payload }, second.privateKey) }),
    hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_QUORUM_NOT_MET"));
  const policy = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  assert.equal(policy.revision, 0);
});

test("Batch 115: revocation requires majority authorization and cannot remove the final active key", async t => {
  const fixture = await makeCriticalQuarantine(t);
  await assert.rejects(() => fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "revoke", keyId: "auditor1", reason: "Retire old key after replacement" }),
    hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_LAST_KEY"));
  const { second } = await rotateKey(fixture);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "revoke", keyId: "auditor1", reason: "Retire old key after replacement" });
  await assert.rejects(() => fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, { authorizations: [{ keyId: "auditor1", signature: signature(challenge.payload, fixture.first.privateKey) }] }),
    hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_QUORUM_NOT_MET"));
  const result = await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, { authorizations: [
      { keyId: "auditor1", signature: signature(challenge.payload, fixture.first.privateKey) },
      { keyId: "auditor2", signature: signature(challenge.payload, second.privateKey) }
    ] });
  assert.equal(result.status, "applied");
  assert.equal(result.activeKeyCount, 1);
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId)).keys.find(item => item.keyId === "auditor1").status, "revoked");
});

test("Batch 115: a trust transition challenge is one-use and stale after another transition", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const { second } = await rotateKey(fixture);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "revoke", keyId: "auditor1", reason: "Retire old key after replacement" });
  const third = generateKeyPairSync("ed25519");
  const rotateChallenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "auditor3", publicKey: third.publicKey });
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, rotateChallenge.id, {
    authorizations: [
      { keyId: "auditor1", signature: signature(rotateChallenge.payload, fixture.first.privateKey) },
      { keyId: "auditor2", signature: signature(rotateChallenge.payload, second.privateKey) }
    ], proofOfPossession: signature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: rotateChallenge.payload }, third.privateKey)
  });
  await assert.rejects(() => fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(
    fixture.ownerId, challenge.id, { authorizations: [
      { keyId: "auditor1", signature: signature(challenge.payload, fixture.first.privateKey) },
      { keyId: "auditor2", signature: signature(challenge.payload, second.privateKey) }
    ] }), hasCode("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CONTEXT_STALE"));
});

test("Batch 115: rotation invalidates attestations issued against the prior trust revision", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    fixture.ownerId, fixture.incidentId, { keyId: "auditor1" });
  await rotateKey(fixture);
  await assert.rejects(() => fixture.app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation(
    fixture.ownerId, challenge.id, signature(challenge.payload, fixture.first.privateKey)),
    hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_TRUST_REVOKED_OR_STALE"));
});

test("Batch 115: verified attestation signed by a subsequently revoked key is reported by trust audit", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const { challenge: oldAttestation } = await makeAttestation(fixture);
  const { second } = await rotateKey(fixture);
  await revokeKey(fixture, "auditor1", [
    { keyId: "auditor1", privateKey: fixture.first.privateKey }, { keyId: "auditor2", privateKey: second.privateKey }
  ]);
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId);
  assert.equal(audit.status, "degraded");
  assert.ok(audit.findings.some(item => item.code === "ATTESTATION_SIGNED_BY_REVOKED_KEY" && item.keyId === "auditor1"));
  await assert.rejects(() => fixture.app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation(
    fixture.ownerId, fixture.incidentId, "Attempt clearance using revoked attestor proof", oldAttestation.id),
    hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_STALE"));
});

test("Batch 115: trust transitions remain owner-scoped", async t => {
  const fixture = await makeCriticalQuarantine(t, "owner-b115-a");
  const { second } = await rotateKey(fixture);
  const policyB = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy("owner-b115-b");
  assert.equal(policyB.activeKeyCount, 1);
  assert.equal(policyB.revision, 0);
  assert.ok(second.privateKey);
});

test("Batch 115: trust policy survives application restart using persisted rotation history", async t => {
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b115-restart-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const fixture = await setup(t, "owner-b115-restart", { auditor1: first.publicKey }, root);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "auditor2", publicKey: second.publicKey });
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, {
    authorizations: [{ keyId: "auditor1", signature: signature(challenge.payload, first.privateKey) }],
    proofOfPossession: signature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: challenge.payload }, second.privateKey)
  });
  const restarted = createAgenticApplication({ storage: createStorage({ root }), integrityAttestationPublicKeys: { auditor1: first.publicKey } });
  const policy = await restarted.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy(fixture.ownerId);
  assert.equal(policy.revision, 1);
  assert.equal(policy.activeKeyCount, 2);
  assert.equal((await restarted.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId)).status, "healthy");
});

test("Batch 115: trust audit detects altered history even if the outer snapshot digest is recomputed", async t => {
  const fixture = await makeCriticalQuarantine(t);
  await rotateKey(fixture);
  const record = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-reconciliation-attestation-trust-policy");
  const current = await fixture.app.store.getEvidence(fixture.ownerId, record.id);
  const snapshot = structuredClone(current.snapshot);
  snapshot.history[0].payload.keyId = "forged-key-id";
  const changed = { ...current, snapshot, digest: digest(canonical(snapshot)) };
  await fixture.app.store.putEvidence(fixture.ownerId, changed, { expectedVersion: current._storage.version });
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "ATTESTATION_TRUST_HISTORY_CHAIN_INVALID"));
});

test("Batch 115: trust audit is read-only and bounded", async t => {
  const fixture = await makeCriticalQuarantine(t);
  await rotateKey(fixture);
  const before = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-reconciliation-attestation-trust-policy");
  const audit = await fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust(fixture.ownerId, { limit: 1 });
  const after = await fixture.app.store.getEvidence(fixture.ownerId, before.id);
  assert.equal(after._storage.version, before._storage.version);
  assert.equal(audit.readOnly, true);
  assert.equal(audit.findings.length <= 1, true);
});

test("Batch 115: HTTP routes and application boundary expose trust policy, transitions, and audit", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(source, /\/attestation-trust"/);
  assert.match(source, /\/attestation-trust\/audit/);
  assert.match(source, /\/attestation-trust\/challenges/);
  assert.match(source, /\/challenges\/:id\/apply/);
  assert.equal(typeof fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestationTrustPolicy, "function");
  assert.equal(typeof fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge, "function");
  assert.equal(typeof fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition, "function");
  assert.equal(typeof fixture.app.auditRecoveryReconciliationMutationOutcomeLedgerAttestationTrust, "function");
});
