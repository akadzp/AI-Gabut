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

async function setup(t, ownerId = "owner-b114", appOptions = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b114-attestation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => new Date(time).toISOString(), ...appOptions });
  return { app, ownerId, now: () => new Date(time).toISOString(), advance: ms => { time += ms; } };
}

async function makeActionApproval(app, ownerId) {
  const work = await app.createWork(ownerId, { objective: "Batch 114 external attestation fixture" });
  await app.transitionWork(ownerId, work.id, "ready");
  await app.transitionWork(ownerId, work.id, "running");
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const action = plan.plan.actions.find(item => item.issueRef && item.operation !== "rerun_audit");
  assert.ok(action);
  const revalidation = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const mutationIntent = { actionId: action.id, operation: action.operation, issueCode: action.issueCode,
    target: action.target, change: { decision: "record-reviewed", ticket: "OPS-114-1" } };
  const approval = await app.approveRecoveryReconciliationAction(ownerId, plan.id, revalidation.id, action.id, mutationIntent, { ttlMs: 60_000 });
  return { action, mutationIntent, approval };
}

async function makeCriticalQuarantine(t, ownerId = "owner-b114") {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const fixture = await setup(t, ownerId, { integrityAttestationPublicKeys: { "independent-auditor": publicKey } });
  const action = await makeActionApproval(fixture.app, ownerId);
  await assert.rejects(() => fixture.app.runApprovedRecoveryReconciliationMutation(
    ownerId, action.approval.id, action.action.id, action.mutationIntent,
    async () => { const error = new Error("simulated uncertain outcome"); error.code = "TEST_UNKNOWN_OUTCOME"; throw error; }
  ), hasCode("TEST_UNKNOWN_OUTCOME"));
  await fixture.app.captureRecoveryReconciliationMutationOutcomeEvidence(ownerId, action.approval.id, {
    outcome: "applied", evidenceRef: "evidence://ops/b114/txn-1", evidenceDigest: digest("b114-applied"),
    verificationMethod: "transaction_log", attemptQuiescent: true,
    quiescenceEvidenceRef: "process://b114/terminal", quiescenceEvidenceDigest: digest("b114-quiescent"),
    quiescenceMethod: "provider_terminal_status", observedAt: fixture.now(), summary: "Verified external mutation outcome"
  });
  const ledger = (await fixture.app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  const trustedLedger = await fixture.app.store.getEvidence(ownerId, ledger.id);
  const damaged = { ...trustedLedger, snapshot: { ...trustedLedger.snapshot,
    entries: trustedLedger.snapshot.entries.map((entry, index) => index === 0 ? { ...entry, outcome: "not_applied" } : entry) } };
  await fixture.app.store.putEvidence(ownerId, damaged, { expectedVersion: trustedLedger._storage.version });
  const recovery = await fixture.app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(recovery.status, "blocked_tamper_or_non_appendable_gap");
  const current = await fixture.app.store.getEvidence(ownerId, ledger.id);
  await fixture.app.store.putEvidence(ownerId, trustedLedger, { expectedVersion: current._storage.version });
  const policy = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId);
  assert.equal(policy.status, "quarantined");
  assert.equal(policy.activeIncident.level, "critical");
  assert.equal((await fixture.app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId)).status, "healthy");
  return { ...fixture, privateKey, incidentId: policy.activeIncident.id };
}

async function issueAndVerify(fixture) {
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    fixture.ownerId, fixture.incidentId, { keyId: "independent-auditor" }
  );
  const signature = sign(null, Buffer.from(canonical(challenge.payload)), fixture.privateKey).toString("base64url");
  const verified = await fixture.app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation(fixture.ownerId, challenge.id, signature);
  return { challenge, signature, verified };
}

test("Batch 114: critical quarantine cannot be acknowledged without independent signed attestation", async t => {
  const fixture = await makeCriticalQuarantine(t);
  await assert.rejects(() => fixture.app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation(
    fixture.ownerId, fixture.incidentId, "Reviewed restored ledger but no external proof"
  ), hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_REQUIRED"));
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(fixture.ownerId)).status, "quarantined");
});

test("Batch 114: a trusted Ed25519 attestation binds incident, policy revision, ledger head, and clean audit", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const { challenge, verified } = await issueAndVerify(fixture);
  assert.equal(challenge.status, "issued");
  assert.equal(verified.status, "verified");
  assert.equal(verified.incidentId, fixture.incidentId);
  const acknowledged = await fixture.app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation(
    fixture.ownerId, fixture.incidentId, "Independent auditor verified restored ledger integrity", challenge.id
  );
  assert.equal(acknowledged.status, "acknowledged");
  assert.ok(acknowledged.attestationDigest);
  const policy = await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(fixture.ownerId);
  assert.equal(policy.status, "clear");
  assert.equal(policy.mutationBlocked, false);
  assert.equal(policy.history.at(-1).type, "acknowledged");
});

test("Batch 114: invalid signatures are rejected and do not consume the challenge", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    fixture.ownerId, fixture.incidentId, { keyId: "independent-auditor" }
  );
  await assert.rejects(() => fixture.app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation(
    fixture.ownerId, challenge.id, Buffer.alloc(64, 7).toString("base64url")
  ), hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_SIGNATURE_INVALID"));
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestation(fixture.ownerId, challenge.id)).status, "issued");
});

test("Batch 114: a verified attestation challenge cannot be replayed", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const { challenge, signature } = await issueAndVerify(fixture);
  await assert.rejects(() => fixture.app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation(
    fixture.ownerId, challenge.id, signature
  ), hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_REPLAYED"));
});

test("Batch 114: policy revision changes invalidate a previously issued challenge", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    fixture.ownerId, fixture.incidentId, { keyId: "independent-auditor" }
  );
  const signature = sign(null, Buffer.from(canonical(challenge.payload)), fixture.privateKey).toString("base64url");
  const policyRecord = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger-policy");
  const current = await fixture.app.store.getEvidence(fixture.ownerId, policyRecord.id);
  const snapshot = { ...current.snapshot, revision: current.snapshot.revision + 1 };
  await fixture.app.store.putEvidence(fixture.ownerId, { ...current, snapshot, digest: digest(canonical(snapshot)) }, { expectedVersion: current._storage.version });
  await assert.rejects(() => fixture.app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation(
    fixture.ownerId, challenge.id, signature
  ), hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_STALE"));
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(fixture.ownerId)).status, "quarantined");
});

test("Batch 114: attestation records remain owner-scoped", async t => {
  const fixture = await makeCriticalQuarantine(t, "owner-b114-a");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    fixture.ownerId, fixture.incidentId, { keyId: "independent-auditor" }
  );
  await assert.rejects(() => fixture.app.getRecoveryReconciliationMutationOutcomeLedgerAttestation("owner-b114-b", challenge.id),
    hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_NOT_FOUND"));
  assert.equal((await fixture.app.listRecoveryReconciliationMutationOutcomeLedgerAttestations("owner-b114-b")).total, 0);
});

test("Batch 114: expired attestation cannot clear quarantine", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const { challenge } = await issueAndVerify(fixture);
  fixture.advance(5 * 60 * 1000 + 1);
  await assert.rejects(() => fixture.app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation(
    fixture.ownerId, fixture.incidentId, "Attestation expired before approval", challenge.id
  ), hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_EXPIRED_OR_INVALID"));
  assert.equal((await fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(fixture.ownerId)).status, "quarantined");
});

test("Batch 114: missing trusted public key fails closed when issuing a challenge", async t => {
  const { app, ownerId } = await setup(t);
  await app.store.putEvidence(ownerId, { id: "unused", kind: "fixture", snapshot: {}, digest: digest("fixture") }, { overwrite: false });
  await assert.rejects(() => app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge(
    ownerId, "no-incident", { keyId: "missing-key" }
  ), hasCode("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_TRUST_NOT_CONFIGURED"));
});

test("Batch 114: policy cannot be forged to clear critical quarantine without a signed receipt", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const policyRecord = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger-policy");
  const raw = await fixture.app.store.getEvidence(fixture.ownerId, policyRecord.id);
  const snapshot = { ...raw.snapshot, status: "clear", activeIncident: null,
    history: raw.snapshot.history.filter(item => item.type !== "acknowledged") };
  await fixture.app.store.putEvidence(fixture.ownerId, { ...raw, snapshot, digest: digest(canonical(snapshot)) }, { expectedVersion: raw._storage.version });
  await assert.rejects(() => fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(fixture.ownerId),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_POLICY_INTEGRITY_FAILED"));
});

test("Batch 114: modifying a signed clearance receipt invalidates the quarantine policy", async t => {
  const fixture = await makeCriticalQuarantine(t);
  const { challenge } = await issueAndVerify(fixture);
  await fixture.app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation(
    fixture.ownerId, fixture.incidentId, "Independent auditor verified restored ledger integrity", challenge.id
  );
  const policyRecord = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger-policy");
  const raw = await fixture.app.store.getEvidence(fixture.ownerId, policyRecord.id);
  const history = raw.snapshot.history.map(item => item.type === "acknowledged"
    ? { ...item, attestationReceipt: { ...item.attestationReceipt, signature: `${item.attestationReceipt.signature[0] === "A" ? "B" : "A"}${item.attestationReceipt.signature.slice(1)}` } }
    : item);
  const snapshot = { ...raw.snapshot, history };
  await fixture.app.store.putEvidence(fixture.ownerId, { ...raw, snapshot, digest: digest(canonical(snapshot)) }, { expectedVersion: raw._storage.version });
  await assert.rejects(() => fixture.app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(fixture.ownerId),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_POLICY_INTEGRITY_FAILED"));
});

test("Batch 114: attestation challenge, verification, listing, and acknowledgement routes are exposed", async t => {
  const { app, ownerId } = await setup(t);
  assert.equal(typeof app.createRecoveryReconciliationMutationOutcomeLedgerAttestationChallenge, "function");
  assert.equal(typeof app.submitRecoveryReconciliationMutationOutcomeLedgerAttestation, "function");
  assert.equal(typeof app.getRecoveryReconciliationMutationOutcomeLedgerAttestation, "function");
  assert.equal(typeof app.listRecoveryReconciliationMutationOutcomeLedgerAttestations, "function");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /mutation-outcome-ledger\/attestation-challenges/);
  assert.match(server, /mutation-outcome-ledger\/attestations\/:id\/verify/);
  assert.match(server, /q\.body\?\.attestationId/);
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId)).status, "clear");
});
