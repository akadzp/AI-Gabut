import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b113") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b113-ledger-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => new Date(now).toISOString() });
  return { app, ownerId, now: () => new Date(now).toISOString(), advance: ms => { now += ms; } };
}

const digest = value => createHash("sha256").update(value).digest("hex");
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const hasCode = code => error => error?.code === code;
function ledgerGenesis(ownerId) {
  return digest(canonical({ domain: "agentic-ai-v4-mutation-outcome-ledger-genesis", ownerId, schemaVersion: 1 }));
}

async function makeActionApproval(app, ownerId) {
  const work = await app.createWork(ownerId, { objective: "Batch 113 mutation outcome ledger fixture" });
  await app.transitionWork(ownerId, work.id, "ready");
  await app.transitionWork(ownerId, work.id, "running");
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const action = plan.plan.actions.find(item => item.issueRef && item.operation !== "rerun_audit");
  assert.ok(action);
  const revalidation = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const mutationIntent = { actionId: action.id, operation: action.operation, issueCode: action.issueCode,
    target: action.target, change: { decision: "record-reviewed", ticket: "OPS-113-1" } };
  const approval = await app.approveRecoveryReconciliationAction(ownerId, plan.id, revalidation.id, action.id, mutationIntent, { ttlMs: 60_000 });
  return { work, evidence, plan, action, revalidation, mutationIntent, approval };
}

async function makeIndeterminate(t, ownerId = "owner-b113") {
  const fixture = await setup(t, ownerId);
  const actionFixture = await makeActionApproval(fixture.app, ownerId);
  await assert.rejects(() => fixture.app.runApprovedRecoveryReconciliationMutation(
    ownerId, actionFixture.approval.id, actionFixture.action.id, actionFixture.mutationIntent,
    async () => { const error = new Error("simulated uncertain callback"); error.code = "TEST_UNKNOWN_OUTCOME"; throw error; }
  ), hasCode("TEST_UNKNOWN_OUTCOME"));
  assert.equal((await fixture.app.verifyRecoveryReconciliationApproval(ownerId, actionFixture.approval.id)).status, "mutation_outcome_unknown");
  const evidence = await fixture.app.captureRecoveryReconciliationMutationOutcomeEvidence(ownerId, actionFixture.approval.id, {
    outcome: "applied", evidenceRef: "evidence://ops/b113/txn-1", evidenceDigest: digest("external-b113-applied"),
    verificationMethod: "transaction_log", attemptQuiescent: true,
    quiescenceEvidenceRef: "process://agentic/b113/terminal", quiescenceEvidenceDigest: digest("quiescence-b113"),
    quiescenceMethod: "provider_terminal_status", observedAt: fixture.now(), summary: "Verified mutation outcome for Batch 113"
  });
  return { ...fixture, ...actionFixture, evidence };
}

async function rewriteLedgerKeeping(app, ownerId, count) {
  const record = (await app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  assert.ok(record);
  const raw = await app.store.getEvidence(ownerId, record.id);
  const entries = raw.snapshot.entries.slice(0, count);
  let previousHash = ledgerGenesis(ownerId);
  const rebuilt = entries.map((item, index) => {
    const { hash, ...body } = item;
    const nextBody = { ...body, sequence: index + 1, previousHash };
    const next = { ...nextBody, hash: digest(canonical(nextBody)) };
    previousHash = next.hash;
    return next;
  });
  const snapshot = { ...raw.snapshot, revision: rebuilt.length, headHash: previousHash, entries: rebuilt, truncated: false };
  await app.store.putEvidence(ownerId, { ...raw, snapshot, digest: digest(canonical(snapshot)) }, { expectedVersion: raw._storage.version });
}

async function tamperLedger(app, ownerId) {
  const record = (await app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  const raw = await app.store.getEvidence(ownerId, record.id);
  const snapshot = { ...raw.snapshot, entries: raw.snapshot.entries.map((item, index) => index === 0 ? { ...item, outcome: "not_applied" } : item) };
  await app.store.putEvidence(ownerId, { ...raw, snapshot }, { expectedVersion: raw._storage.version });
}

test("Batch 113: a missing tail capture event is reconstructed from immutable evidence and requires explicit acknowledgement", async t => {
  const { app, ownerId, evidence } = await makeIndeterminate(t);
  await rewriteLedgerKeeping(app, ownerId, 0);
  const before = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.ok(before.findings.some(item => item.code === "OUTCOME_EVIDENCE_MISSING_FROM_LEDGER"));
  const recovery = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(recovery.status, "recovered");
  assert.equal(recovery.recoveredEvents, 1);
  assert.equal(recovery.audit.status, "healthy");
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId)).entryCount, 1);
  const policy = await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId);
  assert.equal(policy.status, "quarantined");
  assert.equal(policy.activeIncident.level, "high");
  // The evidence is now linked; audit clean means an explicit, reasoned acknowledgement can clear quarantine.
  const acknowledged = await app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId, policy.activeIncident.id, "Evidence chain reconstructed and verified");
  assert.equal(acknowledged.status, "acknowledged");
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId)).status, "clear");
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeEvidence(ownerId, evidence.id)).id, evidence.id);
});

test("Batch 113: a missing completion event is reconstructed from approval resolution history", async t => {
  const { app, ownerId, approval, evidence } = await makeIndeterminate(t);
  await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  await rewriteLedgerKeeping(app, ownerId, 2);
  const before = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.ok(before.findings.some(item => item.code === "RESOLUTION_COMPLETION_EVENT_MISSING"));
  const recovery = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(recovery.status, "recovered");
  assert.equal(recovery.audit.status, "healthy");
  const entries = (await app.listRecoveryReconciliationMutationOutcomeLedgerEntries(ownerId, { limit: 20 })).items;
  assert.equal(entries.length, 3);
  assert.equal(entries[2].eventType, "claim_resolution_completed");
  assert.equal(entries[2].recoveryMethod, "reconstructed_from_approval_history");
  assert.equal((await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId)).status, "healthy");
});

test("Batch 113: a tampered hash chain is quarantined and cannot be repaired by append-only gap recovery", async t => {
  const { app, ownerId } = await makeIndeterminate(t);
  await tamperLedger(app, ownerId);
  const recovery = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(recovery.status, "blocked_tamper_or_non_appendable_gap");
  assert.equal(recovery.recoveredEvents, 0);
  const policy = await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId);
  assert.equal(policy.status, "quarantined");
  assert.equal(policy.activeIncident.level, "critical");
  assert.ok(policy.activeIncident.reasonCodes.includes("MUTATION_OUTCOME_LEDGER_INTEGRITY_FAILED"));
});

test("Batch 113: mutation boundary auto-escalates a tampered ledger and does not invoke the callback", async t => {
  const { app, ownerId } = await makeIndeterminate(t);
  await tamperLedger(app, ownerId);
  const next = await makeActionApproval(app, ownerId);
  let invoked = false;
  await assert.rejects(() => app.runApprovedRecoveryReconciliationMutation(ownerId, next.approval.id, next.action.id, next.mutationIntent, async () => {
    invoked = true;
    return "must not run";
  }), hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_QUARANTINED"));
  assert.equal(invoked, false);
  const policy = await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId);
  assert.equal(policy.status, "quarantined");
  assert.equal(policy.activeIncident.level, "critical");
});

test("Batch 113: a missing capture event in the middle of a chain is non-appendable and remains quarantined", async t => {
  const { app, ownerId, approval, evidence } = await makeIndeterminate(t);
  await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  await rewriteLedgerKeeping(app, ownerId, 2);
  // Keep the resolution intent while removing the capture at the chain head.
  const record = (await app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  const raw = await app.store.getEvidence(ownerId, record.id);
  const kept = raw.snapshot.entries.slice(1);
  let previousHash = ledgerGenesis(ownerId);
  const rebuilt = kept.map((item, index) => {
    const { hash, ...body } = item;
    const nextBody = { ...body, sequence: index + 1, previousHash };
    const next = { ...nextBody, hash: digest(canonical(nextBody)) };
    previousHash = next.hash;
    return next;
  });
  const snapshot = { ...raw.snapshot, revision: rebuilt.length, headHash: previousHash, entries: rebuilt, truncated: false };
  await app.store.putEvidence(ownerId, { ...raw, snapshot, digest: digest(canonical(snapshot)) }, { expectedVersion: raw._storage.version });
  const recovery = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(recovery.status, "blocked_tamper_or_non_appendable_gap");
  assert.equal(recovery.recoveredEvents, 0);
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId)).activeIncident.level, "critical");
});

test("Batch 113: repeating gap recovery after successful repair is idempotent and does not append duplicates", async t => {
  const { app, ownerId } = await makeIndeterminate(t);
  await rewriteLedgerKeeping(app, ownerId, 0);
  const first = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(first.status, "recovered");
  const count = (await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId)).entryCount;
  const second = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  assert.equal(second.status, "clean");
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId)).entryCount, count);
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId)).status, "quarantined");
});

test("Batch 113: acknowledgement cannot clear an escalation while the audit is unhealthy", async t => {
  const { app, ownerId } = await makeIndeterminate(t);
  await tamperLedger(app, ownerId);
  const recovery = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  const policy = await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId);
  await assert.rejects(() => app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId, policy.activeIncident.id, "I reviewed this incident"), hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_NOT_CLEAN"));
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId)).status, "quarantined");
  assert.equal(recovery.recoveredEvents, 0);
});

test("Batch 113: escalation policy is owner-scoped and cross-owner acknowledgement is rejected", async t => {
  const { app, ownerId } = await makeIndeterminate(t, "owner-b113-a");
  await rewriteLedgerKeeping(app, ownerId, 0);
  const recovery = await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  const policy = await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId);
  assert.equal(policy.status, "quarantined");
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation("owner-b113-b")).status, "clear");
  await assert.rejects(() => app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation("owner-b113-b", policy.activeIncident.id, "Attempt cross owner acknowledgement"), hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_INCIDENT_NOT_FOUND"));
  assert.equal(recovery.status, "recovered");
});

test("Batch 113: a corrupted escalation policy fails closed at the mutation boundary", async t => {
  const { app, ownerId } = await makeIndeterminate(t);
  await rewriteLedgerKeeping(app, ownerId, 0);
  await app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps(ownerId);
  const policyRecord = (await app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger-policy");
  assert.ok(policyRecord);
  const raw = await app.store.getEvidence(ownerId, policyRecord.id);
  await app.store.putEvidence(ownerId, { ...raw, snapshot: { ...raw.snapshot, revision: raw.snapshot.revision + 1 } }, { expectedVersion: raw._storage.version });
  const next = await makeActionApproval(app, ownerId);
  let invoked = false;
  await assert.rejects(() => app.runApprovedRecoveryReconciliationMutation(ownerId, next.approval.id, next.action.id, next.mutationIntent, async () => {
    invoked = true;
  }), hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_POLICY_INTEGRITY_FAILED"));
  assert.equal(invoked, false);
});

test("Batch 113: policy APIs and authenticated HTTP routes are exposed", async t => {
  const { app, ownerId } = await setup(t);
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedgerEscalation(ownerId)).status, "clear");
  assert.equal(typeof app.recoverRecoveryReconciliationMutationOutcomeLedgerGaps, "function");
  assert.equal(typeof app.acknowledgeRecoveryReconciliationMutationOutcomeLedgerEscalation, "function");
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /mutation-outcome-ledger\/escalation/);
  assert.match(server, /mutation-outcome-ledger\/recover-gaps/);
  assert.match(server, /mutation-outcome-ledger\/escalation\/:id\/acknowledge/);
});
