import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b112") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b112-outcome-ledger-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => new Date(now).toISOString() });
  return { app, ownerId, root, now: () => new Date(now).toISOString(), advance: ms => { now += ms; } };
}

async function makeActionApproval(app, ownerId) {
  const work = await app.createWork(ownerId, { objective: "Batch 112 mutation outcome ledger fixture" });
  await app.transitionWork(ownerId, work.id, "ready");
  await app.transitionWork(ownerId, work.id, "running");
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const action = plan.plan.actions.find(item => item.issueRef && item.operation !== "rerun_audit");
  assert.ok(action, "fixture must produce an actionable recommendation");
  const revalidation = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  assert.equal(revalidation.snapshot.status, "fresh");
  const mutationIntent = {
    actionId: action.id, operation: action.operation, issueCode: action.issueCode,
    target: action.target, change: { decision: "record-reviewed", ticket: "OPS-112-1" }
  };
  const approval = await app.approveRecoveryReconciliationAction(
    ownerId, plan.id, revalidation.id, action.id, mutationIntent, { ttlMs: 60_000 }
  );
  return { work, evidence, plan, action, revalidation, mutationIntent, approval };
}

function hasCode(expected) { return error => error?.code === expected; }
function digest(value) { return createHash("sha256").update(value).digest("hex"); }
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function ledgerGenesis(ownerId) {
  return digest(canonical({ domain: "agentic-ai-v4-mutation-outcome-ledger-genesis", ownerId, schemaVersion: 1 }));
}
function entryHash(entry) {
  const { hash, ...body } = entry;
  return digest(canonical(body));
}
async function makeIndeterminate(app, ownerId, action, mutationIntent, approval) {
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => {
      const error = new Error("simulated uncertain callback outcome");
      error.code = "TEST_OUTCOME_UNKNOWN";
      throw error;
    }),
    hasCode("TEST_OUTCOME_UNKNOWN")
  );
  assert.equal((await app.verifyRecoveryReconciliationApproval(ownerId, approval.id)).status, "mutation_outcome_unknown");
}
async function captureOutcome(app, ownerId, approval, observedAt, outcome, overrides = {}) {
  return app.captureRecoveryReconciliationMutationOutcomeEvidence(ownerId, approval.id, {
    outcome, evidenceRef: "evidence://ops/txn-112-01", evidenceDigest: digest(`external-artifact:${outcome}`),
    verificationMethod: "transaction_log", attemptQuiescent: true,
    quiescenceEvidenceRef: "process://agentic/attempt-terminal-112",
    quiescenceEvidenceDigest: digest("attempt-quiescence-proof-112"), quiescenceMethod: "provider_terminal_status",
    observedAt, summary: `Verified mutation outcome: ${outcome}`, ...overrides
  });
}

async function createIndeterminateEvidence(t, ownerId = "owner-b112", outcome = "applied") {
  const fixture = await setup(t, ownerId);
  const action = await makeActionApproval(fixture.app, ownerId);
  await makeIndeterminate(fixture.app, ownerId, action.action, action.mutationIntent, action.approval);
  const evidence = await captureOutcome(fixture.app, ownerId, action.approval, fixture.now(), outcome);
  return { ...fixture, ...action, evidence };
}

test("Batch 112: empty owner ledger is deterministic and audit is read-only", async t => {
  const { app, ownerId } = await setup(t);
  const before = await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId);
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  const entries = await app.listRecoveryReconciliationMutationOutcomeLedgerEntries(ownerId);
  assert.equal(before.status, "empty");
  assert.equal(before.revision, 0);
  assert.equal(audit.status, "empty");
  assert.equal(audit.totalFindings, 0);
  assert.equal(audit.automaticRepairAllowed, false);
  assert.deepEqual(entries.items, []);
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId)).headHash, before.headHash);
});

test("Batch 112: capturing outcome evidence appends one owner-scoped hash-chained ledger event", async t => {
  const { app, ownerId, evidence } = await createIndeterminateEvidence(t);
  const ledger = await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId);
  const entries = await app.listRecoveryReconciliationMutationOutcomeLedgerEntries(ownerId);
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(ledger.status, "healthy");
  assert.equal(ledger.entryCount, 1);
  assert.equal(entries.items[0].eventType, "outcome_evidence_captured");
  assert.equal(entries.items[0].evidenceId, evidence.id);
  assert.equal(entries.items[0].sequence, 1);
  assert.equal(entries.items[0].previousHash, ledgerGenesis(ownerId));
  assert.equal(entries.items[0].hash, entryHash(entries.items[0]));
  assert.equal(audit.status, "healthy");
  assert.equal(audit.totalFindings, 0);
});

test("Batch 112: resolution records intent before completion and audit reconciles approval history", async t => {
  const { app, ownerId, approval, evidence } = await createIndeterminateEvidence(t);
  const resolved = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(resolved.status, "resolved_applied");
  const entries = (await app.listRecoveryReconciliationMutationOutcomeLedgerEntries(ownerId, { limit: 20 })).items;
  assert.deepEqual(entries.map(item => item.eventType), [
    "outcome_evidence_captured", "claim_resolution_started", "claim_resolution_completed"
  ]);
  assert.equal(entries[1].previousHash, entries[0].hash);
  assert.equal(entries[2].previousHash, entries[1].hash);
  assert.equal(entries[2].hash, entryHash(entries[2]));
  assert.equal(entries[2].resolutionStatus, "resolved_applied");
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.totalFindings, 0);
});

test("Batch 112: evidence capture and claim resolution replay are idempotent in the ledger", async t => {
  const { app, ownerId, approval, action, mutationIntent, evidence, now } = await createIndeterminateEvidence(t);
  const before = await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId);
  const duplicate = await captureOutcome(app, ownerId, approval, now(), "applied");
  assert.equal(duplicate.id, evidence.id);
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId)).entryCount, before.entryCount);
  const resolved = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(resolved.status, "resolved_applied");
  const afterFirstResolution = await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId);
  const replay = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(replay.status, "already_resolved");
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId)).entryCount, afterFirstResolution.entryCount);
  await assert.rejects(() => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => ({ committed: true })),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_ACTION_ALREADY_CONSUMED"));
});

test("Batch 112: concurrent duplicate evidence captures append only one ledger event", async t => {
  const { app, ownerId, approval, now } = await createIndeterminateEvidence(t);
  const raw = await app.getRecoveryReconciliationMutationOutcomeEvidence(ownerId,
    (await app.listRecoveryReconciliationMutationOutcomeEvidence(ownerId)).items[0].id);
  const input = {
    outcome: raw.snapshot.outcome, evidenceRef: raw.snapshot.evidenceRef, evidenceDigest: raw.snapshot.evidenceDigest,
    verificationMethod: raw.snapshot.verificationMethod, attemptQuiescent: raw.snapshot.attemptQuiescent,
    quiescenceEvidenceRef: raw.snapshot.quiescenceEvidenceRef, quiescenceEvidenceDigest: raw.snapshot.quiescenceEvidenceDigest,
    quiescenceMethod: raw.snapshot.quiescenceMethod, observedAt: raw.snapshot.observedAt, summary: raw.snapshot.summary
  };
  const results = await Promise.all([
    app.captureRecoveryReconciliationMutationOutcomeEvidence(ownerId, approval.id, input),
    app.captureRecoveryReconciliationMutationOutcomeEvidence(ownerId, approval.id, input)
  ]);
  assert.equal(results[0].id, results[1].id);
  const ledger = await app.getRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(ledger.entryCount, 1);
  assert.equal((await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId)).status, "healthy");
  assert.equal(now(), raw.snapshot.capturedAt);
});

test("Batch 112: ledger chain tampering is detected and further appends fail closed", async t => {
  const { app, ownerId, approval, evidence, now } = await createIndeterminateEvidence(t);
  const ledgerRecord = (await app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  assert.ok(ledgerRecord);
  const raw = await app.store.getEvidence(ownerId, ledgerRecord.id);
  const tampered = { ...raw, snapshot: { ...raw.snapshot, entries: raw.snapshot.entries.map(item => ({ ...item, outcome: "not_applied" })) } };
  await app.store.putEvidence(ownerId, tampered, { expectedVersion: raw._storage.version });
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "MUTATION_OUTCOME_LEDGER_INTEGRITY_FAILED"));
  await assert.rejects(() => captureOutcome(app, ownerId, approval, now(), "applied"),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_INTEGRITY_FAILED"));
  assert.equal((await app.getRecoveryReconciliationMutationOutcomeEvidence(ownerId, evidence.id)).id, evidence.id);
});

test("Batch 112: audit detects evidence records missing from an otherwise valid ledger chain", async t => {
  const { app, ownerId, evidence } = await createIndeterminateEvidence(t);
  const ledgerRecord = (await app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  const raw = await app.store.getEvidence(ownerId, ledgerRecord.id);
  const snapshot = { ...raw.snapshot, revision: 0, headHash: ledgerGenesis(ownerId), entries: [], truncated: false };
  await app.store.putEvidence(ownerId, { ...raw, snapshot, digest: digest(canonical(snapshot)) }, { expectedVersion: raw._storage.version });
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "OUTCOME_EVIDENCE_MISSING_FROM_LEDGER" && item.entityId === evidence.id));
});

test("Batch 112: audit detects a missing completion event when approval history says resolution committed", async t => {
  const { app, ownerId, approval, evidence } = await createIndeterminateEvidence(t);
  await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  const ledgerRecord = (await app.store.listEvidence(ownerId)).find(item => item.kind === "recovery-reconciliation-mutation-outcome-ledger");
  const raw = await app.store.getEvidence(ownerId, ledgerRecord.id);
  const retained = raw.snapshot.entries.slice(0, 2);
  let previousHash = ledgerGenesis(ownerId);
  const rebuilt = retained.map((item, index) => {
    const { hash, ...body } = item;
    const nextBody = { ...body, sequence: index + 1, previousHash };
    const next = { ...nextBody, hash: digest(canonical(nextBody)) };
    previousHash = next.hash;
    return next;
  });
  const snapshot = { ...raw.snapshot, revision: rebuilt.length, headHash: previousHash, entries: rebuilt };
  await app.store.putEvidence(ownerId, { ...raw, snapshot, digest: digest(canonical(snapshot)) }, { expectedVersion: raw._storage.version });
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "CLAIM_RESOLUTION_MISSING_FROM_LEDGER" && item.entityId === approval.id));
  assert.ok(audit.findings.some(item => item.code === "RESOLUTION_COMPLETION_EVENT_MISSING"));
});

test("Batch 112: ledger listing is bounded and owner-scoped", async t => {
  const { app, ownerId } = await createIndeterminateEvidence(t, "owner-b112-a");
  const other = await app.getRecoveryReconciliationMutationOutcomeLedger("owner-b112-b");
  const otherAudit = await app.auditRecoveryReconciliationMutationOutcomeLedger("owner-b112-b");
  const page = await app.listRecoveryReconciliationMutationOutcomeLedgerEntries(ownerId, { limit: 1, offset: 0 });
  assert.equal(page.total, 1);
  assert.equal(page.items.length, 1);
  assert.equal(page.truncated, false);
  assert.equal(other.status, "empty");
  assert.equal(otherAudit.status, "empty");
  await assert.rejects(() => app.listRecoveryReconciliationMutationOutcomeLedgerEntries("", {}), /owner/i);
});

test("Batch 112: audit reports corrupt approval guard state instead of throwing", async t => {
  const { app, ownerId, approval, evidence } = await createIndeterminateEvidence(t);
  await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  const raw = await app.store.getEvidence(ownerId, approval.id);
  await app.store.putEvidence(ownerId, { ...raw, guardState: { ...raw.guardState, revision: raw.guardState.revision + 1 } }, { expectedVersion: raw._storage.version });
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "APPROVAL_GUARD_INTEGRITY_FAILED"));
});

test("Batch 112: application APIs and authenticated HTTP routes expose ledger summary, entries, and audit", async t => {
  const { app, ownerId } = await setup(t);
  assert.equal(typeof app.getRecoveryReconciliationMutationOutcomeLedger, "function");
  assert.equal(typeof app.listRecoveryReconciliationMutationOutcomeLedgerEntries, "function");
  assert.equal(typeof app.auditRecoveryReconciliationMutationOutcomeLedger, "function");
  const server = await readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-audit\/mutation-outcome-ledger/);
  assert.match(server, /recovery-audit\/mutation-outcome-ledger\/entries/);
  assert.match(server, /recovery-audit\/mutation-outcome-ledger\/audit/);
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId, { limit: 1 });
  assert.equal(audit.readOnly, true);
  assert.equal(audit.automaticRepairAllowed, false);
});

test("Batch 112: concurrent resolution replay creates one intent and one completion event", async t => {
  const { app, ownerId, approval, evidence } = await createIndeterminateEvidence(t);
  const results = await Promise.all([
    app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id),
    app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id)
  ]);
  assert.ok(results.some(item => item.status === "resolved_applied"));
  assert.ok(results.some(item => item.status === "already_resolved"));
  const entries = (await app.listRecoveryReconciliationMutationOutcomeLedgerEntries(ownerId, { limit: 20 })).items;
  assert.equal(entries.length, 3);
  assert.deepEqual(entries.map(item => item.eventType), [
    "outcome_evidence_captured", "claim_resolution_started", "claim_resolution_completed"
  ]);
  assert.equal((await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId)).status, "healthy");
});

test("Batch 112: conflicting outcome evidence for the same mutation attempt blocks resolution and is audited", async t => {
  const { app, ownerId, approval, evidence, now, advance } = await createIndeterminateEvidence(t);
  advance(1);
  await captureOutcome(app, ownerId, approval, now(), "not_applied", {
    evidenceRef: "evidence://ops/txn-112-conflict", evidenceDigest: digest("external-artifact:conflicting-not-applied"),
    verificationMethod: "idempotency_lookup", summary: "Conflicting provider lookup for the same claim"
  });
  const audit = await app.auditRecoveryReconciliationMutationOutcomeLedger(ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "CONFLICTING_OUTCOME_EVIDENCE_FOR_CLAIM"));
  assert.equal(audit.automaticRepairAllowed, false);
  await assert.rejects(() => app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_CONFLICTING_EVIDENCE"));
});
