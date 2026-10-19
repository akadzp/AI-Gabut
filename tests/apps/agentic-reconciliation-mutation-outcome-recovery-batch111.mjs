import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b111") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b111-outcome-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => new Date(now).toISOString() });
  return { app, ownerId, root, now: () => new Date(now).toISOString(), advance: ms => { now += ms; } };
}

async function makeActionApproval(app, ownerId) {
  const work = await app.createWork(ownerId, { objective: "Batch 111 mutation outcome fixture" });
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
    target: action.target, change: { decision: "record-reviewed", ticket: "OPS-111-1" }
  };
  const approval = await app.approveRecoveryReconciliationAction(
    ownerId, plan.id, revalidation.id, action.id, mutationIntent, { ttlMs: 60_000 }
  );
  return { work, evidence, plan, action, revalidation, mutationIntent, approval };
}

function hasCode(expected) { return error => error?.code === expected; }
function digest(value) { return createHash("sha256").update(value).digest("hex"); }

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
    outcome,
    evidenceRef: "evidence://ops/txn-111-01",
    evidenceDigest: digest(`external-artifact:${outcome}`),
    verificationMethod: "transaction_log",
    attemptQuiescent: true,
    quiescenceEvidenceRef: "process://agentic/attempt-terminal-111",
    quiescenceEvidenceDigest: digest("attempt-quiescence-proof"),
    quiescenceMethod: "provider_terminal_status",
    observedAt,
    summary: `Verified mutation outcome: ${outcome}`,
    ...overrides
  });
}

test("Batch 111: a stale in-progress claim is quarantined as indeterminate, never retried automatically", async t => {
  const { app, ownerId, advance, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  let enteredResolve;
  let releaseResolve;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  const release = new Promise(resolve => { releaseResolve = resolve; });
  const running = app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => {
    enteredResolve();
    await release;
    return { committed: true };
  });
  await entered;
  const before = await app.inspectRecoveryReconciliationMutationClaim(ownerId, approval.id, { staleAfterMs: 1_000 });
  assert.equal(before.status, "in_progress");
  assert.equal(before.stale, false);
  const tooEarly = await app.recoverRecoveryReconciliationMutationClaim(ownerId, approval.id, { staleAfterMs: 1_000 });
  assert.equal(tooEarly.status, "not_stale");
  advance(1_001);
  const recovered = await app.recoverRecoveryReconciliationMutationClaim(ownerId, approval.id, { staleAfterMs: 1_000 });
  assert.equal(recovered.status, "recovered_to_indeterminate");
  assert.equal((await app.inspectRecoveryReconciliationMutationClaim(ownerId, approval.id)).status, "indeterminate");
  releaseResolve();
  await assert.rejects(() => running, hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_UNKNOWN"));
  assert.equal((await app.verifyRecoveryReconciliationApproval(ownerId, approval.id)).status, "mutation_outcome_unknown");
  assert.ok(Date.parse(now()) > Date.parse(before.startedAt));
});

test("Batch 111: an applied outcome consumes the action and is idempotently resolvable", async t => {
  const { app, ownerId, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  const evidence = await captureOutcome(app, ownerId, approval, now(), "applied");
  const resolved = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(resolved.status, "resolved_applied");
  assert.equal(resolved.actionConsumed, true);
  assert.equal((await app.verifyRecoveryReconciliationApproval(ownerId, approval.id)).status, "consumed");
  const replay = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(replay.status, "already_resolved");
  assert.equal(replay.outcome, "applied");
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => ({ committed: true })),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_ACTION_ALREADY_CONSUMED")
  );
});

test("Batch 111: verified not-applied outcome clears the claim but still requires fresh authorization before retry", async t => {
  const { app, ownerId, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  const evidence = await captureOutcome(app, ownerId, approval, now(), "not_applied", {
    verificationMethod: "idempotency_lookup", evidenceRef: "provider://idempotency/lookup-111",
    evidenceDigest: digest("provider-confirmed-not-applied")
  });
  const resolved = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(resolved.status, "resolved_not_applied");
  assert.equal(resolved.retryMayBeConsidered, true);
  assert.equal((await app.inspectRecoveryReconciliationMutationClaim(ownerId, approval.id)).status, "no_active_claim");
  assert.equal((await app.verifyRecoveryReconciliationApproval(ownerId, approval.id)).status, "valid");
  const retry = await app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async context => {
    assert.ok(context.claimId);
    return { committed: true, retry: true };
  });
  assert.equal(retry.result.retry, true);
  assert.equal(retry.authorization.consumed, true);
});

test("Batch 111: unresolved evidence keeps the claim indeterminate and blocks mutation and revocation", async t => {
  const { app, ownerId, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  const evidence = await captureOutcome(app, ownerId, approval, now(), "unresolved", { verificationMethod: "operator_attestation" });
  const resolved = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(resolved.status, "unresolved");
  assert.equal((await app.verifyRecoveryReconciliationApproval(ownerId, approval.id)).status, "mutation_outcome_unknown");
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => ({ committed: true })),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_UNKNOWN")
  );
  await assert.rejects(() => app.revokeRecoveryReconciliationApproval(ownerId, approval.id), hasCode("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_OUTCOME_UNKNOWN"));
});

test("Batch 111: an outcome claim cannot be resolved using evidence from another approval or attempt", async t => {
  const { app, ownerId, now } = await setup(t);
  const first = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, first.action, first.mutationIntent, first.approval);
  const evidence = await captureOutcome(app, ownerId, first.approval, now(), "applied");
  const second = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, second.action, second.mutationIntent, second.approval);
  await assert.rejects(
    () => app.resolveRecoveryReconciliationMutationClaim(ownerId, second.approval.id, evidence.id),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_BINDING_MISMATCH")
  );
  const firstResolved = await app.resolveRecoveryReconciliationMutationClaim(ownerId, first.approval.id, evidence.id);
  assert.equal(firstResolved.status, "resolved_applied");
});

test("Batch 111: a certain outcome requires a verifiable source method and valid evidence digest", async t => {
  const { app, ownerId, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  await assert.rejects(
    () => captureOutcome(app, ownerId, approval, now(), "applied", { verificationMethod: "operator_attestation" }),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INSUFFICIENT")
  );
  await assert.rejects(
    () => captureOutcome(app, ownerId, approval, now(), "not_applied", { evidenceDigest: "not-a-digest" }),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_DIGEST_INVALID")
  );
  await assert.rejects(
    () => captureOutcome(app, ownerId, approval, now(), "not_applied", { attemptQuiescent: false }),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_QUIESCENCE_EVIDENCE_INSUFFICIENT")
  );
  await assert.rejects(
    () => captureOutcome(app, ownerId, approval, "2026-10-10T00:00:00.000Z", "applied"),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_OBSERVED_AT_INVALID")
  );
});

test("Batch 111: cross-owner evidence capture, inspection, and resolution fail closed", async t => {
  const { app, ownerId, now } = await setup(t, "owner-a-b111");
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  await assert.rejects(() => app.inspectRecoveryReconciliationMutationClaim("owner-b-b111", approval.id), hasCode("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND"));
  await assert.rejects(() => app.captureRecoveryReconciliationMutationOutcomeEvidence("owner-b-b111", approval.id, {}), hasCode("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND"));
  const evidence = await captureOutcome(app, ownerId, approval, now(), "applied");
  await assert.rejects(() => app.resolveRecoveryReconciliationMutationClaim("owner-b-b111", approval.id, evidence.id), hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_NOT_FOUND"));
});

test("Batch 111: outcome evidence is immutable, owner-scoped, listable, and digest-verified", async t => {
  const { app, ownerId, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  const evidence = await captureOutcome(app, ownerId, approval, now(), "applied");
  const loaded = await app.getRecoveryReconciliationMutationOutcomeEvidence(ownerId, evidence.id);
  assert.equal(loaded.digest, evidence.digest);
  assert.equal(loaded.snapshot.claimId, evidence.snapshot.claimId);
  assert.equal(loaded.snapshot.automaticExecutionAllowed, false);
  const listed = await app.listRecoveryReconciliationMutationOutcomeEvidence(ownerId, { limit: 10 });
  assert.ok(listed.items.some(item => item.id === evidence.id));
  const raw = await app.store.getEvidence(ownerId, evidence.id);
  await app.store.putEvidence(ownerId, { ...raw, snapshot: { ...raw.snapshot, outcome: "not_applied" } }, { expectedVersion: raw._storage.version });
  await assert.rejects(() => app.getRecoveryReconciliationMutationOutcomeEvidence(ownerId, evidence.id), hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED"));
});

test("Batch 111: an evidence record cannot be replayed against a new claim attempt with the same idempotency key", async t => {
  const { app, ownerId, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  const evidence = await captureOutcome(app, ownerId, approval, now(), "not_applied", { verificationMethod: "idempotency_lookup" });
  const resolved = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(resolved.status, "resolved_not_applied");
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  const claim = await app.inspectRecoveryReconciliationMutationClaim(ownerId, approval.id);
  assert.notEqual(claim.claimId, evidence.snapshot.claimId);
  const replay = await app.resolveRecoveryReconciliationMutationClaim(ownerId, approval.id, evidence.id);
  assert.equal(replay.status, "already_resolved");
  assert.equal((await app.inspectRecoveryReconciliationMutationClaim(ownerId, approval.id)).status, "indeterminate");
});

test("Batch 111: APIs and authenticated route mappings expose claim recovery and evidence resolution", async t => {
  const { app, ownerId, now } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await makeIndeterminate(app, ownerId, action, mutationIntent, approval);
  const claim = await app.inspectRecoveryReconciliationMutationClaim(ownerId, approval.id);
  assert.equal(claim.status, "indeterminate");
  const evidence = await captureOutcome(app, ownerId, approval, now(), "applied");
  const list = await app.listRecoveryReconciliationMutationOutcomeEvidence(ownerId);
  assert.ok(list.items.some(item => item.id === evidence.id));
  const server = await readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-audit\/approvals\/:id\/mutation-claim\/recover/);
  assert.match(server, /recovery-audit\/approvals\/:id\/mutation-outcome-evidence/);
  assert.match(server, /recovery-audit\/approvals\/:id\/mutation-claim\/resolve/);
  assert.match(server, /recovery-audit\/mutation-outcome-evidence\/:id/);
});
