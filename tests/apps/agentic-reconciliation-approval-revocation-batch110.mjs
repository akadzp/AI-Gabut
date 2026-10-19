import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b110") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b110-approval-guard-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => new Date(now).toISOString() });
  return { app, ownerId, root, advance: ms => { now += ms; } };
}

async function makeActionApproval(app, ownerId, options = {}) {
  const work = await app.createWork(ownerId, { objective: "Batch 110 mutation-boundary fixture" });
  await app.transitionWork(ownerId, work.id, "ready");
  await app.transitionWork(ownerId, work.id, "running");
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const action = plan.plan.actions.find(item => item.issueRef && item.operation !== "rerun_audit");
  assert.ok(action, "fixture must produce one actionable recovery recommendation");
  const revalidation = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  assert.equal(revalidation.snapshot.status, "fresh");
  const mutationIntent = options.mutationIntent || {
    actionId: action.id, operation: action.operation, issueCode: action.issueCode,
    target: action.target, change: { decision: "record-reviewed", ticket: "OPS-110-1" }
  };
  const approval = await app.approveRecoveryReconciliationAction(
    ownerId, plan.id, revalidation.id, action.id, mutationIntent, { ttlMs: 60_000 }
  );
  return { work, evidence, plan, action, revalidation, mutationIntent, approval };
}

function hasCode(expected) {
  return error => error?.code === expected;
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

test("Batch 110: action-bound approval binds the exact mutation intent and durable guard state", async t => {
  const { app, ownerId } = await setup(t);
  const { action, mutationIntent, approval } = await makeActionApproval(app, ownerId);
  assert.equal(approval.approval.actionId, action.id);
  assert.match(approval.approval.mutationIntentDigest, /^[a-f0-9]{64}$/);
  assert.match(approval.approval.mutationTargetDigest, /^[a-f0-9]{64}$/);
  assert.equal(approval.guard.revoked, false);
  assert.equal(approval.guard.consumedActionCount, 0);
  assert.equal(approval.approval.executionAllowed, false);
  assert.deepEqual(approval.approval.actionId, mutationIntent.actionId);
});

test("Batch 110: plan-level approval cannot cross the mutation boundary without an action-bound intent", async t => {
  const { app, ownerId } = await setup(t);
  const work = await app.createWork(ownerId, { objective: "Plan approval only" });
  await app.transitionWork(ownerId, work.id, "ready");
  await app.transitionWork(ownerId, work.id, "running");
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const revalidation = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const approval = await app.approveRecoveryReconciliationPlan(ownerId, plan.id, revalidation.id);
  let called = false;
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, plan.plan.actions[0].id, {}, async () => { called = true; }),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_NOT_BOUND")
  );
  assert.equal(called, false);
});

test("Batch 110: revocation is idempotent and immediately invalidates verification and mutation", async t => {
  const { app, ownerId } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  const first = await app.revokeRecoveryReconciliationApproval(ownerId, approval.id, { reasonCode: "OPERATOR_REVOKED" });
  const second = await app.revokeRecoveryReconciliationApproval(ownerId, approval.id, { reasonCode: "OPERATOR_REVOKED" });
  assert.equal(first.status, "revoked");
  assert.equal(first.alreadyRevoked, false);
  assert.equal(second.alreadyRevoked, true);
  assert.equal((await app.verifyRecoveryReconciliationApproval(ownerId, approval.id)).status, "revoked");
  let called = false;
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => { called = true; }),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_REVOKED")
  );
  assert.equal(called, false);
  assert.equal((await app.getRecoveryReconciliationApproval(ownerId, approval.id)).guard.reasonCode, "OPERATOR_REVOKED");
});

test("Batch 110: cross-owner revocation and mutation authorization fail closed", async t => {
  const { app, ownerId } = await setup(t, "owner-a-b110");
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await assert.rejects(
    () => app.revokeRecoveryReconciliationApproval("owner-b-b110", approval.id),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND")
  );
  let called = false;
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation("owner-b-b110", approval.id, action.id, mutationIntent, async () => { called = true; }),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND")
  );
  assert.equal(called, false);
});

test("Batch 110: mutation intent mismatch is rejected before the callback runs", async t => {
  const { app, ownerId } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  const changedIntent = { ...mutationIntent, change: { decision: "delete-record", ticket: "OPS-110-1" } };
  let called = false;
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, changedIntent, async () => { called = true; }),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_INTENT_MISMATCH")
  );
  assert.equal(called, false);
});

test("Batch 110: mutation intent rejects unbound fields and oversized values", async t => {
  const { app, ownerId } = await setup(t);
  const { plan, revalidation, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await assert.rejects(
    () => app.approveRecoveryReconciliationAction(ownerId, plan.id, revalidation.id, action.id, {
      ...mutationIntent, hiddenUnboundField: "must-not-be-ignored"
    }),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID")
  );
  await assert.rejects(
    () => app.approveRecoveryReconciliationAction(ownerId, plan.id, revalidation.id, action.id, {
      ...mutationIntent, change: { note: "x".repeat(1001) }
    }),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_TOO_LARGE")
  );
});

test("Batch 110: mutation guard revalidates current state and exposes expected CAS preconditions", async t => {
  const { app, ownerId } = await setup(t);
  const { work, approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  let observed = null;
  const result = await app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async context => {
    observed = await context.assertPreconditionsCurrent();
    assert.equal(context.expectedPreconditions.digest, action.preconditionDigest);
    assert.ok(context.expectedPreconditions.records.some(record => record.entityType === "work" && record.id === work.id));
    assert.match(context.idempotencyKey, /^[a-f0-9]{48}$/);
    return { committed: true };
  });
  assert.equal(observed.readOnly, true);
  assert.equal(result.result.committed, true);
  assert.equal(result.authorization.consumed, true);
  const stored = await app.getRecoveryReconciliationApproval(ownerId, approval.id);
  assert.equal(stored.guard.consumedActionCount, 1);
  assert.equal(stored.guard.activeMutation, null);
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => ({ committed: true })),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_ACTION_ALREADY_CONSUMED")
  );
});

test("Batch 110: changed preconditions deny mutation before invoking the callback", async t => {
  const { app, ownerId } = await setup(t);
  const { work, approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  const current = await app.store.getWork(ownerId, work.id);
  await app.store.putWork(ownerId, { ...current, auditMarker: "changed-after-approval" }, { expectedVersion: current._storage.version });
  let called = false;
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => { called = true; }),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_NOT_VALID")
  );
  assert.equal(called, false);
});

test("Batch 110: concurrent mutation attempts are serialized by the durable approval guard", async t => {
  const { app, ownerId, root } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  const secondApp = createAgenticApplication({ storage: createStorage({ root }), clock: () => new Date("2026-10-11T00:00:00.000Z").toISOString() });
  const entered = deferred();
  const release = deferred();
  const first = app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => {
    entered.resolve();
    await release.promise;
    return { committed: true };
  });
  await entered.promise;
  await assert.rejects(
    () => secondApp.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => ({ committed: true })),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_IN_PROGRESS")
  );
  await assert.rejects(
    () => secondApp.revokeRecoveryReconciliationApproval(ownerId, approval.id),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_IN_PROGRESS")
  );
  release.resolve();
  const result = await first;
  assert.equal(result.authorization.consumed, true);
});

test("Batch 110: callback failure leaves an indeterminate fail-closed mutation claim", async t => {
  const { app, ownerId } = await setup(t);
  const { approval, action, mutationIntent } = await makeActionApproval(app, ownerId);
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => {
      const error = new Error("callback failed after uncertain side effect");
      error.code = "TEST_MUTATION_FAILURE";
      throw error;
    }),
    hasCode("TEST_MUTATION_FAILURE")
  );
  assert.equal((await app.verifyRecoveryReconciliationApproval(ownerId, approval.id)).status, "mutation_outcome_unknown");
  await assert.rejects(
    () => app.runApprovedRecoveryReconciliationMutation(ownerId, approval.id, action.id, mutationIntent, async () => ({ committed: true })),
    hasCode("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_UNKNOWN")
  );
  await assert.rejects(
    () => app.revokeRecoveryReconciliationApproval(ownerId, approval.id),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_OUTCOME_UNKNOWN")
  );
});

test("Batch 110: tampered guard state is detected by its independent digest", async t => {
  const { app, ownerId } = await setup(t);
  const { approval } = await makeActionApproval(app, ownerId);
  const raw = await app.store.getEvidence(ownerId, approval.id);
  await app.store.putEvidence(ownerId, {
    ...raw, guardState: { ...raw.guardState, revokedAt: "2026-10-11T00:00:00.000Z", revokedBy: ownerId }
  }, { expectedVersion: raw._storage.version });
  await assert.rejects(
    () => app.verifyRecoveryReconciliationApproval(ownerId, approval.id),
    hasCode("RECOVERY_RECONCILIATION_APPROVAL_GUARD_INTEGRITY_FAILED")
  );
});

test("Batch 110: approval listing reports revocation and server exposes action approval/revoke routes", async t => {
  const { app, ownerId } = await setup(t);
  const { approval } = await makeActionApproval(app, ownerId);
  await app.revokeRecoveryReconciliationApproval(ownerId, approval.id);
  const listed = await app.listRecoveryReconciliationApprovals(ownerId, { limit: 10 });
  assert.equal(listed.items.find(item => item.id === approval.id).status, "revoked");
  const server = await readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-audit\/plans\/:id\/actions\/:actionId\/approval/);
  assert.match(server, /recovery-audit\/approvals\/:id\/revoke/);
});
