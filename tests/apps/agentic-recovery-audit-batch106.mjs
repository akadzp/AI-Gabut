import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b106") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b106-audit-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  const work = await app.createWork(ownerId, { objective: "audit recovery integrity" });
  return { app, ownerId, work };
}

async function stateWork(app, ownerId, workId, state) {
  if (state === "draft") return app.store.getWork(ownerId, workId);
  await app.work.transition(ownerId, workId, "ready");
  if (state === "ready") return app.store.getWork(ownerId, workId);
  await app.work.transition(ownerId, workId, "running");
  if (state === "running") return app.store.getWork(ownerId, workId);
  if (state === "waiting_approval") return app.work.transition(ownerId, workId, "waiting_approval");
  if (state === "paused") return app.work.transition(ownerId, workId, "paused");
  if (["completed", "failed", "cancelled", "stopped"].includes(state)) return app.work.transition(ownerId, workId, state);
  throw new Error(`unsupported test state ${state}`);
}

function codes(report) { return report.issues.map(issue => issue.code); }

 test("Batch 106: clean owner scope returns a healthy read-only audit", async t => {
  const { app, ownerId } = await setup(t);
  const report = await app.inspectWorkRecoveryIntegrity(ownerId);
  assert.equal(report.readOnly, true);
  assert.equal(report.status, "healthy");
  assert.deepEqual(report.counts, { error: 0, warning: 0, info: 0 });
  assert.equal(report.issueCount, 0);
});

test("Batch 106: detects missing Work and task links without exposing stored payloads", async t => {
  const { app, ownerId } = await setup(t);
  await app.store.putExecution(ownerId, {
    id: "exec-orphan-b106", ownerId, workId: "missing-work-b106", taskId: "missing-task-b106",
    status: "running", prompt: "sensitive prompt must not appear in audit", updatedAt: new Date().toISOString()
  }, { overwrite: false });
  const report = await app.auditWorkRecovery(ownerId);
  assert.ok(codes(report).includes("EXECUTION_WORK_MISSING"));
  assert.ok(codes(report).includes("EXECUTION_TASK_MISSING"));
  assert.equal(JSON.stringify(report).includes("sensitive prompt"), false);
});

test("Batch 106: detects a running Work without an active durable lease", async t => {
  const { app, ownerId, work } = await setup(t);
  await stateWork(app, ownerId, work.id, "running");
  const report = await app.recoveryAudit.inspect(ownerId);
  assert.ok(codes(report).includes("WORK_RUNNING_WITHOUT_ACTIVE_LEASE"));
  assert.equal(report.status, "unhealthy");
});

test("Batch 106: detects lease owner and fencing mismatches", async t => {
  const { app, ownerId, work } = await setup(t);
  await stateWork(app, ownerId, work.id, "running");
  await app.workExecutionLeaseService.acquire(ownerId, work.id, "lease-owner-not-claimed");
  const report = await app.recoveryAudit.inspect(ownerId);
  assert.ok(codes(report).includes("WORK_LEASE_OWNER_MISMATCH"));
  assert.ok(codes(report).includes("WORK_LEASE_FENCE_MISMATCH"));
});

test("Batch 106: detects execution, Work, and task status divergence", async t => {
  const { app, ownerId, work } = await setup(t);
  await stateWork(app, ownerId, work.id, "paused");
  await app.store.putTask(ownerId, {
    id: "task-status-b106", ownerId, workId: work.id, status: "completed", title: "audit task",
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  }, { overwrite: false });
  await app.store.putExecution(ownerId, {
    id: "exec-status-b106", ownerId, workId: work.id, taskId: "task-status-b106", status: "running",
    updatedAt: new Date().toISOString()
  }, { overwrite: false });
  const report = await app.inspectWorkRecoveryIntegrity(ownerId);
  assert.ok(codes(report).includes("ACTIVE_EXECUTION_FOR_PAUSED_WORK"));
  assert.ok(codes(report).includes("EXECUTION_TASK_STATUS_MISMATCH"));
});

test("Batch 106: detects dangling Work recovery reference and fencing regression", async t => {
  const { app, ownerId, work } = await setup(t);
  const current = await app.store.getWork(ownerId, work.id);
  await app.store.putWork(ownerId, {
    ...current, executionLeaseFence: 2,
    result: { recovery: { status: "interrupted", executionId: "missing-recovery-execution", leaseFence: 7 } }
  }, { overwrite: true, expectedVersion: current._storage?.version });
  const report = await app.recoveryAudit.inspect(ownerId);
  assert.ok(codes(report).includes("WORK_RECOVERY_EXECUTION_MISSING"));
  assert.ok(codes(report).includes("WORK_RECOVERY_FENCE_REGRESSION"));
});

test("Batch 106: audit is read-only and leaves record versions unchanged", async t => {
  const { app, ownerId, work } = await setup(t);
  await app.store.putTask(ownerId, {
    id: "task-readonly-b106", ownerId, workId: work.id, status: "paused", title: "read-only task",
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  }, { overwrite: false });
  await app.store.putExecution(ownerId, {
    id: "exec-readonly-b106", ownerId, workId: work.id, taskId: "task-readonly-b106", status: "paused",
    recoverable: true, recovery: { status: "interrupted", recoverable: true }, updatedAt: new Date().toISOString()
  }, { overwrite: false });
  const before = {
    work: (await app.store.getWork(ownerId, work.id))._storage.version,
    task: (await app.store.getTask(ownerId, "task-readonly-b106"))._storage.version,
    execution: (await app.store.getExecution(ownerId, "exec-readonly-b106"))._storage.version
  };
  await app.recoveryAudit.inspect(ownerId);
  const after = {
    work: (await app.store.getWork(ownerId, work.id))._storage.version,
    task: (await app.store.getTask(ownerId, "task-readonly-b106"))._storage.version,
    execution: (await app.store.getExecution(ownerId, "exec-readonly-b106"))._storage.version
  };
  assert.deepEqual(after, before);
});

test("Batch 106: audit remains owner-scoped", async t => {
  const { app, ownerId } = await setup(t, "owner-a-b106");
  await app.store.putExecution("owner-b-b106", {
    id: "foreign-orphan-b106", ownerId: "owner-b-b106", workId: "foreign-missing-work", taskId: "foreign-missing-task",
    status: "running", updatedAt: new Date().toISOString()
  }, { overwrite: false });
  const report = await app.recoveryAudit.inspect(ownerId);
  assert.equal(report.totals.executions, 0);
  assert.equal(report.issueCount, 0);
});

test("Batch 106: bounded audit reports truncation without false missing-link issues", async t => {
  const { app, ownerId, work } = await setup(t);
  const second = await app.createWork(ownerId, { objective: "second audited Work" });
  await app.store.putTask(ownerId, {
    id: "task-limit-b106", ownerId, workId: second.id, status: "paused", title: "limited task",
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  }, { overwrite: false });
  await app.store.putExecution(ownerId, {
    id: "exec-limit-b106", ownerId, workId: second.id, taskId: "task-limit-b106", status: "paused",
    updatedAt: new Date().toISOString()
  }, { overwrite: false });
  const report = await app.recoveryAudit.inspect(ownerId, { limit: 1 });
  assert.equal(report.truncated, true);
  assert.ok(codes(report).includes("AUDIT_RESULT_TRUNCATED"));
  assert.equal(report.totals.works, 2);
  assert.equal(report.audited.works, 1);
  assert.equal(codes(report).includes("EXECUTION_WORK_MISSING"), false);
  assert.equal(report.issues.find(issue => issue.code === "AUDIT_RESULT_TRUNCATED")?.entityId, ownerId);
});

test("Batch 106: issue ordering is deterministic and owner is mandatory", async t => {
  const { app, ownerId } = await setup(t);
  await app.store.putExecution(ownerId, {
    id: "z-orphan-b106", ownerId, workId: "missing-z", taskId: "missing-z-task", status: "running"
  }, { overwrite: false });
  await app.store.putExecution(ownerId, {
    id: "a-orphan-b106", ownerId, workId: "missing-a", taskId: "missing-a-task", status: "running"
  }, { overwrite: false });
  const first = await app.recoveryAudit.inspect(ownerId);
  const second = await app.recoveryAudit.inspect(ownerId);
  assert.deepEqual(first.issues, second.issues);
  assert.deepEqual(first.issues.map(item => [item.code, item.entityId]), second.issues.map(item => [item.code, item.entityId]));
  await assert.rejects(() => app.recoveryAudit.inspect(""), error => error.code === "RECOVERY_AUDIT_OWNER_REQUIRED");
  assert.equal(typeof app.inspectWorkRecoveryIntegrity, "function");
  assert.equal(typeof app.auditWorkRecovery, "function");
});

test("Batch 106: detects missing Work-owned task/execution references and orphan active tasks", async t => {
  const { app, ownerId, work } = await setup(t);
  const current = await app.store.getWork(ownerId, work.id);
  await app.store.putWork(ownerId, {
    ...current, taskIds: ["missing-attached-task"], executionIds: ["missing-attached-execution"]
  }, { overwrite: true, expectedVersion: current._storage?.version });
  await app.store.putTask(ownerId, {
    id: "orphan-active-task-b106", ownerId, workId: "missing-task-work", status: "running", title: "orphan task",
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  }, { overwrite: false });
  const report = await app.recoveryAudit.inspect(ownerId);
  assert.ok(codes(report).includes("WORK_TASK_REFERENCE_MISSING"));
  assert.ok(codes(report).includes("WORK_EXECUTION_REFERENCE_MISSING"));
  assert.ok(codes(report).includes("TASK_WORK_MISSING"));
  assert.ok(codes(report).includes("ACTIVE_TASK_WITHOUT_EXECUTION"));
});

test("Batch 106: detects a running execution whose durable lease belongs to another run", async t => {
  const { app, ownerId, work } = await setup(t);
  await stateWork(app, ownerId, work.id, "running");
  await app.workExecutionLeaseService.acquire(ownerId, work.id, "different-running-execution");
  await app.store.putExecution(ownerId, {
    id: "running-execution-without-lease-b106", ownerId, workId: work.id, status: "running",
    updatedAt: new Date().toISOString()
  }, { overwrite: false });
  const report = await app.recoveryAudit.inspect(ownerId);
  assert.ok(codes(report).includes("EXECUTION_LEASE_OWNER_MISMATCH"));
  assert.ok(codes(report).includes("WORK_LEASE_OWNER_MISMATCH"));
});
