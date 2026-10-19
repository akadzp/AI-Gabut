import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import { createRecoveryService } from "../../apps/agentic/backend/recovery.js";

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function setup(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b105-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }), workExecutionLeaseMs: options.leaseMs ?? 5000 });
  const ownerId = options.ownerId || "owner-b105";
  const work = await app.createWork(ownerId, { objective: options.objective || "recover interrupted execution" });
  return { app, ownerId, work };
}

async function setWorkState(app, ownerId, workId, state, fence = undefined) {
  const meta = fence == null ? {} : { executionLeaseFence: fence };
  const current = await app.work.raw(ownerId, workId);
  if (current.state === "draft" && state !== "draft") await app.work.transition(ownerId, workId, "ready", meta);
  const afterReady = await app.work.raw(ownerId, workId);
  if (afterReady.state === "ready" && ["running", "waiting_approval", "paused", "completed", "failed", "cancelled", "stopped"].includes(state)) {
    await app.work.transition(ownerId, workId, "running", meta);
  }
  const afterRunning = await app.work.raw(ownerId, workId);
  if (afterRunning.state === "running" && state !== "running") await app.work.transition(ownerId, workId, state, meta);
}

async function seedExecution(app, ownerId, workId, { id = "exec-b105", status = "running", taskStatus = "running", updatedAt = new Date(Date.now() - 60 * 60 * 1000).toISOString(), checkpoint = { stepId: "step-2" } } = {}) {
  const taskId = `task-${id}`;
  await app.store.putTask(ownerId, { id: taskId, ownerId, workId, status: taskStatus, title: "recovery task", createdAt: updatedAt, updatedAt });
  await app.store.putExecution(ownerId, { id, ownerId, workId, taskId, status, checkpoint, startedAt: updatedAt, updatedAt, recoverable: false });
  return { id, taskId };
}

function recoveryFor(app) {
  return createRecoveryService({ store: app.store, work: app.work, workExecutionLeaseService: app.workExecutionLeaseService });
}

test("Batch 105: stale execution is not recovered while its durable lease is active", async t => {
  const { app, ownerId, work } = await setup(t);
  await setWorkState(app, ownerId, work.id, "running");
  const lease = await app.workExecutionLeaseService.acquire(ownerId, work.id, "exec-active");
  await app.work.claimExecution(ownerId, work.id, { executionId: "exec-active", fence: lease.fence });
  await seedExecution(app, ownerId, work.id, { id: "exec-active" });

  const found = await recoveryFor(app).scan(ownerId, { staleAfterMs: 1000 });
  assert.equal(found.length, 0);
  assert.equal((await app.work.raw(ownerId, work.id)).state, "running");
  assert.equal((await app.store.getExecution(ownerId, "exec-active")).status, "running");
  assert.equal((await app.workExecutionLeaseService.inspect(ownerId, work.id)).active, true);
});

test("Batch 105: expired lease recovery fences the old runner and reconciles Work, execution, and task", async t => {
  const { app, ownerId, work } = await setup(t, { leaseMs: 45 });
  await setWorkState(app, ownerId, work.id, "running");
  const oldLease = await app.workExecutionLeaseService.acquire(ownerId, work.id, "exec-crashed");
  await app.work.claimExecution(ownerId, work.id, { executionId: "exec-crashed", fence: oldLease.fence });
  const seeded = await seedExecution(app, ownerId, work.id, { id: "exec-crashed" });
  await delay(65);

  const recovery = recoveryFor(app);
  const found = await recovery.scan(ownerId, { staleAfterMs: 1000 });
  assert.equal(found.length, 1);
  assert.equal(found[0].execution.status, "paused");
  assert.equal(found[0].execution.recovery.recoverable, true);
  assert.equal(found[0].execution.recovery.leaseFence, oldLease.fence + 1);
  assert.deepEqual(found[0].execution.recovery.lastCheckpoint, { stepId: "step-2" });

  const savedWork = await app.work.raw(ownerId, work.id);
  const savedExecution = await app.store.getExecution(ownerId, seeded.id);
  const savedTask = await app.store.getTask(ownerId, seeded.taskId);
  assert.equal(savedWork.state, "paused");
  assert.equal(savedWork.executionLeaseId.startsWith("recovery:exec-crashed:"), true);
  assert.equal(savedWork.executionLeaseFence, oldLease.fence + 1);
  assert.equal(savedWork.result.recovery.executionId, seeded.id);
  assert.equal(savedExecution.status, "paused");
  assert.equal(savedTask.status, "paused");
  await assert.rejects(
    () => app.workExecutionLeaseService.assertOwned(ownerId, work.id, "exec-crashed", oldLease.token),
    error => ["LEASE_NOT_OWNER", "LEASE_EXPIRED"].includes(error.code)
  );
  assert.equal((await recovery.scan(ownerId, { staleAfterMs: 1000 })).length, 0);
});

test("Batch 105: a fresh running record with no active lease is reconciled as lease loss", async t => {
  const { app, ownerId, work } = await setup(t);
  await setWorkState(app, ownerId, work.id, "running");
  const seeded = await seedExecution(app, ownerId, work.id, {
    id: "exec-lost-lease", updatedAt: new Date().toISOString()
  });

  const found = await recoveryFor(app).scan(ownerId, { staleAfterMs: 60_000 });
  assert.equal(found.length, 1);
  assert.equal(found[0].execution.status, "paused");
  assert.equal(found[0].execution.recovery.reason, "lease-loss-reconciled");
  assert.equal((await app.work.raw(ownerId, work.id)).state, "paused");
  assert.equal((await app.store.getExecution(ownerId, seeded.id)).status, "paused");
  assert.equal((await app.store.getTask(ownerId, seeded.taskId)).status, "paused");
});

test("Batch 105: a fresh waiting-approval execution with a released lease is not treated as a crash", async t => {
  const { app, ownerId, work } = await setup(t);
  await setWorkState(app, ownerId, work.id, "waiting_approval");
  const lease = await app.workExecutionLeaseService.acquire(ownerId, work.id, "exec-awaiting-approval");
  await app.workExecutionLeaseService.release(ownerId, work.id, "exec-awaiting-approval", lease.token);
  await seedExecution(app, ownerId, work.id, {
    id: "exec-awaiting-approval", status: "waiting_approval", taskStatus: "waiting_approval",
    updatedAt: new Date().toISOString()
  });

  const found = await recoveryFor(app).scan(ownerId, { staleAfterMs: 60_000 });
  assert.equal(found.length, 0);
  assert.equal((await app.work.raw(ownerId, work.id)).state, "waiting_approval");
  assert.equal((await app.store.getExecution(ownerId, "exec-awaiting-approval")).status, "waiting_approval");
});

test("Batch 105: a terminal Work state resolves stale execution and task without reopening Work", async t => {
  const { app, ownerId, work } = await setup(t);
  await setWorkState(app, ownerId, work.id, "completed");
  const seeded = await seedExecution(app, ownerId, work.id, { id: "exec-work-completed" });

  const found = await recoveryFor(app).scan(ownerId, { staleAfterMs: 1000 });
  assert.equal(found.length, 1);
  assert.equal(found[0].execution.status, "completed");
  assert.equal(found[0].execution.recovery.status, "resolved");
  assert.equal((await app.work.raw(ownerId, work.id)).state, "completed");
  assert.equal((await app.store.getExecution(ownerId, seeded.id)).status, "completed");
  assert.equal((await app.store.getTask(ownerId, seeded.taskId)).status, "completed");
  assert.equal((await recoveryFor(app).list(ownerId)).length, 0);
});

test("Batch 105: recovery repairs a partial crash after Work was paused but before execution and task settled", async t => {
  const { app, ownerId, work } = await setup(t);
  await setWorkState(app, ownerId, work.id, "paused");
  const seeded = await seedExecution(app, ownerId, work.id, { id: "exec-partial-recovery" });

  const found = await recoveryFor(app).scan(ownerId, { staleAfterMs: 1000 });
  assert.equal(found.length, 1);
  assert.equal((await app.work.raw(ownerId, work.id)).state, "paused");
  assert.equal((await app.store.getExecution(ownerId, seeded.id)).status, "paused");
  assert.equal((await app.store.getTask(ownerId, seeded.taskId)).status, "paused");
  assert.equal((await app.work.raw(ownerId, work.id)).result.recovery.executionId, seeded.id);
});

test("Batch 105: lease acquisition honors a minimum fence when the lease record is absent", async t => {
  const { app, ownerId, work } = await setup(t);
  await app.work.claimExecution(ownerId, work.id, { executionId: "prior-fence-owner", fence: 8 });
  const lease = await app.workExecutionLeaseService.acquire(ownerId, work.id, "recovery-after-lease-loss", { minFence: 9 });
  assert.equal(lease.fence, 9);
  await app.workExecutionLeaseService.release(ownerId, work.id, lease.executionId, lease.token);
});


test("Batch 105: concurrent recovery scanners reconcile one interrupted execution once", async t => {
  const { app, ownerId, work } = await setup(t, { leaseMs: 5000 });
  await setWorkState(app, ownerId, work.id, "running");
  const seeded = await seedExecution(app, ownerId, work.id, { id: "exec-concurrent-recovery" });
  const first = recoveryFor(app);
  const second = recoveryFor(app);

  const results = await Promise.all([
    first.scan(ownerId, { staleAfterMs: 1000 }),
    second.scan(ownerId, { staleAfterMs: 1000 })
  ]);
  assert.equal(results.flat().length, 1);
  assert.equal((await app.work.raw(ownerId, work.id)).state, "paused");
  assert.equal((await app.store.getExecution(ownerId, seeded.id)).status, "paused");
  assert.equal((await app.store.getTask(ownerId, seeded.taskId)).status, "paused");
});
