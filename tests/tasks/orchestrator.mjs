import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createStorage } from "../../core/storage/index.js";
import { createStateService } from "../../core/storage/state/index.js";
import { createTaskOrchestrator } from "../../core/tasks/index.js";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-gabut-tasks-"));
try {
  const storage = createStorage({ root });
  const state = createStateService({ storage, namespace: "test-tasks", scopes: ["tasks", "jobs", "executions"] });
  const orchestrator = createTaskOrchestrator({ stateService: state, leaseMs: 5000, executor: async ({ task, checkpoint }) => { await checkpoint({ phase: "work", taskId: task.id }); return { ok: true, value: task.input.value }; } });
  const task = await orchestrator.createTask({ name: "demo", input: { value: 42 }, retryPolicy: { maxAttempts: 2, backoffMs: 0, maxBackoffMs: 0 } });
  assert.equal(task.status, "queued");
  const job = await orchestrator.enqueue(task.id);
  assert.equal(job.status, "queued");
  const claimed = await orchestrator.claimNext({ workerId: "test-worker" });
  assert.equal(claimed.id, job.id);
  assert.equal(claimed.attempt, 1);
  const execution = await orchestrator.startExecution(job.id);
  assert.equal(execution.status, "created");
  const checkpointed = await orchestrator.checkpoint(execution.id, { phase: "manual" });
  assert.equal(checkpointed.status, "checkpointed");
  const finished = await orchestrator.finishExecution(execution.id, { result: { ok: true } });
  assert.equal(finished.status, "completed");
  assert.equal((await orchestrator.getTask(task.id)).status, "completed");
  assert.equal((await orchestrator.getJob(job.id)).status, "completed");
  const autoTask = await orchestrator.createTask({ name: "auto", input: { value: 7 } });
  await orchestrator.enqueue(autoTask.id);
  const autoExecution = await orchestrator.runNext({ workerId: "auto-worker" });
  assert.equal(autoExecution.status, "completed");
  console.log("Task/job/execution orchestration contract: PASS");
} finally { await fs.rm(root, { recursive: true, force: true }); }
