import crypto from "node:crypto";
import { createStateService } from "../storage/state/index.js";
import { TASK_ERRORS, TaskError } from "./errors.js";
import { TASK_STATES, JOB_STATES, EXECUTION_STATES, normalizeRetryPolicy, assertState } from "./contracts.js";

const SCOPES = Object.freeze(["tasks", "jobs", "executions"]);
const DEFAULT_LEASE_MS = 60_000;
const MAX_HISTORY = 50;

const now = () => new Date().toISOString();
const id = prefix => `${prefix}-${crypto.randomUUID()}`;
const assertId = value => {
  if (typeof value !== "string" || !value.trim()) throw new TaskError(TASK_ERRORS.VALIDATION, "ID wajib diisi");
  return value.trim();
};

function appendHistory(record, action, meta = {}) {
  return [...(record.history || []), { at: now(), action, ...meta }].slice(-MAX_HISTORY);
}

export function createTaskOrchestrator({ stateService = null, leaseMs = DEFAULT_LEASE_MS, executor = null } = {}) {
  const state = stateService || createStateService({ namespace: "tasks", scopes: SCOPES });
  const safeLeaseMs = Math.max(1000, Number(leaseMs) || DEFAULT_LEASE_MS);
  const runExecutor = typeof executor === "function" ? executor : null;

  async function getTask(taskId) { return state.get("tasks", assertId(taskId)); }
  async function getJob(jobId) { return state.get("jobs", assertId(jobId)); }
  async function getExecution(executionId) { return state.get("executions", assertId(executionId)); }

  async function createTask({ name = "task", input = {}, metadata = {}, retryPolicy = {} } = {}) {
    const taskId = id("task");
    const task = { id: taskId, type: "task", name: String(name).slice(0, 200), input, metadata, retryPolicy: normalizeRetryPolicy(retryPolicy), status: "queued", createdAt: now(), updatedAt: now(), history: [{ at: now(), action: "created" }] };
    return state.put("tasks", taskId, task, { overwrite: false });
  }

  async function enqueue(taskId, { priority = 0, scheduledAt = null } = {}) {
    const task = await getTask(taskId);
    if (!task) throw new TaskError(TASK_ERRORS.NOT_FOUND, "Task tidak ditemukan");
    assertState(TASK_STATES, task.status, "Task");
    if (!["queued", "failed"].includes(task.status)) throw new TaskError(TASK_ERRORS.INVALID_STATE, `Task tidak dapat di-enqueue dari state ${task.status}`);
    const jobId = id("job");
    const job = { id: jobId, taskId: task.id, type: "job", priority: Number(priority) || 0, scheduledAt, status: "queued", attempt: 0, retryPolicy: task.retryPolicy, createdAt: now(), updatedAt: now(), history: [{ at: now(), action: "queued" }] };
    task.status = "queued"; task.updatedAt = now(); task.history = appendHistory(task, "enqueued", { jobId });
    await state.put("tasks", task.id, task, { expectedVersion: task._storage?.version });
    await state.put("jobs", jobId, job, { overwrite: false });
    return job;
  }

  async function claimNext({ workerId = "worker", nowMs = Date.now() } = {}) {
    const jobIds = await state.list("jobs");
    const jobs = (await Promise.all(jobIds.map(getJob))).filter(Boolean).filter(job => job.status === "queued").sort((a, b) => Number(b.priority || 0) - Number(a.priority || 0) || String(a.createdAt).localeCompare(String(b.createdAt)));
    for (const queuedJob of jobs) {
      const job = queuedJob;
      if (job.scheduledAt && new Date(job.scheduledAt).getTime() > nowMs) continue;
      const task = await getTask(job.taskId);
      if (!task || ["cancelled", "completed"].includes(task.status)) continue;
      job.status = "leased"; job.workerId = String(workerId); job.leaseUntil = new Date(nowMs + safeLeaseMs).toISOString(); job.attempt += 1; job.updatedAt = now(); job.history = appendHistory(job, "leased", { workerId: job.workerId, attempt: job.attempt });
      try { return await state.put("jobs", job.id, job, { expectedVersion: job._storage?.version }); }
      catch (error) { if (error?.code === "CONFLICT") continue; throw error; }
    }
    return null;
  }

  async function startExecution(jobId, { executorInput = {}, executionId = id("execution") } = {}) {
    const job = await getJob(jobId);
    if (!job) throw new TaskError(TASK_ERRORS.NOT_FOUND, "Job tidak ditemukan");
    if (!job.workerId || !job.leaseUntil || new Date(job.leaseUntil).getTime() <= Date.now()) throw new TaskError(TASK_ERRORS.LEASE_LOST, "Job lease tidak valid");
    if (!["leased", "running"].includes(job.status)) throw new TaskError(TASK_ERRORS.INVALID_STATE, `Job tidak dapat dijalankan dari state ${job.status}`);
    const execution = { id: executionId, taskId: job.taskId, jobId: job.id, attempt: job.attempt, status: "created", input: executorInput, createdAt: now(), updatedAt: now(), history: [{ at: now(), action: "created" }] };
    job.status = "running"; job.updatedAt = now(); job.history = appendHistory(job, "started");
    const task = await getTask(job.taskId);
    task.status = "running"; task.updatedAt = now(); task.history = appendHistory(task, "started", { jobId: job.id, executionId });
    await state.put("tasks", task.id, task, { expectedVersion: task._storage?.version });
    await state.put("jobs", job.id, job, { expectedVersion: job._storage?.version });
    return state.put("executions", execution.id, execution, { overwrite: false });
  }

  async function checkpoint(executionId, checkpoint, { status = "checkpointed" } = {}) {
    const execution = await getExecution(executionId);
    if (!execution) throw new TaskError(TASK_ERRORS.NOT_FOUND, "Execution tidak ditemukan");
    assertState(EXECUTION_STATES, status, "Execution");
    if (!["created", "running", "checkpointed"].includes(execution.status)) throw new TaskError(TASK_ERRORS.INVALID_STATE, `Execution tidak dapat checkpoint dari ${execution.status}`);
    execution.status = status; execution.checkpoint = checkpoint; execution.updatedAt = now(); execution.history = appendHistory(execution, "checkpointed");
    return state.put("executions", execution.id, execution, { expectedVersion: execution._storage?.version });
  }

  async function finishExecution(executionId, { status = "completed", result = null, error = null } = {}) {
    const execution = await getExecution(executionId);
    if (!execution) throw new TaskError(TASK_ERRORS.NOT_FOUND, "Execution tidak ditemukan");
    assertState(EXECUTION_STATES, status, "Execution");
    if (!["created", "running", "checkpointed"].includes(execution.status)) throw new TaskError(TASK_ERRORS.INVALID_STATE, `Execution sudah final: ${execution.status}`);
    execution.status = status; execution.result = result; execution.error = error; execution.finishedAt = now(); execution.updatedAt = now(); execution.history = appendHistory(execution, status);
    const savedExecution = await state.put("executions", execution.id, execution, { expectedVersion: execution._storage?.version });
    const job = await getJob(execution.jobId);
    const task = await getTask(execution.taskId);
    if (job) { job.status = status === "completed" ? "completed" : "failed"; job.updatedAt = now(); job.history = appendHistory(job, job.status, { executionId }); await state.put("jobs", job.id, job, { expectedVersion: job._storage?.version }); }
    if (task) { task.status = status === "completed" ? "completed" : "failed"; task.updatedAt = now(); task.history = appendHistory(task, task.status, { executionId }); await state.put("tasks", task.id, task, { expectedVersion: task._storage?.version }); }
    return savedExecution;
  }

  async function cancelTask(taskId, reason = "cancelled") {
    const task = await getTask(taskId); if (!task) throw new TaskError(TASK_ERRORS.NOT_FOUND, "Task tidak ditemukan");
    if (["completed", "cancelled"].includes(task.status)) return task;
    task.status = "cancelled"; task.cancelReason = String(reason).slice(0, 500); task.updatedAt = now(); task.history = appendHistory(task, "cancelled");
    return state.put("tasks", task.id, task, { expectedVersion: task._storage?.version });
  }

  async function retryJob(jobId, error = null) {
    const job = await getJob(jobId); if (!job) throw new TaskError(TASK_ERRORS.NOT_FOUND, "Job tidak ditemukan");
    if (job.attempt >= job.retryPolicy.maxAttempts) throw new TaskError(TASK_ERRORS.RETRY_EXHAUSTED, "Batas retry job tercapai");
    const delay = Math.min(job.retryPolicy.maxBackoffMs, job.retryPolicy.backoffMs * 2 ** Math.max(0, job.attempt - 1));
    job.status = "retrying"; job.error = error; job.updatedAt = now(); job.history = appendHistory(job, "retrying", { delayMs: delay });
    await state.put("jobs", job.id, job, { expectedVersion: job._storage?.version });
    job.status = "queued"; job.scheduledAt = new Date(Date.now() + delay).toISOString(); job.updatedAt = now(); job.history = appendHistory(job, "requeued");
    return state.put("jobs", job.id, job, { expectedVersion: job._storage?.version });
  }

  async function runNext(options = {}) {
    if (!runExecutor) throw new TaskError(TASK_ERRORS.VALIDATION, "Executor belum dikonfigurasi");
    const job = await claimNext(options); if (!job) return null;
    const execution = await startExecution(job.id, { executorInput: options.executorInput || {} });
    try {
      const result = await runExecutor({ task: await getTask(job.taskId), job, execution, checkpoint: data => checkpoint(execution.id, data) });
      return await finishExecution(execution.id, { status: "completed", result });
    } catch (error) {
      await finishExecution(execution.id, { status: "failed", error: error instanceof Error ? error.message : String(error) });
      if (job.attempt < job.retryPolicy.maxAttempts) await retryJob(job.id, error instanceof Error ? error.message : String(error));
      else throw new TaskError(TASK_ERRORS.RETRY_EXHAUSTED, "Execution gagal dan retry habis", { cause: error?.message });
      return getExecution(execution.id);
    }
  }

  async function list(kind) { if (!SCOPES.includes(kind)) throw new TaskError(TASK_ERRORS.VALIDATION, `Scope tidak valid: ${kind}`); return state.list(kind); }
  return Object.freeze({ createTask, enqueue, claimNext, startExecution, checkpoint, finishExecution, cancelTask, retryJob, runNext, getTask, getJob, getExecution, list, retryPolicy: normalizeRetryPolicy });
}

export const taskOrchestrator = createTaskOrchestrator();
