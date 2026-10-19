import { AgenticError } from "./errors.js";
import { createId, assertId } from "./ids.js";

const STATES = Object.freeze(["draft", "ready", "running", "waiting_approval", "paused", "completed", "failed", "cancelled", "stopped"]);
const TERMINAL = new Set(["completed", "failed", "cancelled", "stopped"]);
const text = (value, code, message, max = 12000) => {
  const result = String(value ?? "").trim();
  if (!result) throw new AgenticError(code, message);
  return result.slice(0, max);
};

function publicWork(work) {
  return {
    id: work.id,
    ownerId: work.ownerId,
    projectId: work.projectId || null,
    workspaceId: work.workspaceId || null,
    objective: work.objective,
    context: work.context || {},
    plan: work.plan || null,
    taskIds: [...(work.taskIds || [])],
    executionIds: [...(work.executionIds || [])],
    changeIds: [...(work.changeIds || [])],
    evidenceIds: [...(work.evidenceIds || [])],
    artifactIds: [...(work.artifactIds || [])],
    externalFeedbackIds: [...(work.externalFeedbackIds || [])],
    approvalIds: [...(work.approvalIds || [])],
    result: work.result || null,
    state: work.state,
    priority: work.priority,
    createdAt: work.createdAt,
    updatedAt: work.updatedAt,
    startedAt: work.startedAt || null,
    finishedAt: work.finishedAt || null,
    cancelledAt: work.cancelledAt || null
  };
}

function assertExecutionFence(work, expectedFence) {
  if (expectedFence === undefined || expectedFence === null) return;
  if (Number(work.executionLeaseFence) !== Number(expectedFence)) {
    throw new AgenticError("WORK_EXECUTION_LEASE_LOST", "Execution tidak lagi memiliki fence aktif untuk Work ini", 409, {
      expectedFence,
      currentFence: Number(work.executionLeaseFence) || 0
    });
  }
}

export function createWorkService({ store, tasks = null, executions = null } = {}) {
  if (!store?.putWork || !store?.getWork || !store?.listWorks) {
    throw new TypeError("Work service membutuhkan store work contract");
  }

  async function raw(ownerId, workId) {
    assertId(ownerId, "ownerId");
    assertId(workId, "workId");
    const work = await store.getWork(ownerId, workId);
    if (!work) throw new AgenticError("WORK_NOT_FOUND", "Work tidak ditemukan", 404);
    return work;
  }

  async function get(ownerId, workId) { return publicWork(await raw(ownerId, workId)); }

  async function list(ownerId, options = {}) {
    let items = await store.listWorks(ownerId);
    if (options.state) items = items.filter(work => work.state === options.state);
    if (options.projectId != null) items = items.filter(work => work.projectId === options.projectId);
    if (options.workspaceId != null) items = items.filter(work => work.workspaceId === options.workspaceId);
    return items.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt))).map(publicWork);
  }

  async function create(ownerId, input = {}) {
    const objective = text(input.objective, "INVALID_WORK_OBJECTIVE", "Work objective wajib diisi");
    const timestamp = new Date().toISOString();
    const work = {
      id: input.id || createId("work"), ownerId,
      projectId: input.projectId ? assertId(input.projectId, "projectId") : null,
      workspaceId: input.workspaceId ? assertId(input.workspaceId, "workspaceId") : null,
      objective,
      context: input.context && typeof input.context === "object" ? input.context : {},
      plan: null, taskIds: [], executionIds: [], changeIds: [], evidenceIds: [], artifactIds: [], externalFeedbackIds: [], approvalIds: [],
      result: null, state: "draft", priority: ["low", "normal", "high", "urgent"].includes(input.priority) ? input.priority : "normal",
      createdAt: timestamp, updatedAt: timestamp, startedAt: null, finishedAt: null, cancelledAt: null,
      executionLeaseFence: 0, executionLeaseId: null
    };
    await store.putWork(ownerId, work, { overwrite: false });
    return publicWork(work);
  }

  async function update(ownerId, workId, patch = {}) {
    const current = await raw(ownerId, workId);
    if (TERMINAL.has(current.state)) throw new AgenticError("WORK_TERMINAL", "Work terminal tidak dapat diubah", 409);
    const next = { ...current };
    if (patch.objective !== undefined) next.objective = text(patch.objective, "INVALID_WORK_OBJECTIVE", "Work objective wajib diisi");
    if (patch.context !== undefined) next.context = patch.context;
    if (patch.plan !== undefined) next.plan = patch.plan;
    if (patch.priority !== undefined) next.priority = patch.priority;
    next.updatedAt = new Date().toISOString();
    await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWork(next);
  }

  async function claimExecution(ownerId, workId, { executionId, fence } = {}) {
    assertId(executionId, "executionId");
    if (!Number.isSafeInteger(Number(fence)) || Number(fence) < 1) throw new AgenticError("INVALID_EXECUTION_FENCE", "Execution fence tidak valid", 400);
    const current = await raw(ownerId, workId);
    if (TERMINAL.has(current.state)) throw new AgenticError("WORK_TERMINAL", "Work terminal tidak dapat dijalankan", 409);
    const currentFence = Number(current.executionLeaseFence) || 0;
    if (Number(fence) < currentFence || (Number(fence) === currentFence && current.executionLeaseId && current.executionLeaseId !== executionId)) {
      throw new AgenticError("WORK_EXECUTION_LEASE_LOST", "Execution fence telah digantikan oleh run lain", 409, { currentFence, requestedFence: Number(fence) });
    }
    if (Number(fence) === currentFence && current.executionLeaseId === executionId) return publicWork(current);
    const next = { ...current, executionLeaseFence: Number(fence), executionLeaseId: executionId, updatedAt: new Date().toISOString() };
    await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWork(next);
  }

  async function transition(ownerId, workId, state, meta = {}) {
    const current = await raw(ownerId, workId);
    assertExecutionFence(current, meta.executionLeaseFence);
    if (!STATES.includes(state)) throw new AgenticError("INVALID_WORK_STATE", "State work tidak valid");
    if (TERMINAL.has(current.state)) throw new AgenticError("WORK_TERMINAL", "Work terminal tidak dapat ditransisikan", 409);
    const allowed = {
      draft: new Set(["ready", "cancelled"]),
      ready: new Set(["running", "cancelled"]),
      running: new Set(["waiting_approval", "paused", "completed", "failed", "cancelled", "stopped"]),
      waiting_approval: new Set(["running", "paused", "cancelled", "failed"]),
      paused: new Set(["ready", "running", "cancelled", "stopped"])
    };
    if (!allowed[current.state]?.has(state)) throw new AgenticError("INVALID_WORK_TRANSITION", `Transisi work ${current.state} -> ${state} tidak diizinkan`, 409);
    const timestamp = new Date().toISOString();
    const next = { ...current, state, updatedAt: timestamp };
    if (state === "running" && !next.startedAt) next.startedAt = timestamp;
    if (TERMINAL.has(state)) {
      next.finishedAt = timestamp;
      if (state === "cancelled") next.cancelledAt = timestamp;
      if (meta.result !== undefined) next.result = meta.result;
      else if (meta.error) next.result = { error: String(meta.error) };
    }
    await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWork(next);
  }

  async function attachReference(ownerId, workId, kindOrId, referenceIdOrKind) {
    const fields = { change: "changeIds", evidence: "evidenceIds", approval: "approvalIds", artifact: "artifactIds", "external-feedback": "externalFeedbackIds" };
    let kind; let referenceId;
    if (fields[kindOrId]) { kind = kindOrId; referenceId = referenceIdOrKind; }
    else if (fields[referenceIdOrKind]) { referenceId = kindOrId; kind = referenceIdOrKind; }
    else throw new AgenticError("INVALID_WORK_REFERENCE", "Jenis reference work tidak valid");
    const field = fields[kind];
    assertId(referenceId, `${kind}Id`);
    const current = await raw(ownerId, workId);
    if ((current[field] || []).includes(referenceId)) return publicWork(current);
    const next = { ...current, [field]: [...current[field], referenceId], updatedAt: new Date().toISOString() };
    await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWork(next);
  }

  async function attachTask(ownerId, workId, taskId, options = {}) {
    assertId(taskId, "taskId");
    const current = await raw(ownerId, workId);
    assertExecutionFence(current, options.executionLeaseFence);
    if (store.getTask && !await store.getTask(ownerId, taskId)) throw new AgenticError("TASK_NOT_FOUND", "Task tidak ditemukan", 404);
    if ((current.taskIds || []).includes(taskId)) return publicWork(current);
    const next = { ...current, taskIds: [...(current.taskIds || []), taskId], updatedAt: new Date().toISOString() };
    await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWork(next);
  }

  async function attachExecution(ownerId, workId, executionId, options = {}) {
    assertId(executionId, "executionId");
    const current = await raw(ownerId, workId);
    assertExecutionFence(current, options.executionLeaseFence);
    if (store.getExecution && !await store.getExecution(ownerId, executionId)) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404);
    if ((current.executionIds || []).includes(executionId)) return publicWork(current);
    const next = { ...current, executionIds: [...(current.executionIds || []), executionId], updatedAt: new Date().toISOString() };
    await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWork(next);
  }

  async function reopenForRepair(ownerId, workId, { plan, result } = {}) {
    const current = await raw(ownerId, workId);
    if (current.state !== "failed") throw new AgenticError("WORK_NOT_REPAIRABLE", "Hanya Work failed yang dapat dibuka kembali untuk repair", 409);
    const next = { ...current, state: "ready", plan: plan ?? current.plan, result: result ?? current.result, finishedAt: null, updatedAt: new Date().toISOString() };
    await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWork(next);
  }

  return Object.freeze({ states: STATES, terminalStates: Object.freeze([...TERMINAL]), raw, get, list, create, update, claimExecution, transition, attachReference, attachTask, attachExecution, reopenForRepair });
}
