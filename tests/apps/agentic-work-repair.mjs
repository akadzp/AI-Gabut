import assert from "node:assert/strict";
import test from "node:test";
import { createWorkRepairService } from "../../apps/agentic/backend/work-repair.js";

function runtime({ repairResult = "success", maxIterations = 2 } = {}) {
  const works = new Map();
  const executions = new Map();
  const activities = [];
  const checkpoints = [];
  const store = {
    putWork: async (owner, value) => { const saved = { ...value, ownerId: owner, _storage: { version: (works.get(value.id)?._storage?.version || 0) + 1 } }; works.set(value.id, saved); return saved; },
    getWork: async (_owner, id) => works.get(id) || null,
    putExecution: async (_owner, value) => { executions.set(value.id, value); return value; },
    getExecution: async (_owner, id) => executions.get(id) || null,
    listExecutions: async () => [...executions.values()],
    putActivity: async (_owner, value) => { activities.push(value); return value; },
    putRepairCheckpoint: async (_owner, value) => { checkpoints.push(value); return value; },
    listVerifications: async () => []
  };
  const work = {
    raw: async (_owner, id) => works.get(id),
    get: async (_owner, id) => ({ ...works.get(id), result: works.get(id).result || null }),
    reopenForRepair: async (owner, id, patch) => { const current = works.get(id); const next = { ...current, ...patch, ownerId: owner, state: "ready", finishedAt: null, _storage: { version: current._storage.version + 1 } }; works.set(id, next); return next; }
  };
  const planner = async ({ prompt }) => [{ id: "repair", goal: prompt.includes("Repair iteration") ? "Apply bounded repair" : "repair", tools: ["edit_workspace"] }];
  const execute = async (owner, id) => {
    const current = works.get(id);
    const failed = repairResult === "fail";
    const execution = { id: `execution-${current.result.repair.iteration}`, ownerId: owner, workId: id, status: failed ? "failed" : "completed", error: failed ? "still broken" : null, updatedAt: new Date().toISOString() };
    executions.set(execution.id, execution);
    const next = { ...current, state: failed ? "failed" : "completed", executionIds: [...(current.executionIds || []), execution.id], _storage: { version: current._storage.version + 1 } };
    works.set(id, next);
    return { work: next, execution };
  };
  const service = createWorkRepairService({ store, work, planner, execute });
  return { store, works, executions, activities, checkpoints, service, maxIterations };
}

test("repair classifies failure, replans, reopens work, and persists checkpoints", async () => {
  const r = runtime();
  r.works.set("w1", { id: "w1", ownerId: "u1", objective: "Fix failing work", state: "failed", result: { status: "failed" }, executionIds: [], _storage: { version: 1 } });
  r.executions.set("e0", { id: "e0", ownerId: "u1", workId: "w1", status: "failed", error: "assertion failed", updatedAt: new Date().toISOString() });
  const result = await r.service.repair("u1", "w1", { maxIterations: 2 });
  assert.equal(result.work.state, "completed");
  assert.equal(result.repair.status, "repaired");
  assert.equal(result.repair.history.length, 1);
  assert.ok(r.checkpoints.some(x => x.status === "observed"));
  assert.ok(r.checkpoints.some(x => x.status === "planned"));
  assert.ok(r.checkpoints.some(x => x.status === "completed"));
});

test("repair is bounded by max iterations", async () => {
  const r = runtime({ repairResult: "fail" });
  r.works.set("w2", { id: "w2", ownerId: "u1", objective: "Fix bounded work", state: "failed", result: { repair: { history: [{ iteration: 1 }] } }, executionIds: [], _storage: { version: 1 } });
  r.executions.set("e2", { id: "e2", ownerId: "u1", workId: "w2", status: "failed", error: "still broken", updatedAt: new Date().toISOString() });
  await assert.rejects(() => r.service.repair("u1", "w2", { maxIterations: 1 }), error => error.code === "REPAIR_LIMIT_REACHED");
});

test("repair refuses unsupported failure evidence", async () => {
  const r = runtime();
  r.works.set("w3", { id: "w3", ownerId: "u1", objective: "Unknown failure", state: "failed", result: {}, executionIds: [], _storage: { version: 1 } });
  await assert.rejects(() => r.service.repair("u1", "w3", { maxIterations: 2 }), error => error.code === "REPAIR_NOT_SUPPORTED");
});
