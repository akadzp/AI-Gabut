import assert from "node:assert/strict";
import test from "node:test";
import { createWorkService } from "../../apps/agentic/backend/work.js";

function makeStore() {
  const data = new Map();
  return {
    async putWork(ownerId, work) {
      const key = `${ownerId}--${work.id}`;
      const current = data.get(key);
      const version = (current?._storage?.version || 0) + 1;
      const saved = { ...work, ownerId, _storage: { version } };
      data.set(key, saved);
      return saved;
    },
    async getWork(ownerId, id) {
      return data.get(`${ownerId}--${id}`) || null;
    },
    async listWorks(ownerId) {
      return [...data.values()].filter(x => x.ownerId === ownerId);
    }
  };
}

test("creates an owned work with explicit lifecycle state", async () => {
  const service = createWorkService({ store: makeStore() });
  const work = await service.create("user-a", {
    objective: "Implement repository changes",
    projectId: "project-1",
    workspaceId: "workspace-1",
    priority: "high"
  });
  assert.match(work.id, /^work-/);
  assert.equal(work.ownerId, "user-a");
  assert.equal(work.objective, "Implement repository changes");
  assert.equal(work.state, "draft");
  assert.equal(work.priority, "high");
  assert.deepEqual(work.taskIds, []);
  assert.deepEqual(work.executionIds, []);
});

test("enforces lifecycle transitions and terminal immutability", async () => {
  const service = createWorkService({ store: makeStore() });
  const work = await service.create("user-a", { objective: "Run development work" });
  assert.equal((await service.transition("user-a", work.id, "ready")).state, "ready");
  assert.equal((await service.transition("user-a", work.id, "running")).state, "running");
  assert.equal((await service.transition("user-a", work.id, "paused")).state, "paused");
  assert.equal((await service.transition("user-a", work.id, "running")).state, "running");
  const done = await service.transition("user-a", work.id, "completed", { result: { ok: true } });
  assert.equal(done.state, "completed");
  assert.deepEqual(done.result, { ok: true });
  await assert.rejects(() => service.update("user-a", work.id, { objective: "changed" }), e => e.code === "WORK_TERMINAL");
  await assert.rejects(() => service.transition("user-a", work.id, "running"), e => e.code === "WORK_TERMINAL");
});

test("prevents invalid lifecycle transitions", async () => {
  const service = createWorkService({ store: makeStore() });
  const work = await service.create("user-a", { objective: "Bounded work" });
  await assert.rejects(() => service.transition("user-a", work.id, "running"), e => e.code === "INVALID_WORK_TRANSITION");
  await assert.rejects(() => service.transition("user-a", work.id, "completed"), e => e.code === "INVALID_WORK_TRANSITION");
});

test("references tasks and executions without collapsing them into work", async () => {
  const store = makeStore();
  const service = createWorkService({
    store,
    tasks: { get: async (ownerId, id) => ({ id, ownerId }) },
    executions: { get: async (ownerId, id) => ({ id, ownerId }) }
  });
  const work = await service.create("user-a", { objective: "Coordinate agent execution" });
  await service.attachTask("user-a", work.id, "task-1");
  await service.attachExecution("user-a", work.id, "execution-1");
  await service.attachReference("user-a", work.id, "evidence", "evidence-1");
  const current = await service.get("user-a", work.id);
  assert.deepEqual(current.taskIds, ["task-1"]);
  assert.deepEqual(current.executionIds, ["execution-1"]);
  assert.deepEqual(current.evidenceIds, ["evidence-1"]);
  assert.equal(current.id.startsWith("task-"), false);
});

test("ownership isolation is enforced by the store boundary", async () => {
  const service = createWorkService({ store: makeStore() });
  const work = await service.create("user-a", { objective: "Private work" });
  await assert.rejects(() => service.get("user-b", work.id), e => e.code === "WORK_NOT_FOUND");
  await assert.rejects(() => service.cancel("user-b", work.id), e => e.code === "WORK_NOT_FOUND");
});
