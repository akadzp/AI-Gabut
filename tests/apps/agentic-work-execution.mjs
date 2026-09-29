import assert from "node:assert/strict";
import test from "node:test";
import { createRealtimeService } from "../../apps/agentic/backend/realtime.js";
import { createWorkExecutionService } from "../../apps/agentic/backend/work-execution.js";
import { createWorkService } from "../../apps/agentic/backend/work.js";

function makeStore() {
  const scopes = new Map();
  const scope = name => scopes.get(name) || scopes.set(name, new Map()).get(name);
  const put = (name, ownerId, value) => {
    const values = scope(name);
    const key = `${ownerId}--${value.id}`;
    const previous = values.get(key);
    const saved = { ...value, ownerId, _storage: { version: (previous?._storage?.version || 0) + 1 } };
    values.set(key, saved);
    return saved;
  };
  const get = (name, ownerId, id) => scope(name).get(`${ownerId}--${id}`) || null;
  const list = (name, ownerId) => [...scope(name).values()].filter(value => value.ownerId === ownerId);
  return {
    putWork: async (ownerId, value) => put("work", ownerId, value), getWork: async (ownerId, id) => get("work", ownerId, id), listWorks: async ownerId => list("work", ownerId),
    putTask: async (ownerId, value) => put("task", ownerId, value), getTask: async (ownerId, id) => get("task", ownerId, id), listTasks: async ownerId => list("task", ownerId),
    putExecution: async (ownerId, value) => put("execution", ownerId, value), getExecution: async (ownerId, id) => get("execution", ownerId, id), listExecutions: async ownerId => list("execution", ownerId),
    putActivity: async (ownerId, value) => put("activity", ownerId, value), listActivities: async ownerId => list("activity", ownerId)
  };
}

function workRuntime(agentRunner) {
  const store = makeStore();
  const work = createWorkService({ store });
  const realtime = createRealtimeService({ store });
  const runtime = createWorkExecutionService({
    store,
    work,
    realtime,
    agentRunner,
    planner: async () => [{ id: "inspect", goal: "Inspect repository", tools: ["inspect_project"] }, { id: "verify", goal: "Verify changes", tools: ["run_command"] }],
    approvalAuthority: () => ({ token: "approved-token", expiresAt: "2099-01-01T00:00:00.000Z" }),
    approvalPolicy: tool => ({ permission: "approval", risk: tool === "git_push" ? "critical" : "high", resource: "git" })
  });
  return { store, work, realtime, runtime };
}

test("work planning is observable before a durable work execution runs", async () => {
  const { store, work, realtime, runtime } = workRuntime(async ({ onActivity }) => {
    await onActivity({ action: "tool", status: "completed", label: "Memeriksa repository", meta: { tool: "inspect_project" } });
    return { text: "verified", plan: [{ id: "inspect", goal: "Inspect repository", tools: ["inspect_project"] }] };
  });
  const events = [];
  realtime.subscribe("user-a", event => events.push(event), { workId: "work-test" });
  const created = await work.create("user-a", { id: "work-test", objective: "Inspect and verify the repository" });
  const planned = await runtime.plan("user-a", created.id);
  assert.equal(planned.state, "ready");
  assert.equal(planned.plan.interpretation.summary, "Inspect and verify the repository");
  assert.deepEqual(planned.plan.steps.map(step => step.status), ["planned", "planned"]);
  const result = await runtime.run("user-a", created.id);
  assert.equal(result.work.state, "completed");
  assert.equal(result.execution.status, "completed");
  assert.equal(result.work.taskIds.length, 1);
  assert.equal(result.work.executionIds.length, 1);
  assert.ok((await runtime.listActivities("user-a", created.id)).every(event => event.workId === created.id));
  assert.ok(events.some(event => event.action === "planning"));
  assert.ok(events.every(event => event.workId === created.id));
  assert.equal((await store.listTasks("user-a"))[0].workId, created.id);
});

test("pause stops the active work runner at its next observable boundary and resume starts a new execution", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let started;
  const startedRun = new Promise(resolve => { started = resolve; });
  let calls = 0;
  const { store, work, runtime } = workRuntime(async ({ onActivity }) => {
    calls++;
    await onActivity({ action: "tool", status: "running", label: "Mengubah workspace" });
    if (calls === 1) {
      started();
      await gate;
    }
    await onActivity({ action: "tool", status: "completed", label: "Workspace diperbarui" });
    return { text: "done" };
  });
  const created = await work.create("user-a", { objective: "Make a bounded change" });
  await runtime.plan("user-a", created.id);
  const active = runtime.run("user-a", created.id);
  await startedRun;
  const paused = await runtime.pause("user-a", created.id, "User needs to inspect the plan");
  assert.equal(paused.state, "paused");
  release();
  const pausedRun = await active;
  assert.equal(pausedRun.work.state, "paused");
  assert.equal(pausedRun.execution.status, "paused");
  const resumed = await runtime.run("user-a", created.id);
  assert.equal(resumed.work.state, "completed");
  assert.equal(resumed.execution.status, "completed");
  assert.equal((await store.listExecutions("user-a")).length, 2);
});

test("work execution activity stays owner-scoped", async () => {
  const { work, runtime } = workRuntime(async () => ({ text: "done" }));
  const created = await work.create("user-a", { objective: "Private work" });
  await runtime.plan("user-a", created.id);
  await runtime.run("user-a", created.id);
  await assert.rejects(() => runtime.listActivities("user-b", created.id), error => error.code === "WORK_NOT_FOUND");
});

test("approval request exposes governed risk summary and approval resumes the same work execution", async () => {
  const seen = [];
  const { work, runtime } = workRuntime(async args => {
    seen.push(args);
    if (!args.approvalToken) {
      return {
        text: "blocked",
        tool: { steps: [{ name: "git_push", input: { branch: "main" }, result: { requiresApproval: true, error: "Push requires human approval" } }] }
      };
    }
    return { text: "pushed" };
  });
  const created = await work.create("user-a", { objective: "Push reviewed change" });
  await runtime.plan("user-a", created.id);
  const pending = await runtime.run("user-a", created.id);
  assert.equal(pending.work.state, "waiting_approval");
  assert.equal(pending.execution.approval.risk, "critical");
  assert.equal(pending.execution.approval.affectedResource, "git");
  assert.equal(pending.execution.approval.requestedCapability, "approval");
  assert.equal(pending.execution.approval.status, "pending");
  assert.equal("token" in pending.execution.approval, false);
  const approved = await runtime.approve("user-a", created.id);
  assert.equal(approved.work.state, "completed");
  assert.equal(approved.execution.id, pending.execution.id);
  assert.equal(seen.length, 2);
  assert.equal(seen[1].approvalToken, "approved-token");
  assert.equal(seen[1].executionId, pending.execution.id);
});

test("human can reject or revise a pending work approval without bypassing it", async () => {
  let calls = 0;
  const { store, work, runtime } = workRuntime(async args => {
    calls++;
    if (calls === 1) return { text: "blocked", tool: { steps: [{ name: "git_commit", input: { message: "initial" }, result: { requiresApproval: true, error: "Commit requires human approval" } }] } };
    return { text: args.prompt.includes("use a release note") ? "revised" : "done" };
  });
  const rejected = await work.create("user-a", { objective: "Commit change" });
  await runtime.plan("user-a", rejected.id);
  await runtime.run("user-a", rejected.id);
  const rejectedWork = await runtime.reject("user-a", rejected.id, "Need a release note first");
  assert.equal(rejectedWork.state, "failed");
  assert.equal((await store.listExecutions("user-a"))[0].status, "rejected");

  calls = 0;
  const revised = await work.create("user-a", { objective: "Commit another change" });
  await runtime.plan("user-a", revised.id);
  const pending = await runtime.run("user-a", revised.id);
  const paused = await runtime.revise("user-a", revised.id, "use a release note");
  assert.equal(paused.state, "paused");
  const resumed = await runtime.resume("user-a", revised.id);
  assert.equal(resumed.execution.id, pending.execution.id);
  assert.equal(resumed.work.state, "completed");
});
