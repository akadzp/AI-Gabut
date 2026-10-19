import assert from "node:assert/strict";
import test from "node:test";
import { runAgent } from "../../core/agent-engine/index.js";
import { ExecutionRuntime } from "../../core/agent-engine/reliability/runtime.js";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";

function memoryStorage() {
  const scopes = new Map();
  return {
    records(namespace) {
      if (!scopes.has(namespace)) scopes.set(namespace, new Map());
      const records = scopes.get(namespace);
      return {
        async get(key) { return records.get(key) || null; },
        async put(key, value, options = {}) {
          const previous = records.get(key);
          if (!options.overwrite && previous) throw Object.assign(new Error("duplicate"), { code: "DUPLICATE_RECORD" });
          if (options.expectedVersion != null && previous?._storage?.version !== options.expectedVersion) {
            throw Object.assign(new Error("version conflict"), { code: "VERSION_CONFLICT" });
          }
          const saved = { ...value, _storage: { version: (previous?._storage?.version || 0) + 1 } };
          records.set(key, saved);
          return saved;
        },
        async update(key, value, options = {}) { return this.put(key, value, { ...options, overwrite: true }); },
        async delete(key) { return records.delete(key); },
        async exists(key) { return records.has(key); },
        async list() { return [...records.keys()]; }
      };
    }
  };
}

function deferredRunner() {
  let markStarted;
  const started = new Promise(resolve => { markStarted = resolve; });
  const runner = ({ signal }) => new Promise(resolve => {
    markStarted();
    if (signal.aborted) return resolve({ status: "cancelled", text: "aborted" });
    signal.addEventListener("abort", () => resolve({ status: "cancelled", text: "aborted" }), { once: true });
  });
  return { runner, started };
}

test("provider timeout bounds an unresponsive model and returns stopped status", async () => {
  let providerSignal;
  const result = await runAgent({
    prompt: "test timeout",
    timeoutMs: 15,
    provider: ({ signal }) => { providerSignal = signal; return new Promise(() => {}); }
  });
  assert.equal(result.status, "stopped");
  assert.equal(result.error.code, "AGENT_EXECUTION_TIMEOUT");
  assert.equal(providerSignal.aborted, true);
  assert.equal(result.execution.status, "stopped");
});

test("caller abort cancels provider work and reports a cancelled execution", async () => {
  const controller = new AbortController();
  const pending = runAgent({ prompt: "test cancellation", signal: controller.signal, timeoutMs: 1000, provider: () => new Promise(() => {}) });
  controller.abort();
  const result = await pending;
  assert.equal(result.status, "cancelled");
  assert.equal(result.execution.status, "cancelled");
});

test("failed checkpoint cloning does not consume the runtime step budget", () => {
  const runtime = new ExecutionRuntime({ maxSteps: 1 });
  runtime.start();
  assert.throws(() => runtime.checkpoint({ invalid: () => {} }));
  assert.equal(runtime.snapshot().steps, 0);
  runtime.checkpoint({ stage: "next" });
  assert.equal(runtime.snapshot().steps, 1);
});

test("one active execution per Work is enforced and cancellation settles consistently", async () => {
  const deferred = deferredRunner();
  const app = createAgenticApplication({ storage: memoryStorage(), agentRunner: deferred.runner });
  const work = await app.createWork("owner-1", { objective: "long running work" });
  const firstRun = app.runWork("owner-1", work.id);
  await deferred.started;
  await assert.rejects(() => app.runWork("owner-1", work.id), error => error.code === "WORK_EXECUTION_IN_PROGRESS");
  await app.cancelWork("owner-1", work.id, "test cancellation");
  const outcome = await firstRun;
  assert.equal(outcome.work.state, "cancelled");
  assert.equal(outcome.execution.status, "cancelled");
  assert.equal((await app.getWork("owner-1", work.id)).state, "cancelled");
});

test("pausing an active Work aborts its runner but preserves paused lifecycle state", async () => {
  const deferred = deferredRunner();
  const app = createAgenticApplication({ storage: memoryStorage(), agentRunner: deferred.runner });
  const work = await app.createWork("owner-2", { objective: "pause this work" });
  const firstRun = app.runWork("owner-2", work.id);
  await deferred.started;
  await app.pauseWork("owner-2", work.id, "maintenance pause");
  const outcome = await firstRun;
  assert.equal(outcome.work.state, "paused");
  assert.equal(outcome.execution.status, "paused");
  assert.equal((await app.getWork("owner-2", work.id)).state, "paused");
});

test("stopping an active Work aborts its runner and remains terminal", async () => {
  const deferred = deferredRunner();
  const app = createAgenticApplication({ storage: memoryStorage(), agentRunner: deferred.runner });
  const work = await app.createWork("owner-3", { objective: "stop this work" });
  const firstRun = app.runWork("owner-3", work.id);
  await deferred.started;
  await app.stopWork("owner-3", work.id, "operator stop");
  const outcome = await firstRun;
  assert.equal(outcome.work.state, "stopped");
  assert.equal(outcome.execution.status, "stopped");
  assert.equal((await app.getWork("owner-3", work.id)).state, "stopped");
});

test("Work execution propagates provider timeout to its durable terminal state", async () => {
  const app = createAgenticApplication({ storage: memoryStorage() });
  const work = await app.createWork("owner-4", { objective: "provider timeout end-to-end" });
  const outcome = await app.runWork("owner-4", work.id, {
    timeoutMs: 15,
    provider: () => new Promise(() => {})
  });
  assert.equal(outcome.execution.status, "stopped");
  assert.equal(outcome.work.state, "stopped");
  assert.equal((await app.getWork("owner-4", work.id)).state, "stopped");
});

test("pausing an approval wait reconciles the pending execution and task", async () => {
  const app = createAgenticApplication({
    storage: memoryStorage(),
    agentRunner: async () => ({ approvalRequired: true, approval: { required: true, tool: "git_commit", input: { branch: "work" } } })
  });
  const work = await app.createWork("owner-5", { objective: "approval lifecycle" });
  const waiting = await app.runWork("owner-5", work.id);
  assert.equal(waiting.work.state, "waiting_approval");
  await app.pauseWork("owner-5", work.id, "approval paused");
  const execution = (await app.listExecutions("owner-5")).find(item => item.workId === work.id);
  const task = (await app.listTasks("owner-5")).find(item => item.workId === work.id);
  assert.equal(execution.status, "paused");
  assert.equal(task.status, "paused");
});

test("stopping a previously paused Work reconciles its old execution and task", async () => {
  const deferred = deferredRunner();
  const app = createAgenticApplication({ storage: memoryStorage(), agentRunner: deferred.runner });
  const work = await app.createWork("owner-6", { objective: "pause then stop" });
  const firstRun = app.runWork("owner-6", work.id);
  await deferred.started;
  await app.pauseWork("owner-6", work.id, "first pause");
  await firstRun;
  await app.stopWork("owner-6", work.id, "final stop");
  const execution = (await app.listExecutions("owner-6")).find(item => item.workId === work.id);
  const task = (await app.listTasks("owner-6")).find(item => item.workId === work.id);
  assert.equal(execution.status, "stopped");
  assert.equal(task.status, "stopped");
});
