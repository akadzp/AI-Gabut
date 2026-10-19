import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createStorage } from "../../core/storage/index.js";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function runChild(script, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", chunk => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", chunk => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", code => {
      const line = stdout.trim().split(/\r?\n/).filter(Boolean).at(-1);
      let payload = null;
      try { payload = line ? JSON.parse(line) : null; } catch { /* reported below */ }
      if (code !== 0) return reject(new Error(`child exited ${code}: ${stderr || stdout}`));
      if (!payload) return reject(new Error(`child returned no JSON result: ${stderr || stdout}`));
      resolve(payload);
    });
  });
}

async function withTempRoot(t, prefix = "agentic-lease-b104-") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

test("Batch 104: execution lease is durable and released after a Work run", async t => {
  const root = await withTempRoot(t);
  const app = createAgenticApplication({
    storage: createStorage({ root }),
    agentRunner: async () => ({ status: "completed", text: "done" })
  });
  const work = await app.createWork("owner-lease", { objective: "durable lease record" });
  const result = await app.runWork("owner-lease", work.id);
  const lease = await app.store.getOwned("work-execution-leases", "owner-lease", `work-execution-lease:owner-lease:${work.id}`);
  assert.equal(result.work.state, "completed");
  assert.equal(lease.executionId, result.execution.id);
  assert.equal(lease.fence, 1);
  assert.ok(lease.releasedAt);
  assert.equal(lease.expiresAtMs, 0);
});

test("Batch 104: lease heartbeat renews a run that exceeds the lease duration", async t => {
  const root = await withTempRoot(t);
  const app = createAgenticApplication({
    storage: createStorage({ root }),
    workExecutionLeaseMs: 75,
    agentRunner: async () => { await delay(220); return { status: "completed", text: "renewed" }; }
  });
  const work = await app.createWork("owner-heartbeat", { objective: "long work with heartbeat" });
  const result = await app.runWork("owner-heartbeat", work.id);
  assert.equal(result.work.state, "completed");
  const lease = await app.store.getOwned("work-execution-leases", "owner-heartbeat", `work-execution-lease:owner-heartbeat:${work.id}`);
  assert.ok(lease.renewedAt);
  assert.ok(lease.releasedAt);
});

test("Batch 104: separate Node processes cannot execute the same Work concurrently", async t => {
  const root = await withTempRoot(t);
  const parentApp = createAgenticApplication({ storage: createStorage({ root }) });
  const work = await parentApp.createWork("owner-cross-process", { objective: "cross-process lease race" });
  const appUrl = pathToFileURL(path.resolve("apps/agentic/backend/application.js")).href;
  const storageUrl = pathToFileURL(path.resolve("core/storage/index.js")).href;
  const script = `
    import { createAgenticApplication } from ${JSON.stringify(appUrl)};
    import { createStorage } from ${JSON.stringify(storageUrl)};
    const app = createAgenticApplication({
      storage: createStorage({ root: process.env.V4_STORAGE_ROOT }),
      workExecutionLeaseMs: 3000,
      agentRunner: async () => { await new Promise(resolve => setTimeout(resolve, 600)); return { status: "completed", text: "child completed" }; }
    });
    try {
      const result = await app.runWork(process.env.V4_OWNER, process.env.V4_WORK_ID);
      console.log(JSON.stringify({ kind: "ok", state: result.work.state, executionId: result.execution.id }));
    } catch (error) {
      console.log(JSON.stringify({ kind: "error", code: error.code || "UNKNOWN" }));
      if (error.code !== "WORK_EXECUTION_IN_PROGRESS") process.exitCode = 1;
    }
  `;
  const env = { V4_STORAGE_ROOT: root, V4_OWNER: "owner-cross-process", V4_WORK_ID: work.id };
  const outcomes = await Promise.all([runChild(script, env), runChild(script, env)]);
  assert.equal(outcomes.filter(item => item.kind === "ok").length, 1, JSON.stringify(outcomes));
  assert.equal(outcomes.filter(item => item.kind === "error" && item.code === "WORK_EXECUTION_IN_PROGRESS").length, 1, JSON.stringify(outcomes));
  assert.equal((await parentApp.listExecutions("owner-cross-process")).filter(item => item.workId === work.id).length, 1);
});

test("Batch 104: expired durable leases can be reclaimed with a higher fencing number", async t => {
  const root = await withTempRoot(t);
  const app = createAgenticApplication({ storage: createStorage({ root }), workExecutionLeaseMs: 55 });
  const first = await app.workExecutionLeaseService.acquire("owner-expiry", "work-expiry", "exec-old");
  await delay(75);
  const second = await app.workExecutionLeaseService.acquire("owner-expiry", "work-expiry", "exec-new");
  assert.equal(second.executionId, "exec-new");
  assert.equal(second.fence, first.fence + 1);
  await assert.rejects(
    () => app.workExecutionLeaseService.assertOwned("owner-expiry", "work-expiry", "exec-old", first.token),
    error => error.code === "LEASE_NOT_OWNER" || error.code === "LEASE_EXPIRED"
  );
  await assert.rejects(
    () => app.workExecutionLeaseService.release("owner-expiry", "work-expiry", "exec-old", first.token),
    error => error.code === "LEASE_NOT_OWNER"
  );
  await app.workExecutionLeaseService.release("owner-expiry", "work-expiry", "exec-new", second.token);
});

test("Batch 104: JSON storage atomic updates do not lose cross-process increments", async t => {
  const root = await withTempRoot(t);
  const storageUrl = pathToFileURL(path.resolve("core/storage/index.js")).href;
  const script = `
    import { createStorage } from ${JSON.stringify(storageUrl)};
    const storage = createStorage({ root: process.env.V4_STORAGE_ROOT });
    for (let index = 0; index < 25; index++) {
      await storage.atomicUpdate("counter", current => ({ value: { count: (Number(current?.count) || 0) + 1 } }));
    }
    console.log(JSON.stringify({ ok: true }));
  `;
  const outcomes = await Promise.all([
    runChild(script, { V4_STORAGE_ROOT: root }),
    runChild(script, { V4_STORAGE_ROOT: root }),
    runChild(script, { V4_STORAGE_ROOT: root })
  ]);
  assert.equal(outcomes.every(item => item.ok === true), true);
  const saved = await createStorage({ root }).read("counter");
  assert.equal(saved.count, 75);
});

test("Batch 104: atomic storage recovers a lock abandoned by a dead local process", async t => {
  const root = await withTempRoot(t);
  const storage = createStorage({ root, lockTimeoutMs: 1000, staleLockMs: 1000 });
  const key = "abandoned-lock-key";
  const encoded = Buffer.from(key, "utf8").toString("base64url");
  const lockPath = path.join(root, `${encoded}.json.lock`);
  await fs.mkdir(lockPath);
  await fs.writeFile(path.join(lockPath, "owner.json"), JSON.stringify({ token: "dead-owner", pid: 2147483647, host: os.hostname(), createdAtMs: 1 }));
  const saved = await storage.atomicUpdate(key, () => ({ value: { recovered: true } }));
  assert.equal(saved.recovered, true);
  assert.equal((await storage.read(key)).recovered, true);
});

test("Batch 104: a newer execution fence rejects stale Work transitions", async t => {
  const root = await withTempRoot(t);
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  const work = await app.createWork("owner-fence", { objective: "fencing token" });
  await app.work.claimExecution("owner-fence", work.id, { executionId: "exec-old", fence: 1 });
  await app.work.claimExecution("owner-fence", work.id, { executionId: "exec-new", fence: 2 });
  await assert.rejects(
    () => app.work.transition("owner-fence", work.id, "ready", { executionLeaseFence: 1 }),
    error => error.code === "WORK_EXECUTION_LEASE_LOST"
  );
  const saved = await app.work.raw("owner-fence", work.id);
  assert.equal(saved.executionLeaseFence, 2);
  assert.equal(saved.executionLeaseId, "exec-new");
  assert.equal(saved.state, "draft");
});
