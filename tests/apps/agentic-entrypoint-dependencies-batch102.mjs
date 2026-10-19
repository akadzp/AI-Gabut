import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { encryptSecret, decryptSecret } from "../../apps/agentic/backend/crypto.js";
import { loadAgenticDeployment, assertAllowedOrigin, getSecurityHeaders } from "../../apps/agentic/backend/deployment.js";
import { createRealtimeService } from "../../apps/agentic/backend/realtime.js";

function memoryStorage() {
  const records = new Map();
  return {
    async read(key) { return records.has(key) ? structuredClone(records.get(key)) : null; },
    async write(key, value) { records.set(key, structuredClone(value)); return value; },
    async remove(key) { return records.delete(key); },
    async list(prefix = "") { return [...records.keys()].filter(key => key.startsWith(prefix)).sort(); }
  };
}

test("Batch 102: application entry point initializes all restored services", () => {
  const application = createAgenticApplication({ storage: memoryStorage() });
  for (const name of ["auth", "connections", "workspaces", "github", "work", "workExecution", "workChanges", "verification", "realtime", "missionControl", "missionScheduler"]) {
    assert.ok(application[name], `missing application service: ${name}`);
  }
  for (const name of ["createWorkspace", "getWorkspace", "createConnection", "getConnection", "runWork", "createChange", "verifyWork", "runAllDueMissions"]) {
    assert.equal(typeof application[name], "function", `missing application API: ${name}`);
  }
});

test("Batch 102: auth registration, login, bearer authentication, and logout work", async () => {
  const app = createAgenticApplication({ storage: memoryStorage() });
  const user = await app.auth.register({ email: "owner@example.test", password: "strong-password-102", name: "Owner" });
  assert.equal(user.email, "owner@example.test");
  assert.equal("passwordHash" in user, false);
  await assert.rejects(() => app.auth.register({ email: "OWNER@example.test", password: "strong-password-102", name: "Duplicate" }), error => error.code === "EMAIL_ALREADY_REGISTERED");
  const login = await app.auth.login({ email: "owner@example.test", password: "strong-password-102" });
  assert.equal((await app.auth.authenticate(login.token)).user.id, user.id);
  assert.deepEqual(await app.auth.logout(login.token), { loggedOut: true });
  await assert.rejects(() => app.auth.authenticate(login.token), error => error.code === "AUTH_INVALID");
});

test("Batch 102: work execution fails honestly when no model provider is configured", async () => {
  const app = createAgenticApplication({ storage: memoryStorage() });
  const user = await app.auth.register({ email: "runtime@example.test", password: "strong-password-102", name: "Runtime" });
  const work = await app.createWork(user.id, { objective: "Perform a bounded test task" });
  const planned = await app.planWork(user.id, work.id);
  assert.equal(planned.state, "ready");
  assert.ok(planned.plan.steps.length > 0);
  const run = await app.runWork(user.id, work.id);
  assert.equal(run.work.state, "failed");
  assert.equal(run.execution.status, "failed");
  assert.match(run.result.text, /model provider/i);
});

test("Batch 102: injected agent runner completes Work and persists linked task/execution", async () => {
  const app = createAgenticApplication({
    storage: memoryStorage(),
    agentRunner: async ({ onActivity }) => {
      await onActivity({ action: "checkpoint", status: "completed", meta: { phase: "verified" } });
      return { text: "Task completed by injected provider", execution: { status: "completed" }, status: "completed" };
    }
  });
  const user = await app.auth.register({ email: "provider@example.test", password: "strong-password-102", name: "Provider" });
  const work = await app.createWork(user.id, { objective: "Run through the injected provider" });
  const result = await app.runWork(user.id, work.id);
  assert.equal(result.work.state, "completed");
  assert.equal(result.execution.status, "completed");
  assert.ok(result.execution.checkpoint);
  assert.ok(result.work.taskIds.includes(result.execution.taskId));
  assert.ok(result.work.executionIds.includes(result.execution.id));
});

test("Batch 102: change edits are staged, hash-checked, and rollback does not mutate disk", async () => {
  const app = createAgenticApplication({ storage: memoryStorage() });
  const user = await app.auth.register({ email: "changes@example.test", password: "strong-password-102", name: "Changes" });
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-v4-b102-"));
  try {
    await fs.writeFile(path.join(root, "hello.txt"), "before", "utf8");
    const workspace = await app.createWorkspace(user.id, { name: "Local test", rootPath: root });
    const work = await app.createWork(user.id, { objective: "Edit a file", workspaceId: workspace.id });
    const change = await app.createChange(user.id, work.id, { title: "Test edit" });
    await app.captureChange(user.id, change.id, "hello.txt");
    const edited = await app.editChange(user.id, change.id, { path: "hello.txt", content: "after" });
    assert.equal(edited.files[0].after, "after");
    const reviewed = await app.reviewChange(user.id, change.id, { reviewer: "owner" });
    assert.equal(reviewed.review.status, "approved");
    const rollback = await app.rollbackChange(user.id, change.id, "hello.txt");
    assert.equal(rollback.change.files[0].after, "before");
    assert.equal(await fs.readFile(path.join(root, "hello.txt"), "utf8"), "before");
    await assert.rejects(() => app.editChange(user.id, change.id, { path: "../escape.txt", content: "no" }), error => error.code === "INVALID_CHANGE_PATH");
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test("Batch 102: verification records a safe skipped result when no working directory is configured", async () => {
  const app = createAgenticApplication({ storage: memoryStorage() });
  const user = await app.auth.register({ email: "verify@example.test", password: "strong-password-102", name: "Verify" });
  const work = await app.createWork(user.id, { objective: "Verification target" });
  const result = await app.verifyWork(user.id, work.id);
  assert.equal(result.verification.status, "skipped");
  assert.equal(result.verification.reason, "verification_cwd_not_configured");
  assert.equal((await app.listVerifications(user.id, work.id)).length, 1);
  await assert.rejects(() => app.verifyWork(user.id, work.id, { command: "rm -rf /" }), error => error.code === "VERIFICATION_COMMAND_NOT_ALLOWED");
});

test("Batch 102: realtime replay is owner-scoped, filterable, and supports unsubscribe", async () => {
  const realtime = createRealtimeService({ maxEvents: 100 });
  const received = [];
  const unsubscribe = realtime.subscribe("owner-a", event => received.push(event), { executionId: "exec-1" });
  await realtime.publish("owner-a", { id: "event-1", executionId: "exec-1", sessionId: "session-1", action: "start" });
  await realtime.publish("owner-a", { id: "event-2", executionId: "exec-2", action: "other" });
  await realtime.publish("owner-b", { id: "event-3", executionId: "exec-1", action: "private" });
  assert.equal(received.length, 1);
  assert.equal((await realtime.replay("owner-a", { executionId: "exec-1" })).length, 1);
  assert.equal((await realtime.replay("owner-b")).length, 1);
  unsubscribe();
  await realtime.publish("owner-a", { id: "event-4", executionId: "exec-1" });
  assert.equal(received.length, 1);
});

test("Batch 102: secret encryption uses authenticated ciphertext and rejects tampering", () => {
  const prior = process.env.AGENTIC_ENCRYPTION_KEY;
  process.env.AGENTIC_ENCRYPTION_KEY = "batch-102-test-key-with-sufficient-entropy";
  try {
    const ciphertext = encryptSecret("ghp_example_sensitive_token");
    assert.notEqual(ciphertext, "ghp_example_sensitive_token");
    assert.equal(decryptSecret(ciphertext), "ghp_example_sensitive_token");
    const tampered = `${ciphertext.slice(0, -1)}${ciphertext.endsWith("A") ? "B" : "A"}`;
    assert.throws(() => decryptSecret(tampered), error => error.code === "CREDENTIAL_DECRYPTION_FAILED");
  } finally {
    if (prior === undefined) delete process.env.AGENTIC_ENCRYPTION_KEY;
    else process.env.AGENTIC_ENCRYPTION_KEY = prior;
  }
});

test("Batch 102: deployment configuration rejects unsafe origins and emits baseline headers", () => {
  const deployment = loadAgenticDeployment({ NODE_ENV: "test", AGENTIC_ALLOWED_ORIGINS: "https://app.example.test,not-a-url", AGENTIC_TRUST_PROXY: "false" });
  assert.deepEqual(deployment.allowedOrigins, ["https://app.example.test"]);
  assert.equal(assertAllowedOrigin("https://app.example.test", deployment), true);
  assert.equal(assertAllowedOrigin("https://evil.example.test", deployment), false);
  assert.equal(deployment.trustProxy, false);
  const headers = getSecurityHeaders({ split: true });
  assert.equal(headers["X-Content-Type-Options"], "nosniff");
  assert.equal(headers["X-Frame-Options"], "DENY");
  assert.equal(headers["Cross-Origin-Resource-Policy"], "cross-origin");
});

test("Batch 102: all relative JavaScript imports resolve within the source archive", async () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(here, "../..");
  const files = [];
  async function walk(dir) {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (/\.(?:js|mjs|cjs)$/.test(entry.name)) files.push(full);
    }
  }
  await walk(root);
  const pattern = /(?:from\s*|import\s*\(|require\s*\()\s*["'](\.[^"']+)["']/g;
  const missing = [];
  for (const file of files) {
    const source = await fs.readFile(file, "utf8");
    for (const match of source.matchAll(pattern)) {
      const target = path.resolve(path.dirname(file), match[1]);
      const candidates = [target, `${target}.js`, `${target}.mjs`, `${target}.cjs`, path.join(target, "index.js"), path.join(target, "index.mjs")];
      let found = false;
      for (const candidate of candidates) { try { if ((await fs.stat(candidate)).isFile()) { found = true; break; } } catch {} }
      if (!found) missing.push(`${path.relative(root, file)} -> ${match[1]}`);
    }
  }
  assert.deepEqual(missing, []);
});


test("Batch 102: credential service stores ciphertext and revokes credentials without exposing secrets", async () => {
  const prior = process.env.AGENTIC_ENCRYPTION_KEY;
  process.env.AGENTIC_ENCRYPTION_KEY = "batch-102-credential-test-key-with-entropy";
  try {
    const app = createAgenticApplication({ storage: memoryStorage() });
    const user = await app.auth.register({ email: "credential@example.test", password: "strong-password-102", name: "Credential" });
    const connection = await app.createConnection(user.id, { provider: "github", name: "Test GitHub", status: "active" });
    await app.github.credentials.put(user.id, { connectionId: connection.id, provider: "github", secret: "ghp_sensitive_example_token" });
    assert.equal(await app.github.credentials.getForConnection(user.id, connection.id), "ghp_sensitive_example_token");
    const saved = (await app.store.listConnectionCredentials(user.id))[0];
    assert.equal(saved.ciphertext.includes("ghp_sensitive_example_token"), false);
    await app.github.credentials.revokeForConnection(user.id, connection.id);
    await assert.rejects(() => app.github.credentials.getForConnection(user.id, connection.id), error => error.code === "CREDENTIAL_NOT_FOUND");
  } finally {
    if (prior === undefined) delete process.env.AGENTIC_ENCRYPTION_KEY;
    else process.env.AGENTIC_ENCRYPTION_KEY = prior;
  }
});

test("Batch 102: every top-level application API referenced by the HTTP server exists", async () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const source = await fs.readFile(path.join(root, "apps/agentic/backend/server.js"), "utf8");
  const references = [...new Set([...source.matchAll(/application\.([A-Za-z_$][\w$]*)/g)].map(match => match[1]).filter(name => name !== "js"))];
  const app = createAgenticApplication({ storage: memoryStorage() });
  assert.deepEqual(references.filter(name => !(name in app)), []);
});

test("Batch 102: Express runtime dependency is declared for the HTTP server entry point", async () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const pkg = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));
  assert.match(pkg.dependencies?.express || "", /^\^4\./);
  assert.equal(pkg.scripts?.start, "node apps/agentic/backend/server.js");
});
