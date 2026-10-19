import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createStorage } from "../../core/storage/index.js";
import { createStateService } from "../../core/storage/state/index.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createWorkService } from "../../apps/agentic/backend/work.js";
import { authorizeTool, auditEvent, getToolPolicy, issueApproval, listAuditEvents } from "../../core/security/index.js";

function memoryRecords() {
  const namespaces = new Map();
  return {
    records(namespace) {
      if (!namespaces.has(namespace)) namespaces.set(namespace, new Map());
      const records = namespaces.get(namespace);
      return {
        async get(id) { return records.get(id) ?? null; },
        async put(id, value, options = {}) {
          const current = records.get(id) ?? null;
          if (options.overwrite === false && current) throw Object.assign(new Error("duplicate"), { code: "STATE_RECORD_EXISTS" });
          if (options.expectedVersion !== undefined && current?._storage?.version !== options.expectedVersion) throw Object.assign(new Error("conflict"), { code: "VERSION_CONFLICT" });
          const saved = { ...value, _storage: { version: (current?._storage?.version ?? 0) + 1 } };
          records.set(id, saved);
          return saved;
        },
        async delete(id, options = {}) {
          const current = records.get(id) ?? null;
          if (options.expectedVersion !== undefined && current?._storage?.version !== options.expectedVersion) throw Object.assign(new Error("conflict"), { code: "VERSION_CONFLICT" });
          return records.delete(id);
        },
        async list() { return [...records.keys()]; }
      };
    }
  };
}

test("batch 101 state service isolates namespaces and scopes", async () => {
  const storage = memoryRecords();
  const a = createStateService({ storage, namespace: "agentic", scopes: ["works", "missions"] });
  const b = createStateService({ storage, namespace: "other", scopes: ["works"] });
  await a.put("works", "w1", { id: "w1", value: 1 });
  await a.put("missions", "w1", { id: "w1", value: 2 });
  assert.equal((await a.get("works", "w1")).value, 1);
  assert.equal((await a.get("missions", "w1")).value, 2);
  assert.equal(await b.get("works", "w1"), null);
  await assert.rejects(() => a.get("unknown", "w1"), error => error.code === "STATE_SCOPE_INVALID");
});

test("batch 101 state service enforces overwrite and optimistic versions", async () => {
  const state = createStateService({ storage: memoryRecords(), namespace: "agentic", scopes: ["works"] });
  const first = await state.put("works", "w1", { value: 1 }, { overwrite: false });
  assert.equal(first._storage.version, 1);
  await assert.rejects(() => state.put("works", "w1", { value: 2 }, { overwrite: false }), error => error.code === "STATE_RECORD_EXISTS");
  const second = await state.put("works", "w1", { value: 2 }, { expectedVersion: 1 });
  assert.equal(second._storage.version, 2);
  await assert.rejects(() => state.put("works", "w1", { value: 3 }, { expectedVersion: 1 }), error => error.code === "VERSION_CONFLICT");
  assert.deepEqual(await state.list("works"), ["w1"]);
});

test("batch 101 state service deletes only the expected version", async () => {
  const state = createStateService({ storage: memoryRecords(), namespace: "agentic", scopes: ["works"] });
  const record = await state.put("works", "w1", { value: 1 });
  await assert.rejects(() => state.delete("works", "w1", { expectedVersion: record._storage.version + 1 }), error => error.code === "VERSION_CONFLICT");
  assert.equal(await state.exists("works", "w1"), true);
  assert.equal(await state.delete("works", "w1", { expectedVersion: record._storage.version }), true);
  assert.equal(await state.exists("works", "w1"), false);
});

test("batch 101 JSON storage persists values and lists by prefix", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-state-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const storage = createStorage({ root });
  await storage.write("agentic/works/u1--w1", { id: "w1" });
  await storage.write("agentic/missions/u1--m1", { id: "m1" });
  assert.deepEqual(await storage.read("agentic/works/u1--w1"), { id: "w1" });
  assert.deepEqual(await storage.list("agentic/works/"), ["agentic/works/u1--w1"]);
  assert.equal(await storage.remove("agentic/works/u1--w1"), true);
  assert.equal(await storage.read("agentic/works/u1--w1"), null);
});

test("batch 101 security policy gates high-impact tools by default", () => {
  assert.equal(getToolPolicy("git_commit").requiresApproval, true);
  assert.equal(authorizeTool({ tool: "git_commit", input: { branch: "main" } }).requiresApproval, true);
  assert.equal(authorizeTool({ tool: "read_file", input: { path: "README.md" } }).ok, true);
});

test("batch 101 security approval is bound to tool and canonical input and consumed once", () => {
  const input = { repository: "acme/repo", branch: "agentic/work-1" };
  const grant = issueApproval({ tool: "git_commit", input, sessionId: "u1:chat1" });
  assert.ok(Date.parse(grant.expiresAt) > Date.now());
  assert.equal(authorizeTool({ tool: "git_commit", input: { branch: "agentic/work-1", repository: "acme/repo" }, approvalToken: grant.token }).ok, true);
  assert.equal(authorizeTool({ tool: "git_commit", input, approvalToken: grant.token }).ok, false);
  const other = issueApproval({ tool: "git_push", input });
  assert.equal(authorizeTool({ tool: "git_commit", input, approvalToken: other.token }).ok, false);
});

test("batch 101 audit events retain bounded, non-sensitive fields", () => {
  const event = auditEvent({ actor: "user", action: "agentic-chat", outcome: "completed", principal: { userId: "u1", secret: "do-not-copy" }, sessionId: "s1" });
  assert.equal(event.principal.userId, "u1");
  assert.equal("secret" in event.principal, false);
  assert.ok(listAuditEvents({ limit: 1 }).length <= 1);
});


test("batch 101 Agentic store persists owner-scoped external feedback and Git workflows", async () => {
  const store = createAgenticStore({ storage: memoryRecords() });
  await store.putExternalFeedback("u1", { id: "fb1", ownerId: "u1", status: "failed" }, { overwrite: false });
  await store.putGitWorkflow("u1", { id: "git1", ownerId: "u1", status: "planned" }, { overwrite: false });
  assert.equal((await store.getExternalFeedback("u1", "fb1")).status, "failed");
  assert.equal((await store.listExternalFeedback("u2")).length, 0);
  assert.equal((await store.getGitWorkflow("u1", "git1")).status, "planned");
  assert.equal((await store.listGitWorkflows("u2")).length, 0);
});

test("batch 101 Work records external-feedback references without changing other links", async () => {
  const store = createAgenticStore({ storage: memoryRecords() });
  const work = createWorkService({ store });
  await work.create("u1", { id: "w1", objective: "link external feedback" });
  await work.attachReference("u1", "w1", "fb1", "external-feedback");
  await work.attachReference("u1", "w1", "fb1", "external-feedback");
  const saved = await work.get("u1", "w1");
  assert.deepEqual(saved.externalFeedbackIds, ["fb1"]);
  assert.deepEqual(saved.artifactIds, []);
});
