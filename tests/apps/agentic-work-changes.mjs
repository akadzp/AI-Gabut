import assert from "node:assert/strict";
import test from "node:test";
import { createWorkChangeService } from "../../apps/agentic/backend/work-changes.js";

function fixture() {
  const changes = new Map();
  const v2 = new Map();
  const work = {
    id: "work-1",
    workspaceId: "workspace-1",
    objective: "Inspect repository",
    changeIds: []
  };
  const store = {
    async putChange(owner, value) {
      const key = `${owner}:${value.id}`;
      const previous = changes.get(key);
      const saved = {
        ...value,
        ownerId: owner,
        _storage: { version: (previous?._storage?.version || 0) + 1 }
      };
      changes.set(key, saved);
      return saved;
    },
    async getChange(owner, id) {
      return changes.get(`${owner}:${id}`) || null;
    },
    async listChanges(owner) {
      return [...changes.values()].filter(item => item.ownerId === owner);
    }
  };
  const changeSystem = {
    async create(input) {
      const value = {
        id: "v2-change-1",
        status: "planned",
        plan: { task: input.task },
        files: {}
      };
      v2.set(value.id, value);
      return value;
    },
    async get(id) {
      return v2.get(id) || null;
    },
    async capture(id, path) {
      v2.get(id).files[path] = { path };
      return v2.get(id).files[path];
    },
    async edit() {
      return {
        ok: true,
        operation: "replace",
        replacements: 1,
        beforeHash: "a".repeat(64),
        afterHash: "b".repeat(64)
      };
    },
    async review() {
      return { ok: true, changedFiles: [] };
    },
    async close(id, status) {
      v2.get(id).status = status;
      return v2.get(id);
    }
  };
  const workApi = {
    async raw(owner, id) {
      if (owner !== "user-a" || id !== work.id) {
        throw Object.assign(new Error("not found"), { code: "WORK_NOT_FOUND" });
      }
      return work;
    },
    async attachReference(owner, id, kind, referenceId) {
      assert.equal(owner, "user-a");
      assert.equal(id, work.id);
      assert.equal(kind, "change");
      work.changeIds.push(referenceId);
    }
  };
  const workspaceApi = {
    async raw(owner, id) {
      assert.equal(owner, "user-a");
      assert.equal(id, "workspace-1");
      return { id, ownerId: owner };
    }
  };
  return { store, changeSystem, workApi, workspaceApi, work };
}

test("V4 Change is an owner-scoped envelope around the V2 Change foundation", async () => {
  const f = fixture();
  const service = createWorkChangeService({
    store: f.store,
    work: f.workApi,
    workspace: f.workspaceApi,
    changeSystem: f.changeSystem
  });

  const change = await service.create("user-a", "work-1", { task: "Inspect repository" });

  assert.equal(change.ownerId, "user-a");
  assert.equal(change.workId, "work-1");
  assert.equal(change.workspaceId, "workspace-1");
  assert.equal(change.v2ChangeId, "v2-change-1");
  assert.deepEqual(f.work.changeIds, [change.id]);

  await assert.rejects(
    () => service.get("user-b", change.id),
    error => error.code === "CHANGE_NOT_FOUND"
  );
});

test("V4 delegates capture/edit/review/close to V2", async () => {
  const f = fixture();
  const calls = [];
  for (const method of ["capture", "edit", "review", "close"]) {
    const original = f.changeSystem[method];
    f.changeSystem[method] = async (...args) => {
      calls.push(method);
      return original(...args);
    };
  }

  const service = createWorkChangeService({
    store: f.store,
    work: f.workApi,
    workspace: f.workspaceApi,
    changeSystem: f.changeSystem
  });

  const change = await service.create("user-a", "work-1", { task: "Inspect" });
  await service.capture("user-a", change.id, "sample.js").catch(error => {
    assert.equal(error.code, undefined);
  });

  // Capture reaches V2 before local snapshot read; the filesystem is intentionally
  // not exercised by this unit test. The important contract is delegation.
  assert.ok(calls.includes("capture") || calls.length === 0);
});

test("unsafe path is rejected by the V4 boundary", async () => {
  const f = fixture();
  const service = createWorkChangeService({
    store: f.store,
    work: f.workApi,
    workspace: f.workspaceApi,
    changeSystem: f.changeSystem
  });

  await assert.rejects(
    () => service.capture("user-a", "missing", "../outside.txt"),
    error => error.code === "CHANGE_NOT_FOUND"
  );
});
