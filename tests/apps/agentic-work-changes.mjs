import assert from "node:assert/strict";
import test from "node:test";
import crypto from "node:crypto";
import { createWorkChangeService } from "../../apps/agentic/backend/work-changes.js";

function fixture() {
  const changes = new Map();
  const v2 = new Map();
  const files = new Map([["sample.js", "export const value = 1;\n"]]);
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
        id: `v2-change-${v2.size + 1}`,
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
    async edit(id, input) {
      const content = files.get(input.path);
      const beforeHash = cryptoHash(content);
      const after = content.replace(input.oldText, input.newText);
      files.set(input.path, after);
      const afterHash = cryptoHash(after);
      return {
        ok: true,
        operation: "replace",
        replacements: 1,
        beforeHash,
        afterHash
      };
    },
    async review() {
      return { ok: true, changedFiles: ["sample.js"] };
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
      if (owner !== "user-a" || id !== "workspace-1") {
        throw Object.assign(new Error("not found"), { code: "WORKSPACE_NOT_FOUND" });
      }
      return { id, ownerId: owner, state: "active" };
    }
  };
  const fileSystem = {
    async read(path) {
      if (!files.has(path)) throw new Error(`missing file: ${path}`);
      const content = files.get(path);
      return { path, content, size: Buffer.byteLength(content, "utf8") };
    },
    async write(path, content) {
      files.set(path, content);
    }
  };
  return { store, changeSystem, workApi, workspaceApi, fileSystem, work, files };
}

function cryptoHash(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function serviceFor(f) {
  return createWorkChangeService({
    store: f.store,
    work: f.workApi,
    workspace: f.workspaceApi,
    changeSystem: f.changeSystem,
    fileSystem: f.fileSystem
  });
}

test("V4 Change is an owner-scoped envelope around the V2 Change foundation", async () => {
  const f = fixture();
  const service = serviceFor(f);
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

test("capture, edit and rollback preserve baseline evidence and conflict safety", async () => {
  const f = fixture();
  const service = serviceFor(f);
  const change = await service.create("user-a", "work-1", { task: "Update value" });

  const captured = await service.capture("user-a", change.id, "sample.js");
  assert.equal(captured.baselineSize, Buffer.byteLength("export const value = 1;\n", "utf8"));

  const edited = await service.edit("user-a", change.id, {
    path: "sample.js",
    operation: "replace",
    oldText: "value = 1",
    newText: "value = 2"
  });
  assert.equal(edited.ok, true);
  assert.equal(f.files.get("sample.js"), "export const value = 2;\n");

  const rolledBack = await service.rollback("user-a", change.id, "sample.js");
  assert.equal(rolledBack.ok, true);
  assert.equal(f.files.get("sample.js"), "export const value = 1;\n");

  f.files.set("sample.js", "externally changed\n");
  await assert.rejects(
    () => service.rollback("user-a", change.id, "sample.js"),
    error => error.code === "ROLLBACK_CONFLICT"
  );
});

test("unsafe path is rejected by the V4 boundary", async () => {
  const f = fixture();
  const service = serviceFor(f);
  const change = await service.create("user-a", "work-1", { task: "Inspect" });

  await assert.rejects(
    () => service.capture("user-a", change.id, "../outside.txt"),
    error => error.code === "INVALID_CHANGE_PATH"
  );
});

test("terminal Change cannot be mutated", async () => {
  const f = fixture();
  const service = serviceFor(f);
  const change = await service.create("user-a", "work-1", { task: "Inspect" });
  await service.close("user-a", change.id, "completed");

  await assert.rejects(
    () => service.review("user-a", change.id),
    error => error.code === "CHANGE_TERMINAL"
  );
});
