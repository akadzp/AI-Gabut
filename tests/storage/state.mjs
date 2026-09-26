import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createStorage, createStateService, STORAGE_ERRORS, StorageError } from "../../core/storage/index.js";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-gabut-state-"));
try {
  const storage = createStorage({ root });
  const state = createStateService({ storage });

  await assert.rejects(
    Promise.resolve().then(() => createStateService({ storage, namespace: "../unsafe" })),
    error => error instanceof StorageError && error.code === STORAGE_ERRORS.VALIDATION_ERROR
  );

  assert.deepEqual(state.listScopes(), ["sessions", "memories", "executions", "runtime"]);
  assert.equal(state.hasScope("sessions"), true);
  assert.equal(state.hasScope("unknown"), false);

  const created = await state.put("sessions", "session-1", { messages: [{ role: "user", content: "hello" }] });
  assert.equal(created._storage.version, 1);
  assert.deepEqual(await state.get("sessions", "session-1"), created);
  assert.deepEqual(await state.list("sessions"), ["session-1"]);

  const updated = await state.update("sessions", "session-1", { messages: [{ role: "assistant", content: "hi" }] }, { expectedVersion: 1 });
  assert.equal(updated._storage.version, 2);

  await assert.rejects(
    state.update("sessions", "session-1", { stale: true }, { expectedVersion: 1 }),
    error => error instanceof StorageError && error.code === STORAGE_ERRORS.CONFLICT
  );

  await state.put("memories", "memory-1", { type: "decision", content: "Use storage service" });
  await state.put("executions", "execution-1", { status: "running", turn: 1 });
  await state.put("runtime", "runtime-1", { status: "ready" });

  assert.equal((await state.sessions().exists("session-1")), true);
  assert.equal((await state.memories().exists("memory-1")), true);
  assert.equal((await state.executions().exists("execution-1")), true);
  assert.equal((await state.runtime().exists("runtime-1")), true);

  await state.delete("sessions", "session-1", { expectedVersion: 2 });
  assert.equal(await state.get("sessions", "session-1"), null);

  await assert.rejects(
    state.get("unknown", "key"),
    error => error instanceof StorageError && error.code === STORAGE_ERRORS.NOT_FOUND
  );
  await assert.rejects(
    state.get("sessions", ""),
    error => error instanceof StorageError && error.code === STORAGE_ERRORS.VALIDATION_ERROR
  );

  console.log("Storage state service: PASS");
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
