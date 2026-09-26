import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { createStorage, StorageError } from "../../core/storage/index.js";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-gabut-storage-"));
try {
  const storage = createStorage({ root });
  const records = storage.records("tests");
  const created = await records.put("users/one", { name: "Ada", active: true });
  assert.equal(created._storage.version, 1);
  const loaded = await records.get("users/one");
  assert.equal(loaded.name, "Ada");
  await assert.rejects(() => records.put("users/one", { name: "Grace" }, { expectedVersion: 99 }), error => error instanceof StorageError && error.code === "CONFLICT");
  const updated = await records.update("users/one", { name: "Grace" }, { expectedVersion: 1 });
  assert.equal(updated._storage.version, 2);
  assert.deepEqual(await records.list(), ["users/one"]);

  const objects = storage.objects("blobs");
  await objects.put("sample", Buffer.from("hello"));
  assert.equal((await objects.get("sample")).toString(), "hello");
  assert.equal(await objects.exists("sample"), true);
  await objects.delete("sample");
  assert.equal(await objects.get("sample"), null);

  await assert.rejects(() => records.get("../escape"), error => error instanceof StorageError && error.code === "VALIDATION_ERROR");
  console.log("CORE STORAGE CONTRACT PASS");
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
