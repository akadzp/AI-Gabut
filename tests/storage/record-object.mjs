import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createStorage, STORAGE_ERRORS, StorageError } from "../../core/storage/index.js";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-gabut-storage-"));
try {
  const storage = createStorage({ root });
  const records = storage.records("sessions");
  const objects = storage.objects("artifacts");

  const created = await records.put("user/one", { name: "Gabut", enabled: true });
  assert.equal(created._storage.version, 1);
  assert.match(created._storage.etag, /^[a-f0-9]{64}$/);
  assert.deepEqual((await records.get("user/one")).name, "Gabut");
  assert.deepEqual(await records.list(), ["user/one"]);
  assert.equal(await records.exists("user/one"), true);

  const updated = await records.put("user/one", { name: "Gabut 2" }, { expectedVersion: 1 });
  assert.equal(updated._storage.version, 2);
  await assert.rejects(
    records.put("user/one", { name: "stale" }, { expectedVersion: 1 }),
    error => error instanceof StorageError && error.code === STORAGE_ERRORS.CONFLICT
  );
  await assert.rejects(
    records.put("user/one", { name: "duplicate" }, { overwrite: false }),
    error => error instanceof StorageError && error.code === STORAGE_ERRORS.ALREADY_EXISTS
  );

  for (const key of ["../escape", "/absolute", "a//b", "a/../b"]) {
    await assert.rejects(records.put(key, { bad: true }), error => error instanceof StorageError && error.code === STORAGE_ERRORS.VALIDATION_ERROR);
  }

  assert.equal(await records.delete("user/one", { expectedVersion: 2 }), true);
  assert.equal(await records.get("user/one"), null);
  assert.equal(await records.delete("user/one"), false);

  const bytes = Buffer.from([0, 1, 2, 255]);
  const objectMeta = await objects.put("uploads/sample", bytes);
  assert.equal(objectMeta.size, bytes.length);
  assert.match(objectMeta.etag, /^[a-f0-9]{64}$/);
  assert.deepEqual(await objects.get("uploads/sample"), bytes);
  assert.equal(await objects.exists("uploads/sample"), true);
  assert.equal(await objects.delete("uploads/sample"), true);
  assert.equal(await objects.get("uploads/sample"), null);

  await assert.rejects(objects.put("bad", "not-bytes"), error => error instanceof StorageError && error.code === STORAGE_ERRORS.VALIDATION_ERROR);
  await assert.rejects(objects.put("../escape", bytes), error => error instanceof StorageError && error.code === STORAGE_ERRORS.VALIDATION_ERROR);

  console.log("Storage record/object: PASS");
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
