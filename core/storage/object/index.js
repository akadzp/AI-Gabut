import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { StorageError, STORAGE_ERRORS } from "../errors.js";
import { assertStorageSegment, normalizeStorageKey, resolveStoragePath } from "../path.js";

async function ensureParent(file) { await fs.mkdir(path.dirname(file), { recursive: true }); }
async function atomicWrite(file, value) {
  await ensureParent(file);
  const tmp = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try { await fs.writeFile(tmp, value); await fs.rename(tmp, file); }
  finally { await fs.rm(tmp, { force: true }).catch(() => {}); }
}

export function createObjectStore({ root, namespace, extension = ".bin" }) {
  assertStorageSegment(namespace, "namespace");
  if (!root) throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Storage root is required");
  if (!/^\.[a-zA-Z0-9]+$/.test(extension)) throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Invalid object extension");

  async function put(key, value) {
    if (!(Buffer.isBuffer(value) || value instanceof Uint8Array)) throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Object value must be bytes");
    const safeKey = normalizeStorageKey(key);
    const file = resolveStoragePath(root, namespace, safeKey, extension);
    await atomicWrite(file, Buffer.from(value));
    return { key: safeKey, size: Buffer.byteLength(value), etag: crypto.createHash("sha256").update(value).digest("hex") };
  }

  async function get(key) {
    try { return await fs.readFile(resolveStoragePath(root, namespace, key, extension)); }
    catch (error) { if (error?.code === "ENOENT") return null; throw new StorageError(STORAGE_ERRORS.STORAGE_UNAVAILABLE, "Unable to read object", { cause: error?.message }); }
  }

  async function remove(key) {
    try { await fs.rm(resolveStoragePath(root, namespace, key, extension)); return true; }
    catch (error) { if (error?.code === "ENOENT") return false; throw new StorageError(STORAGE_ERRORS.STORAGE_UNAVAILABLE, "Unable to delete object", { cause: error?.message }); }
  }

  async function exists(key) { return Boolean(await get(key)); }
  return Object.freeze({ put, get, delete: remove, exists });
}
