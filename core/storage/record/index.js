import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { StorageError, STORAGE_ERRORS } from "../errors.js";
import { assertStorageSegment, normalizeStorageKey, resolveStoragePath } from "../path.js";

function now() { return new Date().toISOString(); }
function etag(value) { return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
async function ensureParent(file) { await fs.mkdir(path.dirname(file), { recursive: true }); }
async function atomicWrite(file, content) {
  await ensureParent(file);
  const tmp = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try { await fs.writeFile(tmp, content, "utf8"); await fs.rename(tmp, file); }
  finally { await fs.rm(tmp, { force: true }).catch(() => {}); }
}

export function createRecordStore({ root, namespace }) {
  assertStorageSegment(namespace, "namespace");
  if (!root) throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Storage root is required");

  async function readEnvelope(key) {
    const file = resolveStoragePath(root, namespace, key);
    try { return JSON.parse(await fs.readFile(file, "utf8")); }
    catch (error) {
      if (error?.code === "ENOENT") return null;
      if (error instanceof SyntaxError) throw new StorageError(STORAGE_ERRORS.SERIALIZATION_ERROR, "Stored record is invalid");
      throw new StorageError(STORAGE_ERRORS.STORAGE_UNAVAILABLE, "Unable to read record", { cause: error?.message });
    }
  }

  async function get(key) {
    const envelope = await readEnvelope(key);
    if (!envelope) return null;
    return { ...envelope.data, _storage: { version: envelope.version, etag: envelope.etag, createdAt: envelope.createdAt, updatedAt: envelope.updatedAt } };
  }

  async function put(key, data, { expectedVersion = null, overwrite = true } = {}) {
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Record data must be an object");
    const safeKey = normalizeStorageKey(key);
    const current = await readEnvelope(safeKey);
    if (current && !overwrite) throw new StorageError(STORAGE_ERRORS.ALREADY_EXISTS, "Record already exists");
    if (expectedVersion !== null && (current?.version ?? 0) !== expectedVersion) throw new StorageError(STORAGE_ERRORS.CONFLICT, "Record version conflict", { expectedVersion, actualVersion: current?.version ?? null });
    const timestamp = now();
    const envelope = { version: (current?.version ?? 0) + 1, etag: etag(data), createdAt: current?.createdAt || timestamp, updatedAt: timestamp, data };
    await atomicWrite(resolveStoragePath(root, namespace, safeKey), JSON.stringify(envelope, null, 2));
    return { ...data, _storage: { version: envelope.version, etag: envelope.etag, createdAt: envelope.createdAt, updatedAt: envelope.updatedAt } };
  }

  async function update(key, data, options = {}) { return put(key, data, { ...options, overwrite: true, expectedVersion: options.expectedVersion ?? 0 }); }

  async function remove(key, { expectedVersion = null } = {}) {
    const safeKey = normalizeStorageKey(key);
    const current = await readEnvelope(safeKey);
    if (!current) return false;
    if (expectedVersion !== null && current.version !== expectedVersion) throw new StorageError(STORAGE_ERRORS.CONFLICT, "Record version conflict", { expectedVersion, actualVersion: current.version });
    try { await fs.rm(resolveStoragePath(root, namespace, safeKey)); return true; }
    catch (error) { if (error?.code === "ENOENT") return false; throw new StorageError(STORAGE_ERRORS.STORAGE_UNAVAILABLE, "Unable to delete record", { cause: error?.message }); }
  }

  async function exists(key) { return Boolean(await readEnvelope(key)); }

  async function list() {
    const directory = path.resolve(root, namespace);
    try { await fs.mkdir(directory, { recursive: true }); } catch (error) { throw new StorageError(STORAGE_ERRORS.STORAGE_UNAVAILABLE, "Unable to initialize record namespace", { cause: error?.message }); }
    const output = [];
    async function walk(current, relative = "") {
      for (const entry of await fs.readdir(current, { withFileTypes: true })) {
        const child = path.join(current, entry.name);
        const childRelative = relative ? path.join(relative, entry.name) : entry.name;
        if (entry.isDirectory()) await walk(child, childRelative);
        else if (entry.isFile() && entry.name.endsWith(".json")) output.push(childRelative.slice(0, -5).replaceAll(path.sep, "/"));
      }
    }
    await walk(directory);
    return output.sort();
  }

  return Object.freeze({ get, put, update, delete: remove, exists, list });
}
