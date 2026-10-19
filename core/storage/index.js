import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { randomBytes, randomUUID } from "node:crypto";

const asKey = value => String(value ?? "");
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function isProcessAlive(pid) {
  if (!Number.isSafeInteger(Number(pid)) || Number(pid) <= 0) return false;
  try {
    process.kill(Number(pid), 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

/**
 * Creates a JSON-backed key/value store for Agentic runtime state.
 * Keys are encoded as filenames, writes use atomic rename, and atomicUpdate
 * serializes read/modify/write operations across Node processes sharing root.
 */
export function createStorage({
  root = process.env.AGENTIC_STORAGE_DIR || path.resolve(process.cwd(), ".data", "agentic"),
  lockTimeoutMs = 15_000,
  staleLockMs = 30_000
} = {}) {
  const base = path.resolve(root);
  const host = os.hostname();
  const fileFor = key => path.join(base, `${Buffer.from(asKey(key), "utf8").toString("base64url")}.json`);

  async function read(key) {
    try {
      return JSON.parse(await fs.readFile(fileFor(key), "utf8"));
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      if (error instanceof SyntaxError) {
        const corrupt = new Error(`Stored JSON is invalid for key ${asKey(key).slice(0, 120)}`);
        corrupt.code = "STORAGE_RECORD_INVALID";
        throw corrupt;
      }
      throw error;
    }
  }

  async function write(key, value) {
    const destination = fileFor(key);
    await fs.mkdir(base, { recursive: true });
    const temporary = `${destination}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    try {
      await fs.writeFile(temporary, JSON.stringify(value), { encoding: "utf8", flag: "wx", mode: 0o600 });
      await fs.rename(temporary, destination);
      return value;
    } catch (error) {
      await fs.rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  }

  async function remove(key) {
    try {
      await fs.unlink(fileFor(key));
      return true;
    } catch (error) {
      if (error?.code === "ENOENT") return false;
      throw error;
    }
  }

  async function acquireLock(key) {
    const lockPath = `${fileFor(key)}.lock`;
    const startedAt = Date.now();
    const token = randomUUID();
    await fs.mkdir(base, { recursive: true });

    while (true) {
      try {
        await fs.mkdir(lockPath);
        const owner = { token, pid: process.pid, host, createdAtMs: Date.now() };
        try {
          await fs.writeFile(path.join(lockPath, "owner.json"), JSON.stringify(owner), { encoding: "utf8", flag: "wx", mode: 0o600 });
        } catch (error) {
          await fs.rm(lockPath, { recursive: true, force: true }).catch(() => {});
          throw error;
        }
        return async () => {
          try {
            const current = JSON.parse(await fs.readFile(path.join(lockPath, "owner.json"), "utf8"));
            if (current?.token === token) await fs.rm(lockPath, { recursive: true, force: true });
          } catch (error) {
            if (error?.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
          }
        };
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
      }

      let owner = null;
      let stat = null;
      try {
        [owner, stat] = await Promise.all([
          fs.readFile(path.join(lockPath, "owner.json"), "utf8").then(raw => JSON.parse(raw)).catch(() => null),
          fs.stat(lockPath).catch(() => null)
        ]);
      } catch {
        // A concurrent process may be creating or removing the lock directory.
      }
      const ageMs = stat ? Date.now() - stat.mtimeMs : 0;
      const sameHostDeadOwner = owner?.host === host && !isProcessAlive(owner.pid);
      const oldUnownedLock = !owner && ageMs > staleLockMs;
      const expiredForeignLock = owner?.host !== host && ageMs > staleLockMs;

      if (sameHostDeadOwner || oldUnownedLock || expiredForeignLock) {
        const quarantine = `${lockPath}.stale-${process.pid}-${randomBytes(5).toString("hex")}`;
        try {
          await fs.rename(lockPath, quarantine);
          const movedOwner = await fs.readFile(path.join(quarantine, "owner.json"), "utf8")
            .then(raw => JSON.parse(raw)).catch(() => null);
          // Never discard a lock that changed between the stale check and rename.
          if (owner?.token && movedOwner?.token && owner.token !== movedOwner.token) {
            try { await fs.rename(quarantine, lockPath); } catch { /* a newer lock already exists */ }
          } else {
            await fs.rm(quarantine, { recursive: true, force: true });
          }
          continue;
        } catch (error) {
          if (error?.code === "ENOENT" || error?.code === "EEXIST") continue;
          throw error;
        }
      }

      if (Date.now() - startedAt >= lockTimeoutMs) {
        const error = new Error(`Timed out acquiring storage lock for key ${asKey(key).slice(0, 120)}`);
        error.code = "STORAGE_LOCK_TIMEOUT";
        throw error;
      }
      await sleep(5 + Math.floor(Math.random() * 8));
    }
  }

  /**
   * Atomically read and mutate one key across processes sharing the same root.
   * updater receives the current value and returns one of:
   *   { write: false, result }  - leave state untouched
   *   { delete: true, result }  - delete the key
   *   { value, result }         - persist value
   */
  async function atomicUpdate(key, updater) {
    if (typeof updater !== "function") throw new TypeError("atomicUpdate requires an updater function");
    const release = await acquireLock(key);
    try {
      const current = await read(key);
      const decision = await updater(current);
      if (!decision || typeof decision !== "object" || Array.isArray(decision)) {
        const error = new Error("atomicUpdate updater must return a decision object");
        error.code = "STORAGE_ATOMIC_UPDATE_INVALID";
        throw error;
      }
      if (decision.write === false) return decision.result;
      if (decision.delete === true) {
        await remove(key);
        return decision.result;
      }
      if (!hasOwn(decision, "value")) {
        const error = new Error("atomicUpdate decision must contain value, delete, or write:false");
        error.code = "STORAGE_ATOMIC_UPDATE_INVALID";
        throw error;
      }
      await write(key, decision.value);
      return hasOwn(decision, "result") ? decision.result : decision.value;
    } finally {
      await release();
    }
  }

  async function list(prefix = "") {
    let entries;
    try {
      entries = await fs.readdir(base, { withFileTypes: true });
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      throw error;
    }
    const out = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
      try {
        const key = Buffer.from(entry.name.slice(0, -5), "base64url").toString("utf8");
        if (key.startsWith(String(prefix))) out.push(key);
      } catch {
        // Ignore unrelated or malformed files in the storage directory.
      }
    }
    return out.sort();
  }

  return Object.freeze({ read, write, remove, list, atomicUpdate });
}
