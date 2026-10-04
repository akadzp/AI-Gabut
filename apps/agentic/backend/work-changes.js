import crypto from "node:crypto";
import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";
import {
  readWorkspaceFile as defaultReadWorkspaceFile,
  writeWorkspaceFile as defaultWriteWorkspaceFile
} from "../../../core/workspace/manager.js";
import { workspaceChangeSystem } from "../../../core/workspace/change-system.js";

const TERMINAL = new Set(["completed", "aborted"]);
const MAX_HISTORY = 50;
const MAX_SNAPSHOT_BYTES = 250_000;
const now = () => new Date().toISOString();
const text = value => String(value ?? "").trim();
const sha256 = value => crypto.createHash("sha256").update(String(value), "utf8").digest("hex");

function safePath(value) {
  const path = text(value).replaceAll("\\", "/");
  if (!path || path.startsWith("/") || path.split("/").includes("..")) {
    throw new AgenticError("INVALID_CHANGE_PATH", "Path perubahan tidak valid");
  }
  return path;
}

function snapshot(file) {
  const size = Buffer.byteLength(file.content, "utf8");
  if (size > MAX_SNAPSHOT_BYTES) {
    throw new AgenticError("CHANGE_SNAPSHOT_TOO_LARGE", "Snapshot terlalu besar");
  }
  return {
    content: file.content,
    size,
    hash: sha256(file.content),
    capturedAt: now()
  };
}

function publicChange(record) {
  return {
    id: record.id,
    ownerId: record.ownerId,
    workId: record.workId,
    workspaceId: record.workspaceId,
    v2ChangeId: record.v2ChangeId,
    status: record.status,
    origin: record.origin,
    executionId: record.executionId || null,
    task: record.task,
    plan: record.plan || null,
    files: record.files || {},
    lastReview: record.lastReview || null,
    history: record.history || [],
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    closedAt: record.closedAt || null
  };
}

export function createWorkChangeService({
  store,
  work,
  workspace,
  changeSystem = workspaceChangeSystem,
  fileSystem = {
    read: defaultReadWorkspaceFile,
    write: defaultWriteWorkspaceFile
  }
} = {}) {
  if (!store?.putChange || !store?.getChange || !store?.listChanges) {
    throw new TypeError("Work change membutuhkan change store contract");
  }
  if (!work?.raw || !work?.attachReference || !workspace?.raw) {
    throw new TypeError("Work change membutuhkan work dan workspace contract");
  }
  if (typeof fileSystem?.read !== "function" || typeof fileSystem?.write !== "function") {
    throw new TypeError("Work change membutuhkan file-system contract");
  }

  async function raw(ownerId, id) {
    const record = await store.getChange(ownerId, id);
    if (!record) {
      throw new AgenticError("CHANGE_NOT_FOUND", "Change set tidak ditemukan", 404);
    }
    return record;
  }

  async function mutableWorkspace(ownerId, record) {
    const boundWorkspace = await workspace.raw(ownerId, record.workspaceId);
    if (boundWorkspace.state !== "active") {
      throw new AgenticError("WORKSPACE_INACTIVE", "Workspace tidak aktif", 409);
    }
    return boundWorkspace;
  }

  async function foundation(record) {
    const change = await changeSystem.get(record.v2ChangeId);
    if (!change) {
      throw new AgenticError("V2_CHANGE_NOT_FOUND", "V2 Change foundation tidak ditemukan", 409);
    }
    return change;
  }

  async function save(ownerId, record) {
    record.updatedAt = now();
    return store.putChange(ownerId, record, {
      overwrite: true,
      expectedVersion: record._storage?.version
    });
  }

  async function create(ownerId, workId, input = {}) {
    const currentWork = await work.raw(ownerId, workId);
    if (!currentWork.workspaceId) {
      throw new AgenticError("WORKSPACE_REQUIRED", "Work harus terikat ke workspace", 409);
    }
    const boundWorkspace = await workspace.raw(ownerId, currentWork.workspaceId);
    if (boundWorkspace.state !== "active") {
      throw new AgenticError("WORKSPACE_INACTIVE", "Workspace tidak aktif", 409);
    }

    const task = text(input.task || currentWork.objective).slice(0, 12000);
    if (!task) throw new AgenticError("INVALID_CHANGE_TASK", "Change task wajib diisi");

    const v2 = await changeSystem.create({
      task,
      paths: Array.isArray(input.paths) ? input.paths : [],
      symbols: Array.isArray(input.symbols) ? input.symbols : [],
      depth: input.depth,
      refresh: Boolean(input.refresh)
    });

    const at = now();
    const record = {
      id: input.id || createId("change"),
      ownerId,
      workId,
      workspaceId: boundWorkspace.id,
      v2ChangeId: v2.id,
      status: v2.status,
      origin: input.origin === "human" ? "human" : "agent",
      executionId: input.executionId || null,
      task,
      plan: v2.plan,
      files: {},
      lastReview: null,
      history: [{ at, action: "planned" }],
      createdAt: at,
      updatedAt: at,
      closedAt: null
    };

    await store.putChange(ownerId, record, { overwrite: false });
    await work.attachReference(ownerId, workId, "change", record.id);
    return publicChange(record);
  }

  async function get(ownerId, id) {
    const record = await raw(ownerId, id);
    const v2 = await foundation(record);
    return { ...publicChange(record), plan: v2.plan || record.plan };
  }

  async function list(ownerId, options = {}) {
    let records = await store.listChanges(ownerId);
    if (options.workId) records = records.filter(item => item.workId === options.workId);
    if (options.workspaceId) records = records.filter(item => item.workspaceId === options.workspaceId);
    return records
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)))
      .map(publicChange);
  }

  async function capture(ownerId, id, relativePath) {
    const record = await raw(ownerId, id);
    await mutableWorkspace(ownerId, record);
    if (TERMINAL.has(record.status)) {
      throw new AgenticError("CHANGE_TERMINAL", "Change set terminal", 409);
    }

    const path = safePath(relativePath);
    const file = await fileSystem.read(path);
    const snap = snapshot(file);

    await changeSystem.capture(record.v2ChangeId, path);

    record.files[path] = {
      ...(record.files[path] || {}),
      path,
      baselineHash: snap.hash,
      baselineSize: snap.size,
      snapshot: snap.content,
      capturedAt: snap.capturedAt
    };
    if (record.status === "planned") record.status = "prepared";
    record.history = [
      ...(record.history || []),
      { at: now(), action: "captured", path, hash: snap.hash }
    ].slice(-MAX_HISTORY);
    await save(ownerId, record);

    return {
      path,
      baselineHash: snap.hash,
      baselineSize: snap.size,
      capturedAt: snap.capturedAt
    };
  }

  async function edit(ownerId, id, input = {}) {
    const record = await raw(ownerId, id);
    await mutableWorkspace(ownerId, record);
    if (TERMINAL.has(record.status)) {
      throw new AgenticError("CHANGE_TERMINAL", "Change set terminal", 409);
    }

    const path = safePath(input.path);
    const baseline = record.files[path] || await capture(ownerId, id, path);

    const result = await changeSystem.edit(record.v2ChangeId, {
      ...input,
      path,
      expectedHash: input.expectedHash || baseline.baselineHash
    });
    if (!result.ok) return result;

    record.files[path] = {
      ...baseline,
      lastEdit: {
        operation: result.operation,
        replacements: result.replacements,
        beforeHash: result.beforeHash,
        afterHash: result.afterHash,
        editedAt: now()
      }
    };
    record.status = "changed";
    record.history = [
      ...(record.history || []),
      { at: now(), action: "edited", path, afterHash: result.afterHash }
    ].slice(-MAX_HISTORY);
    await save(ownerId, record);
    return result;
  }

  async function review(ownerId, id, options = {}) {
    const record = await raw(ownerId, id);
    if (TERMINAL.has(record.status)) {
      throw new AgenticError("CHANGE_TERMINAL", "Change set terminal", 409);
    }
    const result = await changeSystem.review(record.v2ChangeId, options);
    record.lastReview = { at: now(), result };
    record.history = [...(record.history || []), { at: now(), action: "reviewed" }]
      .slice(-MAX_HISTORY);
    await save(ownerId, record);
    return result;
  }

  async function rollback(ownerId, id, relativePath) {
    const record = await raw(ownerId, id);
    await mutableWorkspace(ownerId, record);
    if (TERMINAL.has(record.status)) {
      throw new AgenticError("CHANGE_TERMINAL", "Change set terminal", 409);
    }

    const path = safePath(relativePath);
    const entry = record.files[path];
    if (!entry?.snapshot || !entry?.baselineHash) {
      throw new AgenticError("CHANGE_SNAPSHOT_MISSING", "Snapshot rollback tidak tersedia", 409);
    }

    const current = await fileSystem.read(path);
    const expectedCurrentHash = entry.lastEdit?.afterHash || entry.baselineHash;
    const currentHash = sha256(current.content);
    if (currentHash !== expectedCurrentHash) {
      throw new AgenticError(
        "ROLLBACK_CONFLICT",
        "File berubah setelah Change terakhir; rollback dibatalkan",
        409,
        { path, expectedCurrentHash, currentHash }
      );
    }

    await fileSystem.write(path, entry.snapshot);
    const restoredHash = sha256(entry.snapshot);
    if (restoredHash !== entry.baselineHash) {
      throw new AgenticError("ROLLBACK_INTEGRITY_FAILED", "Hash snapshot rollback tidak cocok");
    }

    entry.lastRollback = { restoredHash, rolledBackAt: now() };
    record.status = "prepared";
    record.history = [
      ...(record.history || []),
      { at: now(), action: "rolled_back", path, restoredHash }
    ].slice(-MAX_HISTORY);
    await save(ownerId, record);

    return { ok: true, path, restoredHash, rolledBackAt: entry.lastRollback.rolledBackAt };
  }

  async function close(ownerId, id, status = "completed") {
    const record = await raw(ownerId, id);
    if (!TERMINAL.has(status)) {
      throw new AgenticError("INVALID_CHANGE_STATUS", "Status penutupan Change tidak valid");
    }
    if (TERMINAL.has(record.status)) return get(ownerId, id);

    await changeSystem.close(record.v2ChangeId, status);
    record.status = status;
    record.closedAt = now();
    record.history = [
      ...(record.history || []),
      { at: now(), action: status }
    ].slice(-MAX_HISTORY);
    await save(ownerId, record);
    return get(ownerId, id);
  }

  return Object.freeze({
    raw,
    get,
    list,
    create,
    capture,
    edit,
    review,
    rollback,
    close
  });
}
