import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const now = () => new Date().toISOString();
const clean = (v, max = 4000) => String(v ?? "").trim().slice(0, max);
const hash = value => createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
function relativePath(value) {
  const input = String(value ?? "").replaceAll("\\", "/").trim();
  if (!input || input.length > 1000 || input.startsWith("/") || /^[a-zA-Z]:/.test(input) || input.split("/").some(part => part === ".." || part === "")) {
    throw new AgenticError("INVALID_CHANGE_PATH", "Path change harus relatif dan tidak boleh keluar dari workspace", 400);
  }
  return input;
}
function resolveInside(root, relative) {
  const base = path.resolve(root);
  const target = path.resolve(base, relative);
  if (target !== base && !target.startsWith(`${base}${path.sep}`)) throw new AgenticError("INVALID_CHANGE_PATH", "Path berada di luar workspace", 400);
  return target;
}
function publicChange(change) {
  const { _storage, ...safe } = change;
  return { ...safe, files: (change.files || []).map(file => ({ ...file })) };
}

export function createWorkChangeService({ store, work, workspace } = {}) {
  if (!store?.putChange || !store?.getChange || !store?.listChanges || !work?.raw || !work?.get) throw new TypeError("Work change service membutuhkan store dan work contract");
  async function raw(ownerId, id) {
    const item = await store.getChange(ownerId, id);
    if (!item || item.ownerId !== ownerId) throw new AgenticError("CHANGE_NOT_FOUND", "Change tidak ditemukan", 404);
    return item;
  }
  async function get(ownerId, id) { return publicChange(await raw(ownerId, id)); }
  async function list(ownerId, filters = {}) {
    let items = await store.listChanges(ownerId);
    if (filters.workId) items = items.filter(item => item.workId === filters.workId);
    if (filters.workspaceId) items = items.filter(item => item.workspaceId === filters.workspaceId);
    return items.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt))).map(publicChange);
  }
  async function create(ownerId, workId, input = {}) {
    const linkedWork = await work.raw(ownerId, workId);
    const title = clean(input.title || input.name || "Work change", 240);
    const summary = clean(input.summary || input.description || "", 4000);
    const timestamp = now();
    const item = { id: input.id || createId("change"), ownerId, workId, workspaceId: linkedWork.workspaceId || input.workspaceId || null, title, summary, status: "open", files: [], review: null, createdAt: timestamp, updatedAt: timestamp, closedAt: null };
    await store.putChange(ownerId, item, { overwrite: false });
    await work.attachReference(ownerId, workId, "change", item.id);
    return publicChange(item);
  }
  async function capture(ownerId, changeId, requestedPath) {
    const current = await raw(ownerId, changeId);
    if (current.status !== "open") throw new AgenticError("CHANGE_NOT_OPEN", "Change tidak terbuka untuk diedit", 409);
    const relative = relativePath(requestedPath);
    const linkedWork = await work.raw(ownerId, current.workId);
    const workspaceId = current.workspaceId || linkedWork.workspaceId;
    const ws = workspaceId && workspace?.get ? await workspace.get(ownerId, workspaceId) : null;
    if (!ws?.rootPath) throw new AgenticError("WORKSPACE_ROOT_REQUIRED", "Capture file membutuhkan workspace dengan rootPath lokal", 409);
    const filePath = resolveInside(ws.rootPath, relative);
    let content;
    try { content = await fs.readFile(filePath, "utf8"); }
    catch (error) {
      if (error?.code === "ENOENT") throw new AgenticError("CHANGE_FILE_NOT_FOUND", "File yang akan dicapture tidak ditemukan", 404);
      throw error;
    }
    if (Buffer.byteLength(content, "utf8") > 250_000) throw new AgenticError("CHANGE_FILE_TOO_LARGE", "File melebihi batas capture 250 KB", 413);
    const files = [...(current.files || [])];
    const existingIndex = files.findIndex(file => file.path === relative);
    const existing = existingIndex >= 0 ? files[existingIndex] : null;
    const record = { path: relative, before: content, after: existing?.after ?? content, beforeHash: hash(content), afterHash: hash(existing?.after ?? content), capturedAt: now(), status: "captured" };
    if (existingIndex >= 0) files[existingIndex] = record; else files.push(record);
    const next = { ...current, files, updatedAt: now() };
    await store.putChange(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return { change: publicChange(next), file: { path: relative, size: Buffer.byteLength(content, "utf8"), sha256: record.beforeHash } };
  }
  async function edit(ownerId, changeId, input = {}) {
    const current = await raw(ownerId, changeId);
    if (current.status !== "open") throw new AgenticError("CHANGE_NOT_OPEN", "Change tidak terbuka untuk diedit", 409);
    const relative = relativePath(input.path);
    if (typeof input.content !== "string") throw new AgenticError("CHANGE_CONTENT_REQUIRED", "Content baru harus berupa string", 400);
    if (Buffer.byteLength(input.content, "utf8") > 250_000) throw new AgenticError("CHANGE_FILE_TOO_LARGE", "Content melebihi batas 250 KB", 413);
    const files = [...(current.files || [])];
    const index = files.findIndex(file => file.path === relative);
    const prior = index >= 0 ? files[index] : { path: relative, before: null, beforeHash: null, capturedAt: null, status: "created" };
    const nextFile = { ...prior, path: relative, after: input.content, afterHash: hash(input.content), status: prior.before == null ? "created" : "modified", editedAt: now() };
    if (index >= 0) files[index] = nextFile; else files.push(nextFile);
    const next = { ...current, files, review: null, updatedAt: now() };
    await store.putChange(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicChange(next);
  }
  async function review(ownerId, changeId, input = {}) {
    const current = await raw(ownerId, changeId);
    if (current.status !== "open") throw new AgenticError("CHANGE_NOT_OPEN", "Change tidak terbuka untuk review", 409);
    const issues = [];
    for (const file of current.files || []) {
      try { relativePath(file.path); } catch { issues.push({ code: "INVALID_PATH", path: clean(file.path, 1000) }); }
      if (typeof file.after !== "string" && file.after !== null) issues.push({ code: "INVALID_CONTENT", path: clean(file.path, 1000) });
      if (file.afterHash && file.afterHash !== hash(file.after)) issues.push({ code: "CONTENT_HASH_MISMATCH", path: clean(file.path, 1000) });
    }
    const review = { status: issues.length ? "changes_requested" : "approved", reviewer: clean(input.reviewer || "owner", 120), comment: clean(input.comment || "", 2000), issues, reviewedAt: now(), fileCount: (current.files || []).length };
    const next = { ...current, review, updatedAt: now() };
    await store.putChange(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return { change: publicChange(next), review };
  }
  async function rollback(ownerId, changeId, requestedPath = null) {
    const current = await raw(ownerId, changeId);
    if (current.status !== "open") throw new AgenticError("CHANGE_NOT_OPEN", "Change tidak terbuka untuk rollback", 409);
    const relative = requestedPath == null ? null : relativePath(requestedPath);
    let changed = false;
    const files = (current.files || []).map(file => {
      if (relative && file.path !== relative) return file;
      changed = true;
      return { ...file, after: file.before, afterHash: file.beforeHash, status: "rolled_back", rolledBackAt: now() };
    });
    if (!changed) throw new AgenticError("CHANGE_FILE_NOT_FOUND", "File staged untuk rollback tidak ditemukan", 404);
    const next = { ...current, files, review: null, updatedAt: now() };
    await store.putChange(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return { change: publicChange(next), rolledBack: relative ? [relative] : files.map(file => file.path) };
  }
  async function close(ownerId, changeId, status = "completed") {
    const current = await raw(ownerId, changeId);
    if (current.status === "closed") return publicChange(current);
    if (current.status !== "open") throw new AgenticError("CHANGE_NOT_OPEN", "Change tidak terbuka", 409);
    const finalStatus = ["completed", "cancelled"].includes(status) ? status : "completed";
    const next = { ...current, status: "closed", outcome: finalStatus, closedAt: now(), updatedAt: now() };
    await store.putChange(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicChange(next);
  }
  return Object.freeze({ raw, get, list, create, capture, edit, review, rollback, close, relativePath });
}
