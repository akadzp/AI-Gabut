import crypto from "node:crypto";
import { createStateService } from "../storage/state/index.js";
import { readWorkspaceFile } from "./manager.js";
import { clearProjectIndex } from "./project-index.js";
import { planChange } from "./change-planner.js";
import { reviewChangeSet } from "./change-set-review.js";
import { safeEditFile } from "./safe-editor.js";

const CHANGE_SCOPE = "changes";
const MAX_HISTORY = 50;
function now() { return new Date().toISOString(); }
function assertId(value) { if (typeof value !== "string" || !value.trim()) throw new Error("changeId wajib diisi"); return value.trim(); }
function assertPath(value) { if (typeof value !== "string" || !value.trim()) throw new Error("path wajib diisi"); return value.trim().replaceAll("\\", "/"); }

export function createWorkspaceChangeSystem({ stateService = null } = {}) {
  const state = stateService || createStateService({ namespace: "workspace", scopes: [CHANGE_SCOPE] });
  async function save(record, options = {}) { return state.put(CHANGE_SCOPE, record.id, record, options); }
  async function get(changeId) { return state.get(CHANGE_SCOPE, assertId(changeId)); }

  async function create({ task, paths = [], symbols = [], depth, refresh = false } = {}) {
    const plan = await planChange({ task, paths, symbols, depth, refresh });
    const change = { id: `change-${crypto.randomUUID()}`, type: "workspace-change", status: "planned", createdAt: now(), updatedAt: now(), task: plan.task, plan, files: {}, history: [{ at: now(), action: "planned" }] };
    await save(change);
    return change;
  }

  async function capture(changeId, relativePath) {
    const change = await get(changeId); if (!change) throw new Error("Change set tidak ditemukan");
    const filePath = assertPath(relativePath); const file = await readWorkspaceFile(filePath);
    const hash = crypto.createHash("sha256").update(file.content, "utf8").digest("hex");
    change.files[filePath] = { ...(change.files[filePath] || {}), path: filePath, baselineHash: hash, baselineSize: file.size, capturedAt: now() };
    change.updatedAt = now(); change.status = change.status === "planned" ? "prepared" : change.status;
    change.history = [...(change.history || []), { at: now(), action: "captured", path: filePath }].slice(-MAX_HISTORY);
    await save(change, { expectedVersion: change._storage?.version }); return change.files[filePath];
  }

  async function edit(changeId, input = {}) {
    const change = await get(changeId); if (!change) throw new Error("Change set tidak ditemukan");
    const filePath = assertPath(input.path); const baseline = change.files[filePath] || await capture(changeId, filePath);
    const result = await safeEditFile({ ...input, path: filePath, expectedHash: input.expectedHash || baseline.baselineHash });
    if (result.ok) {
      change.files[filePath] = { ...baseline, lastEdit: { operation: result.operation, replacements: result.replacements, beforeHash: result.beforeHash, afterHash: result.afterHash, editedAt: now() } };
      change.status = "changed"; change.updatedAt = now();
      change.history = [...(change.history || []), { at: now(), action: "edited", path: filePath, afterHash: result.afterHash }].slice(-MAX_HISTORY);
      clearProjectIndex(); await save(change, { expectedVersion: change._storage?.version });
    }
    return result;
  }

  async function review(changeId, options = {}) {
    const change = await get(changeId); if (!change) throw new Error("Change set tidak ditemukan");
    const paths = Object.keys(change.files || {}); const result = await reviewChangeSet({ paths: paths.length ? paths : change.plan?.scope?.relatedFiles, ...options });
    change.lastReview = { at: now(), result }; change.updatedAt = now();
    change.history = [...(change.history || []), { at: now(), action: "reviewed" }].slice(-MAX_HISTORY);
    await save(change, { expectedVersion: change._storage?.version }); return result;
  }

  async function close(changeId, status = "completed") {
    const change = await get(changeId); if (!change) throw new Error("Change set tidak ditemukan");
    if (!["completed", "aborted"].includes(status)) throw new Error("Status penutupan tidak valid");
    change.status = status; change.updatedAt = now(); change.closedAt = now();
    change.history = [...(change.history || []), { at: now(), action: status }].slice(-MAX_HISTORY);
    await save(change, { expectedVersion: change._storage?.version }); return change;
  }
  async function list() { return state.list(CHANGE_SCOPE); }
  return Object.freeze({ create, get, capture, edit, review, close, list });
}

export const workspaceChangeSystem = createWorkspaceChangeSystem();
