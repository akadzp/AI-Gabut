import path from "node:path";
import { AgenticError } from "./errors.js";
import { createId, assertId } from "./ids.js";

const now = () => new Date().toISOString();
const clean = (v, max = 240) => String(v ?? "").trim().slice(0, max);
function safeRelativeFile(value) {
  if (value == null || value === "") return null;
  const input = String(value).replaceAll("\\", "/");
  if (input.startsWith("/") || /^[a-zA-Z]:/.test(input) || input.split("/").some(part => part === ".." || part === "")) {
    throw new AgenticError("INVALID_WORKSPACE_PATH", "Path file harus relatif dan tidak boleh keluar dari workspace", 400);
  }
  return input.slice(0, 1000);
}
function publicWorkspace(item) {
  if (!item) return null;
  const { _storage, ...safe } = item;
  return { ...safe, repository: item.repository ? { ...item.repository } : null, context: item.context && typeof item.context === "object" ? { ...item.context } : {} };
}

export function createWorkspaceService({ store, connections } = {}) {
  if (!store?.putWorkspace || !store?.getWorkspace || !store?.listWorkspaces) throw new TypeError("Workspace service membutuhkan workspace store contract");
  const providers = new Map();
  function registerProvider(name, provider) {
    const key = clean(name, 80).toLowerCase();
    if (!key || !provider || typeof provider !== "object") throw new TypeError("Provider workspace tidak valid");
    providers.set(key, provider);
    return () => providers.delete(key);
  }
  async function raw(ownerId, id) {
    assertId(ownerId, "ownerId"); assertId(id, "workspaceId");
    const item = await store.getWorkspace(ownerId, id);
    return item?.ownerId === ownerId ? item : null;
  }
  async function get(ownerId, id) {
    const item = await raw(ownerId, id);
    if (!item) throw new AgenticError("WORKSPACE_NOT_FOUND", "Workspace tidak ditemukan", 404);
    return publicWorkspace(item);
  }
  async function list(ownerId) {
    return (await store.listWorkspaces(ownerId)).filter(item => item.ownerId === ownerId)
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt))).map(publicWorkspace);
  }
  async function create(ownerId, input = {}) {
    assertId(ownerId, "ownerId");
    const name = clean(input.name || input.title, 160);
    if (!name) throw new AgenticError("INVALID_WORKSPACE_NAME", "Nama workspace wajib diisi", 400);
    const provider = clean(input.provider || (input.connectionId ? "github" : "local"), 80).toLowerCase();
    const connectionId = input.connectionId ? assertId(input.connectionId, "connectionId") : null;
    if (connectionId) {
      if (!connections) throw new AgenticError("CONNECTION_SERVICE_UNAVAILABLE", "Connection service tidak tersedia", 503);
      const connection = await connections.raw(ownerId, connectionId);
      if (!connection || connection.status !== "active") throw new AgenticError("CONNECTION_NOT_FOUND", "Koneksi aktif tidak ditemukan", 404);
    }
    const repoInput = input.repository && typeof input.repository === "object" ? input.repository : {};
    const repository = repoInput.owner && repoInput.name ? {
      owner: clean(repoInput.owner, 160), name: clean(repoInput.name, 160),
      defaultBranch: clean(repoInput.defaultBranch || input.branch || "main", 200)
    } : null;
    if (provider === "github" && (!connectionId || !repository)) throw new AgenticError("GITHUB_WORKSPACE_REPOSITORY_REQUIRED", "Workspace GitHub membutuhkan koneksi dan repository", 400);
    const timestamp = now();
    const rootPath = input.rootPath ? path.resolve(String(input.rootPath)) : null;
    const workspace = {
      id: input.id || createId("workspace"), ownerId, name, provider, connectionId, repository,
      branch: clean(input.branch || repository?.defaultBranch || "main", 200), rootPath,
      currentFile: safeRelativeFile(input.currentFile || null), context: {}, status: "active",
      createdAt: timestamp, updatedAt: timestamp, archivedAt: null, refreshedAt: null
    };
    await store.putWorkspace(ownerId, workspace, { overwrite: false });
    return publicWorkspace(workspace);
  }
  async function patch(ownerId, id, changes = {}) {
    const current = await raw(ownerId, id);
    if (!current) throw new AgenticError("WORKSPACE_NOT_FOUND", "Workspace tidak ditemukan", 404);
    if (current.status === "archived") throw new AgenticError("WORKSPACE_ARCHIVED", "Workspace diarsipkan; restore terlebih dahulu", 409);
    const next = { ...current };
    if (changes.name !== undefined) {
      const name = clean(changes.name, 160);
      if (!name) throw new AgenticError("INVALID_WORKSPACE_NAME", "Nama workspace wajib diisi", 400);
      next.name = name;
    }
    if (changes.currentFile !== undefined) next.currentFile = safeRelativeFile(changes.currentFile);
    if (changes.branch !== undefined) {
      const branch = clean(changes.branch, 200);
      if (!branch || branch.startsWith("/") || branch.includes("..")) throw new AgenticError("INVALID_WORKSPACE_BRANCH", "Nama branch tidak valid", 400);
      next.branch = branch;
    }
    if (changes.context !== undefined) next.context = changes.context && typeof changes.context === "object" ? changes.context : {};
    next.updatedAt = now();
    await store.putWorkspace(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWorkspace(next);
  }
  async function setCurrentFile(ownerId, id, file) { return patch(ownerId, id, { currentFile: file }); }
  async function archive(ownerId, id) {
    const current = await raw(ownerId, id);
    if (!current) throw new AgenticError("WORKSPACE_NOT_FOUND", "Workspace tidak ditemukan", 404);
    if (current.status === "archived") return publicWorkspace(current);
    const next = { ...current, status: "archived", archivedAt: now(), updatedAt: now() };
    await store.putWorkspace(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWorkspace(next);
  }
  async function restore(ownerId, id) {
    const current = await raw(ownerId, id);
    if (!current) throw new AgenticError("WORKSPACE_NOT_FOUND", "Workspace tidak ditemukan", 404);
    const next = { ...current, status: "active", archivedAt: null, updatedAt: now() };
    await store.putWorkspace(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWorkspace(next);
  }
  async function refresh(ownerId, id) {
    const current = await raw(ownerId, id);
    if (!current) throw new AgenticError("WORKSPACE_NOT_FOUND", "Workspace tidak ditemukan", 404);
    if (current.status !== "active") throw new AgenticError("WORKSPACE_INACTIVE", "Workspace tidak aktif", 409);
    let context = current.context || {};
    if (current.provider !== "local") {
      const provider = providers.get(current.provider);
      if (typeof provider?.repositoryContext !== "function") throw new AgenticError("WORKSPACE_PROVIDER_UNAVAILABLE", "Provider workspace tidak menyediakan refresh", 501);
      context = await provider.repositoryContext(ownerId, {
        connection: { id: current.connectionId }, owner: current.repository.owner,
        name: current.repository.name, branch: current.branch
      });
    }
    const next = { ...current, context, refreshedAt: now(), updatedAt: now() };
    await store.putWorkspace(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
    return publicWorkspace(next);
  }
  async function context(ownerId, id) {
    const item = await get(ownerId, id);
    if (item.status !== "active") throw new AgenticError("WORKSPACE_INACTIVE", "Workspace tidak aktif", 409);
    return { id: item.id, name: item.name, provider: item.provider, repository: item.repository, branch: item.branch, rootPath: item.rootPath, currentFile: item.currentFile, context: item.context || {}, refreshedAt: item.refreshedAt || null };
  }
  return Object.freeze({ registerProvider, raw, get, list, create, patch, setCurrentFile, archive, restore, refresh, context, safeRelativeFile });
}
