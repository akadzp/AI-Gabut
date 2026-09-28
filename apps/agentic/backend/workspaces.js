import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const STATES = Object.freeze(["active", "archived"]);

function publicWorkspace(w) {
  return {
    id: w.id,
    ownerId: w.ownerId,
    name: w.name,
    provider: w.provider,
    connectionId: w.connectionId,
    repository: w.repository,
    branch: w.branch,
    context: w.context,
    currentFile: w.currentFile || null,
    state: w.state,
    createdAt: w.createdAt,
    updatedAt: w.updatedAt,
    lastContextRefreshAt: w.lastContextRefreshAt || null
  };
}

function requireText(value, code, message) {
  const x = String(value ?? "").trim();
  if (!x) throw new AgenticError(code, message);
  return x;
}

export function createWorkspaceService({ store, connections, providers = {} } = {}) {
  const registry = new Map(Object.entries(providers));

  function registerProvider(provider, adapter) {
    const id = requireText(provider, "INVALID_WORKSPACE_PROVIDER", "Workspace provider wajib diisi");
    if (!adapter || typeof adapter !== "object") {
      throw new AgenticError("INVALID_WORKSPACE_PROVIDER", `Adapter workspace ${id} tidak valid`);
    }
    registry.set(id, Object.freeze({ ...adapter }));
    return id;
  }

  async function raw(ownerId, id) {
    const w = await store.getWorkspace(ownerId, id);
    if (!w) throw new AgenticError("WORKSPACE_NOT_FOUND", "Workspace tidak ditemukan", 404);
    return w;
  }

  async function get(ownerId, id) {
    return publicWorkspace(await raw(ownerId, id));
  }

  async function list(ownerId) {
    return (await store.listWorkspaces(ownerId)).map(publicWorkspace);
  }

  async function create(ownerId, input = {}) {
    const provider = requireText(input.provider, "INVALID_WORKSPACE_PROVIDER", "Workspace provider wajib diisi");
    const connectionId = requireText(input.connectionId, "INVALID_WORKSPACE_CONNECTION", "Workspace connection wajib diisi");
    const repository = input.repository || {};
    const owner = requireText(repository.owner, "INVALID_WORKSPACE_REPOSITORY", "Repository owner wajib diisi");
    const name = requireText(repository.name, "INVALID_WORKSPACE_REPOSITORY", "Repository name wajib diisi");
    const branch = requireText(input.branch, "INVALID_WORKSPACE_BRANCH", "Workspace branch wajib diisi");

    const connection = await connections.raw(ownerId, connectionId);
    if (connection.provider !== provider) {
      throw new AgenticError("WORKSPACE_PROVIDER_MISMATCH", "Provider workspace tidak sesuai dengan connection", 409);
    }
    if (connection.status !== "active") {
      throw new AgenticError("CONNECTION_INACTIVE", "Connection workspace tidak aktif", 409);
    }

    const adapter = registry.get(provider);
    const now = new Date().toISOString();
    let metadata = input.context || {};
    if (typeof adapter?.repositoryContext === "function") {
      metadata = await adapter.repositoryContext({ ownerId, connection, owner, name, branch, context: metadata });
    }

    const workspace = {
      id: input.id || createId("workspace"),
      name: String(input.name || `${owner}/${name}`).trim().slice(0, 160),
      provider,
      connectionId,
      repository: {
        owner,
        name,
        fullName: repository.fullName || `${owner}/${name}`,
        id: repository.id || null,
        defaultBranch: repository.defaultBranch || null,
        metadata: repository.metadata || null
      },
      branch,
      context: metadata,
      currentFile: input.currentFile || null,
      state: "active",
      createdAt: now,
      updatedAt: now,
      lastContextRefreshAt: now
    };
    await store.putWorkspace(ownerId, workspace);
    return publicWorkspace({ ...workspace, ownerId });
  }

  async function patch(ownerId, id, patch = {}) {
    const current = await raw(ownerId, id);
    const next = { ...current };

    if (patch.name != null) next.name = String(patch.name).trim().slice(0, 160);
    if (patch.currentFile !== undefined) next.currentFile = patch.currentFile || null;
    if (patch.context !== undefined) next.context = patch.context || {};
    if (patch.branch != null) next.branch = requireText(patch.branch, "INVALID_WORKSPACE_BRANCH", "Workspace branch wajib diisi");
    if (patch.state != null) {
      if (!STATES.includes(patch.state)) throw new AgenticError("INVALID_WORKSPACE_STATE", "State workspace tidak valid");
      next.state = patch.state;
    }
    next.updatedAt = new Date().toISOString();
    await store.putWorkspace(ownerId, next, { overwrite: true });
    return publicWorkspace(next);
  }

  async function refresh(ownerId, id) {
    const current = await raw(ownerId, id);
    const adapter = registry.get(current.provider);
    if (typeof adapter?.repositoryContext !== "function") {
      throw new AgenticError("WORKSPACE_REFRESH_UNSUPPORTED", `Provider ${current.provider} belum menyediakan context refresh`, 409);
    }
    const connection = await connections.raw(ownerId, current.connectionId);
    if (connection.status !== "active") throw new AgenticError("CONNECTION_INACTIVE", "Connection workspace tidak aktif", 409);
    const metadata = await adapter.repositoryContext({
      ownerId,
      connection,
      owner: current.repository.owner,
      name: current.repository.name,
      branch: current.branch,
      context: current.context
    });
    const next = { ...current, context: metadata, lastContextRefreshAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    await store.putWorkspace(ownerId, next, { overwrite: true });
    return publicWorkspace(next);
  }

  async function setCurrentFile(ownerId, id, file) {
    await raw(ownerId, id);
    return patch(ownerId, id, { currentFile: file || null });
  }

  async function archive(ownerId, id) {
    return patch(ownerId, id, { state: "archived" });
  }

  async function restore(ownerId, id) {
    return patch(ownerId, id, { state: "active" });
  }

  async function context(ownerId, id) {
    const w = await raw(ownerId, id);
    return {
      workspaceId: w.id,
      provider: w.provider,
      connectionId: w.connectionId,
      repository: w.repository,
      branch: w.branch,
      context: w.context,
      currentFile: w.currentFile || null
    };
  }

  return Object.freeze({ states: STATES, registerProvider, create, get, list, patch, refresh, setCurrentFile, archive, restore, context, raw });
}
