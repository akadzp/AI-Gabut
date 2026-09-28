import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

export const CONNECTION_STATES = Object.freeze([
  "created",
  "authenticating",
  "active",
  "expired",
  "requires_reauth",
  "revoked",
  "disconnected"
]);

const TRANSITIONS = Object.freeze({
  created: new Set(["authenticating", "active", "revoked", "disconnected"]),
  authenticating: new Set(["active", "expired", "requires_reauth", "revoked", "disconnected"]),
  active: new Set(["expired", "requires_reauth", "revoked", "disconnected", "active"]),
  expired: new Set(["authenticating", "active", "revoked", "disconnected"]),
  requires_reauth: new Set(["authenticating", "active", "revoked", "disconnected"]),
  revoked: new Set([]),
  disconnected: new Set(["authenticating", "active"])
});

function now() {
  return new Date().toISOString();
}

function publicConnection(c) {
  return {
    id: c.id,
    provider: c.provider,
    name: c.name,
    account: c.account || null,
    status: c.status,
    credentialRef: c.credentialRef || { type: "provider-credential", id: c.id },
    capabilities: Array.isArray(c.capabilities) ? c.capabilities : [],
    health: c.health || null,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
    lastValidatedAt: c.lastValidatedAt || null
  };
}

function requireProvider(provider) {
  const value = String(provider || "").trim();
  if (!value) throw new AgenticError("INVALID_CONNECTION_PROVIDER", "Connection provider wajib diisi");
  return value;
}

export function createConnectionService({ store, providers = {} } = {}) {
  const registry = new Map(Object.entries(providers));

  function registerProvider(provider, adapter) {
    const id = requireProvider(provider);
    if (!adapter || typeof adapter !== "object") {
      throw new AgenticError("INVALID_CONNECTION_PROVIDER", `Adapter provider ${id} tidak valid`);
    }
    registry.set(id, Object.freeze({ ...adapter }));
    return id;
  }

  async function get(ownerId, id) {
    const c = await store.getConnection(ownerId, id);
    if (!c) throw new AgenticError("CONNECTION_NOT_FOUND", "Connection tidak ditemukan", 404);
    return publicConnection(c);
  }

  async function list(ownerId) {
    return (await store.listConnections(ownerId)).map(publicConnection);
  }

  async function raw(ownerId, id) {
    const c = await store.getConnection(ownerId, id);
    if (!c) throw new AgenticError("CONNECTION_NOT_FOUND", "Connection tidak ditemukan", 404);
    return c;
  }

  async function create(ownerId, input = {}) {
    const provider = requireProvider(input.provider);
    const status = input.status || "created";
    if (!CONNECTION_STATES.includes(status)) {
      throw new AgenticError("INVALID_CONNECTION_STATUS", `Status connection tidak dikenal: ${status}`);
    }
    const timestamp = now();
    const connectionId = input.id || createId("conn");
    const c = {
      id: connectionId,
      provider,
      name: String(input.name || provider).trim().slice(0, 120) || provider,
      account: input.account || null,
      credential: input.credential,
      credentialRef: input.credentialRef || { type: "provider-credential", id: connectionId },
      capabilities: Array.isArray(input.capabilities) ? [...input.capabilities] : [],
      health: input.health || null,
      status,
      createdAt: input.createdAt || timestamp,
      updatedAt: timestamp,
      lastValidatedAt: input.lastValidatedAt || null
    };
    await store.putConnection(ownerId, c);
    return publicConnection(c);
  }

  async function transition(ownerId, id, status, patch = {}) {
    if (!CONNECTION_STATES.includes(status)) {
      throw new AgenticError("INVALID_CONNECTION_STATUS", `Status connection tidak dikenal: ${status}`);
    }
    const current = await raw(ownerId, id);
    if (current.status !== status && !TRANSITIONS[current.status]?.has(status)) {
      throw new AgenticError(
        "INVALID_CONNECTION_TRANSITION",
        `Tidak dapat mengubah connection dari ${current.status} ke ${status}`,
        409,
        { from: current.status, to: status }
      );
    }
    const updated = { ...current, ...patch, id: current.id, provider: current.provider, status, updatedAt: now() };
    await store.putConnection(ownerId, updated, { overwrite: true });
    return publicConnection(updated);
  }

  async function validate(ownerId, id) {
    const current = await raw(ownerId, id);
    const adapter = registry.get(current.provider);
    if (typeof adapter?.validate !== "function") {
      throw new AgenticError("CONNECTION_VALIDATION_UNSUPPORTED", `Provider ${current.provider} belum menyediakan validation`, 409);
    }
    try {
      const result = await adapter.validate({ ownerId, connection: current });
      const status = result?.status || "active";
      const updated = {
        ...current,
        ...(result?.patch || {}),
        status,
        lastValidatedAt: now(),
        updatedAt: now()
      };
      await store.putConnection(ownerId, updated, { overwrite: true });
      return publicConnection(updated);
    } catch (error) {
      if (error instanceof AgenticError && [401, 403].includes(error.status)) {
        const updated = { ...current, status: "requires_reauth", lastValidatedAt: now(), updatedAt: now() };
        await store.putConnection(ownerId, updated, { overwrite: true });
        throw error;
      }
      throw error;
    }
  }

  async function health(ownerId, id) {
    const current = await raw(ownerId, id);
    const adapter = registry.get(current.provider);
    if (typeof adapter?.health !== "function") {
      throw new AgenticError("CONNECTION_HEALTH_UNSUPPORTED", `Provider ${current.provider} belum menyediakan health check`, 409);
    }
    const result = await adapter.health({ ownerId, connection: current });
    const healthState = result?.health || { status: "unknown", checkedAt: now() };
    const updated = { ...current, health: healthState, updatedAt: now() };
    await store.putConnection(ownerId, updated, { overwrite: true });
    return healthState;
  }

  async function disconnect(ownerId, id) {
    const current = await raw(ownerId, id);
    const adapter = registry.get(current.provider);
    if (typeof adapter?.disconnect === "function") {
      await adapter.disconnect({ ownerId, connection: current });
    }
    return transition(ownerId, id, "disconnected");
  }

  async function revoke(ownerId, id) {
    const current = await raw(ownerId, id);
    const adapter = registry.get(current.provider);
    if (typeof adapter?.revoke === "function") {
      await adapter.revoke({ ownerId, connection: current });
    }
    return transition(ownerId, id, "revoked");
  }

  return Object.freeze({
    states: CONNECTION_STATES,
    registerProvider,
    create,
    get,
    list,
    validate,
    health,
    disconnect,
    revoke,
    transition,
    publicConnection,
    raw
  });
}
