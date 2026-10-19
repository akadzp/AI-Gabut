import { AgenticError } from "./errors.js";
import { createId, assertId } from "./ids.js";

const now = () => new Date().toISOString();
const clean = (value, max = 160) => String(value ?? "").trim().slice(0, max);
const publicConnection = record => {
  if (!record) return null;
  const { credential, secret, token, _storage, ...safe } = record;
  return { ...safe, credentialRef: record.credentialRef ? { ...record.credentialRef } : null };
};

export function createConnectionService({ store } = {}) {
  if (!store?.putConnection || !store?.getConnection || !store?.listConnections) throw new TypeError("Connection service membutuhkan connection store contract");
  const providers = new Map();
  function registerProvider(name, provider) {
    const key = clean(name, 80).toLowerCase();
    if (!key || !provider || typeof provider !== "object") throw new TypeError("Provider koneksi tidak valid");
    providers.set(key, provider);
    return () => providers.delete(key);
  }
  async function raw(ownerId, id) {
    assertId(ownerId, "ownerId"); assertId(id, "connectionId");
    const connection = await store.getConnection(ownerId, id);
    return connection?.ownerId === ownerId ? connection : null;
  }
  async function get(ownerId, id) {
    const connection = await raw(ownerId, id);
    if (!connection) throw new AgenticError("CONNECTION_NOT_FOUND", "Koneksi tidak ditemukan", 404);
    return publicConnection(connection);
  }
  async function list(ownerId) {
    return (await store.listConnections(ownerId)).filter(item => item.ownerId === ownerId)
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt))).map(publicConnection);
  }
  async function create(ownerId, input = {}) {
    assertId(ownerId, "ownerId");
    const provider = clean(input.provider, 80).toLowerCase();
    const name = clean(input.name || provider, 120);
    if (!/^[a-z][a-z0-9_-]{0,79}$/.test(provider)) throw new AgenticError("INVALID_CONNECTION_PROVIDER", "Provider koneksi tidak valid", 400);
    if (!name) throw new AgenticError("INVALID_CONNECTION_NAME", "Nama koneksi wajib diisi", 400);
    const timestamp = now();
    const record = {
      id: input.id || createId("connection"), ownerId, provider, name,
      account: input.account && typeof input.account === "object" ? {
        login: clean(input.account.login, 160) || null,
        id: input.account.id == null ? null : String(input.account.id).slice(0, 120),
        avatarUrl: clean(input.account.avatarUrl, 2000) || null
      } : null,
      credentialRef: input.credentialRef && typeof input.credentialRef === "object" ? { ...input.credentialRef } : null,
      status: ["active", "inactive", "disconnected", "revoked"].includes(input.status) ? input.status : "inactive",
      health: null, createdAt: timestamp, updatedAt: timestamp, disconnectedAt: null, revokedAt: null
    };
    await store.putConnection(ownerId, record, { overwrite: false });
    return publicConnection(record);
  }
  async function validate(ownerId, id) {
    const connection = await raw(ownerId, id);
    if (!connection) throw new AgenticError("CONNECTION_NOT_FOUND", "Koneksi tidak ditemukan", 404);
    if (["revoked", "disconnected"].includes(connection.status)) throw new AgenticError("CONNECTION_INACTIVE", "Koneksi tidak aktif; hubungkan kembali terlebih dahulu", 409);
    const provider = providers.get(connection.provider);
    if (typeof provider?.validate !== "function") throw new AgenticError("CONNECTION_VALIDATION_UNSUPPORTED", "Provider tidak menyediakan validasi koneksi", 501);
    const result = await provider.validate(ownerId, { connection: publicConnection(connection) });
    const updated = { ...connection, ...(result?.patch || {}), status: result?.status || "active", validatedAt: now(), updatedAt: now() };
    await store.putConnection(ownerId, updated, { overwrite: true, expectedVersion: connection._storage?.version });
    return publicConnection(updated);
  }
  async function health(ownerId, id) {
    const connection = await raw(ownerId, id);
    if (!connection) throw new AgenticError("CONNECTION_NOT_FOUND", "Koneksi tidak ditemukan", 404);
    const provider = providers.get(connection.provider);
    if (typeof provider?.health !== "function") return { status: "unknown", checkedAt: now(), reason: "Provider tidak menyediakan health check" };
    const result = await provider.health(ownerId, { connection: publicConnection(connection), credential: null });
    const health = result?.health || result || { status: "unknown" };
    const updated = { ...connection, health, healthCheckedAt: now(), updatedAt: now() };
    await store.putConnection(ownerId, updated, { overwrite: true, expectedVersion: connection._storage?.version });
    return health;
  }
  async function disconnect(ownerId, id) {
    const connection = await raw(ownerId, id);
    if (!connection) throw new AgenticError("CONNECTION_NOT_FOUND", "Koneksi tidak ditemukan", 404);
    if (connection.status === "revoked") return publicConnection(connection);
    const updated = { ...connection, status: "disconnected", disconnectedAt: now(), updatedAt: now() };
    await store.putConnection(ownerId, updated, { overwrite: true, expectedVersion: connection._storage?.version });
    return publicConnection(updated);
  }
  async function revoke(ownerId, id) {
    const connection = await raw(ownerId, id);
    if (!connection) throw new AgenticError("CONNECTION_NOT_FOUND", "Koneksi tidak ditemukan", 404);
    const provider = providers.get(connection.provider);
    if (typeof provider?.revoke === "function") await provider.revoke(ownerId, id);
    else if (store.listConnectionCredentials && store.putConnectionCredential) {
      for (const credential of (await store.listConnectionCredentials(ownerId)).filter(item => item.connectionId === id && !item.revokedAt)) {
        await store.putConnectionCredential(ownerId, { ...credential, ciphertext: "", revokedAt: now(), updatedAt: now() }, { overwrite: true, expectedVersion: credential._storage?.version });
      }
    }
    const updated = { ...connection, credentialRef: null, status: "revoked", revokedAt: now(), updatedAt: now() };
    await store.putConnection(ownerId, updated, { overwrite: true, expectedVersion: connection._storage?.version });
    return publicConnection(updated);
  }
  return Object.freeze({ registerProvider, raw, get, list, create, validate, health, disconnect, revoke });
}
