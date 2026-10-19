import { encryptSecret, decryptSecret } from "./crypto.js";
import { createId } from "./ids.js";
import { AgenticError } from "./errors.js";

export function createCredentialService({ store } = {}) {
  if (!store?.putConnectionCredential || !store?.getConnectionCredential || !store?.listConnectionCredentials) {
    throw new TypeError("Credential service membutuhkan connection credential store contract");
  }

  async function put(ownerId, { connectionId, provider, secret } = {}) {
    if (!ownerId || !connectionId || !provider || typeof secret !== "string" || !secret) {
      throw new AgenticError("INVALID_CREDENTIAL", "Owner, connection, provider, dan secret wajib diisi", 400);
    }
    const current = (await store.listConnectionCredentials(ownerId)).find(item => item.connectionId === connectionId && item.provider === provider && !item.revokedAt);
    const now = new Date().toISOString();
    const record = {
      id: current?.id || createId("credential"), ownerId, connectionId, provider,
      ciphertext: encryptSecret(secret), createdAt: current?.createdAt || now, updatedAt: now, revokedAt: null
    };
    await store.putConnectionCredential(ownerId, record, current ? { overwrite: true, expectedVersion: current._storage?.version } : { overwrite: false });
    return Object.freeze({ type: "provider-credential", id: record.id, provider, connectionId });
  }

  async function getForConnection(ownerId, connectionId) {
    const record = (await store.listConnectionCredentials(ownerId)).find(item => item.connectionId === connectionId && !item.revokedAt);
    if (!record) throw new AgenticError("CREDENTIAL_NOT_FOUND", "Credential untuk koneksi tidak ditemukan", 404);
    try { return decryptSecret(record.ciphertext); }
    catch (error) { throw new AgenticError(error.code || "CREDENTIAL_INVALID", error.message, 409); }
  }

  async function revokeForConnection(ownerId, connectionId) {
    const records = (await store.listConnectionCredentials(ownerId)).filter(item => item.connectionId === connectionId && !item.revokedAt);
    const now = new Date().toISOString();
    for (const record of records) {
      await store.putConnectionCredential(ownerId, { ...record, ciphertext: "", revokedAt: now, updatedAt: now }, { overwrite: true, expectedVersion: record._storage?.version });
    }
    return { revoked: records.length, connectionId };
  }

  return Object.freeze({ put, getForConnection, revokeForConnection });
}
