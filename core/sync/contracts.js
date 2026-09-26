import { SyncError, SYNC_ERRORS } from "./errors.js";

export const SYNC_STATES = Object.freeze(["idle", "planned", "applying", "completed", "failed", "conflicted"]);
export const CHANGE_TYPES = Object.freeze(["create", "update", "delete", "unchanged", "conflict"]);

const HASH = /^[a-f0-9]{64}$/;

export function assertState(states, value, label) {
  if (!states.includes(value)) throw new SyncError(SYNC_ERRORS.INVALID_STATE, `${label} state tidak valid: ${value}`);
  return value;
}

export function normalizeSyncId(value) {
  if (typeof value !== "string" || !value.trim()) throw new SyncError(SYNC_ERRORS.VALIDATION, "Sync ID wajib diisi");
  return value.trim();
}

export function normalizeResourceKey(value) {
  if (typeof value !== "string" || !value.trim()) throw new SyncError(SYNC_ERRORS.VALIDATION, "Resource key wajib diisi");
  return value.trim().replaceAll("\\", "/");
}

export function hashContent(value) {
  return HASH.test(value) ? value : null;
}

export function normalizeSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new SyncError(SYNC_ERRORS.VALIDATION, "Snapshot harus berupa object");
  }
  const source = String(snapshot.source || "").trim();
  if (!source) throw new SyncError(SYNC_ERRORS.VALIDATION, "Snapshot source wajib diisi");
  const resources = {};
  for (const [rawKey, rawValue] of Object.entries(snapshot.resources || {})) {
    const key = normalizeResourceKey(rawKey);
    if (!rawValue || typeof rawValue !== "object") throw new SyncError(SYNC_ERRORS.VALIDATION, `Resource tidak valid: ${key}`);
    resources[key] = {
      key,
      hash: String(rawValue.hash || ""),
      value: rawValue.value ?? null,
      metadata: rawValue.metadata && typeof rawValue.metadata === "object" ? rawValue.metadata : {}
    };
  }
  return { source, version: String(snapshot.version || "1"), capturedAt: snapshot.capturedAt || new Date().toISOString(), resources };
}
