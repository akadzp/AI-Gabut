import crypto from "node:crypto";
import { createStateService } from "../storage/state/index.js";
import { SYNC_ERRORS, SyncError } from "./errors.js";
import { SYNC_STATES, assertState, normalizeSnapshot, normalizeSyncId } from "./contracts.js";
import { diffSnapshots } from "./diff.js";
import { planReconciliation, applyReconciliationPlan } from "./reconcile.js";

const SCOPE = "syncs";
const MAX_HISTORY = 50;
const now = () => new Date().toISOString();

function history(record, action, meta = {}) {
  return [...(record.history || []), { at: now(), action, ...meta }].slice(-MAX_HISTORY);
}

export function createSyncManager({ stateService = null, adapter = null } = {}) {
  const state = stateService || createStateService({ namespace: "sync", scopes: [SCOPE] });
  const get = syncId => state.get(SCOPE, normalizeSyncId(syncId));
  const save = (record, options = {}) => state.put(SCOPE, record.id, record, options);

  async function create({ name = "sync", source, target, strategy = "manual", metadata = {} } = {}) {
    if (!source || !target) throw new SyncError(SYNC_ERRORS.VALIDATION, "source dan target wajib diisi");
    const record = {
      id: `sync-${crypto.randomUUID()}`, type: "sync", name: String(name).slice(0, 200),
      source, target, strategy, metadata, status: "idle", createdAt: now(), updatedAt: now(),
      history: [{ at: now(), action: "created" }]
    };
    return save(record, { overwrite: false });
  }

  async function capture(syncId, side, snapshot) {
    const record = await get(syncId);
    if (!record) throw new SyncError(SYNC_ERRORS.NOT_FOUND, "Sync tidak ditemukan");
    if (!["base", "local", "remote"].includes(side)) throw new SyncError(SYNC_ERRORS.VALIDATION, "Side snapshot tidak valid");
    const normalized = normalizeSnapshot(snapshot);
    record.snapshots = { ...(record.snapshots || {}), [side]: normalized };
    record.updatedAt = now(); record.history = history(record, "snapshot-captured", { side });
    return save(record, { expectedVersion: record._storage?.version });
  }

  async function inspect(syncId) {
    const record = await get(syncId);
    if (!record) throw new SyncError(SYNC_ERRORS.NOT_FOUND, "Sync tidak ditemukan");
    const snapshots = record.snapshots || {};
    if (!snapshots.base || !snapshots.remote) throw new SyncError(SYNC_ERRORS.VALIDATION, "Base dan remote snapshot diperlukan");
    const diff = diffSnapshots(snapshots.base, snapshots.remote);
    record.lastDiff = diff; record.status = diff.counts.conflict ? "conflicted" : "planned";
    record.updatedAt = now(); record.history = history(record, "inspected");
    await save(record, { expectedVersion: record._storage?.version });
    return diff;
  }

  async function plan(syncId, { strategy = null } = {}) {
    const record = await get(syncId);
    if (!record) throw new SyncError(SYNC_ERRORS.NOT_FOUND, "Sync tidak ditemukan");
    const snapshots = record.snapshots || {};
    if (!snapshots.base || !snapshots.local || !snapshots.remote) throw new SyncError(SYNC_ERRORS.VALIDATION, "Base, local, dan remote snapshot diperlukan");
    const plan = planReconciliation({ base: snapshots.base, local: snapshots.local, remote: snapshots.remote, strategy: strategy || record.strategy });
    record.lastPlan = plan; record.status = plan.conflicts.length ? "conflicted" : "planned";
    record.updatedAt = now(); record.history = history(record, "reconciliation-planned", { conflicts: plan.conflicts.length });
    await save(record, { expectedVersion: record._storage?.version });
    return plan;
  }

  async function apply(syncId, { plan: suppliedPlan = null, readOnly = false } = {}) {
  let record = await get(syncId);
  if (!record) throw new SyncError(SYNC_ERRORS.NOT_FOUND, "Sync tidak ditemukan");

  const plan = suppliedPlan || record.lastPlan;
  if (!plan) throw new SyncError(SYNC_ERRORS.VALIDATION, "Reconciliation plan belum tersedia");
  if (record.status === "applying") {
    throw new SyncError(SYNC_ERRORS.INVALID_STATE, "Sync sedang applying");
  }

  record.status = "applying";
  record.updatedAt = now();

  record = await save(record, {
    expectedVersion: record._storage?.version
  });

  try {
    const result = applyReconciliationPlan(plan, {
      readOnly,
      apply: adapter?.apply
    });

    record.lastResult = result;
    record.status = result.ok ? "completed" : "conflicted";
    record.updatedAt = now();
    record.history = history(
      record,
      result.ok ? "applied" : "blocked",
      { applied: result.applied?.length || 0 }
    );

    return await save(record, {
      expectedVersion: record._storage?.version
    });
  } catch (error) {
    record.status = "failed";
    record.error = error instanceof Error ? error.message : String(error);
    record.updatedAt = now();
    record.history = history(record, "failed");

    await save(record, {
      expectedVersion: record._storage?.version
    });

    throw new SyncError(
      SYNC_ERRORS.APPLY_FAILED,
      "Reconciliation apply gagal",
      { cause: record.error }
    );
  }
}

  async function refresh(syncId, { base, local, remote } = {}) {
    const record = await get(syncId);
    if (!record) throw new SyncError(SYNC_ERRORS.NOT_FOUND, "Sync tidak ditemukan");
    if (!adapter?.snapshot) throw new SyncError(SYNC_ERRORS.ADAPTER, "Adapter snapshot belum dikonfigurasi");
    const snapshots = await adapter.snapshot({ sync: record, base, local, remote });
    for (const [side, snapshot] of Object.entries(snapshots || {})) {
      if (["base", "local", "remote"].includes(side)) record.snapshots = { ...(record.snapshots || {}), [side]: normalizeSnapshot(snapshot) };
    }
    record.updatedAt = now(); record.history = history(record, "refreshed");
    return save(record, { expectedVersion: record._storage?.version });
  }

  async function close(syncId, status = "completed") {
    const record = await get(syncId);
    if (!record) throw new SyncError(SYNC_ERRORS.NOT_FOUND, "Sync tidak ditemukan");
    assertState(["completed", "failed"], status, "Sync close");
    record.status = status; record.closedAt = now(); record.updatedAt = now(); record.history = history(record, status);
    return save(record, { expectedVersion: record._storage?.version });
  }

  async function list() { return state.list(SCOPE); }

  return Object.freeze({ create, get, capture, inspect, plan, apply, refresh, close, list });
}

export const syncManager = createSyncManager();
