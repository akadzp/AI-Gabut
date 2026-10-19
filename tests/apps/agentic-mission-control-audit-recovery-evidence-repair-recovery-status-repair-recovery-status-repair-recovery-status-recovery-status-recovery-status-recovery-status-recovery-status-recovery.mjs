import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

function runtime(initial, { emit = null, conflictWrites = [] } = {}) {
  let current = { ...initial };
  const events = [];
  const conflicts = new Set(conflictWrites);
  let writes = 0;
  const store = {
    async getOwned(_scope, ownerId, id) {
      if (id !== current.id || ownerId !== current.ownerId) return null;
      return current;
    },
    async putOwned(_scope, ownerId, id, next, options = {}) {
      assert.equal(ownerId, current.ownerId);
      assert.equal(id, current.id);
      writes += 1;
      if (conflicts.has(writes)) {
        current = { ...current, _storage: { ...(current._storage || {}), version: (current._storage?.version || 0) + 1 } };
        throw Object.assign(new Error('VERSION_CONFLICT'), { code: 'VERSION_CONFLICT' });
      }
      assert.equal(options.expectedVersion, current._storage?.version);
      current = { ...next, _storage: { ...(next._storage || {}), version: (current._storage?.version || 0) + 1 } };
      return current;
    },
    current: () => current,
    writes: () => writes
  };
  const observability = {
    async event(...args) {
      events.push(args);
      return emit ? emit(args, events.length) : { ok: true };
    },
    async snapshot(_ownerId, mission) { return mission; }
  };
  return {
    store,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-10T00:00:00.000Z' }),
    events
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 79 } };
const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const eventType = 'mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
const dedupeKey = 'control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:m1';
const conflictCode = 'MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_VERSION_CONFLICT';
const pendingInvalid = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_PENDING_INVALID';
const errorWithoutPending = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING';
const intent = { reconciliationId: null, createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: false };

test('batch 80 emits the Batch 79 repair evidence and clears the durable intent', async () => {
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: null });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.attempted, true);
  assert.equal(out.recovered, true);
  assert.equal(out.phase, 'clear');
  assert.equal(out.observabilityEmitted, true);
  assert.equal(r.events.length, 1);
  assert.equal(r.events[0][2], eventType);
  assert.equal(r.events[0][3].dedupeKey, dedupeKey);
  assert.equal(r.events[0][3].reconciliationId, null);
  assert.equal(r.events[0][3].repairedByRetry, false);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.writes(), 1);
});

test('batch 80 stores a bounded emission error and retains the pending intent', async () => {
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: null }, { emit: async () => { throw new Error('E'.repeat(1200)); } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.pending, true);
  assert.equal(out.observabilityEmitted, false);
  assert.equal(out.error.length, 1000);
  assert.deepEqual(r.store.current()[pendingKey], intent);
  assert.equal(r.store.current()[errorKey].length, 1000);
  assert.equal(r.events.length, 1);
  assert.equal(r.store.writes(), 1);
});

test('batch 80 retries a persisted intent using the same dedupe key', async () => {
  let fail = true;
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: 'EVENT_DOWN' }, { emit: async () => { if (fail) { fail = false; throw new Error('EVENT_DOWN'); } } });
  const first = await r.service[method]('u1', 'm1');
  assert.equal(first.phase, 'pending');
  const second = await r.service[method]('u1', 'm1');
  assert.equal(second.recovered, true);
  assert.equal(second.phase, 'clear');
  assert.equal(r.events.length, 2);
  assert.equal(r.events[0][3].dedupeKey, r.events[1][3].dedupeKey);
  assert.equal(r.events[1][3].dedupeKey, dedupeKey);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.writes(), 2);
});

test('batch 80 rejects malformed pending metadata without mutation or emission', async () => {
  const r = runtime({ ...base, [pendingKey]: ['bad-intent'], [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.deepEqual(out.issues.map(issue => issue.code), [pendingInvalid]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 80 rejects an orphaned durable error marker', async () => {
  const r = runtime({ ...base, [pendingKey]: null, [errorKey]: 'ORPHANED_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'error');
  assert.equal(out.valid, false);
  assert.deepEqual(out.issues.map(issue => issue.code), [errorWithoutPending]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 80 is a read-only no-op when the durable state is clear', async () => {
  const r = runtime({ ...base, [pendingKey]: null, [errorKey]: null });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'clear');
  assert.equal(out.recovered, false);
  assert.equal(out.attempted, false);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 80 retries finalization version conflicts with deterministic deduplication', async () => {
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: null }, { conflictWrites: [1] });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(out.recoveredByRetry, true);
  assert.equal(out.phase, 'clear');
  assert.equal(r.events.length, 2);
  assert.equal(r.events[0][3].dedupeKey, dedupeKey);
  assert.equal(r.events[1][3].dedupeKey, dedupeKey);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.writes(), 2);
});

test('batch 80 stops after bounded repeated version conflicts and preserves intent', async () => {
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: null }, { conflictWrites: [1, 2] });
  await assert.rejects(() => r.service[method]('u1', 'm1'), error => error.code === conflictCode && error.status === 409);
  assert.deepEqual(r.store.current()[pendingKey], intent);
  assert.equal(r.store.writes(), 2);
  assert.equal(r.events.length, 2);
  assert.equal(r.events[0][3].dedupeKey, r.events[1][3].dedupeKey);
});

test('batch 80 retries after a conflict while persisting an emission error', async () => {
  let fail = true;
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: null }, { conflictWrites: [1], emit: async () => { if (fail) { fail = false; throw new Error('EVENT_DOWN'); } } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(out.recoveredByRetry, true);
  assert.equal(out.phase, 'clear');
  assert.equal(r.events.length, 2);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
});

test('batch 80 remains owner-scoped', async () => {
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: null });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});
