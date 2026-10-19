import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

function runtime(initial, conflicts = 0) {
  let current = { ...initial };
  let conflictsRemaining = conflicts;
  let writes = 0;
  let emissions = 0;
  const store = {
    async getOwned(_scope, ownerId, id) {
      if (id !== current.id || ownerId !== current.ownerId) return null;
      return current;
    },
    async putOwned(_scope, ownerId, id, next, options = {}) {
      assert.equal(ownerId, current.ownerId);
      assert.equal(id, current.id);
      writes += 1;
      if (conflictsRemaining > 0) {
        conflictsRemaining -= 1;
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
    async event() { emissions += 1; throw new Error('REPAIR_MUST_NOT_EMIT'); },
    async snapshot(_ownerId, mission) { return mission; },
    emissions: () => emissions
  };
  return {
    store,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-09T00:00:00.000Z' }),
    observability
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 72 } };
const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
const method = 'repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus';
const conflictCode = 'MISSION_CONTROL_AUDIT_RECOVERY_EVIDENCE_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_VERSION_CONFLICT';
const intent = { reconciliationId: 'recon-71', createdAt: '2026-10-09T00:00:00.000Z', repairedByRetry: true };

 test('batch 73 clears only an orphaned durable error from Batch 69/70 recovery observability', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.valid, true);
  assert.equal(out.pending, false);
  assert.equal(out.error, null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(out.storageVersion, 73);
  assert.equal(r.store.writes(), 1);
  assert.equal(r.observability.emissions(), 0);
 });

test('batch 73 preserves valid pending intent and its error without replay or mutation', async () => {
  const r = runtime({ ...base, [pendingKey]: intent, [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.valid, true);
  assert.equal(out.pending, true);
  assert.equal(out.error, 'EVENT_DOWN');
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.observability.emissions(), 0);
 });

test('batch 73 fails closed and preserves malformed pending intent', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'], [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.deepEqual(out.issues.map(issue => issue.code), [
    'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID'
  ]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.observability.emissions(), 0);
 });

test('batch 73 is a no-op when recovery-observability state is clear', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.valid, true);
  assert.equal(out.pending, false);
  assert.equal(out.error, null);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.observability.emissions(), 0);
 });

test('batch 73 retries an optimistic-concurrency conflict against the latest version', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' }, 1);
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.repairedByRetry, true);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.writes(), 2);
  assert.equal(out.storageVersion, 74);
 });

test('batch 73 fails closed after bounded repeated version conflicts', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' }, 2);
  await assert.rejects(() => r.service[method]('u1', 'm1'), error => error.code === conflictCode && error.status === 409);
  assert.equal(r.store.current()[errorKey], 'EVENT_DOWN');
  assert.equal(r.store.writes(), 2);
  assert.equal(r.observability.emissions(), 0);
 });

test('batch 73 remains owner-scoped', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.observability.emissions(), 0);
 });
