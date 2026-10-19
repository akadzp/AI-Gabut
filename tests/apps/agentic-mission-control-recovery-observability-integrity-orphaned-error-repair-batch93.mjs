import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

function runtime(initial, { conflicts = 0 } = {}) {
  let current = { ...initial };
  let writes = 0;
  let emissions = 0;
  let conflictsRemaining = conflicts;
  const store = {
    async getOwned(_scope, ownerId, id) {
      if (id !== current.id || ownerId !== current.ownerId) return null;
      return current;
    },
    async putOwned(_scope, ownerId, id, next, options = {}) {
      writes += 1;
      if (id !== current.id || ownerId !== current.ownerId) throw new Error('OWNER_SCOPE_MISMATCH');
      if (conflictsRemaining > 0) {
        conflictsRemaining -= 1;
        current = { ...current, _storage: { version: (current._storage?.version ?? 0) + 1 } };
        const error = new Error('VERSION_CONFLICT');
        error.code = 'VERSION_CONFLICT';
        throw error;
      }
      assert.equal(options.expectedVersion, current._storage?.version);
      current = { ...next, _storage: { version: (current._storage?.version ?? 0) + 1 } };
      return current;
    },
    current: () => current,
    writes: () => writes
  };
  const observability = {
    async event() { emissions += 1; throw new Error('ORPHAN_REPAIR_MUST_NOT_EMIT'); },
    async snapshot(_ownerId, mission) { return mission; }
  };
  return {
    store,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-10T00:00:00.000Z' }),
    emissions: () => emissions
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 92 } };
const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const verify = 'verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const orphanCode = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';
const pending = { reconciliationId: 'recon-92', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: false };

function assertNoEmission(r) {
  assert.equal(r.emissions(), 0);
}

test('batch 93 clears only the verified orphaned integrity error with a version-checked write', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' });
  const before = await r.service[verify]('u1', 'm1');
  assert.deepEqual(before.issues, [{ code: orphanCode }]);
  const out = await r.service[method]('u1', 'm1');
  assert.deepEqual(out, {
    missionId: 'm1', ownerId: 'u1', changed: true, repaired: true, valid: true,
    issues: [], pending: false, repairedByRetry: false, error: null, storageVersion: 93
  });
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.writes(), 1);
  assertNoEmission(r);
});

test('batch 93 is a no-op when the integrity observability state is already clear', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.valid, true);
  assert.deepEqual(out.issues, []);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 93 preserves pending intent and its associated error marker', async () => {
  const r = runtime({ ...base, [pendingKey]: pending, [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.valid, true);
  assert.equal(out.pending, true);
  assert.deepEqual(out.issues, []);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 93 fails closed and preserves malformed pending intent', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'], [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.ok(out.issues.some(issue => issue.code.endsWith('PENDING_INVALID')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 93 retries a version conflict against the latest state', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' }, { conflicts: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.repairedByRetry, true);
  assert.equal(out.storageVersion, 94);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.writes(), 2);
  assertNoEmission(r);
});

test('batch 93 stops after bounded repeated version conflicts without clearing the marker', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' }, { conflicts: 5 });
  await assert.rejects(() => r.service[method]('u1', 'm1'), error => error.code.includes('VERSION_CONFLICT'));
  assert.equal(r.store.current()[errorKey], 'EVENT_DOWN');
  assert.equal(r.store.writes(), 2);
  assertNoEmission(r);
});

test('batch 93 clears only the exact orphaned-error verifier finding', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_ERROR' });
  const before = await r.service[verify]('u1', 'm1');
  assert.deepEqual(before.issues, [{ code: orphanCode }]);
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.repaired, true);
  assert.deepEqual(out.issues, []);
  assertNoEmission(r);
});

test('batch 93 remains owner-scoped', async () => {
  const r = runtime({ ...base, [errorKey]: 'EVENT_DOWN' });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});
