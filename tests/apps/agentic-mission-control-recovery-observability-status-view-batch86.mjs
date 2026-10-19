import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const prefix = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
const pending = { reconciliationId: 'recon-84', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: true };

function runtime(initial) {
  let current = { ...initial };
  let writes = 0;
  let emissions = 0;
  const store = {
    async getOwned(_scope, ownerId, id) {
      if (id !== current.id || ownerId !== current.ownerId) return null;
      return current;
    },
    async putOwned() {
      writes += 1;
      throw new Error('READ_ONLY_STATUS_MUST_NOT_WRITE');
    },
    current: () => current,
    writes: () => writes
  };
  const observability = {
    async event() {
      emissions += 1;
      throw new Error('READ_ONLY_STATUS_MUST_NOT_EMIT');
    },
    async snapshot(_ownerId, mission) { return mission; }
  };
  return {
    store,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-10T00:00:00.000Z' }),
    emissions: () => emissions
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 85 } };
function assertReadOnly(r, before) {
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
}

test('batch 86 reports clear state without mutation or event emission', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.deepEqual(out, {
    missionId: 'm1', ownerId: 'u1', phase: 'clear', valid: true, recoverable: false, pending: false,
    reconciliationId: null, repairedByRetry: false, createdAt: null, error: null, issues: [], storageVersion: 85
  });
  assertReadOnly(r, before);
});

test('batch 86 reports valid pending intent and bounded durable error', async () => {
  const r = runtime({ ...base, [pendingKey]: pending, [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, true);
  assert.equal(out.recoverable, true);
  assert.equal(out.pending, true);
  assert.equal(out.reconciliationId, 'recon-84');
  assert.equal(out.createdAt, pending.createdAt);
  assert.equal(out.repairedByRetry, true);
  assert.equal(out.error, 'EVENT_DOWN');
  assert.deepEqual(out.issues, []);
  assertReadOnly(r, before);
});

test('batch 86 accepts nullable reconciliation ID from the durable intent contract', async () => {
  const r = runtime({ ...base, [pendingKey]: { reconciliationId: null, createdAt: pending.createdAt, repairedByRetry: false } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, true);
  assert.equal(out.recoverable, true);
  assert.equal(out.reconciliationId, null);
  assert.equal(out.repairedByRetry, false);
  assert.deepEqual(out.issues, []);
});

test('batch 86 reports malformed metadata with stable issue codes', async () => {
  const r = runtime({ ...base, [pendingKey]: { reconciliationId: '', createdAt: '', repairedByRetry: 'yes' } });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.recoverable, false);
  assert.deepEqual(out.issues.map(issue => issue.code), [
    `${prefix}OBSERVABILITY_RECONCILIATION_ID_INVALID`,
    `${prefix}OBSERVABILITY_CREATED_AT_INVALID`,
    `${prefix}OBSERVABILITY_RETRY_FLAG_INVALID`
  ]);
  assertReadOnly(r, before);
});

test('batch 86 bounds metadata and durable error output', async () => {
  const r = runtime({
    ...base,
    [pendingKey]: { reconciliationId: 'r'.repeat(201), createdAt: 't'.repeat(101), repairedByRetry: false },
    [errorKey]: 'e'.repeat(1100)
  });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.reconciliationId, null);
  assert.equal(out.createdAt, null);
  assert.equal(out.error.length, 1000);
  assert.deepEqual(out.issues.map(issue => issue.code), [
    `${prefix}OBSERVABILITY_RECONCILIATION_ID_TOO_LONG`,
    `${prefix}OBSERVABILITY_CREATED_AT_TOO_LONG`
  ]);
});

test('batch 86 detects orphaned durable error without repairing it', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'error');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.error, 'ORPHANED_ERROR');
  assert.deepEqual(out.issues, [{ code: `${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING` }]);
  assertReadOnly(r, before);
});

test('batch 86 rejects non-object pending intent without mutation or emission', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'] });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.equal(out.recoverable, false);
  assert.deepEqual(out.issues, [{ code: `${prefix}OBSERVABILITY_PENDING_INVALID` }]);
  assertReadOnly(r, before);
});

test('batch 86 remains owner-scoped', async () => {
  const r = runtime({ ...base, [pendingKey]: pending });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 86 never exposes raw malformed objects in the result', async () => {
  const raw = { token: 'secret-like-value', nested: { arbitrary: true } };
  const r = runtime({ ...base, [pendingKey]: raw, [errorKey]: { message: 'bounded' } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recoverable, false);
  assert.equal(out.reconciliationId, null);
  assert.equal(out.createdAt, null);
  assert.equal(out.error, '[object Object]');
  assert.equal(JSON.stringify(out).includes('secret-like-value'), false);
});
