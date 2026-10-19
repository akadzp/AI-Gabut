import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

function runtime(initial) {
  let current = { ...initial };
  let writes = 0;
  const events = [];
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
    async event(...args) { events.push(args); throw new Error('READ_ONLY_STATUS_MUST_NOT_EMIT'); },
    async snapshot(_ownerId, mission) { return mission; }
  };
  return {
    store,
    events,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-09T00:00:00.000Z' })
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 41 } };
const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusError';
const method = 'auditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatus';
const pending = { reconciliationId: 'recon-70', createdAt: '2026-10-09T00:00:00.000Z', repairedByRetry: true };

test('batch 71 reports clear Batch 70 recovery-observability state without mutation or emission', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.deepEqual(out, {
    missionId: 'm1', ownerId: 'u1', phase: 'clear', valid: true, recoverable: false, pending: false,
    reconciliationId: null, repairedByRetry: false, createdAt: null, error: null, issues: [], storageVersion: 41
  });
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 71 exposes bounded metadata for a valid pending Batch 70 recovery intent', async () => {
  const r = runtime({ ...base, [pendingKey]: pending, [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, true);
  assert.equal(out.pending, true);
  assert.equal(out.recoverable, true);
  assert.equal(out.reconciliationId, 'recon-70');
  assert.equal(out.createdAt, pending.createdAt);
  assert.equal(out.repairedByRetry, true);
  assert.equal(out.error, 'EVENT_DOWN');
  assert.equal(out.storageVersion, 41);
  assert.deepEqual(out.issues, []);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 71 reports an orphaned durable error as an integrity issue', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'error');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.error, 'ORPHANED_ERROR');
  assert.deepEqual(out.issues, [{ code: 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING' }]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 71 fails closed for a malformed pending intent shape', async () => {
  const r = runtime({ ...base, [pendingKey]: ['bad-intent'], [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.equal(out.recoverable, false);
  assert.deepEqual(out.issues, [{ code: 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_PENDING_INVALID' }]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 71 reports invalid fields and bounds returned metadata', async () => {
  const r = runtime({
    ...base,
    [pendingKey]: { reconciliationId: 'r'.repeat(250), createdAt: 't'.repeat(130), repairedByRetry: 'yes' },
    [errorKey]: 'e'.repeat(1100)
  });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.reconciliationId, null);
  assert.equal(out.createdAt, null);
  assert.equal(out.repairedByRetry, false);
  assert.equal(out.error.length, 1000);
  assert.deepEqual(out.issues.map(issue => issue.code), [
    'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECONCILIATION_ID_INVALID',
    'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_CREATED_AT_INVALID',
    'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RETRY_FLAG_INVALID'
  ]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});

test('batch 71 remains owner-scoped', async () => {
  const r = runtime({ ...base, [pendingKey]: pending });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.events.length, 0);
});
