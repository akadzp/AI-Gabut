import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const prefix = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
const dedupeKey = 'control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:m1';
const pending = { reconciliationId: 'recon-85', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: true };

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
      throw new Error('READ_ONLY_VERIFIER_MUST_NOT_WRITE');
    },
    current: () => current,
    writes: () => writes
  };
  const observability = {
    async event() {
      emissions += 1;
      throw new Error('READ_ONLY_VERIFIER_MUST_NOT_EMIT');
    },
    async snapshot(_ownerId, mission) { return mission; }
  };
  return {
    store,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-10T00:00:00.000Z' }),
    emissions: () => emissions
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 86 } };
function assertReadOnly(r, before) {
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
}

test('batch 87 verifies clear Batch 86 state without mutation or event emission', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.deepEqual(out, {
    missionId: 'm1', ownerId: 'u1', phase: 'clear', valid: true, pending: false, recoverable: false,
    reconciliationId: null, dedupeKey: null, createdAt: null, repairedByRetry: false, error: null,
    issues: [], storageVersion: 86
  });
  assertReadOnly(r, before);
});

test('batch 87 verifies valid pending metadata and deterministic mission-scoped dedupe key', async () => {
  const r = runtime({ ...base, [pendingKey]: pending, [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, true);
  assert.equal(out.pending, true);
  assert.equal(out.recoverable, true);
  assert.equal(out.reconciliationId, 'recon-85');
  assert.equal(out.createdAt, pending.createdAt);
  assert.equal(out.repairedByRetry, true);
  assert.equal(out.dedupeKey, dedupeKey);
  assert.equal(out.error, 'EVENT_DOWN');
  assert.deepEqual(out.issues, []);
  assertReadOnly(r, before);
});

test('batch 87 accepts a nullable reconciliation ID under the durable intent contract', async () => {
  const r = runtime({ ...base, [pendingKey]: { reconciliationId: null, createdAt: pending.createdAt, repairedByRetry: false } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, true);
  assert.equal(out.recoverable, true);
  assert.equal(out.reconciliationId, null);
  assert.equal(out.repairedByRetry, false);
  assert.equal(out.dedupeKey, dedupeKey);
  assert.deepEqual(out.issues, []);
});

test('batch 87 reports malformed pending metadata with stable issue codes', async () => {
  const r = runtime({ ...base, [pendingKey]: { reconciliationId: '', createdAt: '', repairedByRetry: 'yes' } });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.recoverable, false);
  assert.deepEqual(out.issues.map(issue => issue.code), [
    `${prefix}RECONCILIATION_ID_INVALID`,
    `${prefix}CREATED_AT_MISSING`,
    `${prefix}RETRY_FLAG_INVALID`
  ]);
  assertReadOnly(r, before);
});

test('batch 87 bounds metadata and durable error output', async () => {
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
    `${prefix}RECONCILIATION_ID_TOO_LONG`,
    `${prefix}CREATED_AT_TOO_LONG`
  ]);
  assert.equal(out.dedupeKey, dedupeKey);
});

test('batch 87 detects orphaned durable error without repairing it', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'error');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.dedupeKey, null);
  assert.equal(out.error, 'ORPHANED_ERROR');
  assert.deepEqual(out.issues, [{ code: `${prefix}ERROR_WITHOUT_PENDING` }]);
  assertReadOnly(r, before);
});

test('batch 87 rejects non-object pending intent without mutation or event emission', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'] });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.equal(out.recoverable, false);
  assert.equal(out.dedupeKey, dedupeKey);
  assert.deepEqual(out.issues, [{ code: `${prefix}PENDING_INVALID` }]);
  assertReadOnly(r, before);
});

test('batch 87 fails closed when deterministic dedupe key exceeds its bound', async () => {
  const id = 'm'.repeat(300);
  const r = runtime({ ...base, id, [pendingKey]: pending });
  const out = await r.service[method]('u1', id);
  assert.equal(out.valid, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.dedupeKey, null);
  assert.deepEqual(out.issues, [{ code: `${prefix}DEDUPE_KEY_INVALID` }]);
});

test('batch 87 remains owner-scoped', async () => {
  const r = runtime({ ...base, [pendingKey]: pending });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});
