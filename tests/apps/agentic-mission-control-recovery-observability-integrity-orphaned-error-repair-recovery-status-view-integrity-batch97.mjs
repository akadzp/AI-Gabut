import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const prefix = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
const dedupeKey = id => `control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${id}`;
const pending = { reconciliationId: 'recon-96', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: true };

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

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 96 } };
function assertReadOnly(r, before) {
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
}

test('batch 97 verifies clear Batch 96 state without mutation or event emission', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.deepEqual(out, {
    missionId: 'm1', ownerId: 'u1', phase: 'clear', valid: true, pending: false, recoverable: false,
    reconciliationId: null, dedupeKey: null, createdAt: null, repairedByRetry: false, error: null, issues: [], storageVersion: 96
  });
  assertReadOnly(r, before);
});

test('batch 97 verifies valid pending metadata and the deterministic mission-scoped dedupe key', async () => {
  const r = runtime({ ...base, [pendingKey]: pending, [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, true);
  assert.equal(out.pending, true);
  assert.equal(out.recoverable, true);
  assert.equal(out.reconciliationId, 'recon-96');
  assert.equal(out.createdAt, pending.createdAt);
  assert.equal(out.repairedByRetry, true);
  assert.equal(out.dedupeKey, dedupeKey('m1'));
  assert.equal(out.error, 'EVENT_DOWN');
  assert.deepEqual(out.issues, []);
  assertReadOnly(r, before);
});

test('batch 97 accepts a nullable reconciliation ID under the durable-intent contract', async () => {
  const r = runtime({ ...base, [pendingKey]: { reconciliationId: null, createdAt: pending.createdAt, repairedByRetry: false } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, true);
  assert.equal(out.recoverable, true);
  assert.equal(out.reconciliationId, null);
  assert.equal(out.createdAt, pending.createdAt);
  assert.equal(out.repairedByRetry, false);
  assert.equal(out.dedupeKey, dedupeKey('m1'));
  assert.deepEqual(out.issues, []);
});

test('batch 97 reports malformed pending metadata with stable issue codes', async () => {
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

test('batch 97 bounds metadata and durable error output', async () => {
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
  assert.equal(out.dedupeKey, dedupeKey('m1'));
  assert.deepEqual(out.issues.map(issue => issue.code), [
    `${prefix}OBSERVABILITY_RECONCILIATION_ID_TOO_LONG`,
    `${prefix}OBSERVABILITY_CREATED_AT_TOO_LONG`
  ]);
});

test('batch 97 detects an orphaned durable error without repairing it', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'error');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.dedupeKey, null);
  assert.equal(out.error, 'ORPHANED_ERROR');
  assert.deepEqual(out.issues, [{ code: `${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING` }]);
  assertReadOnly(r, before);
});

test('batch 97 rejects non-object pending intent without mutation or emission', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'] });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.equal(out.recoverable, false);
  assert.equal(out.dedupeKey, null);
  assert.deepEqual(out.issues, [{ code: `${prefix}OBSERVABILITY_PENDING_INVALID` }]);
  assertReadOnly(r, before);
});

test('batch 97 fails closed when the deterministic dedupe key exceeds 260 characters', async () => {
  const id = 'm'.repeat(230);
  const r = runtime({ ...base, id, [pendingKey]: pending });
  const before = r.store.current();
  const out = await r.service[method]('u1', id);
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.dedupeKey, null);
  assert.ok(out.issues.some(issue => issue.code === `${prefix}OBSERVABILITY_DEDUPE_KEY_INVALID`));
  assertReadOnly(r, before);
});

test('batch 97 remains owner-scoped', async () => {
  const r = runtime({ ...base, [pendingKey]: pending });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 97 never exposes arbitrary fields from malformed pending objects', async () => {
  const r = runtime({ ...base, [pendingKey]: { token: 'secret-like-value', nested: { arbitrary: true } } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.recoverable, false);
  assert.equal(out.reconciliationId, null);
  assert.equal(out.createdAt, null);
  assert.equal(out.dedupeKey, dedupeKey('m1'));
  assert.equal(JSON.stringify(out).includes('secret-like-value'), false);
  assert.equal(JSON.stringify(out).includes('arbitrary'), false);
});

test('batch 97 application-boundary mapping uses the same verifier', async () => {
  const fs = await import('node:fs/promises');
  const source = await fs.readFile(new URL('../../apps/agentic/backend/application.js', import.meta.url), 'utf8');
  assert.ok(source.includes('verifyMissionControlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus:missionControl.verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus'));
});
