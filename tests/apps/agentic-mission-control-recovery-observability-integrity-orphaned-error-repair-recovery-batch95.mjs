import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const sourceErrorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const expectedEventType = 'mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
const expectedDedupeKey = id => `control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${id}`;
const prefix = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_';
const pending = { reconciliationId: 'recon-94', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: true };

function runtime(initial, { conflicts = 0, emitFailures = 0, writeFailures = 0, onEvent = null, errorMessage = 'EVENT_DOWN' } = {}) {
  let current = { ...initial };
  let writes = 0;
  let emissions = 0;
  let conflictsRemaining = conflicts;
  let failuresRemaining = emitFailures;
  let writeFailuresRemaining = writeFailures;
  const events = [];
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
      if (writeFailuresRemaining > 0) {
        writeFailuresRemaining -= 1;
        throw new Error('STORE_DOWN');
      }
      assert.equal(options.expectedVersion, current._storage?.version);
      current = { ...next, _storage: { version: (current._storage?.version ?? 0) + 1 } };
      return current;
    },
    current: () => current,
    writes: () => writes
  };
  const observability = {
    async event(ownerId, missionId, eventType, payload) {
      emissions += 1;
      events.push({ ownerId, missionId, eventType, payload });
      if (onEvent) await onEvent({ current, ownerId, missionId, eventType, payload });
      if (failuresRemaining > 0) {
        failuresRemaining -= 1;
        throw new Error(errorMessage);
      }
      return { id: `event-${emissions}` };
    },
    async snapshot(_ownerId, mission) { return mission; }
  };
  return {
    store,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-10T00:00:00.000Z' }),
    events,
    emissions: () => emissions
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 94 } };

function assertNoEmission(r) { assert.equal(r.emissions(), 0); }

test('batch 95 recovers valid Batch 94 intent and clears pending/error after event emission', async () => {
  let sawDurableIntent = false;
  const r = runtime({ ...base, [pendingKey]: pending, [errorKey]: 'PREVIOUS_FAILURE', [sourceErrorKey]: 'SOURCE_ERROR' }, {
    onEvent: async ({ current, eventType, payload }) => {
      sawDurableIntent = current[pendingKey] === pending && current[errorKey] === 'PREVIOUS_FAILURE';
      assert.equal(eventType, expectedEventType);
      assert.equal(payload.dedupeKey, expectedDedupeKey('m1'));
      assert.equal(payload.reconciliationId, 'recon-94');
      assert.equal(payload.repairedByRetry, true);
    }
  });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(sawDurableIntent, true);
  assert.equal(out.attempted, true);
  assert.equal(out.recovered, true);
  assert.equal(out.phase, 'clear');
  assert.equal(out.valid, true);
  assert.equal(out.pending, false);
  assert.equal(out.observabilityEmitted, true);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.current()[sourceErrorKey], 'SOURCE_ERROR');
  assert.equal(r.events[0].ownerId, 'u1');
  assert.equal(r.events[0].missionId, 'm1');
  assert.equal(r.events[0].eventType, expectedEventType);
  assert.equal(r.events[0].payload.source, 'mission-control');
  assert.equal(r.events[0].payload.dedupeKey, expectedDedupeKey('m1'));
  assert.equal(r.store.writes(), 1);
  assert.equal(r.emissions(), 1);
});

test('batch 95 persists a bounded error and retains pending intent when event emission fails', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { emitFailures: 1, errorMessage: 'E'.repeat(1500) });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.attempted, true);
  assert.equal(out.recovered, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.pending, true);
  assert.equal(out.observabilityEmitted, false);
  assert.equal(out.error, 'E'.repeat(1000));
  assert.equal(r.store.current()[pendingKey], pending);
  assert.equal(r.store.current()[errorKey], 'E'.repeat(1000));
  assert.equal(r.emissions(), 1);
});

test('batch 95 fails closed for malformed pending intent without writes or event emission', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'] });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.attempted, false);
  assert.equal(out.recovered, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.deepEqual(out.issues, [{ code: `${prefix}OBSERVABILITY_PENDING_INVALID` }]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 95 fails closed for an orphaned destination error marker', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_DESTINATION_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'error');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.deepEqual(out.issues, [{ code: `${prefix}OBSERVABILITY_ERROR_WITHOUT_PENDING` }]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 95 is a no-op when no pending intent or error marker exists', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.attempted, false);
  assert.equal(out.recovered, false);
  assert.equal(out.phase, 'clear');
  assert.equal(out.valid, true);
  assert.deepEqual(out.issues, []);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 95 retries version conflicts with the same dedupe key', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { conflicts: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(out.recoveredByRetry, true);
  assert.equal(out.pending, false);
  assert.equal(r.emissions(), 2);
  assert.equal(r.events[0].payload.dedupeKey, expectedDedupeKey('m1'));
  assert.equal(r.events[1].payload.dedupeKey, expectedDedupeKey('m1'));
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
});

test('batch 95 stops after bounded repeated version conflicts and preserves the intent', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { conflicts: 5 });
  await assert.rejects(() => r.service[method]('u1', 'm1'), error => error.code === 'MISSION_CONTROL_RECOVERY_OBSERVABILITY_INTEGRITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_RECOVERY_VERSION_CONFLICT');
  assert.deepEqual(r.store.current()[pendingKey], pending);
  assert.equal(r.store.writes(), 2);
  assert.equal(r.emissions(), 2);
});

test('batch 95 retries after a conflict while persisting an emission error', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { conflicts: 1, emitFailures: 1, errorMessage: 'TEMPORARY_DOWN' });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(out.recoveredByRetry, true);
  assert.equal(out.pending, false);
  assert.equal(r.emissions(), 2);
  assert.equal(r.events[0].payload.dedupeKey, r.events[1].payload.dedupeKey);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
});

test('batch 95 reports a clear-write failure without discarding the durable intent', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { writeFailures: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.attempted, true);
  assert.equal(out.recovered, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.pending, true);
  assert.equal(out.observabilityEmitted, true);
  assert.equal(out.error, 'STORE_DOWN');
  assert.deepEqual(r.store.current()[pendingKey], pending);
  assert.equal(r.emissions(), 1);
});

test('batch 95 accepts a nullable reconciliation ID and emits null', async () => {
  const r = runtime({ ...base, [pendingKey]: { ...pending, reconciliationId: null } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(r.events[0].payload.reconciliationId, null);
  assert.equal(r.events[0].payload.dedupeKey, expectedDedupeKey('m1'));
});

test('batch 95 rejects invalid reconciliation ID, timestamp, or retry flag', async () => {
  const invalid = [
    { ...pending, reconciliationId: 'x'.repeat(201) },
    { ...pending, createdAt: 'x'.repeat(101) },
    { ...pending, repairedByRetry: 'yes' }
  ];
  for (const intent of invalid) {
    const r = runtime({ ...base, [pendingKey]: intent });
    const before = r.store.current();
    const out = await r.service[method]('u1', 'm1');
    assert.equal(out.valid, false);
    assert.equal(out.pending, true);
    assert.deepEqual(out.issues, [{ code: `${prefix}OBSERVABILITY_PENDING_INVALID` }]);
    assert.strictEqual(r.store.current(), before);
    assert.equal(r.store.writes(), 0);
    assert.equal(r.emissions(), 0);
  }
});

test('batch 95 remains owner-scoped', async () => {
  const r = runtime({ ...base, [pendingKey]: pending });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 95 fails closed when the mission-scoped dedupe key exceeds its bound', async () => {
  const longId = 'm'.repeat(280);
  const r = runtime({ ...base, id: longId, [pendingKey]: pending });
  const before = r.store.current();
  const out = await r.service[method]('u1', longId);
  assert.equal(out.valid, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.pending, true);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_DEDUPE_KEY_INVALID')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});
