import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'recoverAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const pending = { reconciliationId: 'recon-84', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: true };
const expectedEventType = 'mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired';
const expectedDedupeKey = id => `control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:${id}`;

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

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 84 } };

test('batch 85 recovers a valid durable intent and clears pending/error after emission', async () => {
  let sawPendingBeforeEmission = false;
  const r = runtime({ ...base, [pendingKey]: pending, [errorKey]: 'PREVIOUS_FAILURE' }, {
    onEvent: async ({ current }) => { sawPendingBeforeEmission = current[pendingKey] === pending && current[errorKey] === 'PREVIOUS_FAILURE'; }
  });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(sawPendingBeforeEmission, true);
  assert.equal(out.attempted, true);
  assert.equal(out.recovered, true);
  assert.equal(out.phase, 'clear');
  assert.equal(out.valid, true);
  assert.equal(out.pending, false);
  assert.equal(out.observabilityEmitted, true);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.events[0].eventType, expectedEventType);
  assert.equal(r.events[0].payload.dedupeKey, expectedDedupeKey(base.id));
  assert.equal(r.events[0].payload.reconciliationId, 'recon-84');
  assert.equal(r.events[0].payload.repairedByRetry, true);
});

test('batch 85 persists bounded error and keeps pending intent when emission fails', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { emitFailures: 1, errorMessage: 'x'.repeat(1500) });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.pending, true);
  assert.equal(out.observabilityEmitted, false);
  assert.equal(out.error.length, 1000);
  assert.deepEqual(r.store.current()[pendingKey], pending);
  assert.equal(r.store.current()[errorKey].length, 1000);
  assert.equal(r.emissions(), 1);
});

test('batch 85 retry reuses the deterministic dedupe key and clears the intent on success', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { emitFailures: 1 });
  const first = await r.service[method]('u1', 'm1');
  assert.equal(first.pending, true);
  const second = await r.service[method]('u1', 'm1');
  assert.equal(second.recovered, true);
  assert.equal(second.pending, false);
  assert.equal(r.events[0].payload.dedupeKey, r.events[1].payload.dedupeKey);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
});

test('batch 85 rejects malformed pending intent without mutation or emission', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'], [errorKey]: 'OLD_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.pending, true);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_PENDING_INVALID')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 85 fails closed on an error marker without pending intent', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'error');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_ERROR_WITHOUT_PENDING')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 85 is a no-op when state is clear', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.phase, 'clear');
  assert.equal(out.valid, true);
  assert.equal(out.attempted, false);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 85 retries optimistic-concurrency conflict with the same dedupe key', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { conflicts: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(out.recoveredByRetry, true);
  assert.equal(r.emissions(), 2);
  assert.equal(r.events[0].payload.dedupeKey, r.events[1].payload.dedupeKey);
  assert.equal(r.store.current()[pendingKey], null);
});

test('batch 85 stops after bounded repeated version conflicts', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { conflicts: 5 });
  await assert.rejects(() => r.service[method]('u1', 'm1'), error => error.code.includes('VERSION_CONFLICT'));
  assert.deepEqual(r.store.current()[pendingKey], pending);
  assert.equal(r.store.writes(), 2);
  assert.equal(r.emissions(), 2);
});

test('batch 85 returns a recoverable pending result when clearing state fails after emission', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { writeFailures: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, false);
  assert.equal(out.phase, 'pending');
  assert.equal(out.pending, true);
  assert.equal(out.observabilityEmitted, true);
  assert.equal(out.error, 'STORE_DOWN');
  assert.deepEqual(r.store.current()[pendingKey], pending);
  assert.equal(r.emissions(), 1);
});

test('batch 85 handles a null reconciliation ID without leaking malformed values', async () => {
  const r = runtime({ ...base, [pendingKey]: { ...pending, reconciliationId: null } });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(r.events[0].payload.reconciliationId, null);
});

test('batch 85 remains owner-scoped', async () => {
  const r = runtime({ ...base, [pendingKey]: pending });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 85 persists emission failure and can recover it after one write conflict', async () => {
  const r = runtime({ ...base, [pendingKey]: pending }, { emitFailures: 1, conflicts: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.recovered, true);
  assert.equal(out.recoveredByRetry, true);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.events[0].payload.dedupeKey, r.events[1].payload.dedupeKey);
});
