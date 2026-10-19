import test from 'node:test';
import assert from 'node:assert/strict';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

const sourcePendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const sourceErrorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability';
const verifier = 'verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const orphanCode = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_ERROR_WITHOUT_PENDING';

function versionConflict() {
  const error = new Error('VERSION_CONFLICT');
  error.code = 'VERSION_CONFLICT';
  return error;
}

function runtime(initial, { conflicts = 0, emitFailures = 0, emitErrorMessage = 'EVENT_DOWN', onEvent = null } = {}) {
  let current = { ...initial };
  let writes = 0;
  let emissions = 0;
  let conflictsRemaining = conflicts;
  let failuresRemaining = emitFailures;
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
        throw versionConflict();
      }
      if (options.expectedVersion !== current._storage?.version) throw versionConflict();
      current = { ...next, _storage: { version: (current._storage?.version ?? 0) + 1 } };
      return current;
    },
    current: () => current,
    writes: () => writes
  };
  const observability = {
    async event(ownerId, missionId, eventType, payload) {
      emissions += 1;
      const event = { ownerId, missionId, eventType, payload };
      events.push(event);
      if (onEvent) await onEvent({ current, replaceCurrent: next => { current = next; }, ...event });
      if (failuresRemaining > 0) {
        failuresRemaining -= 1;
        throw new Error(emitErrorMessage);
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

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 93 } };
const sourcePending = { reconciliationId: 'recon-93', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: false };

function assertNoEmission(r) { assert.equal(r.emissions(), 0); }

test('batch 94 persists the verified source repair and durable intent before event emission', async () => {
  let sawPreparedState = false;
  const r = runtime({ ...base, [sourceErrorKey]: 'ORPHANED_ERROR' }, {
    onEvent: async ({ current }) => {
      sawPreparedState = current[sourceErrorKey] === null && current[pendingKey]?.createdAt === '2026-10-10T00:00:00.000Z';
    }
  });
  const before = await r.service[verifier]('u1', 'm1');
  assert.deepEqual(before.issues, [{ code: orphanCode }]);
  const out = await r.service[method]('u1', 'm1');
  assert.equal(sawPreparedState, true);
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.valid, true);
  assert.equal(out.pending, false);
  assert.equal(out.observabilityEmitted, true);
  assert.equal(out.error, null);
  assert.equal(r.store.current()[sourceErrorKey], null);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.writes(), 2);
  assert.equal(r.emissions(), 1);
  assert.equal(r.events[0].ownerId, 'u1');
  assert.equal(r.events[0].missionId, 'm1');
  assert.equal(r.events[0].eventType, 'mission_control_audit_recovery_evidence_repair_recovery_status_repair_recovery_status_repair_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_recovery_status_repaired');
  assert.equal(r.events[0].payload.source, 'mission-control');
  assert.equal(r.events[0].payload.reconciliationId, null);
  assert.equal(r.events[0].payload.dedupeKey, `control-audit-recovery-repair-recovery-status-repair-recovery-status-repair-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status-recovery-status:m1`);
});

test('batch 94 retains durable intent and a bounded error when event emission fails', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'ORPHANED_ERROR' }, { emitFailures: 1, emitErrorMessage: 'E'.repeat(1500) });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.pending, true);
  assert.equal(out.observabilityEmitted, false);
  assert.equal(out.error, 'E'.repeat(1000));
  assert.equal(r.store.current()[sourceErrorKey], null);
  assert.equal(typeof r.store.current()[pendingKey], 'object');
  assert.equal(r.store.current()[errorKey], 'E'.repeat(1000));
  assert.equal(r.emissions(), 1);
});

test('batch 94 retries a pending intent with the same dedupe key and clears it after success', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'ORPHANED_ERROR' }, { emitFailures: 1 });
  const first = await r.service[method]('u1', 'm1');
  assert.equal(first.pending, true);
  const second = await r.service[method]('u1', 'm1');
  assert.equal(second.pending, false);
  assert.equal(second.observabilityEmitted, true);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.events[0].payload.dedupeKey, r.events[1].payload.dedupeKey);
  assert.equal(r.emissions(), 2);
});

test('batch 94 rejects malformed destination intent without emitting or mutating', async () => {
  const r = runtime({ ...base, [pendingKey]: ['malformed'] });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_PENDING_INVALID')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 94 fails closed on an orphaned destination error marker', async () => {
  const r = runtime({ ...base, [errorKey]: 'DESTINATION_ORPHAN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_ERROR_WITHOUT_PENDING')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 94 preserves valid source pending intent and its source error', async () => {
  const r = runtime({ ...base, [sourcePendingKey]: sourcePending, [sourceErrorKey]: 'SOURCE_ERROR' });
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

test('batch 94 preserves malformed source pending intent and reports verifier issues', async () => {
  const r = runtime({ ...base, [sourcePendingKey]: ['malformed'], [sourceErrorKey]: 'SOURCE_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.ok(out.issues.length > 0);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 94 is a no-op when source state is clear', async () => {
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

test('batch 94 retries source repair after a version conflict', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'ORPHANED_ERROR' }, { conflicts: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.repairedByRetry, true);
  assert.equal(r.store.current()[sourceErrorKey], null);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.emissions(), 1);
});

test('batch 94 stops after bounded repeated version conflicts without emitting', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'ORPHANED_ERROR' }, { conflicts: 5 });
  await assert.rejects(() => r.service[method]('u1', 'm1'), error => error.code.includes('VERSION_CONFLICT'));
  assert.equal(r.store.current()[sourceErrorKey], 'ORPHANED_ERROR');
  assert.equal(r.store.current()[pendingKey] ?? null, null);
  assert.equal(r.emissions(), 0);
});

test('batch 94 remains owner-scoped', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'ORPHANED_ERROR' });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});

test('batch 94 reuses the dedupe key after a concurrent version change during emission', async () => {
  let bumped = false;
  const r = runtime({ ...base, [sourceErrorKey]: 'ORPHANED_ERROR' }, {
    onEvent: async ({ current, replaceCurrent }) => {
      if (!bumped) {
        bumped = true;
        replaceCurrent({ ...current, _storage: { version: (current._storage?.version ?? 0) + 1 } });
      }
    }
  });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.pending, false);
  assert.equal(r.emissions(), 2);
  assert.equal(r.events[0].payload.dedupeKey, r.events[1].payload.dedupeKey);
  assert.equal(r.store.current()[pendingKey], null);
});


test('batch 94 fails closed when the mission-scoped dedupe key exceeds its bound', async () => {
  const longId = 'm'.repeat(280);
  const r = runtime({ ...base, id: longId, [sourceErrorKey]: 'ORPHANED_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', longId);
  assert.equal(out.valid, false);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_DEDUPE_KEY_INVALID')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assertNoEmission(r);
});
