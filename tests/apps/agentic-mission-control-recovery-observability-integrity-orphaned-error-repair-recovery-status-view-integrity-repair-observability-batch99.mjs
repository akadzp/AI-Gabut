import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { createMissionControl } from '../../apps/agentic/backend/mission-control.js';

const sourcePendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const sourceErrorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const pendingKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusPending';
const errorKey = 'controlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusError';
const method = 'repairAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability';
const boundary = 'repairMissionControlAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusWithObservability';
const verify = 'verifyAuditRecoveryEvidenceRepairRecoveryStatusRepairRecoveryStatusRepairRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatusRecoveryStatus';
const sourceOrphanCode = 'RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_REPAIR_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_RECOVERY_STATUS_OBSERVABILITY_ERROR_WITHOUT_PENDING';
const pendingIntent = { reconciliationId: null, createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: false };

function runtime(initial, { conflicts = 0, failEmissions = 0 } = {}) {
  let current = { ...initial };
  let writes = 0;
  let emissions = 0;
  let conflictsRemaining = conflicts;
  let emissionFailuresRemaining = failEmissions;
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
      if (emissionFailuresRemaining > 0) {
        emissionFailuresRemaining -= 1;
        throw new Error('EVENT_DOWN');
      }
    },
    async snapshot(_ownerId, mission) { return mission; }
  };
  return {
    store,
    service: createMissionControl({ missionStore: store, observability, clock: () => '2026-10-10T00:00:00.000Z' }),
    emissions: () => emissions,
    events
  };
}

const base = { id: 'm1', ownerId: 'u1', status: 'paused', controlHistory: [], _storage: { version: 98 } };

test('batch 99 atomically repairs the exact orphan and emits deterministic evidence', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'EVENT_DOWN' });
  const before = await r.service[verify]('u1', 'm1');
  assert.deepEqual(before.issues, [{ code: sourceOrphanCode }]);
  const out = await r.service[method]('u1', 'm1');
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
  assert.equal(r.events[0].eventType, 'mission_control_audit_recovery_evidence_repair_recovery_status_view_integrity_orphaned_error_repaired');
  assert.equal(r.events[0].payload.dedupeKey, 'control-audit-recovery-status-view-integrity-orphaned-error-repair:m1');
});

test('batch 99 is a no-op when source and destination are clear', async () => {
  const r = runtime(base);
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.repaired, false);
  assert.equal(out.pending, false);
  assert.deepEqual(out.issues, []);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 99 preserves a valid source pending intent and associated error', async () => {
  const r = runtime({ ...base, [sourcePendingKey]: { reconciliationId: 'source-1', createdAt: '2026-10-10T00:00:00.000Z', repairedByRetry: false }, [sourceErrorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.pending, true);
  assert.deepEqual(out.issues, []);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 99 fails closed and preserves malformed source pending intent', async () => {
  const malformed = ['bad'];
  const r = runtime({ ...base, [sourcePendingKey]: malformed, [sourceErrorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, false);
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_PENDING_INVALID')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 99 retains destination intent and bounded error when event emission fails', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'EVENT_DOWN' }, { failEmissions: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.pending, true);
  assert.equal(out.observabilityEmitted, false);
  assert.equal(out.error, 'EVENT_DOWN');
  assert.equal(r.store.current()[sourceErrorKey], null);
  assert.deepEqual(r.store.current()[pendingKey], pendingIntent);
  assert.equal(r.store.current()[errorKey], 'EVENT_DOWN');
  assert.equal(r.emissions(), 1);
});

test('batch 99 retries pending evidence without replaying source repair', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'EVENT_DOWN' }, { failEmissions: 1 });
  const first = await r.service[method]('u1', 'm1');
  assert.equal(first.pending, true);
  const writesAfterFirst = r.store.writes();
  const second = await r.service[method]('u1', 'm1');
  assert.equal(second.changed, false);
  assert.equal(second.repaired, true);
  assert.equal(second.pending, false);
  assert.equal(second.observabilityEmitted, true);
  assert.equal(r.store.current()[sourceErrorKey], null);
  assert.equal(r.store.current()[pendingKey], null);
  assert.equal(r.store.current()[errorKey], null);
  assert.equal(r.store.writes(), writesAfterFirst + 1);
  assert.equal(r.emissions(), 2);
  assert.equal(r.events[0].payload.dedupeKey, r.events[1].payload.dedupeKey);
});

test('batch 99 fails closed on malformed destination intent', async () => {
  const r = runtime({ ...base, [pendingKey]: ['bad'], [errorKey]: 'EVENT_DOWN' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, true);
  assert.ok(out.issues.some(issue => issue.code.endsWith('OBSERVABILITY_PENDING_INVALID')));
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 99 does not clear a destination error marker without pending intent', async () => {
  const r = runtime({ ...base, [errorKey]: 'ORPHANED_DESTINATION_ERROR' });
  const before = r.store.current();
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.valid, false);
  assert.equal(out.pending, false);
  assert.deepEqual(out.issues, [{ code: 'RECOVERY_STATUS_VIEW_INTEGRITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_ERROR_WITHOUT_PENDING' }]);
  assert.strictEqual(r.store.current(), before);
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 99 retries a version conflict against current source state', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'EVENT_DOWN' }, { conflicts: 1 });
  const out = await r.service[method]('u1', 'm1');
  assert.equal(out.changed, true);
  assert.equal(out.repaired, true);
  assert.equal(out.repairedByRetry, true);
  assert.equal(out.pending, false);
  assert.equal(out.observabilityEmitted, true);
  assert.equal(r.store.current()[sourceErrorKey], null);
  assert.equal(r.emissions(), 1);
});

test('batch 99 stops after bounded repeated conflicts without clearing source error', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'EVENT_DOWN' }, { conflicts: 5 });
  await assert.rejects(() => r.service[method]('u1', 'm1'), error => error.code === 'MISSION_CONTROL_RECOVERY_STATUS_VIEW_INTEGRITY_ORPHANED_ERROR_REPAIR_OBSERVABILITY_VERSION_CONFLICT');
  assert.equal(r.store.current()[sourceErrorKey], 'EVENT_DOWN');
  assert.equal(r.store.current()[pendingKey] ?? null, null);
  assert.equal(r.store.writes(), 2);
  assert.equal(r.emissions(), 0);
});

test('batch 99 remains owner-scoped', async () => {
  const r = runtime({ ...base, [sourceErrorKey]: 'EVENT_DOWN' });
  await assert.rejects(() => r.service[method]('u2', 'm1'), error => error.code === 'MISSION_NOT_FOUND');
  assert.equal(r.store.writes(), 0);
  assert.equal(r.emissions(), 0);
});

test('batch 99 is exposed through the application boundary', async () => {
  const source = await fs.readFile(new URL('../../apps/agentic/backend/application.js', import.meta.url), 'utf8');
  assert.ok(source.includes(`${boundary}:missionControl.${method}`));
});
