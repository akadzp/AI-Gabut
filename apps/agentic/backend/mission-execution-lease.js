import { randomUUID } from "node:crypto";

function leaseError(code, message, details = undefined) {
  return Object.assign(new Error(message), { code, ...(details === undefined ? {} : { details }) });
}

/**
 * Durable owner-scoped lease primitive. Stores that implement mutateOwned make
 * acquisition/renew/release atomic across processes; older test adapters retain
 * a compatibility fallback without claiming cross-process guarantees.
 */
export function createMissionExecutionLease({
  leaseStore,
  clock = () => new Date().toISOString(),
  leaseMs = 55 * 60 * 1000,
  scope = "mission-leases",
  keyPrefix = "mission-lease"
} = {}) {
  if (!leaseStore || typeof leaseStore.getOwned !== "function" || typeof leaseStore.putOwned !== "function") {
    throw new TypeError("leaseStore must implement getOwned and putOwned");
  }
  if (!Number.isFinite(Number(leaseMs)) || Number(leaseMs) <= 0) throw new TypeError("leaseMs must be positive");

  const nowMs = () => {
    const value = clock();
    return typeof value === "number" ? value : Date.parse(value);
  };
  const key = (ownerId, resourceId) => `${keyPrefix}:${ownerId}:${resourceId}`;

  async function mutateLease(ownerId, resourceId, operation) {
    const recordId = key(ownerId, resourceId);
    if (typeof leaseStore.mutateOwned === "function") {
      return leaseStore.mutateOwned(scope, ownerId, recordId, operation);
    }
    const current = await leaseStore.getOwned(scope, ownerId, recordId);
    const decision = await operation(current);
    if (decision.write === false) return decision.result;
    if (decision.delete === true) {
      if (typeof leaseStore.removeOwned === "function") await leaseStore.removeOwned(scope, ownerId, recordId);
      return decision.result;
    }
    const saved = await leaseStore.putOwned(scope, ownerId, recordId, decision.value);
    return decision.result === undefined ? (saved ?? decision.value) : decision.result;
  }

  function assertArguments(ownerId, resourceId, executionId) {
    if (!ownerId || !resourceId || !executionId) throw leaseError("INVALID_ARGUMENT", "ownerId, resourceId and executionId are required");
  }

  async function acquire(ownerId, resourceId, executionId, { minFence = 1 } = {}) {
    assertArguments(ownerId, resourceId, executionId);
    const minimumFence = Math.max(1, Math.floor(Number(minFence) || 1));
    const now = nowMs();
    return mutateLease(ownerId, resourceId, current => {
      if (current && !current.releasedAt && Number(current.expiresAtMs) > now) {
        if (current.executionId === executionId) return { write: false, result: current };
        throw leaseError("LEASE_CONFLICT", "execution is already leased", { ownerId, resourceId, executionId: current.executionId, expiresAt: current.expiresAt });
      }
      const lease = {
        ownerId,
        resourceId,
        executionId,
        token: randomUUID(),
        fence: Math.max(Number(current?.fence) || 0, minimumFence - 1) + 1,
        acquiredAt: clock(),
        expiresAt: new Date(now + Number(leaseMs)).toISOString(),
        expiresAtMs: now + Number(leaseMs)
      };
      return { value: lease, result: lease };
    });
  }

  async function renew(ownerId, resourceId, executionId, token = null) {
    assertArguments(ownerId, resourceId, executionId);
    const now = nowMs();
    return mutateLease(ownerId, resourceId, current => {
      if (!current || current.executionId !== executionId || (token && current.token !== token)) {
        throw leaseError("LEASE_NOT_OWNER", "execution lease is not owned by this execution");
      }
      if (current.releasedAt || Number(current.expiresAtMs) <= now) {
        throw leaseError("LEASE_EXPIRED", "execution lease has expired");
      }
      const lease = {
        ...current,
        renewedAt: clock(),
        expiresAt: new Date(now + Number(leaseMs)).toISOString(),
        expiresAtMs: now + Number(leaseMs)
      };
      return { value: lease, result: lease };
    });
  }

  async function release(ownerId, resourceId, executionId, token = null) {
    assertArguments(ownerId, resourceId, executionId);
    return mutateLease(ownerId, resourceId, current => {
      if (!current) return { write: false, result: { released: false } };
      if (current.executionId !== executionId || (token && current.token !== token)) {
        throw leaseError("LEASE_NOT_OWNER", "execution lease is not owned by this execution");
      }
      if (current.releasedAt) return { write: false, result: { released: false } };
      const lease = { ...current, releasedAt: clock(), expiresAtMs: 0 };
      return { value: lease, result: { released: true } };
    });
  }

  async function assertOwned(ownerId, resourceId, executionId, token = null) {
    assertArguments(ownerId, resourceId, executionId);
    const current = await leaseStore.getOwned(scope, ownerId, key(ownerId, resourceId));
    if (!current || current.executionId !== executionId || (token && current.token !== token)) {
      throw leaseError("LEASE_NOT_OWNER", "execution lease is not owned by this execution");
    }
    if (current.releasedAt || Number(current.expiresAtMs) <= nowMs()) {
      throw leaseError("LEASE_EXPIRED", "execution lease has expired");
    }
    return current;
  }

  async function inspect(ownerId, resourceId) {
    if (!ownerId || !resourceId) throw leaseError("INVALID_ARGUMENT", "ownerId and resourceId are required");
    const current = await leaseStore.getOwned(scope, ownerId, key(ownerId, resourceId));
    if (!current) return { exists: false, active: false, expired: false, released: false, executionId: null, fence: 0, expiresAt: null, expiresAtMs: 0, releasedAt: null };
    const released = Boolean(current.releasedAt);
    const expired = !released && Number(current.expiresAtMs) <= nowMs();
    return {
      exists: true,
      active: !released && !expired,
      expired,
      released,
      executionId: current.executionId || null,
      fence: Math.max(0, Number(current.fence) || 0),
      expiresAt: current.expiresAt || null,
      expiresAtMs: Number(current.expiresAtMs) || 0,
      releasedAt: current.releasedAt || null
    };
  }

  return Object.freeze({ acquire, renew, release, assertOwned, inspect, leaseMs: Number(leaseMs), heartbeatMs: Math.max(5, Math.floor(Number(leaseMs) / 3)) });
}

export function createWorkExecutionLease(options = {}) {
  return createMissionExecutionLease({
    ...options,
    scope: "work-execution-leases",
    keyPrefix: "work-execution-lease"
  });
}
