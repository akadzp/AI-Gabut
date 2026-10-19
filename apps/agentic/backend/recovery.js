import { randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const RECOVERABLE_EXECUTION = new Set(["running", "waiting_approval"]);
const TERMINAL = new Set(["completed", "failed", "cancelled", "stopped", "max_turns"]);
const WORK_TERMINAL = new Set(["completed", "failed", "cancelled", "stopped"]);
const STALE_AFTER_MS = 15 * 60 * 1000;
const clean = (value, max = 1000) => String(value ?? "").slice(0, max);

function recoveryMeta(execution, reason, detectedAt, staleAfterMs, extra = {}) {
  return {
    status: "interrupted",
    recoverable: true,
    reason,
    detectedAt,
    staleAfterMs,
    lastCheckpoint: execution.checkpoint || execution.recovery?.lastCheckpoint || null,
    lastActivityAt: execution.updatedAt || execution.startedAt || null,
    resumeCount: Number(execution.recovery?.resumeCount || 0),
    ...extra
  };
}

function isVersionConflict(error) {
  return ["VERSION_CONFLICT", "STATE_VERSION_CONFLICT"].includes(error?.code);
}

export function createRecoveryService({ store, work = null, workExecutionLeaseService = null } = {}) {
  if (!store?.listExecutions || !store?.putExecution || !store?.getExecution) {
    throw new TypeError("Recovery service membutuhkan execution store");
  }

  async function saveWorkRecovery(ownerId, workId, recovery, fence = null, recoveryExecutionId = null) {
    if (!store.getWork || !store.putWork) return null;
    for (let attempt = 0; attempt < 4; attempt++) {
      const current = work?.raw ? await work.raw(ownerId, workId) : await store.getWork(ownerId, workId);
      if (!current) return null;
      if (WORK_TERMINAL.has(current.state)) return current;
      if (fence != null && (Number(current.executionLeaseFence) !== Number(fence) || current.executionLeaseId !== recoveryExecutionId)) {
        throw new AgenticError("WORK_EXECUTION_LEASE_LOST", "Recovery kehilangan fencing authority sebelum menyimpan metadata Work", 409, {
          expectedFence: fence,
          currentFence: Number(current.executionLeaseFence) || 0
        });
      }
      const existing = current.result?.recovery;
      if (existing?.status === "interrupted" && existing?.executionId === recovery.executionId && existing?.detectedAt === recovery.detectedAt) return current;
      const next = {
        ...current,
        result: { ...(current.result || {}), recovery },
        updatedAt: recovery.detectedAt
      };
      try {
        return await store.putWork(ownerId, next, { overwrite: true, expectedVersion: current._storage?.version });
      } catch (error) {
        if (!isVersionConflict(error) || attempt === 3) throw error;
      }
    }
    return null;
  }

  async function settleTask(ownerId, taskId, status, timestamp, reason = null, { force = false } = {}) {
    if (!taskId || !store.getTask || !store.putTask) return null;
    for (let attempt = 0; attempt < 4; attempt++) {
      const task = await store.getTask(ownerId, taskId);
      if (!task || (TERMINAL.has(task.status) && !force)) return task;
      if (task.status === status) return task;
      try {
        return await store.putTask(ownerId, {
          ...task,
          status,
          error: status === "paused" ? null : clean(reason || status, 1000),
          finishedAt: status === "paused" ? null : (task.finishedAt || timestamp),
          updatedAt: timestamp
        }, { overwrite: true, expectedVersion: task._storage?.version });
      } catch (error) {
        if (!isVersionConflict(error) || attempt === 3) throw error;
      }
    }
    return null;
  }

  async function updateExecutionRecovery(ownerId, execution, status, recovery, timestamp, reason = null) {
    for (let attempt = 0; attempt < 4; attempt++) {
      const latest = await store.getExecution(ownerId, execution.id);
      if (!latest) return null;
      if (TERMINAL.has(latest.status)) return null;
      if (!RECOVERABLE_EXECUTION.has(latest.status) && latest.recovery?.status !== "interrupted") return null;
      const next = {
        ...latest,
        status,
        recovery,
        recoveryCheckpoint: latest.checkpoint || latest.recoveryCheckpoint || null,
        recoverable: status === "paused",
        error: status === "paused" ? null : clean(reason || latest.error || status, 1000),
        finishedAt: status === "paused" ? null : (latest.finishedAt || timestamp),
        updatedAt: timestamp
      };
      try {
        return await store.putExecution(ownerId, next, { overwrite: true, expectedVersion: latest._storage?.version });
      } catch (error) {
        if (!isVersionConflict(error) || attempt === 3) throw error;
      }
    }
    return null;
  }

  async function recoverLegacy(owner, execution, staleAfterMs, detectedAt) {
    const workBound = Boolean(execution.workId && store.getWork && store.putWork);
    const interrupted = {
      ...execution,
      status: workBound ? "paused" : "interrupted",
      recovery: recoveryMeta(execution, "runtime-restart-or-stale", detectedAt, staleAfterMs),
      recoveryCheckpoint: execution.checkpoint || null,
      recoverable: true,
      updatedAt: detectedAt
    };
    await store.putExecution(owner, interrupted, { expectedVersion: execution._storage?.version });

    if (execution.workId && store.getWork && store.putWork) {
      const currentWork = await store.getWork(owner, execution.workId);
      if (currentWork && ["running", "waiting_approval"].includes(currentWork.state)) {
        const next = {
          ...currentWork,
          state: "paused",
          result: {
            ...(currentWork.result || {}),
            recovery: {
              status: "interrupted", recoverable: true, reason: "runtime-restart-or-stale",
              executionId: execution.id, detectedAt, lastCheckpoint: execution.checkpoint || null,
              resumeCount: Number(currentWork.result?.recovery?.resumeCount || 0)
            }
          },
          updatedAt: detectedAt
        };
        await store.putWork(owner, next, { overwrite: true, expectedVersion: currentWork._storage?.version });
      }
    }
    if (execution.taskId) await settleTask(owner, execution.taskId, "paused", detectedAt);
    return interrupted;
  }

  async function reconcileWithLease(ownerId, candidate, staleAfterMs, detectedAt, { stale = true } = {}) {
    if (!candidate.workId || !workExecutionLeaseService) return recoverLegacy(ownerId, candidate, staleAfterMs, detectedAt);
    const workId = candidate.workId;
    const observedWork = store.getWork ? await store.getWork(ownerId, workId) : null;
    const minFence = Math.max(1, (Number(observedWork?.executionLeaseFence) || 0) + 1);
    const recoveryExecutionId = `recovery:${String(candidate.id).slice(0, 120)}:${randomUUID()}`;
    let recoveryLease;
    try {
      recoveryLease = await workExecutionLeaseService.acquire(ownerId, workId, recoveryExecutionId, { minFence });
    } catch (error) {
      if (error?.code === "LEASE_CONFLICT") return null;
      throw error;
    }

    try {
      const latest = await store.getExecution(ownerId, candidate.id);
      if (!latest || TERMINAL.has(latest.status) || !RECOVERABLE_EXECUTION.has(latest.status)) return null;
      const timestamp = new Date().toISOString();
      let currentWork = store.getWork ? await store.getWork(ownerId, workId) : null;
      let targetStatus = "paused";
      let recoverable = true;
      let reason = stale ? "runtime-restart-or-expired-lease" : "lease-loss-reconciled";

      if (!currentWork) {
        targetStatus = "failed";
        recoverable = false;
        reason = "work-missing";
      } else if (WORK_TERMINAL.has(currentWork.state)) {
        targetStatus = currentWork.state;
        recoverable = false;
        reason = "work-terminal-state-reconciled";
      } else if (!["running", "waiting_approval", "paused"].includes(currentWork.state)) {
        targetStatus = "failed";
        recoverable = false;
        reason = "work-state-mismatch";
      }

      if (currentWork && !WORK_TERMINAL.has(currentWork.state)) {
        if (work?.claimExecution) {
          await work.claimExecution(ownerId, workId, { executionId: recoveryExecutionId, fence: recoveryLease.fence });
          currentWork = await (work.raw ? work.raw(ownerId, workId) : store.getWork(ownerId, workId));
          if (["running", "waiting_approval"].includes(currentWork.state)) {
            await work.transition(ownerId, workId, "paused", { executionLeaseFence: recoveryLease.fence });
            currentWork = await (work.raw ? work.raw(ownerId, workId) : store.getWork(ownerId, workId));
          }
        } else if (["running", "waiting_approval"].includes(currentWork.state)) {
          const next = { ...currentWork, state: "paused", updatedAt: timestamp };
          await store.putWork(ownerId, next, { overwrite: true, expectedVersion: currentWork._storage?.version });
          currentWork = await store.getWork(ownerId, workId);
        }
      }

      // A concurrent user control may have made Work terminal after the first read.
      currentWork = store.getWork ? await store.getWork(ownerId, workId) : currentWork;
      if (currentWork && WORK_TERMINAL.has(currentWork.state)) {
        targetStatus = currentWork.state;
        recoverable = false;
        reason = "work-terminal-state-reconciled";
      } else if (currentWork && currentWork.state === "paused") {
        targetStatus = "paused";
        recoverable = true;
      }

      const recovery = recoverable
        ? recoveryMeta(latest, reason, timestamp, staleAfterMs, { leaseFence: recoveryLease.fence, leaseRecoveredAt: timestamp })
        : {
            status: "resolved", recoverable: false, reason, detectedAt: timestamp, staleAfterMs,
            lastCheckpoint: latest.checkpoint || latest.recovery?.lastCheckpoint || null,
            lastActivityAt: latest.updatedAt || latest.startedAt || null,
            resumeCount: Number(latest.recovery?.resumeCount || 0), outcome: targetStatus,
            leaseFence: recoveryLease.fence, leaseRecoveredAt: timestamp
          };

      const updatedExecution = await updateExecutionRecovery(ownerId, latest, targetStatus, recovery, timestamp,
        targetStatus === "paused" ? null : reason);
      if (!updatedExecution) return null;

      const taskStatus = targetStatus === "paused" ? "paused" : (WORK_TERMINAL.has(targetStatus) ? targetStatus : "failed");
      if (latest.taskId) await settleTask(ownerId, latest.taskId, taskStatus, timestamp, reason, { force: true });

      if (currentWork && !WORK_TERMINAL.has(currentWork.state) && targetStatus === "paused") {
        await saveWorkRecovery(ownerId, workId, {
          status: "interrupted", recoverable: true, reason, executionId: latest.id, detectedAt: timestamp,
          lastCheckpoint: latest.checkpoint || latest.recovery?.lastCheckpoint || null,
          resumeCount: Number(currentWork.result?.recovery?.resumeCount || latest.recovery?.resumeCount || 0),
          leaseFence: recoveryLease.fence
        }, recoveryLease.fence, recoveryExecutionId);
      }

      return { ...updatedExecution, recovery };
    } finally {
      try { await workExecutionLeaseService.release(ownerId, workId, recoveryExecutionId, recoveryLease.token); }
      catch { /* a newer owner may already have reclaimed the lease */ }
    }
  }

  async function scan(ownerId = null, options = {}) {
    const staleAfterMs = Math.max(1000, Number(options.staleAfterMs) || STALE_AFTER_MS);
    const owners = ownerId ? [ownerId] : await store.listUsers().then(items => items.map(item => item.id));
    const found = [];
    const now = Date.now();

    for (const owner of owners) {
      for (const execution of await store.listExecutions(owner)) {
        if (!RECOVERABLE_EXECUTION.has(execution.status)) continue;
        const updated = Date.parse(execution.updatedAt || execution.startedAt || "");
        const stale = !Number.isFinite(updated) || now - updated >= staleAfterMs;
        if (!stale && workExecutionLeaseService?.inspect && execution.workId) {
          const lease = await workExecutionLeaseService.inspect(owner, execution.workId);
          const linkedWork = store.getWork ? await store.getWork(owner, execution.workId) : null;
          const activeRunLostLease = execution.status === "running" && !lease.active;
          const approvalStateMismatch = execution.status === "waiting_approval" && linkedWork?.state !== "waiting_approval";
          if (!activeRunLostLease && !approvalStateMismatch) continue;
        } else if (!stale) {
          continue;
        }
        const detectedAt = new Date().toISOString();
        const reconciled = await reconcileWithLease(owner, execution, staleAfterMs, detectedAt, { stale });
        if (reconciled) found.push({ ownerId: owner, execution: reconciled });
      }
    }
    return found;
  }

  async function list(ownerId) {
    const executions = await store.listExecutions(ownerId);
    const works = store.listWorks ? await store.listWorks(ownerId) : [];
    return works
      .filter(item => item.result?.recovery?.status === "interrupted")
      .map(item => ({
        workId: item.id,
        state: item.state,
        objective: item.objective,
        recovery: item.result.recovery,
        updatedAt: item.updatedAt,
        execution: executions.find(execution => execution.id === item.result.recovery.executionId) || null
      }))
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  }

  async function get(ownerId, id) {
    const execution = await store.getExecution(ownerId, id);
    if (!execution) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404);
    if (!execution.recoverable && !execution.recovery?.recoverable) {
      throw new AgenticError("EXECUTION_NOT_RECOVERABLE", "Execution tidak berada pada recovery state", 409);
    }
    return execution;
  }

  async function prepareResume(ownerId, id) {
    const execution = await get(ownerId, id);
    if (!execution.workId) throw new AgenticError("RECOVERY_WORK_REQUIRED", "Recovery execution tidak memiliki Work", 409);
    const currentWork = store.getWork ? await store.getWork(ownerId, execution.workId) : null;
    if (!currentWork) throw new AgenticError("WORK_NOT_FOUND", "Work recovery tidak ditemukan", 404);
    if (currentWork.state !== "paused") throw new AgenticError("WORK_NOT_RESUMABLE", "Work recovery harus berada pada state paused", 409);

    const timestamp = new Date().toISOString();
    const next = {
      ...execution,
      status: "paused",
      recovery: {
        ...execution.recovery,
        resumeCount: Number(execution.recovery?.resumeCount || 0) + 1,
        lastCheckpoint: execution.checkpoint || execution.recovery?.lastCheckpoint || null,
        lastResumePreparedAt: timestamp
      },
      updatedAt: timestamp
    };
    await store.putExecution(ownerId, next, { overwrite: true, expectedVersion: execution._storage?.version });
    return { work: currentWork, execution: next };
  }

  async function clear(ownerId, id, outcome = "completed") {
    const execution = await store.getExecution(ownerId, id);
    if (!execution) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404);
    const timestamp = new Date().toISOString();
    const next = {
      ...execution,
      recovery: { ...(execution.recovery || {}), status: "resolved", recoverable: false, outcome, resolvedAt: timestamp },
      updatedAt: timestamp
    };
    return store.putExecution(ownerId, next, { overwrite: true, expectedVersion: execution._storage?.version });
  }

  async function markResuming(ownerId, id) {
    const execution = await get(ownerId, id);
    const timestamp = new Date().toISOString();
    const next = {
      ...execution,
      status: "running",
      recoverable: false,
      recovery: { ...(execution.recovery || {}), status: "resuming", recoverable: false, lastResumedAt: timestamp },
      updatedAt: timestamp
    };
    return store.putExecution(ownerId, next, { overwrite: true, expectedVersion: execution._storage?.version });
  }

  return Object.freeze({ scan, list, get, prepareResume, markResuming, clear, staleAfterMs: STALE_AFTER_MS, recoverableStatuses: [...RECOVERABLE_EXECUTION] });
}
