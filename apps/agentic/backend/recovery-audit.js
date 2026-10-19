import { AgenticError } from "./errors.js";

const ACTIVE_EXECUTION = new Set(["running", "waiting_approval"]);
const TERMINAL = new Set(["completed", "failed", "cancelled", "stopped", "max_turns"]);
const TERMINAL_WORK = new Set(["completed", "failed", "cancelled", "stopped"]);
const MAX_ID = 200;
const MAX_MESSAGE = 240;

const bounded = (value, max = MAX_ID) => String(value ?? "").slice(0, max);
const statusForTask = status => {
  if (status === "interrupted") return "paused";
  return status;
};

/**
 * Read-only, owner-scoped cross-record integrity audit for Work recovery state.
 * It deliberately returns identifiers and bounded issue metadata only; it never
 * persists repairs, changes lease state, or exposes lease tokens.
 */
export function createRecoveryAuditService({ store, workExecutionLeaseService = null, clock = () => new Date().toISOString() } = {}) {
  if (!store?.listWorks || !store?.listExecutions || !store?.listTasks) {
    throw new TypeError("Recovery audit membutuhkan listWorks, listExecutions, dan listTasks");
  }

  async function inspect(ownerId, options = {}) {
    if (typeof ownerId !== "string" || !ownerId.trim()) {
      throw new AgenticError("RECOVERY_AUDIT_OWNER_REQUIRED", "Owner wajib ditentukan untuk audit recovery", 400);
    }
    const limit = Math.max(1, Math.min(500, Math.floor(Number(options.limit) || 250)));
    const [allWorks, allExecutions, allTasks] = await Promise.all([
      store.listWorks(ownerId), store.listExecutions(ownerId), store.listTasks(ownerId)
    ]);
    const truncated = allWorks.length > limit || allExecutions.length > limit || allTasks.length > limit;
    const works = allWorks.slice().sort((a, b) => bounded(a.id).localeCompare(bounded(b.id))).slice(0, limit);
    const executions = allExecutions.slice().sort((a, b) => bounded(a.id).localeCompare(bounded(b.id))).slice(0, limit);
    const tasks = allTasks.slice().sort((a, b) => bounded(a.id).localeCompare(bounded(b.id))).slice(0, limit);
    // Keep complete lookup maps so a limited audit never mislabels a record
    // outside the inspected page as missing merely because it was not selected.
    const workById = new Map(allWorks.map(item => [item.id, item]));
    const executionById = new Map(allExecutions.map(item => [item.id, item]));
    const taskById = new Map(allTasks.map(item => [item.id, item]));
    const issues = [];
    const add = (code, severity, entityType, entityId, relatedId, message) => {
      issues.push({
        code: bounded(code, 80), severity,
        entityType: bounded(entityType, 40), entityId: bounded(entityId),
        relatedId: relatedId == null ? null : bounded(relatedId),
        message: bounded(message, MAX_MESSAGE)
      });
    };

    for (const execution of executions) {
      const work = execution.workId ? workById.get(execution.workId) : null;
      const task = execution.taskId ? taskById.get(execution.taskId) : null;
      if (execution.workId && !work) {
        add("EXECUTION_WORK_MISSING", "error", "execution", execution.id, execution.workId, "Execution references a Work that is not present in the audited owner scope.");
      }
      if (execution.taskId && !task) {
        add("EXECUTION_TASK_MISSING", "error", "execution", execution.id, execution.taskId, "Execution references a task that is not present in the audited owner scope.");
      }
      if (task && execution.workId && task.workId && task.workId !== execution.workId) {
        add("EXECUTION_TASK_WORK_MISMATCH", "error", "execution", execution.id, task.id, "Execution and linked task reference different Works.");
      }
      if (work && ACTIVE_EXECUTION.has(execution.status)) {
        const expectedWorkState = execution.status;
        if (work.state !== expectedWorkState && work.state !== "paused") {
          add("EXECUTION_WORK_STATUS_MISMATCH", TERMINAL_WORK.has(work.state) ? "error" : "warning", "execution", execution.id, work.id, `Execution status ${execution.status} conflicts with Work state ${work.state}.`);
        } else if (work.state === "paused") {
          add("ACTIVE_EXECUTION_FOR_PAUSED_WORK", "warning", "execution", execution.id, work.id, "Execution is active while its Work is paused.");
        }
      }
      if (task && execution.status && task.status) {
        const expectedTaskStatus = statusForTask(execution.status);
        if (task.status !== expectedTaskStatus && !(TERMINAL.has(execution.status) && TERMINAL.has(task.status) && execution.status === task.status)) {
          const bothRecoverable = ["paused", "interrupted"].includes(execution.status) && task.status === "paused";
          if (!bothRecoverable) {
            add("EXECUTION_TASK_STATUS_MISMATCH", "warning", "execution", execution.id, task.id, `Execution status ${execution.status} conflicts with task status ${task.status}.`);
          }
        }
      }
      if (execution.recoverable && !execution.recovery) {
        add("RECOVERY_METADATA_MISSING", "warning", "execution", execution.id, execution.workId || null, "Execution is marked recoverable but has no recovery metadata.");
      }
      if (execution.recovery?.status === "interrupted" && execution.status !== "paused") {
        add("RECOVERY_EXECUTION_STATUS_MISMATCH", "warning", "execution", execution.id, execution.workId || null, "Interrupted recovery metadata should accompany a paused execution.");
      }
      if (execution.recovery?.leaseFence != null && !Number.isSafeInteger(Number(execution.recovery.leaseFence))) {
        add("RECOVERY_FENCE_INVALID", "error", "execution", execution.id, execution.workId || null, "Recovery lease fence is not a safe integer.");
      }
      if (execution.status === "running" && execution.workId && workExecutionLeaseService?.inspect) {
        const lease = await workExecutionLeaseService.inspect(ownerId, execution.workId);
        if (!lease.active) {
          add("EXECUTION_RUNNING_WITHOUT_ACTIVE_LEASE", "error", "execution", execution.id, execution.workId, "Execution is running but its Work has no active durable lease.");
        } else if (lease.executionId !== execution.id) {
          add("EXECUTION_LEASE_OWNER_MISMATCH", "error", "execution", execution.id, lease.executionId, "Active durable lease belongs to a different execution.");
        }
      }
    }

    const linkedExecutionTaskIds = new Set(allExecutions.map(item => item.taskId).filter(Boolean));
    for (const task of tasks) {
      if (task.workId && !workById.has(task.workId)) {
        add("TASK_WORK_MISSING", "error", "task", task.id, task.workId, "Task references a Work that is not present in the audited owner scope.");
      }
      if (["running", "waiting_approval"].includes(task.status) && !linkedExecutionTaskIds.has(task.id)) {
        add("ACTIVE_TASK_WITHOUT_EXECUTION", "warning", "task", task.id, task.workId || null, "Task is active but no execution references it.");
      }
    }

    for (const work of works) {
      for (const taskId of Array.isArray(work.taskIds) ? work.taskIds : []) {
        if (!taskById.has(taskId)) add("WORK_TASK_REFERENCE_MISSING", "warning", "work", work.id, taskId, "Work references a task that is not present in the audited owner scope.");
      }
      for (const executionId of Array.isArray(work.executionIds) ? work.executionIds : []) {
        if (!executionById.has(executionId)) add("WORK_EXECUTION_REFERENCE_MISSING", "warning", "work", work.id, executionId, "Work references an execution that is not present in the audited owner scope.");
      }
      const recovery = work.result?.recovery;
      if (recovery?.status === "interrupted") {
        const executionId = recovery.executionId;
        const execution = executionId ? executionById.get(executionId) : null;
        if (!execution) {
          add("WORK_RECOVERY_EXECUTION_MISSING", "error", "work", work.id, executionId || null, "Work recovery metadata references an execution that is not present in the audited owner scope.");
        } else {
          if (execution.workId && execution.workId !== work.id) {
            add("WORK_RECOVERY_EXECUTION_WORK_MISMATCH", "error", "work", work.id, execution.id, "Work recovery metadata points to an execution belonging to another Work.");
          }
          if (execution.recovery?.status && execution.recovery.status !== "interrupted" && execution.recovery.status !== "resuming") {
            add("WORK_RECOVERY_METADATA_MISMATCH", "warning", "work", work.id, execution.id, "Work and execution recovery metadata disagree on recovery status.");
          }
        }
        if (recovery.leaseFence != null && Number(work.executionLeaseFence || 0) < Number(recovery.leaseFence)) {
          add("WORK_RECOVERY_FENCE_REGRESSION", "error", "work", work.id, executionId || null, "Work fencing number is lower than its recorded recovery fencing number.");
        }
      }

      if (work.state === "running" && workExecutionLeaseService?.inspect) {
        const lease = await workExecutionLeaseService.inspect(ownerId, work.id);
        if (!lease.active) {
          add("WORK_RUNNING_WITHOUT_ACTIVE_LEASE", "error", "work", work.id, null, "Work is running but has no active durable execution lease.");
        } else {
          if (!work.executionLeaseId || work.executionLeaseId !== lease.executionId) {
            add("WORK_LEASE_OWNER_MISMATCH", "warning", "work", work.id, lease.executionId, "Active durable lease owner does not match the Work execution lease reference.");
          }
          if (Number(work.executionLeaseFence || 0) !== Number(lease.fence || 0)) {
            add("WORK_LEASE_FENCE_MISMATCH", "warning", "work", work.id, lease.executionId, "Active durable lease fencing number does not match the Work record.");
          }
        }
      }
      if (TERMINAL_WORK.has(work.state) && workExecutionLeaseService?.inspect) {
        const lease = await workExecutionLeaseService.inspect(ownerId, work.id);
        if (lease.active) add("TERMINAL_WORK_HAS_ACTIVE_LEASE", "warning", "work", work.id, lease.executionId, "Terminal Work still has an active durable execution lease.");
      } else if (work.state === "paused" && workExecutionLeaseService?.inspect) {
        const lease = await workExecutionLeaseService.inspect(ownerId, work.id);
        if (lease.active) add("PAUSED_WORK_HAS_ACTIVE_LEASE", "warning", "work", work.id, lease.executionId, "Paused Work still has an active durable execution lease.");
      }
    }

    if (truncated) {
      add("AUDIT_RESULT_TRUNCATED", "warning", "audit", ownerId, null, `Audit limited to ${limit} records per entity type; one or more collections contain additional records.`);
    }

    const severityRank = { error: 0, warning: 1, info: 2 };
    issues.sort((a, b) => (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9)
      || a.code.localeCompare(b.code) || a.entityType.localeCompare(b.entityType)
      || a.entityId.localeCompare(b.entityId) || String(a.relatedId || "").localeCompare(String(b.relatedId || "")));
    const counts = { error: 0, warning: 0, info: 0 };
    for (const issue of issues) counts[issue.severity] = (counts[issue.severity] || 0) + 1;
    return {
      ownerId: bounded(ownerId), checkedAt: bounded(clock(), 64), readOnly: true,
      truncated, limits: { recordsPerEntity: limit },
      totals: { works: allWorks.length, executions: allExecutions.length, tasks: allTasks.length },
      audited: { works: works.length, executions: executions.length, tasks: tasks.length },
      status: counts.error ? "unhealthy" : counts.warning ? "degraded" : "healthy",
      issueCount: issues.length, counts, issues
    };
  }

  return Object.freeze({ inspect, audit: inspect });
}
