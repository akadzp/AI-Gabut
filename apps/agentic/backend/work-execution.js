import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";
import { createExecutionId } from "../../../core/agent-engine/reliability/runtime.js";

const now = () => new Date().toISOString();
const clean = (v, max = 12000) => String(v ?? "").trim().slice(0, max);
const TERMINAL = new Set(["completed", "failed", "cancelled", "stopped"]);
const CONTROLLED_STATES = new Set(["paused", "cancelled", "stopped"]);
const runKey = (ownerId, workId) => `${String(ownerId)}\u0000${String(workId)}`;

async function runWithAbort(runner, input, signal) {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : Object.assign(new Error("Execution dibatalkan"), { code: "AGENT_EXECUTION_CANCELLED" });
  if (!signal) return runner(input);
  let abortListener;
  const aborted = new Promise((_, reject) => {
    abortListener = () => reject(signal.reason instanceof Error ? signal.reason : Object.assign(new Error("Execution dibatalkan"), { code: "AGENT_EXECUTION_CANCELLED" }));
    signal.addEventListener("abort", abortListener, { once: true });
  });
  try {
    const operation = Promise.resolve().then(() => {
      if (signal.aborted) throw signal.reason instanceof Error ? signal.reason : Object.assign(new Error("Execution dibatalkan"), { code: "AGENT_EXECUTION_CANCELLED" });
      return runner({ ...input, signal });
    });
    return await Promise.race([operation, aborted]);
  } finally {
    signal.removeEventListener("abort", abortListener);
  }
}

export function createWorkExecutionService({ store, work, realtime = null, agentRunner, planner, approvalAuthority = null, approvalPolicy = null, executionLeaseService = null } = {}) {
  if (!store?.putTask || !store?.putExecution || !store?.getExecution || !store?.listActivities || !work?.raw || !work?.get || !work?.transition || typeof agentRunner !== "function" || typeof planner !== "function") {
    throw new TypeError("Work execution membutuhkan store, work, runner, dan planner contract");
  }

  const activeRuns = new Map();

  async function record(ownerId, event) {
    const item = { id: createId("activity"), ownerId, type: "work_execution", action: clean(event.action || "activity", 160), status: clean(event.status || "running", 80), label: clean(event.label || event.action || "Work activity", 300), meta: event.meta && typeof event.meta === "object" ? event.meta : {}, error: event.error ? clean(event.error, 1000) : null, workId: event.workId || null, taskId: event.taskId || null, executionId: event.executionId || null, sessionId: null, createdAt: now() };
    await store.putActivity(ownerId, item, { overwrite: false });
    if (realtime?.publish) await realtime.publish(ownerId, item);
    return item;
  }
  async function settleOtherRuns(ownerId, workId, status, { excludeExecutionId = null, reason = null } = {}) {
    const executions = (await store.listExecutions(ownerId)).filter(item => item.workId === workId && item.id !== excludeExecutionId && !TERMINAL.has(item.status));
    for (const item of executions) {
      const latest = await store.getExecution(ownerId, item.id);
      if (!latest || TERMINAL.has(latest.status) || latest.status === status) continue;
      const timestamp = now();
      await store.putExecution(ownerId, {
        ...latest,
        status,
        error: status === "paused" ? null : clean(reason || status, 1000),
        finishedAt: status === "paused" ? null : (latest.finishedAt || timestamp),
        updatedAt: timestamp
      }, { overwrite: true, expectedVersion: latest._storage?.version });
      if (latest.taskId && store.getTask) {
        const task = await store.getTask(ownerId, latest.taskId);
        if (task && !TERMINAL.has(task.status) && task.status !== status) {
          await store.putTask(ownerId, { ...task, status, updatedAt: timestamp }, { overwrite: true, expectedVersion: task._storage?.version });
        }
      }
    }
  }

  async function plan(ownerId, workId, options = {}) {
    const current = await work.raw(ownerId, workId);
    if (TERMINAL.has(current.state)) throw new AgenticError("WORK_TERMINAL", "Work terminal tidak dapat direncanakan ulang", 409);
    const planned = await planner({ prompt: clean(options.instruction || current.objective, 12000), objective: current.objective, provider: options.provider, model: options.model, conversation: Array.isArray(options.conversation) ? options.conversation : [], maxSteps: 20 });
    const steps = (Array.isArray(planned) ? planned : planned?.steps || []).slice(0, 20).map((step, index) => ({ id: clean(step?.id || `step-${index + 1}`, 120), goal: clean(step?.goal || step?.title || "Work step", 1000), tools: Array.isArray(step?.tools) ? step.tools.map(x => clean(x, 80)).slice(0, 20) : [], status: "planned", order: index + 1 }));
    if (!steps.length) throw new AgenticError("WORK_PLAN_EMPTY", "Planner tidak menghasilkan langkah", 500);
    const nextPlan = { version: 1, status: "ready", objective: current.objective, steps, currentStepId: null, createdAt: now(), updatedAt: now() };
    await work.update(ownerId, workId, { plan: nextPlan });
    const refreshed = await work.raw(ownerId, workId);
    if (refreshed.state === "draft") await work.transition(ownerId, workId, "ready");
    await record(ownerId, { workId, action: "planning", status: "completed", label: "Work plan tersimpan", meta: { stepCount: steps.length } });
    return work.get(ownerId, workId);
  }

  async function ensureRunning(ownerId, workId, runEntry) {
    const fence = runEntry?.lease?.fence;
    if (executionLeaseService && runEntry?.lease) {
      await work.claimExecution(ownerId, workId, { executionId: runEntry.executionId, fence });
    }
    let current = await work.raw(ownerId, workId);
    const transitionMeta = fence == null ? {} : { executionLeaseFence: fence };
    if (current.state === "draft") { await work.transition(ownerId, workId, "ready", transitionMeta); current = await work.raw(ownerId, workId); }
    if (current.state === "paused") { await work.transition(ownerId, workId, "ready", transitionMeta); current = await work.raw(ownerId, workId); }
    if (current.state === "ready") { await work.transition(ownerId, workId, "running", transitionMeta); current = await work.raw(ownerId, workId); }
    if (current.state !== "running") throw new AgenticError("WORK_NOT_RUNNABLE", `Work tidak dapat dijalankan dari state ${current.state}`, 409, { state: current.state });
    return current;
  }

  async function runInternal(ownerId, workId, options = {}, runEntry) {
    const current = await ensureRunning(ownerId, workId, runEntry);
    const confirmed = await work.raw(ownerId, workId);
    if (confirmed.state !== "running") throw new AgenticError("WORK_NOT_RUNNABLE", `Work tidak dapat dijalankan dari state ${confirmed.state}`, 409, { state: confirmed.state });
    const timestamp = now();
    const task = { id: createId("task"), ownerId, workId, status: "running", title: current.objective.slice(0, 160), createdAt: timestamp, updatedAt: timestamp };
    const execution = { id: runEntry?.executionId || createExecutionId(), ownerId, workId, taskId: task.id, status: "running", prompt: current.objective, plan: current.plan || null, checkpoint: null, approval: null, result: null, error: null, startedAt: timestamp, updatedAt: timestamp, finishedAt: null };
    await store.putTask(ownerId, task, { overwrite: false });
    await store.putExecution(ownerId, execution, { overwrite: false });
    if (runEntry) runEntry.executionId = execution.id;
    const fenceOptions = runEntry?.lease?.fence == null ? {} : { executionLeaseFence: runEntry.lease.fence };
    await work.attachTask?.(ownerId, workId, task.id, fenceOptions);
    await work.attachExecution?.(ownerId, workId, execution.id, fenceOptions);
    await record(ownerId, { workId, taskId: task.id, executionId: execution.id, action: "execution_started", status: "running", label: "Work execution dimulai" });

    async function assertExecutionLease() {
      if (!executionLeaseService || !runEntry?.lease) return null;
      try {
        const currentLease = await executionLeaseService.assertOwned(ownerId, workId, execution.id, runEntry.lease.token);
        runEntry.lease = currentLease;
        return currentLease;
      } catch (error) {
        throw new AgenticError("WORK_EXECUTION_LEASE_LOST", "Work execution lease hilang atau kedaluwarsa; hasil run lama tidak akan dipersistenkan", 409, { causeCode: error?.code || "LEASE_NOT_OWNER" });
      }
    }

    async function updateExecution(patch) {
      await assertExecutionLease();
      const latest = await store.getExecution(ownerId, execution.id);
      if (!latest) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404);
      const next = { ...latest, ...patch, updatedAt: now() };
      await store.putExecution(ownerId, next, { overwrite: true, expectedVersion: latest._storage?.version });
      Object.assign(execution, next);
      return next;
    }
    const onActivity = async event => {
      if (options.signal?.aborted) return;
      try { await assertExecutionLease(); } catch (error) { if (!options.signal?.aborted) runEntry?.controller?.abort(error); return; }
      const currentWork = await work.raw(ownerId, workId);
      if (currentWork.state !== "running") return;
      const currentExecution = await store.getExecution(ownerId, execution.id);
      if (!currentExecution || ["completed", "failed", "cancelled", "stopped", "paused", "waiting_approval"].includes(currentExecution.status)) return;
      const action = clean(event?.action || "agent_activity", 160);
      await record(ownerId, { ...event, workId, taskId: task.id, executionId: execution.id, action });
      if (action === "checkpoint") await updateExecution({ checkpoint: event.meta || null });
      if (action === "planning" && event.status === "completed" && event.meta) await updateExecution({ plan: event.meta });
    };

    async function settleControlledState(result, error) {
      await assertExecutionLease();
      const latestWork = await work.raw(ownerId, workId);
      if (!CONTROLLED_STATES.has(latestWork.state)) return null;
      const status = latestWork.state;
      const timestamp = now();
      const latestExecution = await store.getExecution(ownerId, execution.id);
      if (latestExecution && (latestExecution.status !== status || (status !== "paused" && !latestExecution.finishedAt))) {
        await store.putExecution(ownerId, { ...latestExecution, status, error: status === "paused" ? null : clean(error?.message || result?.error?.message || result?.text || latestWork.result?.error || status, 1000), finishedAt: status === "paused" ? null : (latestExecution.finishedAt || timestamp), updatedAt: timestamp }, { overwrite: true, expectedVersion: latestExecution._storage?.version });
      }
      const savedTask = await store.getTask(ownerId, task.id);
      if (savedTask && savedTask.status !== status) await store.putTask(ownerId, { ...savedTask, status, updatedAt: timestamp }, { overwrite: true, expectedVersion: savedTask._storage?.version });
      await record(ownerId, { workId, taskId: task.id, executionId: execution.id, action: status === "paused" ? "execution_paused" : status === "cancelled" ? "execution_cancelled" : "execution_stopped", status, label: status === "paused" ? "Execution dijeda" : status === "cancelled" ? "Execution dibatalkan" : "Execution dihentikan", error: error?.message || null });
      return { work: await work.get(ownerId, workId), execution: await store.getExecution(ownerId, execution.id), result: result || { status, text: clean(error?.message || status, 1000) }, interrupted: true };
    }

    try {
      const result = await runWithAbort(agentRunner, { prompt: current.objective, provider: options.provider, model: options.model, conversation: Array.isArray(options.conversation) ? options.conversation : [], context: current.context || {}, plan: current.plan || null, approvalToken: options.approvalToken || null, principal: { userId: ownerId }, applicationId: "agentic", executionId: execution.id, agentExecutionId: execution.id, timeoutMs: options.timeoutMs, onActivity }, options.signal);
      await assertExecutionLease();
      const controlled = await settleControlledState(result, null);
      if (controlled) return controlled;
      const approval = result?.approval?.required ? result.approval : result?.approvalRequired ? result.approval : null;
      if (approval?.required && !options.approvalToken) {
        const pending = { ...approval, tool: clean(approval.tool, 120), input: approval.input && typeof approval.input === "object" ? approval.input : {}, reason: clean(approval.reason || "Tool memerlukan human approval", 1000), requestedAt: now() };
        await updateExecution({ status: "waiting_approval", approval: pending, result: null });
        await store.putTask(ownerId, { ...task, status: "waiting_approval", updatedAt: now() }, { overwrite: true, expectedVersion: (await store.getTask(ownerId, task.id))?._storage?.version });
        await work.transition(ownerId, workId, "waiting_approval", { result: { approval: pending }, ...fenceOptions });
        await record(ownerId, { workId, taskId: task.id, executionId: execution.id, action: "approval_required", status: "waiting", label: `Approval diperlukan · ${pending.tool}`, meta: { tool: pending.tool, reason: pending.reason } });
        return { work: await work.get(ownerId, workId), execution: await store.getExecution(ownerId, execution.id), result, approvalRequired: true };
      }
      const status = result?.execution?.status || result?.status || "completed";
      const terminal = status === "cancelled" ? "cancelled" : status === "stopped" || status === "max_turns" ? "stopped" : status === "failed" ? "failed" : "completed";
      const finishedAt = now();
      await updateExecution({ status: terminal, result: result?.text == null ? result : String(result.text).slice(0, 12000), error: terminal === "failed" ? clean(result?.error?.message || result?.execution?.error || result?.text || "Execution gagal", 2000) : null, finishedAt });
      const savedTask = await store.getTask(ownerId, task.id);
      await store.putTask(ownerId, { ...savedTask, status: terminal, updatedAt: finishedAt }, { overwrite: true, expectedVersion: savedTask?._storage?.version });
      const workBeforeFinish = await work.raw(ownerId, workId);
      await work.transition(ownerId, workId, terminal, { result: { ...(workBeforeFinish.result || {}), status: terminal, text: clean(result?.text || "", 12000), executionId: execution.id, plan: result?.plan || current.plan || null }, ...fenceOptions });
      await record(ownerId, { workId, taskId: task.id, executionId: execution.id, action: "execution_finished", status: terminal, label: terminal === "completed" ? "Work selesai" : `Work ${terminal}`, meta: { status: terminal } });
      return { work: await work.get(ownerId, workId), execution: await store.getExecution(ownerId, execution.id), result };
    } catch (error) {
      if (error?.code === "WORK_EXECUTION_LEASE_LOST") throw error;
      await assertExecutionLease();
      const controlled = await settleControlledState(null, error);
      if (controlled) return controlled;
      const latest = await store.getExecution(ownerId, execution.id);
      if (latest && !TERMINAL.has(latest.status)) await store.putExecution(ownerId, { ...latest, status: "failed", error: clean(error?.message || error, 2000), finishedAt: now(), updatedAt: now() }, { overwrite: true, expectedVersion: latest._storage?.version });
      const savedTask = await store.getTask(ownerId, task.id);
      if (savedTask && !TERMINAL.has(savedTask.status)) await store.putTask(ownerId, { ...savedTask, status: "failed", updatedAt: now() }, { overwrite: true, expectedVersion: savedTask._storage?.version });
      const latestWork = await work.raw(ownerId, workId);
      if (latestWork.state === "running") await work.transition(ownerId, workId, "failed", { error: clean(error?.message || error, 2000), ...fenceOptions });
      await record(ownerId, { workId, taskId: task.id, executionId: execution.id, action: "execution_failed", status: "failed", label: "Work execution gagal", error: clean(error?.message || error, 1000) });
      throw error;
    }
  }

  async function run(ownerId, workId, options = {}) {
    const key = runKey(ownerId, workId);
    if (activeRuns.has(key)) throw new AgenticError("WORK_EXECUTION_IN_PROGRESS", "Work ini sudah memiliki execution aktif", 409, { workId });
    const controller = new AbortController();
    const entry = { controller, executionId: createExecutionId(), lease: null, promise: null, heartbeat: null };
    const externalSignal = options.signal;
    let forwardAbort = null;
    let heartbeatBusy = false;
    if (externalSignal) {
      forwardAbort = () => controller.abort(externalSignal.reason instanceof Error ? externalSignal.reason : Object.assign(new Error("Execution dibatalkan oleh pemanggil"), { code: "AGENT_EXECUTION_CANCELLED" }));
      if (externalSignal.aborted) forwardAbort();
      else externalSignal.addEventListener("abort", forwardAbort, { once: true });
    }
    activeRuns.set(key, entry);
    try {
      if (executionLeaseService) {
        try {
          entry.lease = await executionLeaseService.acquire(ownerId, workId, entry.executionId);
        } catch (error) {
          if (error?.code === "LEASE_CONFLICT") throw new AgenticError("WORK_EXECUTION_IN_PROGRESS", "Work ini sedang dijalankan oleh proses lain", 409, { workId, leaseExpiresAt: error?.details?.expiresAt || error?.lease?.expiresAt || null });
          throw error;
        }
        const heartbeatMs = executionLeaseService.heartbeatMs || Math.max(1000, Math.floor((executionLeaseService.leaseMs || 120000) / 3));
        entry.heartbeat = setInterval(async () => {
          if (heartbeatBusy || controller.signal.aborted || !entry.lease) return;
          heartbeatBusy = true;
          try {
            entry.lease = await executionLeaseService.renew(ownerId, workId, entry.executionId, entry.lease.token);
          } catch (error) {
            const lost = new AgenticError("WORK_EXECUTION_LEASE_LOST", "Work execution lease tidak dapat diperpanjang; run dibatalkan demi keamanan", 409, { causeCode: error?.code || "LEASE_RENEW_FAILED" });
            if (!controller.signal.aborted) controller.abort(lost);
          } finally {
            heartbeatBusy = false;
          }
        }, heartbeatMs);
        entry.heartbeat.unref?.();
      }
      entry.promise = runInternal(ownerId, workId, { ...options, signal: controller.signal }, entry);
      return await entry.promise;
    } finally {
      if (entry.heartbeat) clearInterval(entry.heartbeat);
      if (externalSignal && forwardAbort) externalSignal.removeEventListener("abort", forwardAbort);
      if (activeRuns.get(key) === entry) activeRuns.delete(key);
      if (executionLeaseService && entry.lease) {
        try { await executionLeaseService.release(ownerId, workId, entry.executionId, entry.lease.token); } catch { /* another fence may already own the lease */ }
      }
    }
  }

  async function resume(ownerId, workId, options = {}) {
    const current = await work.raw(ownerId, workId);
    if (current.state !== "paused") throw new AgenticError("WORK_NOT_RESUMABLE", "Hanya Work paused yang dapat dilanjutkan", 409);
    return run(ownerId, workId, options);
  }
  async function approve(ownerId, workId, options = {}) {
    const current = await work.raw(ownerId, workId);
    if (current.state !== "waiting_approval") throw new AgenticError("WORK_APPROVAL_NOT_PENDING", "Work tidak sedang menunggu approval", 409);
    const latest = (await store.listExecutions(ownerId)).filter(item => item.workId === workId && item.status === "waiting_approval").sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)))[0];
    if (!latest?.approval) throw new AgenticError("WORK_APPROVAL_NOT_FOUND", "Approval pending tidak ditemukan", 409);
    if (latest.approval.expiresAt && Date.parse(latest.approval.expiresAt) <= Date.now()) throw new AgenticError("APPROVAL_EXPIRED", "Approval sudah kedaluwarsa", 409);
    let approvalToken = options.approvalToken || null;
    if (!approvalToken && approvalAuthority && latest.approval.tool) {
      const issued = approvalAuthority({ tool: latest.approval.tool, input: latest.approval.input || {}, sessionId: `${ownerId}:work:${workId}`, principalId: ownerId, reason: latest.approval.reason || "Approved by owner" });
      approvalToken = issued?.token || null;
    }
    await store.putExecution(ownerId, { ...latest, status: "completed", result: { status: "approval_granted", approvedAt: now() }, approval: { ...latest.approval, approvedAt: now() }, finishedAt: now(), updatedAt: now() }, { overwrite: true, expectedVersion: latest._storage?.version });
    await work.transition(ownerId, workId, "running");
    return run(ownerId, workId, { ...options, approvalToken });
  }
  async function reject(ownerId, workId, reason = "Approval ditolak") {
    const current = await work.raw(ownerId, workId);
    if (current.state !== "waiting_approval") throw new AgenticError("WORK_APPROVAL_NOT_PENDING", "Work tidak sedang menunggu approval", 409);
    const latest = (await store.listExecutions(ownerId)).filter(item => item.workId === workId && item.status === "waiting_approval").sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)))[0];
    if (latest) await store.putExecution(ownerId, { ...latest, status: "failed", approval: { ...(latest.approval || {}), rejectedAt: now(), rejectionReason: clean(reason, 1000) }, error: clean(reason, 1000), finishedAt: now(), updatedAt: now() }, { overwrite: true, expectedVersion: latest._storage?.version });
    await work.transition(ownerId, workId, "failed", { error: clean(reason, 1000) });
    await record(ownerId, { workId, executionId: latest?.id || null, action: "approval_rejected", status: "failed", label: "Approval ditolak", error: clean(reason, 1000) });
    return work.get(ownerId, workId);
  }
  async function revise(ownerId, workId, instruction) {
    const current = await work.raw(ownerId, workId);
    if (TERMINAL.has(current.state) || current.state === "running") throw new AgenticError("WORK_NOT_REVISABLE", "Work tidak dapat direvisi pada state saat ini", 409);
    const revision = clean(instruction, 4000);
    if (!revision) throw new AgenticError("INVALID_REVISION", "Instruksi revisi wajib diisi", 400);
    const objective = `${current.objective}\n\nRevision instruction: ${revision}`.slice(0, 12000);
    const updated = await work.update(ownerId, workId, { objective, plan: null });
    const refreshed = await work.raw(ownerId, workId);
    if (refreshed.state === "waiting_approval") await work.transition(ownerId, workId, "paused");
    await record(ownerId, { workId, action: "work_revised", status: "completed", label: "Instruksi Work diperbarui" });
    return updated;
  }
  async function pause(ownerId, workId, reason = null) {
    const current = await work.raw(ownerId, workId);
    if (current.state === "waiting_approval") {
      const result = await work.transition(ownerId, workId, "paused", { result: current.result });
      const active = activeRuns.get(runKey(ownerId, workId));
      active?.controller.abort(Object.assign(new Error(clean(reason, 1000) || "Work dijeda oleh owner"), { code: "WORK_PAUSED" }));
      await settleOtherRuns(ownerId, workId, "paused", { excludeExecutionId: active?.executionId, reason });
      await record(ownerId, { workId, action: "work_paused", status: "paused", label: "Work dijeda", meta: { reason: clean(reason, 1000) || null } });
      return result;
    }
    if (current.state !== "running") throw new AgenticError("WORK_NOT_PAUSABLE", "Hanya Work running atau waiting approval yang dapat dijeda", 409);
    const result = await work.transition(ownerId, workId, "paused", { result: { ...(current.result || {}), pauseReason: clean(reason, 1000) || null, pausedAt: now() } });
    const active = activeRuns.get(runKey(ownerId, workId));
    active?.controller.abort(Object.assign(new Error(clean(reason, 1000) || "Work dijeda oleh owner"), { code: "WORK_PAUSED" }));
    await settleOtherRuns(ownerId, workId, "paused", { excludeExecutionId: active?.executionId, reason });
    await record(ownerId, { workId, action: "work_paused", status: "paused", label: "Work dijeda", meta: { reason: clean(reason, 1000) || null } });
    return result;
  }
  async function stop(ownerId, workId, reason = null) {
    const current = await work.raw(ownerId, workId);
    if (!["running", "paused"].includes(current.state)) throw new AgenticError("WORK_NOT_STOPPABLE", "Work harus running atau paused untuk dihentikan", 409);
    const result = await work.transition(ownerId, workId, "stopped", { result: { ...(current.result || {}), stopReason: clean(reason, 1000) || null } });
    const active = activeRuns.get(runKey(ownerId, workId));
    active?.controller.abort(Object.assign(new Error(clean(reason, 1000) || "Work dihentikan oleh owner"), { code: "WORK_STOPPED" }));
    await settleOtherRuns(ownerId, workId, "stopped", { excludeExecutionId: active?.executionId, reason });
    await record(ownerId, { workId, action: "work_stopped", status: "stopped", label: "Work dihentikan" });
    return result;
  }
  async function cancel(ownerId, workId, reason = null) {
    const current = await work.raw(ownerId, workId);
    if (TERMINAL.has(current.state)) return work.get(ownerId, workId);
    const result = await work.transition(ownerId, workId, "cancelled", { result: { ...(current.result || {}), cancelReason: clean(reason, 1000) || null } });
    const active = activeRuns.get(runKey(ownerId, workId));
    active?.controller.abort(Object.assign(new Error(clean(reason, 1000) || "Work dibatalkan oleh owner"), { code: "WORK_CANCELLED" }));
    await settleOtherRuns(ownerId, workId, "cancelled", { excludeExecutionId: active?.executionId, reason: reason || "Dibatalkan oleh owner" });
    await record(ownerId, { workId, action: "work_cancelled", status: "cancelled", label: "Work dibatalkan" });
    return result;
  }
  async function listActivities(ownerId, workId) {
    const current = await work.raw(ownerId, workId);
    const executionIds = new Set(current.executionIds || []);
    const taskIds = new Set(current.taskIds || []);
    return (await store.listActivities(ownerId)).filter(item => item.workId === workId || executionIds.has(item.executionId) || taskIds.has(item.taskId)).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
  }
  return Object.freeze({ plan, run, resume, approve, reject, revise, pause, stop, cancel, listActivities });
}
