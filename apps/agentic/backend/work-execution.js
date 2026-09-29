import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const EXECUTION_TERMINAL = new Set(["completed", "failed", "cancelled", "stopped", "max_turns", "rejected"]);
const APPROVAL_TTL_MS = 5 * 60 * 1000;

function planSteps(steps) {
  if (!Array.isArray(steps) || !steps.length) {
    throw new AgenticError("INVALID_WORK_PLAN", "Plan work harus memiliki minimal satu langkah");
  }
  return steps.slice(0, 20).map((step, index) => ({
    id: String(step?.id || `step-${index + 1}`).slice(0, 120),
    goal: String(step?.goal || "Lanjutkan pekerjaan").slice(0, 1000),
    tools: Array.isArray(step?.tools) ? step.tools.map(tool => String(tool).slice(0, 120)).slice(0, 20) : [],
    status: "planned"
  }));
}

function publicPlan(steps, objective) {
  return {
    version: 1,
    status: "ready",
    interpretation: {
      objective: String(objective).slice(0, 12000),
      summary: String(objective).replace(/\s+/g, " ").trim().slice(0, 240)
    },
    steps: planSteps(steps),
    currentStepId: null,
    replanAvailable: false,
    createdAt: new Date().toISOString()
  };
}

function statusFromResult(result) {
  if (result?.execution?.status === "failed") return "failed";
  if (result?.execution?.status === "cancelled") return "cancelled";
  if (result?.autonomy?.status === "stopped") return "stopped";
  if (/mencapai batas maksimum/i.test(String(result?.text || ""))) return "max_turns";
  return "completed";
}

function approvalCandidate(result) {
  const step = result?.tool?.steps?.at(-1);
  if (!step?.result?.requiresApproval) return null;
  return {
    tool: step.name,
    input: step.input || {},
    reason: step.result.error || "Tool memerlukan human approval"
  };
}

function approvalSummary(candidate, policy = {}) {
  return {
    id: createId("approval"),
    status: "pending",
    tool: candidate.tool,
    input: candidate.input,
    reason: candidate.reason,
    risk: policy.risk || "high",
    affectedResource: policy.resource || "unknown",
    requestedCapability: policy.permission || "approval",
    requestedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(),
    decision: null
  };
}

export function createWorkExecutionService({ store, work, realtime, agentRunner, planner, approvalAuthority, approvalPolicy = () => ({}) } = {}) {
  if (!store?.putTask || !store?.putExecution || !store?.putActivity || !work?.raw || !agentRunner || !planner || !approvalAuthority) {
    throw new TypeError("Work execution membutuhkan store, work, planner, runner, dan approval authority");
  }

  async function emit(ownerId, workId, executionId, event) {
    const activity = {
      id: createId("activity"),
      workId,
      executionId,
      sessionId: null,
      type: "work_activity",
      action: String(event.action || "work").slice(0, 120),
      status: String(event.status || "running").slice(0, 80),
      label: String(event.label || event.action || "Work activity").slice(0, 300),
      meta: event.meta && typeof event.meta === "object" ? event.meta : {},
      error: event.error ? String(event.error).slice(0, 2000) : null,
      createdAt: new Date().toISOString()
    };
    await store.putActivity(ownerId, activity, { overwrite: false });
    await realtime.publish(ownerId, activity);
    return activity;
  }

  async function updateTask(ownerId, id, patch) {
    const current = await store.getTask(ownerId, id);
    if (!current) return null;
    return store.putTask(ownerId, { ...current, ...patch, id: current.id, updatedAt: new Date().toISOString() }, { overwrite: true, expectedVersion: current._storage?.version });
  }

  async function updateExecution(ownerId, id, patch) {
    const current = await store.getExecution(ownerId, id);
    if (!current) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404);
    return store.putExecution(ownerId, { ...current, ...patch, id: current.id, updatedAt: new Date().toISOString() }, { overwrite: true, expectedVersion: current._storage?.version });
  }

  async function activeExecution(ownerId, workId) {
    const executions = await store.listExecutions(ownerId);
    return executions
      .filter(execution => execution.workId === workId && ["running", "waiting_approval"].includes(execution.status))
      .sort((left, right) => String(right.updatedAt).localeCompare(String(left.updatedAt)))[0] || null;
  }

  async function latestExecution(ownerId, workId, statuses) {
    const executions = await store.listExecutions(ownerId);
    return executions
      .filter(execution => execution.workId === workId && statuses.includes(execution.status))
      .sort((left, right) => String(right.updatedAt).localeCompare(String(left.updatedAt)))[0] || null;
  }

  async function plan(ownerId, workId, options = {}) {
    const current = await work.raw(ownerId, workId);
    if (!["draft", "ready", "paused"].includes(current.state)) {
      throw new AgenticError("WORK_NOT_PLANNABLE", "Work hanya dapat direncanakan sebelum atau saat jeda execution", 409);
    }
    const steps = await planner({
      prompt: current.objective,
      provider: options.provider,
      model: options.model,
      conversation: Array.isArray(options.conversation) ? options.conversation : []
    });
    const nextPlan = publicPlan(steps, current.objective);
    const updated = await work.update(ownerId, workId, { plan: nextPlan });
    const ready = updated.state === "draft" ? await work.transition(ownerId, workId, "ready") : updated;
    await emit(ownerId, workId, null, {
      action: "planning",
      status: "completed",
      label: `Rencana siap · ${nextPlan.steps.length} langkah`,
      meta: { steps: nextPlan.steps.length }
    });
    return ready;
  }

  async function execute(ownerId, workId, options = {}, existing = null) {
    const initial = await work.raw(ownerId, workId);
    if (!existing && !["ready", "paused"].includes(initial.state)) {
      throw new AgenticError("WORK_NOT_READY", "Work harus berstatus ready sebelum dijalankan", 409);
    }
    if (!initial.plan?.steps?.length) {
      throw new AgenticError("WORK_PLAN_REQUIRED", "Work harus memiliki plan sebelum dijalankan", 409);
    }
    if (!existing && await activeExecution(ownerId, workId)) {
      throw new AgenticError("WORK_EXECUTION_ACTIVE", "Work sudah memiliki execution aktif", 409);
    }

    if (initial.state === "paused") await work.transition(ownerId, workId, "ready");
    const running = await work.transition(ownerId, workId, "running");
    const now = new Date().toISOString();
    const task = existing ? await store.getTask(ownerId, existing.taskId) : {
      id: createId("task"), ownerId, workId, sessionId: null, planStepId: running.plan.steps[0].id,
      title: running.plan.steps[0].goal, status: "running", progress: { completed: 0, total: running.plan.steps.length },
      createdAt: now, updatedAt: now, finishedAt: null
    };
    const execution = existing || {
      id: createId("work-execution"), ownerId, workId, sessionId: null, taskId: task.id,
      status: "running", prompt: running.objective, plan: running.plan, currentStep: running.plan.steps[0].id,
      checkpoint: null, approval: null, interventions: [], result: null, error: null, startedAt: now, updatedAt: now, finishedAt: null
    };
    if (!existing) {
      await store.putTask(ownerId, task, { overwrite: false });
      await store.putExecution(ownerId, execution, { overwrite: false });
      await work.attachTask(ownerId, workId, task.id);
      await work.attachExecution(ownerId, workId, execution.id);
      await emit(ownerId, workId, execution.id, { action: "execution", status: "running", label: "Execution dimulai" });
    } else {
      await updateTask(ownerId, task.id, { status: "running", finishedAt: null });
      await updateExecution(ownerId, execution.id, { status: "running", finishedAt: null, error: null });
      await emit(ownerId, workId, execution.id, { action: "execution_resumed", status: "running", label: "Execution dilanjutkan dari checkpoint" });
    }

    const onActivity = async event => {
      const latest = await work.raw(ownerId, workId);
      if (latest.state === "paused") throw new AgenticError("WORK_PAUSED", "Work dijeda", 409);
      if (latest.state === "stopped") throw new AgenticError("WORK_STOPPED", "Work dihentikan", 409);
      if (latest.state === "cancelled") throw new AgenticError("WORK_CANCELLED", "Work dibatalkan", 409);
      const current = await store.getExecution(ownerId, execution.id);
      if (current?.status === "paused") throw new AgenticError("WORK_PAUSED", "Work dijeda", 409);
      if (current?.status === "stopped") throw new AgenticError("WORK_STOPPED", "Work dihentikan", 409);
      if (current?.status === "cancelled") throw new AgenticError("WORK_CANCELLED", "Work dibatalkan", 409);
      await updateExecution(ownerId, execution.id, { currentStep: event.action || current?.currentStep || null, checkpoint: event.action === "checkpoint" ? event.meta || null : current?.checkpoint || null });
      await emit(ownerId, workId, execution.id, event);
    };

    try {
      const result = await agentRunner({
        prompt: running.objective,
        provider: options.provider,
        model: options.model,
        conversation: Array.isArray(options.conversation) ? options.conversation : [],
        sessionId: `work:${ownerId}:${workId}`,
        principal: { userId: ownerId },
        applicationId: "agentic",
        executionId: execution.id,
        agentExecutionId: execution.id,
        approvalToken: options.approvalToken || null,
        onActivity
      });
      const approval = approvalCandidate(result);
      if (approval) {
        const request = approvalSummary(approval, approvalPolicy(approval.tool));
        const waiting = await updateExecution(ownerId, execution.id, { status: "waiting_approval", approval: request });
        await updateTask(ownerId, task.id, { status: "waiting_approval" });
        await work.transition(ownerId, workId, "waiting_approval");
        await emit(ownerId, workId, execution.id, { action: "approval_required", status: "waiting", label: `Approval diperlukan · ${approval.tool}`, meta: { approval: request } });
        return { work: await work.get(ownerId, workId), execution: waiting, approvalRequired: true };
      }
      const status = statusFromResult(result);
      const finishedAt = new Date().toISOString();
      const completed = await updateExecution(ownerId, execution.id, { status, result: result?.text || null, plan: result?.plan ? publicPlan(result.plan, running.objective) : execution.plan, finishedAt });
      await updateTask(ownerId, task.id, { status, progress: { completed: status === "completed" ? running.plan.steps.length : 0, total: running.plan.steps.length }, finishedAt });
      const state = status === "completed" ? "completed" : status === "cancelled" ? "cancelled" : status === "stopped" || status === "max_turns" ? "stopped" : "failed";
      await work.transition(ownerId, workId, state, { result: state === "failed" ? { status, message: result?.text || null, replanAvailable: true } : { status, message: result?.text || null } });
      await emit(ownerId, workId, execution.id, { action: "execution", status: state === "completed" ? "completed" : "finished", label: state === "completed" ? "Execution selesai" : `Execution berhenti · ${state}`, meta: { status } });
      return { work: await work.get(ownerId, workId), execution: completed, result };
    } catch (error) {
      if (["WORK_PAUSED", "WORK_STOPPED", "WORK_CANCELLED"].includes(error?.code)) {
        return { work: await work.get(ownerId, workId), execution: await store.getExecution(ownerId, execution.id) };
      }
      const failedAt = new Date().toISOString();
      await updateExecution(ownerId, execution.id, { status: "failed", error: error?.message || String(error), finishedAt: failedAt });
      await updateTask(ownerId, task.id, { status: "failed", finishedAt: failedAt });
      await work.transition(ownerId, workId, "failed", { result: { status: "failed", message: error?.message || String(error), replanAvailable: true } });
      await emit(ownerId, workId, execution.id, { action: "execution", status: "failed", label: "Execution gagal; replan tersedia", error: error?.message || String(error) });
      throw error;
    }
  }

  async function run(ownerId, workId, options = {}) {
    return execute(ownerId, workId, options);
  }

  async function approve(ownerId, workId) {
    const current = await work.raw(ownerId, workId);
    const execution = await latestExecution(ownerId, workId, ["waiting_approval"]);
    if (current.state !== "waiting_approval" || !execution?.approval || execution.approval.status !== "pending") {
      throw new AgenticError("APPROVAL_NOT_PENDING", "Work tidak sedang menunggu approval", 409);
    }
    if (Date.parse(execution.approval.expiresAt) <= Date.now()) {
      await updateExecution(ownerId, execution.id, { approval: { ...execution.approval, status: "expired", decision: { at: new Date().toISOString() } } });
      await emit(ownerId, workId, execution.id, { action: "approval_expired", status: "expired", label: "Approval sudah kedaluwarsa" });
      throw new AgenticError("APPROVAL_EXPIRED", "Approval sudah kedaluwarsa", 409);
    }
    const issued = approvalAuthority({ tool: execution.approval.tool, input: execution.approval.input, principalId: ownerId, sessionId: `work:${ownerId}:${workId}`, executionId: execution.id, reason: execution.approval.reason });
    const approved = await updateExecution(ownerId, execution.id, { approval: { ...execution.approval, status: "approved", decision: { at: new Date().toISOString(), by: ownerId } } });
    await emit(ownerId, workId, execution.id, { action: "approval_approved", status: "approved", label: `Approval diberikan · ${approved.approval.tool}`, meta: { approval: approved.approval } });
    return execute(ownerId, workId, { approvalToken: issued.token }, approved);
  }

  async function reject(ownerId, workId, reason = "Approval ditolak oleh user") {
    const current = await work.raw(ownerId, workId);
    const execution = await latestExecution(ownerId, workId, ["waiting_approval"]);
    if (current.state !== "waiting_approval" || !execution?.approval || execution.approval.status !== "pending") throw new AgenticError("APPROVAL_NOT_PENDING", "Work tidak sedang menunggu approval", 409);
    const now = new Date().toISOString();
    const message = String(reason || "Approval ditolak oleh user").slice(0, 2000);
    await updateExecution(ownerId, execution.id, { status: "rejected", approval: { ...execution.approval, status: "rejected", decision: { at: now, by: ownerId, reason: message } }, error: message, finishedAt: now });
    await updateTask(ownerId, execution.taskId, { status: "rejected", finishedAt: now });
    await work.transition(ownerId, workId, "failed", { result: { status: "rejected", reason: message } });
    await emit(ownerId, workId, execution.id, { action: "approval_rejected", status: "rejected", label: "Approval ditolak; execution tidak dijalankan", meta: { reason: message } });
    return work.get(ownerId, workId);
  }

  async function revise(ownerId, workId, instruction) {
    const message = String(instruction || "").trim().slice(0, 12000);
    if (!message) throw new AgenticError("INVALID_INTERVENTION", "Instruksi revisi wajib diisi");
    const current = await work.raw(ownerId, workId);
    if (!["running", "waiting_approval", "paused"].includes(current.state)) throw new AgenticError("WORK_NOT_INTERVENABLE", "Work tidak dapat direvisi pada state ini", 409);
    const execution = await latestExecution(ownerId, workId, ["running", "waiting_approval", "paused"]);
    if (!execution) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution aktif tidak ditemukan", 404);
    if (current.state !== "paused") await work.transition(ownerId, workId, "paused");
    const at = new Date().toISOString();
    const intervention = { id: createId("intervention"), type: "revise_instruction", instruction: message, at, by: ownerId };
    await updateExecution(ownerId, execution.id, { status: "paused", prompt: `${execution.prompt}\n\nInstruksi revisi dari user:\n${message}`, approval: execution.approval?.status === "pending" ? { ...execution.approval, status: "superseded" } : execution.approval, interventions: [...(execution.interventions || []), intervention] });
    await updateTask(ownerId, execution.taskId, { status: "paused" });
    await emit(ownerId, workId, execution.id, { action: "instruction_revised", status: "paused", label: "Instruksi direvisi; lanjutkan saat siap", meta: { intervention } });
    return work.get(ownerId, workId);
  }

  async function resume(ownerId, workId, options = {}) {
    const current = await work.raw(ownerId, workId);
    if (current.state !== "paused") throw new AgenticError("WORK_NOT_PAUSED", "Work tidak sedang dijeda", 409);
    const execution = await latestExecution(ownerId, workId, ["paused"]);
    if (!execution) return run(ownerId, workId, options);
    if (execution.approval?.status === "pending") {
      await updateExecution(ownerId, execution.id, { status: "waiting_approval" });
      await updateTask(ownerId, execution.taskId, { status: "waiting_approval" });
      await work.transition(ownerId, workId, "ready");
      await work.transition(ownerId, workId, "waiting_approval");
      await emit(ownerId, workId, execution.id, { action: "approval_resumed", status: "waiting", label: "Menunggu keputusan approval" });
      return { work: await work.get(ownerId, workId), execution: await store.getExecution(ownerId, execution.id), approvalRequired: true };
    }
    return execute(ownerId, workId, options, execution);
  }

  async function control(ownerId, workId, action, reason) {
    const current = await work.raw(ownerId, workId);
    const execution = await activeExecution(ownerId, workId);
    const now = new Date().toISOString();
    if (action === "pause") {
      if (!["running", "waiting_approval"].includes(current.state)) throw new AgenticError("WORK_NOT_RUNNING", "Hanya work berjalan atau menunggu approval yang dapat dijeda", 409);
      await work.transition(ownerId, workId, "paused");
      if (execution) await updateExecution(ownerId, execution.id, { status: "paused", pauseReason: String(reason || "Work dijeda").slice(0, 2000) });
      if (execution) await updateTask(ownerId, execution.taskId, { status: "paused" });
    } else if (action === "stop") {
      if (!["running", "paused"].includes(current.state)) throw new AgenticError("WORK_NOT_STOPPABLE", "Work tidak dapat dihentikan pada state ini", 409);
      await work.transition(ownerId, workId, "stopped", { result: { status: "stopped", reason: String(reason || "Work dihentikan").slice(0, 2000) } });
      if (execution) await updateExecution(ownerId, execution.id, { status: "stopped", finishedAt: now, error: String(reason || "Work dihentikan") });
      if (execution) await updateTask(ownerId, execution.taskId, { status: "stopped", finishedAt: now });
    } else if (action === "cancel") {
      if (["completed", "failed", "cancelled", "stopped"].includes(current.state)) throw new AgenticError("WORK_TERMINAL", "Work terminal tidak dapat dibatalkan", 409);
      await work.cancel(ownerId, workId, reason);
      if (execution) await updateExecution(ownerId, execution.id, { status: "cancelled", finishedAt: now, error: String(reason || "Work dibatalkan") });
      if (execution) await updateTask(ownerId, execution.taskId, { status: "cancelled", finishedAt: now });
    } else {
      throw new AgenticError("INVALID_WORK_CONTROL", "Kontrol work tidak valid");
    }
    await emit(ownerId, workId, execution?.id || null, { action, status: "completed", label: `Work ${action === "pause" ? "dijeda" : action === "stop" ? "dihentikan" : "dibatalkan"}` });
    return work.get(ownerId, workId);
  }

  async function listActivities(ownerId, workId) {
    await work.raw(ownerId, workId);
    return (await store.listActivities(ownerId)).filter(activity => activity.workId === workId).sort((left, right) => String(left.createdAt).localeCompare(String(right.createdAt)));
  }

  return Object.freeze({ plan, run, resume, approve, reject, revise, pause: (ownerId, workId, reason) => control(ownerId, workId, "pause", reason), stop: (ownerId, workId, reason) => control(ownerId, workId, "stop", reason), cancel: (ownerId, workId, reason) => control(ownerId, workId, "cancel", reason), listActivities });
}
