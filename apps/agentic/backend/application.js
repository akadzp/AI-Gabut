import { createAgenticStore } from "./store.js";
import { createAuthService } from "./auth.js";
import { createGitHubService } from "./github.js";
import { createId } from "./ids.js";
import { AgenticError } from "./errors.js";
import { runAgent } from "../../../core/agent-engine/index.js";
import { createExecutionId } from "../../../core/agent-engine/reliability/runtime.js";
import { issueApproval } from "../../../core/security/index.js";
import { extractMemoryCandidates, addMemories, retrieveMemories, resolveMemoryConflicts, getActiveMemories } from "../../../core/agent-engine/index.js";
import { auditEvent } from "../../../core/security/index.js";

function executionStatusFromResult(result) {
  const autonomy = result?.autonomy;
  if (result?.execution?.status === "failed") return "failed";
  if (result?.execution?.status === "cancelled") return "cancelled";
  if (result?.approval?.required || result?.status === "waiting_approval") return "waiting_approval";
  if (autonomy?.status === "stopped" || /Execution dihentikan secara bounded/i.test(String(result?.text || ""))) return "stopped";
  if (/mencapai batas maksimum/i.test(String(result?.text || ""))) return "max_turns";
  return "completed";
}

function approvalCandidate(result) {
  const steps = result?.tool?.steps || [];
  const last = steps.at(-1);
  if (!last?.result?.requiresApproval) return null;
  return { tool: last.name, input: last.input || {}, reason: last.result.error || "Tool memerlukan human approval" };
}

export function createAgenticApplication({ storage = undefined, agentRunner = runAgent } = {}) {
  const store = createAgenticStore({ storage });
  const auth = createAuthService({ store });
  const github = createGitHubService({ store });

  async function createChatSession(u, { title = "New Chat", connectionId = null, workspaceId = null } = {}) {
    const s = { id: createId("chat"), title: String(title || "New Chat").trim().slice(0, 160), connectionId, workspaceId, messages: [], memories: [], taskId: null, executionId: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    await store.putChatSession(u, s);
    return s;
  }

  async function getSession(u, id) {
    if (id) {
      const s = await store.getChatSession(u, id);
      if (!s) throw new AgenticError("SESSION_NOT_FOUND", "Chat session tidak ditemukan", 404);
      return s;
    }
    return createChatSession(u, {});
  }

  async function recordActivity(u, executionId, sessionId, event) {
    const activity = { id: event.id || createId("activity"), ownerId: u, executionId, sessionId, type: event.type || "activity", action: event.action || "unknown", status: event.status || "running", label: String(event.label || event.action || "Activity").slice(0, 300), meta: event.meta || {}, error: event.error || null, createdAt: new Date().toISOString() };
    await store.putActivity(u, activity);
    return activity;
  }

  async function createExecution(u, sessionId, prompt) {
    const id = createExecutionId();
    const task = { id: createId("task"), ownerId: u, sessionId, status: "running", title: String(prompt).slice(0, 160), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    const execution = { id, ownerId: u, sessionId, taskId: task.id, status: "running", prompt: String(prompt).slice(0, 12000), plan: null, currentStep: null, checkpoint: null, approval: null, result: null, error: null, startedAt: new Date().toISOString(), updatedAt: new Date().toISOString(), finishedAt: null };
    await store.putTask(u, task);
    await store.putExecution(u, execution);
    return execution;
  }

  async function updateExecution(u, id, patch) {
    const current = await store.getExecution(u, id);
    if (!current) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404);
    const next = { ...current, ...patch, id: current.id, ownerId: u, updatedAt: new Date().toISOString() };
    await store.putExecution(u, next);
    if (["completed", "failed", "cancelled", "stopped", "max_turns"].includes(next.status) && current.taskId) {
      const task = await store.getTask(u, current.taskId);
      if (task) await store.putTask(u, { ...task, status: next.status, updatedAt: next.updatedAt });
    }
    return next;
  }

  async function ensureExecutionActive(u, id) {
    const execution = await store.getExecution(u, id);
    if (!execution) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404);
    if (execution.status === "cancelled") throw new AgenticError("EXECUTION_CANCELLED", "Execution dibatalkan", 409);
    return execution;
  }

  async function runExecution(u, s, prompt, options = {}) {
    const execution = options.resumeExecutionId ? await ensureExecutionActive(u, options.resumeExecutionId) : await createExecution(u, s.id, prompt);
    s.taskId = execution.taskId;
    s.executionId = execution.id;
    s.executionId = execution.id;
    await store.putChatSession(u, s);
    const emit = async event => {
      const current = await store.getExecution(u, execution.id);
      if (current?.status === "cancelled") throw new AgenticError("EXECUTION_CANCELLED", "Execution dibatalkan", 409);
      await recordActivity(u, execution.id, s.id, event);
      if (event.action === "planning" && event.status === "completed") await updateExecution(u, execution.id, { plan: event.meta || null });
      if (event.action === "checkpoint") await updateExecution(u, execution.id, { checkpoint: event.meta || null });
    };
    try {
      const result = await agentRunner({ prompt, provider: options.provider, model: options.model, conversation: s.messages.slice(-20).map(m => ({ role: m.role, content: m.content })), memories: getActiveMemories(s.memories), sessionId: `${u}:${s.id}`, approvalToken: options.approvalToken || null, principal: { userId: u }, applicationId: "agentic", executionId: options.resumeExecutionId || undefined, agentExecutionId: execution.id, onActivity: emit });
      const candidate = approvalCandidate(result);
      if (candidate && !options.approvalToken) {
        const approval = issueApproval({ tool: candidate.tool, input: candidate.input, sessionId: `${u}:${s.id}`, reason: candidate.reason });
        await updateExecution(u, execution.id, { status: "waiting_approval", approval: { tool: candidate.tool, input: candidate.input, reason: candidate.reason, expiresAt: approval.expiresAt }, result: null });
        await recordActivity(u, execution.id, s.id, { action: "approval_required", status: "waiting", label: `Approval diperlukan · ${candidate.tool}`, meta: { tool: candidate.tool, expiresAt: approval.expiresAt } });
        return { sessionId: s.id, execution: { ...execution, status: "waiting_approval", approval: { tool: candidate.tool, reason: candidate.reason, expiresAt: approval.expiresAt } }, plan: result.plan || null, approvalRequired: true };
      }
      const status = executionStatusFromResult(result);
      const final = await updateExecution(u, execution.id, { status, result: result.text || null, plan: result.plan || null, finishedAt: status === "completed" || status === "failed" || status === "stopped" || status === "max_turns" ? new Date().toISOString() : null });
      await recordActivity(u, execution.id, s.id, { action: "execution", status: status === "completed" ? "completed" : "finished", label: status === "completed" ? "Pekerjaan selesai" : `Execution selesai · ${status}`, meta: { status } });
      return { result, execution: final };
    } catch (error) {
      const status = error?.code === "EXECUTION_CANCELLED" ? "cancelled" : "failed";
      const final = await updateExecution(u, execution.id, { status, error: error?.message || String(error), finishedAt: new Date().toISOString() });
      await recordActivity(u, execution.id, s.id, { action: "execution", status: "error", label: status === "cancelled" ? "Execution dibatalkan" : "Execution gagal", error: final.error, meta: { status } });
      if (status === "cancelled") return { result: { text: "Execution dibatalkan." }, execution: final };
      throw error;
    }
  }

  async function chat(u, { sessionId, prompt, provider, model, approvalToken = null } = {}) {
    if (typeof prompt !== "string" || !prompt.trim()) throw new AgenticError("INVALID_PROMPT", "Prompt wajib diisi");
    const s = await getSession(u, sessionId);
    const user = { id: createId("msg"), role: "user", content: prompt.trim().slice(0, 12000), createdAt: new Date().toISOString() };
    s.messages.push(user);
    const run = await runExecution(u, s, user.content, { provider, model, approvalToken });
    if (!run.approvalRequired) {
      const result = run.result;
      const assistant = { id: createId("msg"), role: "assistant", content: String(result.text || ""), createdAt: new Date().toISOString(), executionId: run.execution.id };
      s.messages.push(assistant);
      addMemories(s.memories, extractMemoryCandidates(user.content));
      resolveMemoryConflicts(s.memories);
      s.executionId = run.execution.id;
      s.updatedAt = new Date().toISOString();
      await store.putChatSession(u, s);
      auditEvent({ actor: "user", action: "agentic-chat", outcome: run.execution.status, principal: { userId: u }, sessionId: s.id, applicationId: "agentic", executionId: run.execution.id });
      return { sessionId: s.id, message: assistant, execution: run.execution, plan: result.plan || null, memory: { active: getActiveMemories(s.memories).length, relevant: retrieveMemories(s.memories, user.content).length } };
    }
    await store.putChatSession(u, s);
    return run;
  }

  async function approveExecution(u, id) {
    const execution = await ensureExecutionActive(u, id);
    if (execution.status !== "waiting_approval" || !execution.approval) throw new AgenticError("APPROVAL_NOT_PENDING", "Execution tidak sedang menunggu approval", 409);
    if (execution.approval.expiresAt && Date.parse(execution.approval.expiresAt) <= Date.now()) throw new AgenticError("APPROVAL_EXPIRED", "Approval sudah kedaluwarsa", 409);
    const issued = issueApproval({ tool: execution.approval.tool, input: execution.approval.input, sessionId: `${u}:${execution.sessionId}`, reason: execution.approval.reason });
    const s = await getSession(u, execution.sessionId);
    await updateExecution(u, id, { status: "running", approval: null });
    return runExecution(u, s, execution.prompt, { approvalToken: issued.token, resumeExecutionId: id });
  }

  async function cancelExecution(u, id) {
    const execution = await ensureExecutionActive(u, id);
    if (["completed", "failed", "cancelled", "stopped", "max_turns"].includes(execution.status)) return execution;
    const next = await updateExecution(u, id, { status: "cancelled", finishedAt: new Date().toISOString(), error: "Execution dibatalkan oleh user" });
    await recordActivity(u, id, execution.sessionId, { action: "execution", status: "cancelled", label: "Execution dibatalkan", meta: { status: "cancelled" } });
    return next;
  }

  async function createWorkspace(u, input) { const w = { id: createId("workspace"), provider: input.provider, connectionId: input.connectionId, resource: input.resource, branch: input.branch || null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }; await store.putWorkspace(u, w); return w; }

  return Object.freeze({ store, auth, github, createChatSession, chat, approveExecution, cancelExecution, createWorkspace, getExecution: async (u, id) => { const e = await store.getExecution(u, id); if (!e) throw new AgenticError("EXECUTION_NOT_FOUND", "Execution tidak ditemukan", 404); return e; }, listExecutions: u => store.listExecutions(u), listSessions: u => store.listChatSessions(u), listConnections: u => store.listConnections(u), listWorkspaces: u => store.listWorkspaces(u), listTasks: u => store.listTasks(u), listActivities: u => store.listActivities(u) });
}
