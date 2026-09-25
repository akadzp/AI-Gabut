import "dotenv/config";
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runAgent } from "../10-agentic/core/agent.js";
import { getOrCreateSession, addMessage, getRecentMessages, getMemories } from "../10-agentic/context/session.js";
import { extractMemoryCandidates, addMemories, retrieveMemories, getActiveMemories, resolveMemoryConflicts } from "../10-agentic/context/memory.js";
import { runGitTool } from "../10-agentic/tools/git.js";
import { TOOL_CATALOG, TOOL_DEFINITIONS } from "../10-agentic/core/tool-registry.js";
import { buildToolIntelligence, discoverTools } from "../10-agentic/core/tool-intelligence.js";
import { listModels } from "../10-agentic/models/index.js";
import { routeModel, getModelCandidates } from "../10-agentic/models/model-router.js";
import { getEvaluationCases } from "../10-agentic/evaluation/benchmarks.js";
import { scoreTrajectory, analyzeFailures } from "../10-agentic/evaluation/evaluator.js";
import { getSpecialists, buildSpecialistPlan, createSpecialistHandoff, coordinateSpecialists } from "../10-agentic/specialists/orchestrator.js";
import { getGovernancePolicy, issueApproval, getAuditTrail } from "../80-security/governance/policy.js";
import { resumeExecution, getReliabilityMetrics, getReliabilityLimits } from "../10-agentic/reliability/runtime.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "..", "public")));

function writeStreamEvent(res, event) {
  res.write(`${JSON.stringify(event)}\n`);
}

app.get("/api/governance/policy", (_req, res) => {
  res.json({ ok: true, policy: getGovernancePolicy() });
});

app.get("/api/governance/audit", (req, res) => {
  res.json({ ok: true, entries: getAuditTrail({ limit: req.query.limit }) });
});

app.post("/api/governance/approvals", (req, res) => {
  try {
    const { tool, input = {}, sessionId = null, reason = "" } = req.body || {};
    if (typeof tool !== "string" || !tool.trim()) return res.status(400).json({ ok: false, error: "tool wajib diisi" });
    const approval = issueApproval({ tool: tool.trim(), input, sessionId, reason });
    res.status(201).json({ ok: true, approval });
  } catch (error) {
    res.status(400).json({ ok: false, error: error instanceof Error ? error.message : "Approval gagal" });
  }
});

app.get("/api/reliability", (_req, res) => {
  res.json({ ok: true, metrics: getReliabilityMetrics(), limits: getReliabilityLimits() });
});

app.get("/api/executions/:id", async (req, res) => {
  try { const execution = await resumeExecution(req.params.id); res.json({ ok: true, execution }); }
  catch (error) { res.status(404).json({ ok: false, error: error instanceof Error ? error.message : "Execution checkpoint tidak ditemukan" }); }
});

app.post("/api/executions/:id/resume", async (req, res) => {
  try {
    const execution = await resumeExecution(req.params.id);
    if (!execution.prompt) return res.status(400).json({ ok: false, error: "Execution tidak memiliki prompt" });
    const session = getOrCreateSession(execution.sessionId);
    const history = getRecentMessages(session);
    const result = await runAgent({ prompt: execution.prompt, provider: req.body?.provider, model: req.body?.model, conversation: history, memories: getMemories(session), sessionId: session.id, approvalToken: req.body?.approvalToken, executionId: execution.id });
    res.json({ ok: true, sessionId: session.id, ...result });
  } catch (error) { res.status(500).json({ ok: false, error: error instanceof Error ? error.message : "Resume gagal" }); }
});

app.get("/api/evaluation/cases", (req, res) => {
  const filter = typeof req.query.q === "string" ? req.query.q : "";
  const cases = getEvaluationCases(filter).map(item => ({ id: item.id, category: item.category, prompt: item.prompt, expected: item.expected }));
  res.json({ ok: true, count: cases.length, cases });
});

app.post("/api/evaluation/score", (req, res) => {
  try {
    const score = scoreTrajectory({ trajectory: req.body?.trajectory, expected: req.body?.expected, thresholds: req.body?.thresholds });
    res.json({ ok: true, score });
  } catch (error) {
    res.status(400).json({ ok: false, error: error instanceof Error ? error.message : "Evaluation gagal" });
  }
});

app.post("/api/evaluation/failures", (req, res) => {
  try {
    res.json({ ok: true, analysis: analyzeFailures(req.body?.results) });
  } catch (error) {
    res.status(400).json({ ok: false, error: error instanceof Error ? error.message : "Failure analysis gagal" });
  }
});

app.get("/api/specialists", (req, res) => {
  const prompt = typeof req.query.prompt === "string" ? req.query.prompt : "";
  const plan = buildSpecialistPlan({ prompt });
  res.json({ ok: true, specialists: getSpecialists(), plan });
});

app.post("/api/specialists/handoff", (req, res) => {
  try { res.json(createSpecialistHandoff(req.body || {})); }
  catch (error) { res.status(400).json({ ok: false, error: error instanceof Error ? error.message : "Handoff gagal" }); }
});

app.post("/api/specialists/coordinate", (req, res) => {
  try { res.json(coordinateSpecialists(req.body || {})); }
  catch (error) { res.status(400).json({ ok: false, error: error instanceof Error ? error.message : "Coordination gagal" }); }
});

app.get("/api/model-routing", (req, res) => {
  const prompt = typeof req.query.prompt === "string" ? req.query.prompt : "";
  const route = routeModel({ prompt });
  res.json({ ok: route.ok, route, candidates: getModelCandidates().map(candidate => ({
    provider: candidate.provider, model: candidate.model, capabilities: candidate.capabilities,
    maxContextTokens: candidate.maxContextTokens, latencyMs: candidate.latencyMs,
    inputCost: candidate.inputCost, outputCost: candidate.outputCost, tags: candidate.tags
  })) });
});

app.get("/api/models", async (req, res) => {
  try {
    const provider = req.query.provider;
    if (!["openai", "gemini"].includes(provider)) {
      return res.status(400).json({ error: "provider harus openai atau gemini" });
    }
    const models = await listModels(provider);
    res.json({ ok: true, provider, count: models.length, models });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: error instanceof Error ? error.message : "Gagal mengambil model" });
  }
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "ai-gabut", version: "m7.19-change-set-review" });
});

app.get("/api/capabilities", (_req, res) => {
  res.json({ ok: true, capabilities: TOOL_CATALOG.capabilities });
});

app.get("/api/integrations", (_req, res) => {
  res.json({ ok: true, integrations: TOOL_CATALOG.integrationCatalog });
});

app.get("/api/tools", (req, res) => {
  const query = typeof req.query.q === "string" ? req.query.q : "";
  const discovered = discoverTools({ query, definitions: TOOL_DEFINITIONS, limit: 20 });
  res.json({ ok: true, query, capabilities: TOOL_CATALOG.capabilities.length, integrations: TOOL_CATALOG.integrations.length, discovered, intelligence: buildToolIntelligence({ query, definitions: TOOL_DEFINITIONS }).selected });
});

app.get("/api/git/status", async (_req, res) => {
  try { res.json(await runGitTool("status")); }
  catch (error) { res.status(500).json({ ok: false, error: error.message }); }
});

app.get("/api/git/changes", async (_req, res) => {
  try { res.json(await runGitTool("changes")); }
  catch (error) { res.status(500).json({ ok: false, error: error.message }); }
});

app.get("/api/git/diff", async (req, res) => {
  try { res.json(await runGitTool("diff", { staged: req.query.staged === "true" })); }
  catch (error) { res.status(500).json({ ok: false, error: error.message }); }
});

app.get("/api/memory", (req, res) => {
  const session = getOrCreateSession(req.query.sessionId);
  res.json({
    ok: true,
    sessionId: session.id,
    memories: getActiveMemories(getMemories(session)),
    total: getActiveMemories(getMemories(session)).length
  });
});

app.get("/api/git/log", async (req, res) => {
  try { res.json(await runGitTool("log", { limit: req.query.limit })); }
  catch (error) { res.status(500).json({ ok: false, error: error.message }); }
});

app.post("/api/chat", async (req, res) => {
  try {
    const { prompt, provider, model, sessionId, approvalToken } = req.body ?? {};
    if (typeof prompt !== "string" || !prompt.trim()) {
      return res.status(400).json({ error: "prompt wajib diisi" });
    }

    const session = getOrCreateSession(sessionId);
    const history = getRecentMessages(session);
    const result = await runAgent({
      prompt: prompt.trim(), provider, model, conversation: history, memories: getMemories(session), sessionId: session.id, approvalToken
    });
    addMessage(session, "user", prompt.trim());
    addMessage(session, "assistant", result.text || "");
    addMemories(session.memories, extractMemoryCandidates(prompt.trim()));
    resolveMemoryConflicts(session.memories);

    res.json({ ok: true, sessionId: session.id, ...result });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: error instanceof Error ? error.message : "Internal server error" });
  }
});

app.post("/api/chat/stream", async (req, res) => {
  const requestStarted = Date.now();
  const { prompt, provider, model, sessionId, approvalToken } = req.body ?? {};

  if (typeof prompt !== "string" || !prompt.trim()) {
    return res.status(400).json({ error: "prompt wajib diisi" });
  }

  res.status(200);
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const session = getOrCreateSession(sessionId);
  const history = getRecentMessages(session);
  let sequence = 0;

  const emit = async event => {
    writeStreamEvent(res, {
      sequence: ++sequence,
      serverTime: new Date().toISOString(),
      ...event
    });
  };

  try {
    await emit({ type: "session", sessionId: session.id });
    const result = await runAgent({
      prompt: prompt.trim(), provider, model, conversation: history, memories: getMemories(session), sessionId: session.id, approvalToken,
      onActivity: activity => emit(activity)
    });

    let workspaceState = null;
    const stateStarted = Date.now();
    const stateId = `activity-${++sequence}`;
    await emit({
      type: "activity", id: stateId, action: "workspace", label: "Memeriksa status workspace dan Git", status: "running"
    });
    try {
      workspaceState = await runGitTool("changes");
      await emit({
        type: "activity", id: stateId, action: "workspace", label: "Memeriksa status workspace dan Git",
        status: workspaceState?.ok === false ? "error" : "completed", durationMs: Date.now() - stateStarted,
        meta: workspaceState?.files ? {
          branch: workspaceState.branch,
          staged: workspaceState.files.staged.length,
          unstaged: workspaceState.files.unstaged.length,
          untracked: workspaceState.files.untracked.length
        } : {},
        error: workspaceState?.ok === false ? workspaceState.error : undefined
      });
    } catch (error) {
      await emit({ type: "activity", id: stateId, action: "workspace", label: "Gagal memeriksa status workspace dan Git", status: "error", durationMs: Date.now() - stateStarted, error: error.message });
    }

    addMessage(session, "user", prompt.trim());
    addMessage(session, "assistant", result.text || "");
    const memoryChanges = addMemories(session.memories, extractMemoryCandidates(prompt.trim()));
    const memoryConflicts = resolveMemoryConflicts(session.memories);

    await emit({
      type: "result",
      ok: true,
      sessionId: session.id,
      text: result.text || "",
      plan: result.plan,
      tool: result.tool,
      workspaceState,
      memory: {
        active: getActiveMemories(getMemories(session)).length,
        relevant: retrieveMemories(getMemories(session), prompt.trim()).length,
        added: memoryChanges.added.length,
        superseded: memoryChanges.superseded.length
      },
      durationMs: Date.now() - requestStarted,
      startedAt: new Date(requestStarted).toISOString(),
      completedAt: new Date().toISOString()
    });
  } catch (error) {
    console.error(error);
    await emit({
      type: "error", ok: false, error: error instanceof Error ? error.message : "Internal server error",
      durationMs: Date.now() - requestStarted
    });
  } finally {
    res.end();
  }
});

app.listen(PORT, () => {
  console.log(`AI-Gabut M7.7 Capability / Integration Architecture running at http://localhost:${PORT}`);
});
