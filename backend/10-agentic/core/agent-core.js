import { chatWithRoutedProvider, routeModel } from "../models/model-router.js";
import {
  createAgentContext,
  recordObservation,
  recordToolResult,
  setPlan,
  advancePlan,
  getCurrentStep
} from "../context/context.js";
import { prepareContext, buildContextPrompt, compactContextForActivity } from "../context/context-intelligence.js";
import { createPlan } from "../planning/planner.js";
import { TOOL_DEFINITIONS, executeTool } from "./tool-registry.js";
import { buildToolIntelligence, normalizeToolInput, validateToolCall, interpretToolResult } from "./tool-intelligence.js";
import { establishReasoningLifecycle, summarizeReasoningLifecycle } from "../reasoning/reasoning-lifecycle.js";
import { createExecutionAutonomy, recordToolAction, checkpointExecution } from "../reasoning/execution-autonomy.js";
import { buildSpecialistPlan } from "../specialists/orchestrator.js";
import { withTimeout, getReliabilityLimits } from "../reliability/runtime.js";

const MAX_AGENT_TURNS = 24;
const MAX_VERIFICATION_RECOVERY_CYCLES = 2;

const AGENT_SYSTEM = `
You are AI-Gabut, a personal AI Development Agent.

You operate using an observe -> reason -> act -> verify loop.

Available tools:
${TOOL_DEFINITIONS.map(t => `- ${t.name}: ${t.description}`).join("\n")}

Architecture:
- Capabilities are local Agent abilities such as reasoning, coding, filesystem, terminal, and Git.
- Integrations are external services such as GitHub. Do not assume an integration is available just because Git is available.
- Keep coding workflows independent from hosting-provider integrations.

Tool request format:
<tool>{"name":"TOOL_NAME","input":{}}</tool>

Rules:
- Never invent file contents, command output, Git status, test results, or project facts.
- Use tools when actual workspace information is required.
- Before deep planning, use understand_task when the request contains multiple actions, unclear scope, or meaningful constraints. Then use decompose_task for multi-step work to create a bounded dependency-aware execution outline, followed by create_execution_plan when the task needs an operational execution plan. Use goal_management to establish explicit goals and completion criteria when the task has multiple outcomes or meaningful constraints. Use goal_management update/assess with observable evidence; never mark a goal complete merely because a plan or action exists. For substantial tasks, prefer reasoning_lifecycle to establish the full task/goal/decomposition/planning/execution context in one bounded operation. Use its result as the initial reasoning state, then use the narrower reasoning tools only when fresh evidence requires a targeted update. Use execution_control to advance only with explicit outcome evidence and use replan_execution when material state changes occur; refresh evidence before consequential actions. Use execution_reasoning to decide the next bounded action from explicit state/evidence instead of inventing a transition. For substantial tasks, use specialist_orchestration to assign bounded Planner/Coding/Research/Testing/Reviewer/Coordinator roles and preserve explicit evidence-based handoffs; do not imply hidden parallel execution. Treat these outputs as bounded evidence, not as hidden reasoning or the final interpretation.
- For codebase questions, prefer inspect_project/search_files/find_symbol/search_code/find_references/find_file_references before reading many files. Use inspect_code for AST-level structure and find_semantic_references when exact identifier references matter.
- When you need to know where a symbol is used or which files import another file, use find_references or find_file_references instead of reading the whole repository.
- When an identifier may refer to a local declaration or imported symbol, use resolve_symbol. When understanding function-to-function flow, use call_graph before reading unrelated files.
- Before making a potentially broad code change, use analyze_impact to inspect reverse local-import dependencies. Use dependency_graph when you need the broader project dependency map.
- Use read_file only for files that are relevant to the current task.
- Before editing existing code, prefer plan_change and then edit_file. edit_file requires the SHA-256 hash of the exact file version you inspected; never invent the hash.
- Prefer edit_file for targeted modifications because it detects stale files and validates JavaScript syntax before applying the change. Use write_file primarily for creating new files or deliberate full-file replacement.
- Prefer small, verifiable actions.
- After a tool result, inspect the result before deciding the next action.
- Use git_changes when the user asks for repository changes or a complete Git-state check; git diff alone does not show untracked files.
- For framework-sensitive changes, use analyze_frameworks to identify observable framework packages, config files, and project conventions before editing.
- For migrations or upgrades, use plan_migration before editing to identify dependency, framework, contract, schema, and source evidence; do not assume undocumented upstream breaking changes.
- Before commit approval or when the user asks to review current changes, use review_change_set to inspect staged, unstaged, and untracked files plus static impact/contract/schema/framework risks; do not treat git diff alone as a complete change set.
- After editing, use analyze_tests to identify likely targeted tests and available project-level checks. For refactoring requests, prefer plan_refactoring before editing. If verification fails, use diagnose_verification_failure on the actual verification result before deciding what to edit, then use plan_change when the cause or impact is broad. Use plan_verification to determine the executable verification set from actual changed files and package scripts. Then use execute_verification to run only the planner-generated checks. Do not invent verification commands or pass arbitrary commands to execute_verification.
- Do not commit or push unless explicit approval is present.
- If a tool returns an error, reason from that actual error.
- Do not expose hidden reasoning or chain-of-thought. Give the user concise conclusions and observable work results.
- When the goal is complete, answer with what was actually done.
`;

function parseToolRequest(text) {
  const match = String(text || "").match(/<tool>\s*([\s\S]*?)\s*<\/tool>/i);
  if (!match) return null;
  try {
    const value = JSON.parse(match[1]);
    if (!value || typeof value.name !== "string") return null;
    if (!value.input || typeof value.input !== "object") value.input = {};
    return value;
  } catch {
    return null;
  }
}

function contextSummary(context) {
  const current = getCurrentStep(context);
  return JSON.stringify({
    goal: context.goal,
    reasoningLifecycle: context.reasoningLifecycle ? summarizeReasoningLifecycle(context.reasoningLifecycle) : null,
    plan: context.plan,
    currentStep: current,
    memories: context.retrievedMemories.map(memory => ({ type: memory.type, content: memory.content, importance: memory.importance })),
    observations: context.observations.slice(-10),
    recentToolResults: context.toolHistory.slice(-8).map(entry => ({
      name: entry.name,
      input: entry.input,
      result: entry.result
    }))
  }, null, 2);
}

function activityLabel(name, input = {}) {
  const labels = {
    terminal: "Menjalankan perintah terminal",
    list_files: "Memeriksa struktur workspace",
    read_file: "Membaca file",
    write_file: "Menulis file",
    edit_file: "Menerapkan perubahan kode secara aman",
    git_status: "Memeriksa Git status",
    git_changes: "Memeriksa perubahan Git",
    git_diff: "Membaca Git diff",
    git_log: "Membaca riwayat Git",
    git_add: "Men-stage perubahan Git",
    git_commit: "Membuat commit Git",
    git_push: "Push ke Git remote",
    inspect_project: "Memetakan struktur project",
    search_files: "Mencari file dan simbol yang relevan",
    find_symbol: "Mencari simbol di source code",
    search_code: "Mencari teks di source code",
    inspect_code: "Menganalisis struktur AST source code",
    find_semantic_references: "Mencari referensi AST ke simbol",
    resolve_symbol: "Menyelesaikan binding simbol",
    call_graph: "Menganalisis hubungan pemanggilan fungsi",
    find_references: "Mencari reference simbol di source code",
    find_file_references: "Mencari file yang mengimpor file lain",
    plan_change: "Menyusun rencana perubahan dan dampaknya",
    analyze_tests: "Menganalisis test yang relevan terhadap perubahan",
    diagnose_verification_failure: "Mendiagnosis kegagalan verifikasi dari output aktual",
  plan_refactoring: "Menyusun rencana refactoring berbasis evidence",
    plan_verification: "Menyusun pemeriksaan verifikasi yang relevan",
    execute_verification: "Menjalankan pemeriksaan verifikasi yang relevan",
    review_change_set: "Meninjau change set dan dampak perubahan sebelum commit",
    understand_task: "Memahami tujuan, target, batasan, dan ambiguitas permintaan",
    decompose_task: "Memecah pekerjaan menjadi langkah terurut yang dapat diverifikasi",
    create_execution_plan: "Menyusun execution plan berbasis scope, dependency, gate, dan verification",
    execution_control: "Mengendalikan fase execution plan dengan outcome dan evidence eksplisit",
    replan_execution: "Menyusun instruksi replanning berbasis state change dan evidence terbaru",
    execution_reasoning: "Menentukan langkah eksekusi berikutnya dari state dan evidence aktual",
    reasoning_lifecycle: "Membangun lifecycle reasoning end-to-end sebelum eksekusi",
    establish_task_goal_context: "Menyatukan task, goal, constraint, dan ambiguity sebelum planning"
  };
  let label = labels[name] || `Menjalankan ${name}`;
  if (name === "read_file" && input.path) label += ` · ${input.path}`;
  if (name === "write_file" && input.path) label += ` · ${input.path}`;
  if (name === "terminal" && input.command) label += ` · ${input.command}`;
  return label;
}

function summarizeTool(name, input, result) {
  if (result?.ok === false) return { error: result.error || "Tool gagal" };
  if (name === "read_file" && typeof result?.content === "string") {
    return { sizeBytes: Buffer.byteLength(result.content, "utf8") };
  }
  if (name === "write_file" && input?.path) return { path: input.path };
  if (name === "edit_file") return { path: result?.path, replacements: result?.replacements, conflict: result?.conflict, validationFailed: result?.validationFailed, validation: result?.validation?.ok };
  if (name === "list_files" && Array.isArray(result?.entries)) return { count: result.entries.length };
  if (name === "inspect_project") return { files: result?.fileCount, directories: result?.directoryCount, symbols: result?.symbolCount };
  if (name === "search_files" && Array.isArray(result?.results)) return { matches: result.results.length };
  if (name === "find_symbol" && Array.isArray(result?.results)) return { matches: result.results.length };
  if (name === "search_code" && Array.isArray(result?.results)) return { matches: result.results.length };
  if (name === "resolve_symbol" && Array.isArray(result?.bindings)) return { bindings: result.bindings.length, parser: result.parser };
  if (name === "call_graph" && Array.isArray(result?.edges)) return { edges: result.edges.length, parser: result.parser };
  if (name === "plan_migration") return { affectedFiles: result?.affectedFiles?.length || 0, blockers: result?.blockers?.length || 0, warnings: result?.warnings?.length || 0 };
  if (name === "review_change_set") return { files: result?.summary?.files || 0, staged: result?.summary?.staged || 0, unstaged: result?.summary?.unstaged || 0, untracked: result?.summary?.untracked || 0, risks: result?.risks?.length || 0, findings: result?.findings?.length || 0 };
  if (name === "understand_task") return { taskType: result?.taskType, actions: result?.actions?.length || 0, files: result?.targets?.files?.length || 0, constraints: result?.constraints?.length || 0, ambiguity: result?.ambiguity?.length || 0, confidence: result?.confidence };
  if (name === "decompose_task") return { steps: result?.steps?.length || 0, dependencies: result?.dependencies?.length || 0, taskType: result?.task?.type };
  if (name === "create_execution_plan") return { phases: result?.plan?.phases?.length || 0, dependencies: result?.plan?.dependencies?.length || 0, taskType: result?.plan?.taskType, targets: result?.plan?.targets?.files?.length || 0 };
  if (name === "execution_control") return { status: result?.state?.status || result?.status, currentPhase: result?.state?.currentPhase || result?.currentPhase, transition: result?.transition, replanRequired: result?.replanRequired };
  if (name === "replan_execution") return { reason: result?.reason?.code, changedFiles: result?.evidence?.changedFiles?.length || 0, invalidatedPhases: result?.replan?.invalidatedPhases?.length || 0, warnings: result?.warnings?.length || 0 };
  if (name === "goal_management") return { operation: result?.operation || result?.transition || "", status: result?.status || result?.state?.status, goals: result?.goals?.length || result?.state?.goals?.length || 0, blockers: result?.blockers?.length || 0 };
  if (name === "establish_task_goal_context") return { taskType: result?.task?.type, goals: result?.goals?.length || 0, constraints: result?.constraints?.length || 0, unresolvedAmbiguities: result?.ambiguity?.unresolved?.length || 0, readyForPlanning: result?.decision?.readyForPlanning };
  if (name === "build_reasoning_plan") return { mode: result?.strategy?.mode, horizons: result?.strategy?.horizonCount, steps: result?.steps?.length || 0, phases: result?.phases?.length || 0, gates: result?.gates?.length || 0, ready: result?.readiness?.ready };
  if (name === "execution_reasoning") return { operation: result?.operation, decision: result?.decision?.decision, status: result?.state?.status, transition: result?.transition, replanRequired: result?.replanRequired };
  if (name === "reasoning_lifecycle") return summarizeReasoningLifecycle(result);
  if (name === "find_references" && Array.isArray(result?.results)) return { matches: result.results.length, relatedFiles: result?.relatedFiles?.length || 0 };
  if (name === "find_file_references" && Array.isArray(result?.results)) return { matches: result.results.length };
  if (name === "analyze_tests" && Array.isArray(result?.testFiles)) return { testFiles: result.testFiles.length, relatedTests: result.relatedTests?.length || 0, scripts: result.scripts?.length || 0 };
  if (name === "diagnose_verification_failure" && Array.isArray(result?.diagnoses)) return { analyzedFailures: result.analyzedFailures, categories: [...new Set(result.diagnoses.map(item => item.category))], relevantFiles: [...new Set(result.diagnoses.flatMap(item => item.relevantFiles || []))].length };
  if (name === "analyze_contracts" && result?.counts) return { files: result.counts.files, endpoints: result.counts.endpoints, exports: result.counts.exports, imports: result.counts.imports };
  if (name === "analyze_schemas" && result?.counts) return { files: result.counts.files, schemas: result.counts.schemas };
  if (name === "plan_verification" && Array.isArray(result?.checks)) return { checks: result.checks.length, files: result.files?.length || 0, executed: result.execution?.performed === true };
  if (name === "execute_verification" && result?.summary) return { total: result.summary.total, passed: result.summary.passed, failed: result.summary.failed, stoppedOnFailure: result.summary.stoppedOnFailure, recovery: result.summary.failed > 0 ? "bounded-recovery" : "none" };
  if (name === "git_changes" && result?.files) {
    return {
      branch: result.branch,
      staged: result.files.staged.length,
      unstaged: result.files.unstaged.length,
      untracked: result.files.untracked.length
    };
  }
  return {};
}

async function emitActivity(onActivity, payload) {
  if (typeof onActivity === "function") await onActivity(payload);
}

export async function runAgentV2({ prompt, provider, model, conversation = [], memories = [], onActivity, sessionId = null, approvalToken = null, resumeCheckpoint = null, onCheckpoint = null }) {
  const startedAt = Date.now();
  const context = createAgentContext({ prompt, provider, model, conversation, memories });
  const preparedContext = prepareContext({ prompt, conversation, memories });
  context.conversation = preparedContext.conversation;
  context.conversationSummary = preparedContext.conversationSummary;
  context.retrievedMemories = preparedContext.memories;
  context.contextIntelligence = preparedContext;
  const modelRoute = routeModel({ prompt, conversation: preparedContext.conversation, provider, model });
  context.modelRoute = modelRoute;
  const reasoningLifecycle = establishReasoningLifecycle({ prompt, conversation, memories: context.retrievedMemories, sessionId: context.sessionId || null });
  const toolIntelligence = buildToolIntelligence({ prompt, definitions: TOOL_DEFINITIONS, context: preparedContext });
  context.toolIntelligence = toolIntelligence;
  context.reasoningLifecycle = reasoningLifecycle;
  let autonomy = createExecutionAutonomy({
    plan: reasoningLifecycle.reasoningPlan || reasoningLifecycle.planning?.plan || null,
    state: reasoningLifecycle.execution,
    context: reasoningLifecycle.context
  });
  const specialistPlan = buildSpecialistPlan({ prompt, context: preparedContext, reasoning: reasoningLifecycle });
  let activitySeq = 0;
  const nextActivityId = () => `activity-${++activitySeq}`;

  const planningId = nextActivityId();
  await emitActivity(onActivity, { id: planningId, type: "activity", action: "planning", label: "Memahami permintaan dan membuat rencana", status: "running" });
  const planStarted = Date.now();
  let plan;
  try {
    plan = await createPlan({ prompt, provider: modelRoute.provider, model: modelRoute.model, conversation });
    setPlan(context, plan);
    await emitActivity(onActivity, {
      id: planningId, type: "activity", action: "planning", label: `Rencana dibuat · ${plan.length} langkah`, status: "completed",
      durationMs: Date.now() - planStarted, meta: { steps: plan.length }
    });
  } catch (error) {
    await emitActivity(onActivity, {
      id: planningId, type: "activity", action: "planning", label: "Gagal membuat rencana", status: "error",
      durationMs: Date.now() - planStarted, error: error instanceof Error ? error.message : "Planner gagal"
    });
    throw error;
  }

  const history = context.conversation.map(message => ({
    role: message.role,
    content: message.content
  }));
  const messages = [
    { role: "system", content: AGENT_SYSTEM },
    ...history,
    {
      role: "user",
      content:
        `Current user request:\n${prompt}\n\n` +
        `Initial plan:\n${JSON.stringify(plan, null, 2)}\n\n` +
        `Integrated reasoning lifecycle:\n${JSON.stringify(summarizeReasoningLifecycle(reasoningLifecycle), null, 2)}\n\n` +
        `Specialist orchestration:\n${JSON.stringify(specialistPlan, null, 2)}\n\n` +
        `Context intelligence:\n${JSON.stringify(compactContextForActivity(preparedContext), null, 2)}\n\n` +
        `Tool intelligence:\n${JSON.stringify({ selected: toolIntelligence.selected, chain: toolIntelligence.chain }, null, 2)}\n\n` +
        buildContextPrompt(preparedContext)
    }
  ];
  const steps = [];
  let verificationRecoveryCycles = 0;
  const reliabilityLimits = getReliabilityLimits();
  if (resumeCheckpoint?.messages?.length) {
    messages.length = 0;
    messages.push(...resumeCheckpoint.messages);
    if (Array.isArray(resumeCheckpoint.steps)) {
      steps.push(...resumeCheckpoint.steps);
      for (const entry of resumeCheckpoint.steps) { recordToolResult(context, entry); }
    }
    if (resumeCheckpoint.autonomy) autonomy = resumeCheckpoint.autonomy;
    verificationRecoveryCycles = Number(resumeCheckpoint.verificationRecoveryCycles || 0);
    await emitActivity(onActivity, { id: nextActivityId(), type: "activity", action: "checkpoint_resume", label: `Melanjutkan execution dari checkpoint · turn ${resumeCheckpoint.turn || 0}`, status: "completed", meta: { turn: resumeCheckpoint.turn || 0, steps: steps.length } });
  }
  const autonomyCheckpoint = checkpointExecution({
    runtime: autonomy,
    label: 'Initial execution state',
    evidence: { reasoning: summarizeReasoningLifecycle(reasoningLifecycle) }
  });
  if (autonomyCheckpoint.ok) autonomy = autonomyCheckpoint.runtime;
  const contextActivityId = nextActivityId();
  await emitActivity(onActivity, {
    id: contextActivityId, type: "activity", action: "context",
    label: "Menyiapkan context dan memory yang relevan", status: "completed",
    durationMs: 0, meta: { ...compactContextForActivity(preparedContext), discoveredTools: toolIntelligence.discovered.length, selectedTools: toolIntelligence.selected.length, chainSteps: toolIntelligence.chain.length, specialists: specialistPlan.specialists.map(item => item.id), specialistStages: specialistPlan.stages.length }
  });
  await emitActivity(onActivity, {
    id: nextActivityId(), type: "activity", action: "specialist_orchestration",
    label: `Menentukan specialist path · ${specialistPlan.specialists.map(item => item.name).join(" → ")}`, status: "completed",
    meta: { mode: specialistPlan.mode, stages: specialistPlan.stages.map(stage => ({ id: stage.id, specialist: stage.specialist, dependsOn: stage.dependsOn })) }
  });
  await emitActivity(onActivity, {
    id: nextActivityId(), type: "activity", action: "model_routing",
    label: `Memilih model · ${modelRoute.provider || "unknown"}/${modelRoute.model || "unavailable"}`, status: modelRoute.ok ? "completed" : "error",
    meta: { mode: modelRoute.mode, taskTypes: modelRoute.taskTypes, estimatedTokens: modelRoute.estimatedTokens, candidates: modelRoute.candidates, fallbackCandidates: modelRoute.fallbackCandidates }
  });

  for (let turn = Number(resumeCheckpoint?.turn || 0); turn < Math.min(MAX_AGENT_TURNS, reliabilityLimits.maxAgentTurns); turn++) {
    const modelStarted = Date.now();
    const reasoningId = nextActivityId();
    await emitActivity(onActivity, { id: reasoningId, type: "activity", action: "reasoning", label: "Agent memproses langkah berikutnya", status: "running" });
    const response = await withTimeout(chatWithRoutedProvider({
      prompt,
      provider: modelRoute.provider,
      model: modelRoute.model,
      route: modelRoute,
      messages: [
        ...messages,
        {
          role: "user",
          content:
            `CURRENT AGENT STATE:\n${contextSummary(context)}\n\n` +
            "Continue the task. Request one tool at a time when needed, or provide the final answer if complete."
        }
      ]
    }), reliabilityLimits.operationTimeoutMs, "model execution");
    await emitActivity(onActivity, {
      id: reasoningId, type: "activity", action: "reasoning", label: "Agent memproses langkah berikutnya", status: "completed",
      durationMs: Date.now() - modelStarted
    });

    const request = parseToolRequest(response.text);
    if (!request) {
      context.status = "done";
      return {
        text: response.text,
        plan: context.plan,
        routing: response.routing,
        tool: steps.length ? { steps } : null,
        durationMs: Date.now() - startedAt
      };
    }

    const toolStarted = Date.now();
    const toolActivityId = nextActivityId();
    await emitActivity(onActivity, {
      id: toolActivityId,
      type: "activity", action: "tool", label: activityLabel(request.name, request.input), status: "running",
      meta: { tool: request.name }
    });

    const normalizedInput = normalizeToolInput(request.name, request.input);
    const validation = validateToolCall({ name: request.name, input: normalizedInput, definitions: TOOL_DEFINITIONS });
    let result;
    if (!validation.ok) {
      result = { ok: false, error: validation.error, toolIntelligence: validation };
    } else {
      try {
        result = await withTimeout(executeTool(request.name, normalizedInput, { sessionId, approvalToken }), reliabilityLimits.operationTimeoutMs, `tool ${request.name}`);
      } catch (error) {
        result = { ok: false, error: error instanceof Error ? error.message : "Tool gagal" };
      }
    }
    const interpreted = interpretToolResult({ name: request.name, input: normalizedInput, result });

    const autonomyResult = recordToolAction({
      runtime: autonomy,
      name: request.name,
      input: normalizedInput,
      result,
      context: { ...reasoningLifecycle.context, plan: reasoningLifecycle.reasoningPlan || reasoningLifecycle.planning?.plan || null }
    });
    if (autonomyResult.ok) autonomy = autonomyResult.runtime;

    const entry = { name: request.name, input: normalizedInput, result, toolIntelligence: interpreted };
    steps.push(entry);
    recordToolResult(context, entry);
    recordObservation(context, {
      type: "tool_result",
      tool: request.name,
      ok: result?.ok !== false,
      summary: summarizeTool(request.name, normalizedInput, result),
      interpretation: interpreted
    });

    await emitActivity(onActivity, {
      id: toolActivityId,
      type: "activity",
      action: "tool",
      label: activityLabel(request.name, request.input),
      status: result?.ok === false ? "error" : "completed",
      durationMs: Date.now() - toolStarted,
      meta: {
        tool: request.name,
        ...summarizeTool(request.name, normalizedInput, result),
        toolInterpretation: interpreted,
        autonomyDecision: autonomy.decision,
        autonomyStatus: autonomy.status,
        autonomyTurn: autonomy.turnCount
      },
      error: result?.ok === false ? result.error : undefined
    });

    if (autonomyResult.stop) {
      await emitActivity(onActivity, {
        id: nextActivityId(), type: 'activity', action: 'execution_control',
        label: `Autonomy dihentikan · ${autonomyResult.stopReason}`, status: 'completed',
        meta: { decision: autonomy.decision, turnCount: autonomy.turnCount, toolFailures: autonomy.toolFailures }
      });
    }

    let followUp = interpreted.ok
      ? "Use only this actual result. Continue the original goal."
      : `Tool failure interpretation: ${JSON.stringify(interpreted)}. Follow the suggested recovery using observable evidence; do not invent missing results.`;
    if (request.name === "execute_verification" && result?.summary?.failed > 0) {
      if (verificationRecoveryCycles < MAX_VERIFICATION_RECOVERY_CYCLES) {
        verificationRecoveryCycles += 1;
        followUp =
          `Verification failed. Recovery cycle ${verificationRecoveryCycles}/${MAX_VERIFICATION_RECOVERY_CYCLES}. ` +
          "Use diagnose_verification_failure on the actual failed verification result, then inspect the diagnosed relevant files before editing. " +
          "Read only the relevant files, use plan_change when the impact is broad, then apply a small safe edit and rerun verification. " +
          "Do not claim success until an actual verification run passes. If the failure is unrelated to the change or cannot be safely repaired, report that explicitly.";
        await emitActivity(onActivity, {
          id: nextActivityId(),
          type: "activity",
          action: "verification_recovery",
          label: `Menganalisis kegagalan verifikasi · siklus ${verificationRecoveryCycles}/${MAX_VERIFICATION_RECOVERY_CYCLES}`,
          status: "completed",
          meta: { failed: result.summary.failed, recoveryCycle: verificationRecoveryCycles, maxRecoveryCycles: MAX_VERIFICATION_RECOVERY_CYCLES }
        });
      } else {
        followUp =
          "Verification still fails after the maximum bounded recovery cycles. Do not keep editing automatically. " +
          "Inspect the actual failure and report the remaining blocker and verification evidence.";
      }
    }

    messages.push(
      { role: "assistant", content: response.text },
      {
        role: "user",
        content:
          `EXECUTION AUTONOMY STATE:\n${JSON.stringify({ status: autonomy.status, decision: autonomy.decision, turnCount: autonomy.turnCount, toolFailures: autonomy.toolFailures, recoveryCycles: autonomy.recoveryCycles }, null, 2)}\n\n` +
          `ACTUAL TOOL RESULT (${request.name}):\n` +
          `${JSON.stringify(result, null, 2)}\n\n` +
          followUp
      }
    );

    if (typeof onCheckpoint === "function") {
      await onCheckpoint({
        type: "tool-result", turn: turn + 1, steps: structuredClone(steps), messages: structuredClone(messages),
        autonomy: structuredClone(autonomy), verificationRecoveryCycles, status: autonomy.status
      });
    }

    if (getCurrentStep(context)) advancePlan(context);

    if (autonomyResult.stop) {
      context.status = 'stopped';
      return {
        text: `Execution dihentikan secara bounded: ${autonomyResult.stopReason}`,
        plan: context.plan,
        routing: { selectedProvider: modelRoute.provider, selectedModel: modelRoute.model },
        tool: { steps },
        autonomy: { status: autonomy.status, decision: autonomy.decision, turnCount: autonomy.turnCount, toolFailures: autonomy.toolFailures, recoveryCycles: autonomy.recoveryCycles, checkpoints: autonomy.checkpoints },
        durationMs: Date.now() - startedAt
      };
    }
  }

  return {
    text: `Agent mencapai batas maksimum ${MAX_AGENT_TURNS} turns. Pekerjaan dihentikan agar tidak berjalan tanpa batas.`,
    plan: context.plan,
    routing: { selectedProvider: modelRoute.provider, selectedModel: modelRoute.model },
    tool: { steps },
    durationMs: Date.now() - startedAt
  };
}
