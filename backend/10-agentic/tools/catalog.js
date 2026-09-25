import { runTerminalTool } from "./terminal.js";
import { runWorkspaceTool } from "./workspace.js";
import { runGitTool } from "./git.js";
import { understandTask } from "../reasoning/task-understanding.js";
import { decomposeTask } from "../reasoning/task-decomposition.js";
import { createExecutionPlan } from "../reasoning/planning-intelligence.js";
import { createExecutionState, advanceExecution, requestExecutionReplan } from "../reasoning/execution-control.js";
import { createReplan } from "../reasoning/replanning-intelligence.js";
import { createGoalState, updateGoalState, assessGoals } from "../reasoning/goal-management.js";
import { establishTaskGoalContext } from "../reasoning/task-goal-context.js";
import { buildReasoningPlan } from "../reasoning/reasoning-plan.js";
import { runExecutionReasoning } from "../reasoning/execution-reasoning.js";
import { establishReasoningLifecycle } from "../reasoning/reasoning-lifecycle.js";
import { buildSpecialistPlan, createSpecialistHandoff, coordinateSpecialists, getSpecialists } from "../specialists/orchestrator.js";

export const CAPABILITY_GROUPS = {
  core: {
    name: "core",
    description: "Local execution primitives available to the Agent.",
    tools: ["terminal", "list_files", "read_file", "write_file", "edit_file"]
  },
  coding: {
    name: "coding",
    description: "Code-understanding and software-development capabilities independent of any external service.",
    tools: [
      "inspect_project", "search_files", "find_symbol", "search_code",
      "find_references", "find_file_references", "dependency_graph", "analyze_impact",
      "inspect_code", "find_semantic_references", "resolve_symbol", "call_graph", "plan_change", "analyze_tests", "diagnose_verification_failure", "plan_refactoring", "analyze_contracts", "analyze_schemas", "analyze_frameworks", "plan_migration", "review_change_set"
    ]
  },
  reasoning: {
    name: "reasoning",
    description: "Bounded task-understanding primitives used by the Agent before deeper planning.",
    tools: ["understand_task", "decompose_task", "create_execution_plan", "execution_control", "replan_execution", "goal_management", "establish_task_goal_context", "build_reasoning_plan", "execution_reasoning", "reasoning_lifecycle"]
  },
  specialist: {
    name: "specialist",
    description: "Role-based specialist coordination over the same bounded Agent runtime.",
    tools: ["specialist_orchestration"]
  },
  evaluation: {
    name: "evaluation",
    description: "Local Agent evaluation and benchmarking primitives; evaluation does not execute arbitrary model actions.",
    tools: []
  },
  version_control: {
    name: "version_control",
    description: "Local Git version-control operations. Git hosting providers are integrations, not capabilities.",
    tools: ["git_status", "git_changes", "git_diff", "git_log", "git_add", "git_commit", "git_push"]
  }
};

export const CAPABILITY_TOOL_DEFINITIONS = [
  { name: "understand_task", description: "Extract task type, actions, targets, constraints, and ambiguity signals before planning.", permission: "read", capability: "reasoning" },
  { name: "decompose_task", description: "Create a bounded, dependency-aware task execution outline from understood task evidence without exposing hidden reasoning.", permission: "read", capability: "reasoning" },
  { name: "create_execution_plan", description: "Create a bounded operational execution plan from task understanding, decomposition, constraints, and available evidence; does not execute actions.", permission: "read", capability: "reasoning" },
  { name: "execution_control", description: "Advance or block a bounded execution plan using explicit phase outcomes and evidence; does not execute arbitrary actions or implicitly commit/push.", permission: "write", capability: "reasoning" },
  { name: "replan_execution", description: "Create a bounded replanning directive from execution state changes and fresh evidence; does not execute or edit anything.", permission: "read", capability: "reasoning" },
  { name: "goal_management", description: "Create, update, or assess explicit task goals and completion criteria using observable evidence; does not execute edits or commit/push.", permission: "write", capability: "reasoning" },
  { name: "establish_task_goal_context", description: "Build an integrated task, goal, constraint, and ambiguity context before planning consequential work; read-only and bounded.", permission: "read", capability: "reasoning" },
  { name: "build_reasoning_plan", description: "Build an integrated decomposition, execution strategy, dependency graph, gates, and bounded long-horizon plan from task context; does not execute actions.", permission: "read", capability: "reasoning" },
  { name: "execution_reasoning", description: "Decide whether to inspect, continue, diagnose, recover, replan, clarify, or report based on explicit execution state and observable evidence; does not execute actions.", permission: "write", capability: "reasoning" },
  { name: "reasoning_lifecycle", description: "Build the bounded end-to-end task, goal, decomposition, planning, execution-state, and next-action context in one operation; does not execute actions.", permission: "read", capability: "reasoning" },
  { name: "specialist_orchestration", description: "Plan specialist roles and observable handoffs for planner, coding, research, testing, reviewer, and coordinator roles; does not execute hidden parallel work.", permission: "read", capability: "specialist" },
  { name: "terminal", description: "Run an allowed terminal command inside the workspace.", permission: "write", capability: "core" },
  { name: "list_files", description: "List files and directories in the workspace.", permission: "read", capability: "core" },
  { name: "read_file", description: "Read a file from the workspace.", permission: "read", capability: "core" },
  { name: "write_file", description: "Create or replace a workspace file.", permission: "write", capability: "core" },
  { name: "edit_file", description: "Safely edit an existing file with an expected SHA-256 and stale-write protection.", permission: "write", capability: "coding" },
  { name: "inspect_project", description: "Build a compact structural map of the workspace and project metadata.", permission: "read", capability: "coding" },
  { name: "search_files", description: "Search relevant project file paths and symbols before reading files.", permission: "read", capability: "coding" },
  { name: "find_symbol", description: "Find exported JavaScript/TypeScript symbols by name.", permission: "read", capability: "coding" },
  { name: "dependency_graph", description: "Build a lightweight project dependency graph from resolved local imports.", permission: "read", capability: "coding" },
  { name: "analyze_impact", description: "Analyze files that may be affected by changing a project file.", permission: "read", capability: "coding" },
  { name: "inspect_code", description: "Parse a JavaScript/TypeScript source file with AST semantics without reading the full file into the model.", permission: "read", capability: "coding" },
  { name: "find_semantic_references", description: "Find AST identifier references with exact line and column information.", permission: "read", capability: "coding" },
  { name: "resolve_symbol", description: "Resolve a symbol to its local declaration or imported target in a specific source file.", permission: "read", capability: "coding" },
  { name: "call_graph", description: "Inspect local and imported function call edges without reading the entire repository.", permission: "read", capability: "coding" },
  { name: "plan_change", description: "Build a read-only change plan before editing.", permission: "read", capability: "coding" },
  { name: "analyze_tests", description: "Analyze likely tests and project verification scripts for changed source files without executing them.", permission: "read", capability: "coding" },
  { name: "diagnose_verification_failure", description: "Classify actual verification failures and identify relevant files and next diagnostic actions without editing or executing commands.", permission: "read", capability: "coding" },
  { name: "plan_refactoring", description: "Build a read-only refactoring plan from symbol/reference evidence before editing.", permission: "read", capability: "coding" },
  { name: "analyze_contracts", description: "Analyze observable API routes and module contracts without executing the application.", permission: "read", capability: "coding" },
  { name: "analyze_schemas", description: "Analyze observable TypeScript, runtime validation, and JSON schemas without executing the application.", permission: "read", capability: "coding" },
  { name: "analyze_frameworks", description: "Detect observable framework usage, configuration files, and common project conventions without executing the application.", permission: "read", capability: "coding" },
  { name: "plan_migration", description: "Build a read-only migration plan from dependency, framework, contract, schema, and source evidence.", permission: "read", capability: "coding" },
  { name: "review_change_set", description: "Review the current Git change set and static risk/impact evidence before commit.", permission: "read", capability: "coding" },
  { name: "search_code", description: "Search source-code contents and return matching paths, line numbers, and short snippets.", permission: "read", capability: "coding" },
  { name: "plan_verification", description: "Build a read-only verification plan from changed files and project scripts; does not execute commands.", permission: "read", capability: "coding" },
  { name: "execute_verification", description: "Execute checks generated by the verification planner through the terminal safety policy.", permission: "write", capability: "coding" },
  { name: "find_references", description: "Find declarations, imports, and references to a JavaScript/TypeScript symbol.", permission: "read", capability: "coding" },
  { name: "find_file_references", description: "Find workspace files that import a specific project file.", permission: "read", capability: "coding" },
  { name: "git_status", description: "Read the current Git status.", permission: "read", capability: "version_control" },
  { name: "git_diff", description: "Read the current Git diff. Untracked files are not included by git diff.", permission: "read", capability: "version_control" },
  { name: "git_changes", description: "Read Git branch/status plus staged, unstaged, and untracked changes.", permission: "read", capability: "version_control" },
  { name: "git_log", description: "Read recent Git commits.", permission: "read", capability: "version_control" },
  { name: "git_add", description: "Stage explicitly selected paths.", permission: "write", capability: "version_control" },
  { name: "git_commit", description: "Create a Git commit.", permission: "approval", capability: "version_control" },
  { name: "git_push", description: "Push commits to a Git remote. This is still a local Git operation; hosting-provider APIs belong under integrations.", permission: "approval", capability: "version_control" }
];

const gitActions = {
  git_status: "status",
  git_diff: "diff",
  git_changes: "changes",
  git_log: "log",
  git_add: "add",
  git_commit: "commit",
  git_push: "push"
};

export async function executeCapabilityTool(name, input = {}, governance = {}) {
  if (name === "terminal") return runTerminalTool(input);
  if (name === "understand_task") return understandTask(input);
  if (name === "decompose_task") return decomposeTask(input);
  if (name === "create_execution_plan") return createExecutionPlan(input);
  if (name === "replan_execution") return createReplan(input);
  if (name === "establish_task_goal_context") return establishTaskGoalContext(input);
  if (name === "build_reasoning_plan") return buildReasoningPlan(input);
  if (name === "execution_reasoning") return runExecutionReasoning(input);
  if (name === "reasoning_lifecycle") return establishReasoningLifecycle(input);
  if (name === "specialist_orchestration") {
    if (input?.operation === "catalog") return { ok: true, type: "specialist-catalog", specialists: getSpecialists() };
    if (input?.operation === "plan") return buildSpecialistPlan(input);
    if (input?.operation === "handoff") return createSpecialistHandoff(input);
    if (input?.operation === "coordinate") return coordinateSpecialists(input);
    return { ok: false, error: "specialist_orchestration operation must be catalog, plan, handoff, or coordinate" };
  }
  if (name === "goal_management") {
    if (input?.operation === "create") return createGoalState(input);
    if (input?.operation === "update") return updateGoalState(input);
    if (input?.operation === "assess") return assessGoals(input);
    return { ok: false, error: "goal_management operation must be create, update, or assess" };
  }
  if (name === "execution_control") {
    if (input?.operation === "create") return createExecutionState(input);
    if (input?.operation === "advance") return advanceExecution(input);
    if (input?.operation === "replan") return requestExecutionReplan(input);
    return { ok: false, error: "execution_control operation must be create, advance, or replan" };
  }

  const workspaceTools = [
    "list_files", "read_file", "write_file", "edit_file", "inspect_project", "search_files", "find_symbol",
    "search_code", "inspect_code", "find_semantic_references", "find_references", "find_file_references",
    "dependency_graph", "analyze_impact", "resolve_symbol", "call_graph", "plan_change", "analyze_tests", "diagnose_verification_failure", "plan_refactoring", "analyze_contracts", "analyze_schemas", "analyze_frameworks", "plan_migration", "review_change_set", "plan_verification", "execute_verification"
  ];
  if (workspaceTools.includes(name)) return runWorkspaceTool(name, input);

  if (gitActions[name]) {
    if (["git_commit", "git_push"].includes(name) && input?.approved !== true) {
      return { ok: false, blocked: true, requiresApproval: true, error: `${name} requires explicit approval` };
    }
    return runGitTool(gitActions[name], input);
  }

  throw new Error(`Capability tool tidak dikenal: ${name}`);
}
