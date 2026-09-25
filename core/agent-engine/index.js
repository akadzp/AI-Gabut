/**
 * Public Agent Engine boundary.
 *
 * Consumers outside the engine must import Agent Engine services from this
 * module instead of reaching into context, reasoning, model, tool, evaluation,
 * specialist, or reliability internals directly.
 */
export { runAgent } from "./core/agent.js";

export {
  getOrCreateSession,
  addMessage,
  getRecentMessages,
  getMemories
} from "./context/session.js";

export {
  extractMemoryCandidates,
  addMemories,
  retrieveMemories,
  getActiveMemories,
  resolveMemoryConflicts
} from "./context/memory.js";

export { runGitTool } from "./tools/git.js";

export { TOOL_CATALOG, TOOL_DEFINITIONS } from "./core/tool-registry.js";
export { buildToolIntelligence, discoverTools } from "./core/tool-intelligence.js";

export { listModels } from "./models/index.js";
export { routeModel, getModelCandidates } from "./models/model-router.js";

export { getEvaluationCases } from "./evaluation/benchmarks.js";
export { scoreTrajectory, analyzeFailures } from "./evaluation/evaluator.js";

export {
  getSpecialists,
  buildSpecialistPlan,
  createSpecialistHandoff,
  coordinateSpecialists
} from "./specialists/orchestrator.js";

export {
  resumeExecution,
  getReliabilityMetrics,
  getReliabilityLimits
} from "./reliability/runtime.js";
