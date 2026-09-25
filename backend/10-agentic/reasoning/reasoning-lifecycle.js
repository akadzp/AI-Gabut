import { understandTask } from './task-understanding.js';
import { createGoalState } from './goal-management.js';
import { establishTaskGoalContext } from './task-goal-context.js';
import { decomposeTask } from './task-decomposition.js';
import { createExecutionPlan } from './planning-intelligence.js';
import { buildReasoningPlan } from './reasoning-plan.js';
import { createExecutionState } from './execution-control.js';
import { runExecutionReasoning } from './execution-reasoning.js';

const MAX_TEXT = 12000;

function clean(value, max = MAX_TEXT) {
  return String(value ?? '').trim().slice(0, max);
}

/**
 * Build the bounded end-to-end reasoning state used by the Agent before tool execution.
 * This is orchestration only: it does not execute workspace mutations, terminal commands,
 * commits, pushes, or expose hidden chain-of-thought.
 */
export function establishReasoningLifecycle({ prompt = '', conversation = [], memories = [], sessionId = null } = {}) {
  const text = clean(prompt);
  const understanding = understandTask({ prompt: text, conversation });
  const goalState = createGoalState({ prompt: text, understanding, constraints: understanding.constraints || [] });
  const taskGoal = establishTaskGoalContext({
    prompt: text,
    conversation,
    understanding,
    goalState
  });

  const decomposition = decomposeTask({
    prompt: text,
    understanding,
    conversation
  });

  const planning = createExecutionPlan({
    prompt: text,
    understanding,
    decomposition,
    evidence: { taskGoal }
  });

  const reasoningPlan = buildReasoningPlan({
    prompt: text,
    context: taskGoal,
    understanding,
    decomposition,
    planning,
    goals: goalState,
    evidence: { memories: memories.slice(-8) }
  });

  const executionPlan = reasoningPlan.ok ? reasoningPlan : planning.plan;
  const executionState = createExecutionState({ plan: executionPlan, sessionId });
  const initialDecision = runExecutionReasoning({
    operation: 'decide',
    plan: executionPlan,
    state: executionState,
    context: taskGoal
  });

  return {
    ok: Boolean(understanding?.ok && taskGoal?.ok && decomposition?.ok && planning?.ok && reasoningPlan?.ok && executionState?.ok),
    type: 'integrated-reasoning-lifecycle',
    task: understanding,
    goals: goalState,
    context: taskGoal,
    decomposition,
    planning,
    reasoningPlan,
    execution: executionState,
    decision: initialDecision?.decision || null,
    lifecycle: [
      'understand',
      'establish-goals-and-constraints',
      'decompose',
      'plan',
      'initialize-execution-state',
      'decide-next-action'
    ],
    policy: {
      bounded: true,
      refreshAfterMaterialEvidence: true,
      noImplicitScopeExpansion: true,
      noImplicitCommitOrPush: true,
      consequentialActionsRequireEvidence: true
    }
  };
}

export function summarizeReasoningLifecycle(lifecycle) {
  return {
    ready: Boolean(lifecycle?.context?.decision?.readyForPlanning && lifecycle?.reasoningPlan?.readiness?.ready),
    taskType: lifecycle?.context?.task?.type || lifecycle?.task?.taskType || 'general',
    goals: lifecycle?.goals?.goals?.length || 0,
    constraints: lifecycle?.context?.constraints?.length || 0,
    unresolvedAmbiguities: lifecycle?.context?.ambiguity?.unresolved?.length || 0,
    steps: lifecycle?.reasoningPlan?.steps?.length || 0,
    phases: lifecycle?.reasoningPlan?.phases?.length || 0,
    horizonCount: lifecycle?.reasoningPlan?.strategy?.horizonCount || 1,
    currentPhase: lifecycle?.execution?.currentPhase || null,
    decision: lifecycle?.decision?.decision || null
  };
}
