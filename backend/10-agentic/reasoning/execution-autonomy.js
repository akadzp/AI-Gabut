import { runExecutionReasoning } from './execution-reasoning.js';

const DEFAULT_POLICY = Object.freeze({
  maxTurns: 24,
  maxToolFailures: 3,
  maxRepeatedToolCalls: 2,
  maxRecoveryCycles: 2,
  requireEvidenceForConsequentialActions: true,
  stopOnTerminalState: true
});

function clean(value, max = 1000) {
  return String(value ?? '').trim().slice(0, max);
}

function unique(values, max = 16) {
  return [...new Set((Array.isArray(values) ? values : []).map(value => clean(value, 300)).filter(Boolean))].slice(0, max);
}

function signature(name, input) {
  let serialized = '{}';
  try { serialized = JSON.stringify(input ?? {}); } catch { /* ignore */ }
  return `${name}:${serialized}`.slice(0, 2000);
}

export function createExecutionAutonomy({ plan, state, context = {}, policy = {} } = {}) {
  const effectivePolicy = { ...DEFAULT_POLICY, ...policy };
  return {
    ok: true,
    status: state?.status || 'ready',
    state: state || null,
    policy: effectivePolicy,
    turnCount: 0,
    toolFailures: 0,
    recoveryCycles: 0,
    repeatedToolCalls: 0,
    lastToolSignature: null,
    events: [],
    checkpoints: [],
    decision: runExecutionReasoning({ operation: 'decide', plan, state, context })?.decision || null
  };
}

function pushEvent(runtime, event) {
  runtime.events.push({
    at: new Date().toISOString(),
    ...event
  });
  runtime.events = runtime.events.slice(-32);
}

export function observeExecution({ runtime, observation = {}, context = {} } = {}) {
  if (!runtime) return { ok: false, error: 'Execution autonomy runtime is required.' };
  const next = structuredClone(runtime);
  pushEvent(next, { type: 'observation', observation });
  const decision = runExecutionReasoning({
    operation: 'decide',
    plan: context.plan || null,
    state: next.state,
    context,
    latestResult: observation.result || null
  });
  next.decision = decision.decision || null;
  return { ok: true, runtime: next, decision: next.decision };
}

export function recordToolAction({ runtime, name, input = {}, result = null, context = {} } = {}) {
  if (!runtime) return { ok: false, error: 'Execution autonomy runtime is required.' };
  const next = structuredClone(runtime);
  next.turnCount += 1;
  const currentSignature = signature(name, input);
  next.repeatedToolCalls = currentSignature === next.lastToolSignature ? next.repeatedToolCalls + 1 : 0;
  next.lastToolSignature = currentSignature;
  if (result?.ok === false) next.toolFailures += 1;
  else next.toolFailures = 0;

  const event = {
    type: 'tool-result',
    tool: name,
    ok: result?.ok !== false,
    summary: clean(result?.error || result?.summary?.execution || '', 500)
  };
  pushEvent(next, event);

  if (result?.ok === false) {
    if (next.recoveryCycles < next.policy.maxRecoveryCycles) next.recoveryCycles += 1;
  }

  const latestResult = result || { ok: false, error: 'No tool result supplied.' };
  const reasoning = runExecutionReasoning({
    operation: result?.ok === false ? 'replan' : 'decide',
    plan: context.plan || null,
    state: next.state,
    context,
    latestResult,
    reason: result?.ok === false ? result.error : '',
    materialChange: result?.ok === false
  });
  next.decision = reasoning.decision || null;

  const stopReason = stoppingReason(next, reasoning);
  if (stopReason) next.status = 'stopped';

  return {
    ok: true,
    runtime: next,
    reasoning,
    stop: Boolean(stopReason),
    stopReason
  };
}

export function advanceExecutionPhase({ runtime, plan, phaseId, outcome, evidence = [], note = '', context = {} } = {}) {
  if (!runtime) return { ok: false, error: 'Execution autonomy runtime is required.' };
  const next = structuredClone(runtime);
  const result = runExecutionReasoning({ operation: 'advance', plan, state: next.state, phaseId, outcome, evidence, note, context });
  if (!result.ok) return { ok: false, error: result.error, runtime: next };
  next.state = result.state;
  next.status = result.state?.status || next.status;
  next.decision = result.decision || null;
  pushEvent(next, { type: 'phase-transition', phaseId, outcome, transition: result.transition, evidence: unique(evidence) });
  return { ok: true, runtime: next, reasoning: result, stop: next.status === 'completed' && next.policy.stopOnTerminalState };
}

export function checkpointExecution({ runtime, label = '', evidence = {} } = {}) {
  if (!runtime) return { ok: false, error: 'Execution autonomy runtime is required.' };
  const next = structuredClone(runtime);
  const checkpoint = {
    id: `checkpoint-${next.checkpoints.length + 1}`,
    label: clean(label, 200) || `Checkpoint ${next.checkpoints.length + 1}`,
    turnCount: next.turnCount,
    status: next.status,
    state: next.state,
    evidence
  };
  next.checkpoints.push(checkpoint);
  next.checkpoints = next.checkpoints.slice(-8);
  pushEvent(next, { type: 'checkpoint', checkpointId: checkpoint.id, label: checkpoint.label });
  return { ok: true, runtime: next, checkpoint };
}

function stoppingReason(runtime, reasoning) {
  if (runtime.turnCount >= runtime.policy.maxTurns) return `Maximum execution turns reached (${runtime.policy.maxTurns}).`;
  if (runtime.toolFailures >= runtime.policy.maxToolFailures) return `Maximum consecutive tool failures reached (${runtime.policy.maxToolFailures}).`;
  if (runtime.repeatedToolCalls >= runtime.policy.maxRepeatedToolCalls) return `Repeated identical tool action detected (${runtime.policy.maxRepeatedToolCalls + 1} attempts).`;
  if (runtime.policy.stopOnTerminalState && ['completed', 'blocked', 'failed', 'stopped'].includes(runtime.state?.status)) return `Execution entered terminal state: ${runtime.state.status}.`;
  if (reasoning?.decision?.decision === 'clarify') return 'Execution requires clarification before consequential actions.';
  return null;
}

export const EXECUTION_AUTONOMY_CAPABILITIES = [
  'observe_plan_act',
  'verification_loop',
  'recovery_loop',
  'stopping_criteria',
  'bounded_autonomy',
  'checkpointing',
  'iterative_execution'
];
