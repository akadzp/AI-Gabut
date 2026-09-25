import { decideNextAction } from './decision-making.js';
import { createExecutionState, advanceExecution, requestExecutionReplan } from './execution-control.js';
import { createReplan } from './replanning-intelligence.js';

function clean(value, max = 500) { return String(value ?? '').trim().slice(0, max); }

export function runExecutionReasoning({ operation = 'decide', plan, state, phaseId, outcome, evidence = [], note = '', context = {}, latestResult = null, reason = '', materialChange = true, constraints = [] } = {}) {
  if (operation === 'create') {
    const execution = createExecutionState({ plan, sessionId: context?.sessionId });
    return { ok: execution.ok, type: 'execution-reasoning', operation, state: execution, decision: decideNextAction({ context, executionState: execution }) };
  }

  if (operation === 'advance') {
    const advanced = advanceExecution({ plan, state, phaseId, outcome, evidence, note });
    if (!advanced.ok) return { ok: false, type: 'execution-reasoning', operation, error: advanced.error, state: advanced.state };
    const decision = advanced.transition === 'advance' && !latestResult
      ? { ok: true, decision: 'continue', reason: 'Phase completed with explicit evidence; continue to the next runnable phase.', requiredEvidence: Array.isArray(evidence) ? evidence.slice(0, 12) : [], confidence: 'high' }
      : decideNextAction({ context, executionState: advanced.state, latestResult });
    return { ok: true, type: 'execution-reasoning', operation, state: advanced.state, transition: advanced.transition, replanRequired: advanced.replanRequired, decision };
  }

  if (operation === 'replan') {
    const directive = requestExecutionReplan({ state, reason, materialChange });
    const replan = createReplan({ plan, state, reason, evidence: latestResult || {}, constraints });
    return { ok: true, type: 'execution-reasoning', operation, state, decision: { decision: 'replan', reason: clean(reason) || 'Material state change', confidence: 'high' }, directive, replan };
  }

  const decision = decideNextAction({ context, executionState: state, latestResult });
  return { ok: true, type: 'execution-reasoning', operation: 'decide', decision, state: state || null };
}
