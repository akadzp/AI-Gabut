import assert from 'node:assert/strict';
import { createExecutionPlan } from '../../core/agent-engine/reasoning/planning-intelligence.js';
import { createExecutionState, advanceExecution, requestExecutionReplan } from '../../core/agent-engine/reasoning/execution-control.js';

const plan = createExecutionPlan({
  prompt: 'Perbaiki auth dan jalankan test',
  understanding: { taskType: 'modification', actions: ['edit', 'test'], targets: { files: ['backend/auth.js'] }, constraints: [], ambiguity: [] },
  decomposition: { steps: [] }
}).plan;

let result = createExecutionState({ plan, sessionId: 'check' });
assert.equal(result.status, 'ready');
assert.equal(result.currentPhase, 'scope');

let advanced = advanceExecution({ plan, state: result, phaseId: 'scope', outcome: 'success', evidence: ['scope-confirmed'] });
assert.equal(advanced.ok, true);
assert.equal(advanced.state.currentPhase, 'evidence');

advanced = advanceExecution({ plan, state: advanced.state, phaseId: 'evidence', outcome: 'failure', evidence: ['tool error'] });
assert.equal(advanced.replanRequired, true);
assert.equal(advanced.transition, 'recovery-required');

const replan = requestExecutionReplan({ state: advanced.state, reason: 'verification failure changed the execution state' });
assert.equal(replan.replanRequired, true);
assert.equal(replan.status, 'replan-required');

console.log('Execution Control Intelligence: OK');
