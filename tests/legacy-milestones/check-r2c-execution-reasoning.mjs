import assert from 'node:assert/strict';
import { runExecutionReasoning } from '../../core/agent-engine/reasoning/execution-reasoning.js';

const plan = { phases: [
  { id: 'inspect', title: 'Inspect', purpose: 'Inspect', dependsOn: [] },
  { id: 'edit', title: 'Edit', purpose: 'Edit', dependsOn: ['inspect'] },
  { id: 'verify', title: 'Verify', purpose: 'Verify', dependsOn: ['edit'] }
] };
const context = { decision: { readyForPlanning: true }, ambiguity: { unresolved: [] }, sessionId: 'r2c-test' };
const created = runExecutionReasoning({ operation: 'create', plan, context });
assert.equal(created.ok, true);
assert.equal(created.state.currentPhase, 'inspect');
assert.equal(created.decision.decision, 'inspect');

const advanced = runExecutionReasoning({ operation: 'advance', plan, state: created.state, phaseId: 'inspect', outcome: 'success', evidence: ['backend/auth.js read'] , context });
assert.equal(advanced.ok, true);
assert.equal(advanced.state.currentPhase, 'edit');
assert.equal(advanced.decision.decision, 'continue');

const failed = runExecutionReasoning({ operation: 'advance', plan, state: advanced.state, phaseId: 'edit', outcome: 'failure', evidence: ['stale hash'], context });
assert.equal(failed.ok, true);
assert.equal(failed.replanRequired, true);
assert.equal(failed.decision.decision, 'replan');

const replan = runExecutionReasoning({ operation: 'replan', plan, state: failed.state, reason: 'verification failed', latestResult: { changedFiles: ['backend/auth.js'] }, context });
assert.equal(replan.ok, true);
assert.equal(replan.decision.decision, 'replan');
assert.equal(replan.replan.ok, true);

const ambiguous = runExecutionReasoning({ operation: 'decide', state: created.state, context: { decision: { readyForPlanning: false }, ambiguity: { unresolved: ['missing-target'] } } });
assert.equal(ambiguous.decision.decision, 'clarify');
console.log('R2-C Execution Reasoning: OK (control + decision + replanning)');
