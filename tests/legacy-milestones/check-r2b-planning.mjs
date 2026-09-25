import assert from 'node:assert/strict';
import { buildReasoningPlan } from '../../core/agent-engine/reasoning/reasoning-plan.js';

const context = {
  task: { type: 'modification', goal: 'Refactor auth flow across the service', actions: ['inspect', 'edit', 'test'], targets: { files: ['backend/auth.js', 'core/api/server.js'] } },
  goals: [{ id: 'primary', title: 'Refactor auth safely', criteria: [{ id: 'verified', required: true }] }],
  constraints: ['preserve-api', 'no-commit-or-push'],
  ambiguity: { unresolved: [] },
  decision: { readyForPlanning: true }
};
const decomposition = {
  steps: [
    { id: 'understand', title: 'Confirm scope', purpose: 'Confirm scope', dependsOn: [] },
    { id: 'inspect', title: 'Inspect', purpose: 'Gather evidence', dependsOn: ['understand'] },
    { id: 'impact', title: 'Impact', purpose: 'Assess impact', dependsOn: ['inspect'] },
    { id: 'plan-change', title: 'Plan change', purpose: 'Bound changes', dependsOn: ['impact'] },
    { id: 'edit', title: 'Edit', purpose: 'Apply changes', dependsOn: ['plan-change'] },
    { id: 'verify', title: 'Verify', purpose: 'Verify', dependsOn: ['edit'] },
    { id: 'report', title: 'Report', purpose: 'Report', dependsOn: ['verify'] }
  ]
};
const result = buildReasoningPlan({ prompt: context.task.goal, context, decomposition, goals: { goals: context.goals } });
assert.equal(result.ok, true);
assert.equal(result.readiness.ready, true);
assert.equal(result.strategy.mode, 'long-horizon');
assert.ok(result.steps.length >= 7);
assert.ok(result.phases.some(p => p.id === 'change'));
assert.ok(result.phases.some(p => p.id === 'verify'));
assert.equal(result.executionPolicy.noImplicitCommitOrPush, true);

const ambiguous = buildReasoningPlan({
  prompt: 'ubah itu',
  context: { task: { type: 'general', goal: 'ubah itu', actions: [] }, ambiguity: { unresolved: ['missing-target'] }, decision: { readyForPlanning: false } }
});
assert.equal(ambiguous.readiness.ready, false);
assert.equal(ambiguous.readiness.requiresClarification, true);
console.log(`R2-B Planning Intelligence: OK (${result.strategy.mode}, ${result.steps.length} steps, ${result.phases.length} phases)`);
