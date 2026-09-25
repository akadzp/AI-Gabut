import assert from 'node:assert/strict';
import { createGoalState, updateGoalState, assessGoals } from '../../core/agent-engine/reasoning/goal-management.js';

const state = createGoalState({
  prompt: 'Perbaiki authentication tanpa mengubah API',
  constraints: ['preserve-api', 'no-commit'],
  goals: [
    { id: 'auth', title: 'Fix authentication', description: 'Authentication flow works', priority: 'critical', criteria: [
      { id: 'tests', description: 'Relevant authentication verification passes' },
      { id: 'api', description: 'Existing API contract remains compatible' }
    ] }
  ]
});
assert.equal(state.ok, true);
assert.equal(state.status, 'active');
assert.deepEqual(state.constraints, ['preserve-api', 'no-commit']);

const progress = updateGoalState({ state, goalId: 'auth', criterionId: 'tests', status: 'met', evidence: ['npm test: PASS'] });
assert.equal(progress.ok, true);
assert.equal(progress.state.status, 'active');

const blocked = updateGoalState({ state: progress.state, goalId: 'auth', criterionId: 'api', status: 'failed', evidence: ['contract check: changed'] });
assert.equal(blocked.ok, true);
assert.equal(blocked.state.status, 'blocked');

const assessment = assessGoals({ state: blocked.state });
assert.equal(assessment.ok, true);
assert.equal(assessment.completion.complete, false);
assert.deepEqual(assessment.blockers, ['auth']);
assert.deepEqual(assessment.goals[0].unmetCriteria, ['api']);

const complete = updateGoalState({ state: progress.state, goalId: 'auth', criterionId: 'api', status: 'met', evidence: ['API compatibility verified'] });
assert.equal(complete.state.status, 'completed');
assert.equal(assessGoals({ state: complete.state }).completion.complete, true);

console.log('Goal Management Intelligence: OK');
