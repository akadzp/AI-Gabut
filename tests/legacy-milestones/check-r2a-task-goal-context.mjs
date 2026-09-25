import assert from 'node:assert/strict';
import { establishTaskGoalContext } from '../../core/agent-engine/reasoning/task-goal-context.js';

const result = establishTaskGoalContext({
  prompt: 'Perbaiki auth di backend/auth.js, jangan ubah API dan jangan commit atau push.',
  conversation: [],
  understanding: {
    taskType: 'modification',
    goal: 'Perbaiki auth di backend/auth.js',
    actions: ['edit'],
    targets: { files: ['backend/auth.js'] },
    constraints: ['preserve-api', 'no-commit-or-push'],
    ambiguity: [],
    confidence: 'high'
  }
});
assert.equal(result.ok, true);
assert.equal(result.task.type, 'modification');
assert.ok(result.goals.length >= 1);
assert.ok(result.constraints.includes('preserve-api'));
assert.ok(result.constraints.includes('no-commit-or-push'));
assert.equal(result.decision.readyForPlanning, true);
assert.equal(result.decision.mutationAllowed, true);
assert.equal(result.decision.commitOrPushAllowed, false);

const ambiguous = establishTaskGoalContext({
  prompt: 'ubah itu',
  conversation: [],
  understanding: {
    taskType: 'modification', goal: 'ubah itu', actions: ['edit'], targets: { files: [] }, constraints: [], ambiguity: ['target-not-explicit'], confidence: 'partial'
  }
});
assert.equal(ambiguous.decision.clarificationRequired, true);
assert.equal(ambiguous.decision.readyForPlanning, false);
console.log('R2-A Task/Goal Context: OK');
