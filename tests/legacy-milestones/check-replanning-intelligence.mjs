import assert from 'node:assert/strict';
import { createReplan } from '../../core/agent-engine/reasoning/replanning-intelligence.js';

const plan = {
  phases: [
    { id: 'inspect', title: 'Inspect', purpose: 'Gather evidence' },
    { id: 'edit', title: 'Edit', purpose: 'Apply bounded change', dependsOn: ['inspect'] },
    { id: 'verify', title: 'Verify', purpose: 'Run relevant verification', dependsOn: ['edit'] }
  ]
};

const result = createReplan({
  plan,
  state: { status: 'failed', currentPhase: 'verify', completedPhases: ['inspect', 'edit'], stepCount: 4 },
  reason: 'verification failed after source file changed',
  evidence: { changedFiles: ['backend/auth.js', 'test/auth.test.js'] },
  constraints: ['do not change API']
});

assert.equal(result.ok, true);
assert.equal(result.reason.code, 'verification-failure');
assert.deepEqual(result.sourceState.completedPhases, ['inspect', 'edit']);
assert.deepEqual(result.evidence.changedFiles, ['backend/auth.js', 'test/auth.test.js']);
assert.equal(result.replan.required, true);
assert.ok(result.replan.inspectFirst.some(item => item.includes('verification failure')));
assert.ok(result.replan.remainingPhaseIds.includes('verify'));
assert.equal(result.policy.noImplicitEdit, true);
assert.equal(result.policy.noImplicitCommitOrPush, true);

const invalid = createReplan({
  plan,
  state: { currentPhase: 'missing', completedPhases: ['inspect', 'ghost'] },
  reason: 'workspace changed'
});
assert.equal(invalid.ok, true);
assert.ok(invalid.warnings.some(item => item.includes('outside the supplied plan')));

console.log('Replanning Intelligence: OK');
