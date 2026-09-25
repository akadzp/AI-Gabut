import assert from 'node:assert/strict';
import { createExecutionAutonomy, recordToolAction, checkpointExecution } from '../../core/agent-engine/reasoning/execution-autonomy.js';

const plan = {
  phases: [
    { id: 'inspect', title: 'Inspect', purpose: 'Inspect current evidence' },
    { id: 'verify', title: 'Verify', purpose: 'Verify the result', dependsOn: ['inspect'] }
  ]
};
const state = { status: 'ready', currentPhase: 'inspect', completedPhases: [], failedPhases: [], blockedPhases: [], stepCount: 0, events: [] };
const runtime = createExecutionAutonomy({ plan, state, context: { decision: { readyForPlanning: true } } });
assert.equal(runtime.ok, true);
assert.equal(runtime.policy.maxTurns, 24);

const checkpoint = checkpointExecution({ runtime, label: 'start', evidence: { source: 'test' } });
assert.equal(checkpoint.ok, true);
assert.equal(checkpoint.runtime.checkpoints.length, 1);

const success = recordToolAction({
  runtime: checkpoint.runtime,
  name: 'read_file',
  input: { path: 'core/api/server.js' },
  result: { ok: true, content: 'x' },
  context: { decision: { readyForPlanning: true }, plan }
});
assert.equal(success.ok, true);
assert.equal(success.runtime.toolFailures, 0);
assert.equal(success.stop, false);

const failure = recordToolAction({
  runtime: success.runtime,
  name: 'read_file',
  input: { path: 'missing.js' },
  result: { ok: false, error: 'file not found' },
  context: { decision: { readyForPlanning: true }, plan }
});
assert.equal(failure.ok, true);
assert.equal(failure.runtime.recoveryCycles, 1);
assert.equal(failure.runtime.decision?.decision, 'replan');
assert.equal(failure.stop, false);

let repeated = failure.runtime;
for (let i = 0; i < 3; i++) {
  const result = recordToolAction({
    runtime: repeated,
    name: 'read_file',
    input: { path: 'same.js' },
    result: { ok: true, content: 'x' },
    context: { decision: { readyForPlanning: true }, plan }
  });
  repeated = result.runtime;
  if (result.stop) {
    assert.match(result.stopReason, /Repeated identical tool action/);
    break;
  }
}
assert.equal(repeated.status, 'stopped');
console.log('R5 EXECUTION AUTONOMY CHECK PASSED');
