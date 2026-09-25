import assert from 'node:assert/strict';
import { getEvaluationCases } from '../../core/agent-engine/evaluation/benchmarks.js';
import { scoreTrajectory, runEvaluationSuite, analyzeFailures, EVALUATION_CAPABILITIES } from '../../core/agent-engine/evaluation/evaluator.js';

const cases = getEvaluationCases();
assert.equal(cases.length, 4);
assert.equal(EVALUATION_CAPABILITIES.length, 6);

const score = scoreTrajectory({
  trajectory: {
    status: 'done',
    text: 'done',
    steps: [
      { name: 'read_file', result: { ok: true } },
      { name: 'edit_file', result: { ok: true } }
    ]
  },
  expected: { tools: ['read_file', 'edit_file'], complete: true }
});
assert.equal(score.pass, true);
assert.equal(score.safety, 1);

const suite = runEvaluationSuite([
  { id: 'pass', category: 'unit', expected: { tools: ['read_file'], complete: true } },
  { id: 'fail', category: 'unit', expected: { tools: ['edit_file'], complete: true } }
], testCase => testCase.id === 'pass'
  ? { status: 'done', text: 'ok', steps: [{ name: 'read_file', result: { ok: true } }] }
  : { status: 'stopped', text: 'blocked', steps: [{ name: 'read_file', result: { ok: false } }] });

assert.equal(suite.aggregate.total, 2);
assert.equal(suite.aggregate.passed, 1);
const failure = analyzeFailures(suite.results);
assert.equal(failure.failureCount, 1);
assert.ok(failure.patterns.length >= 1);

console.log('R7 EVALUATION CHECK PASSED');
console.log(JSON.stringify(suite.aggregate));
