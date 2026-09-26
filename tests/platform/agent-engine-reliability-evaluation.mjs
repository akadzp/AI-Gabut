import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-gabut-step05-'));
process.env.AI_RELIABILITY_DIR = dir;

const runtime = await import('../../core/agent-engine/reliability/runtime.js');
const evaluator = await import('../../core/agent-engine/evaluation/evaluator.js');

const execution = await runtime.startExecution({ sessionId: 'step05', prompt: 'reliability' });
await runtime.checkpointExecutionState({
  id: execution.id,
  checkpoint: { type: 'tool-result', turn: 1, steps: [{ name: 'read_file' }], messages: [] }
});
const resumed = await runtime.resumeExecution(execution.id);
assert.equal(resumed.checkpoint.turn, 1);

const order = [];
await Promise.all([
  runtime.withExecutionLock('same', async () => { order.push(1); await new Promise(resolve => setTimeout(resolve, 10)); order.push(2); }),
  runtime.withExecutionLock('same', async () => order.push(3))
]);
assert.deepEqual(order, [1, 2, 3]);
assert.equal(runtime.getReliabilityMetrics().activeLocks, 0);

let timedOut = false;
try {
  await runtime.withTimeout(new Promise(resolve => setTimeout(resolve, 150)), 100, 'step05-timeout');
} catch {
  timedOut = true;
}
assert.equal(timedOut, true);
assert.equal(runtime.getReliabilityMetrics().timeouts >= 1, true);

const inefficient = evaluator.scoreTrajectory({
  trajectory: { status: 'done', text: 'done', steps: [{ name: 'wrong_tool', result: { ok: true } }] },
  expected: { tools: ['read_file'], complete: true }
});
assert.equal(inefficient.pass, false);

const asyncSuite = await evaluator.runEvaluationSuiteAsync([
  { id: 'async-pass', category: 'runtime', expected: { tools: ['read_file'], complete: true } },
  { id: 'async-fail', category: 'runtime', expected: { tools: ['edit_file'], complete: true } }
], async testCase => {
  await new Promise(resolve => setTimeout(resolve, 1));
  return testCase.id === 'async-pass'
    ? { status: 'done', text: 'ok', steps: [{ name: 'read_file', result: { ok: true } }] }
    : { status: 'done', text: 'blocked', steps: [{ name: 'read_file', result: { ok: true } }] };
});
assert.equal(asyncSuite.aggregate.total, 2);
assert.equal(asyncSuite.aggregate.passed, 1);

await runtime.finishExecution({ id: execution.id, status: 'completed', result: { ok: true } });
assert.equal((await runtime.loadExecution(execution.id)).status, 'completed');

console.log('AGENT ENGINE RELIABILITY & EVALUATION CHECK PASS');
