import assert from 'node:assert/strict';
import { understandTask } from '../../core/agent-engine/reasoning/task-understanding.js';
import { decomposeTask } from '../../core/agent-engine/reasoning/task-decomposition.js';
import { createExecutionPlan } from '../../core/agent-engine/reasoning/planning-intelligence.js';

const understanding = understandTask({
  prompt: 'Perbaiki authentication di backend/auth.js, jangan ubah API, jalankan test, dan jangan commit atau push.'
});
const decomposition = decomposeTask({ prompt: 'Perbaiki authentication di backend/auth.js', understanding });
const result = createExecutionPlan({ prompt: 'Perbaiki authentication di backend/auth.js', understanding, decomposition });

assert.equal(result.ok, true);
assert.ok(result.plan.phases.length >= 4);
assert.ok(result.plan.phases.some(item => item.id === 'impact'));
assert.ok(result.plan.phases.some(item => item.id === 'change'));
assert.ok(result.plan.phases.some(item => item.id === 'verify'));
assert.equal(result.plan.executionPolicy.noArbitraryCommands, true);
assert.equal(result.plan.executionPolicy.noCommitOrPushUnlessExplicitlyApproved, true);
assert.ok(result.plan.phases.every(item => Array.isArray(item.dependsOn)));
console.log(`Planning Intelligence: OK (${result.plan.phases.length} phases)`);
