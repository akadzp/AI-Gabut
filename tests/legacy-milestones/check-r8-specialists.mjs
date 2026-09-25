import assert from 'node:assert/strict';
import { getSpecialists, buildSpecialistPlan, createSpecialistHandoff, coordinateSpecialists, SPECIALIST_CAPABILITIES } from '../../core/agent-engine/specialists/orchestrator.js';
import { CAPABILITY_TOOL_DEFINITIONS, CAPABILITY_GROUPS } from '../../core/agent-engine/tools/catalog.js';

const specialists = getSpecialists();
assert.equal(specialists.length, 6);
assert.ok(SPECIALIST_CAPABILITIES.includes('agent_orchestration'));
assert.ok(CAPABILITY_GROUPS.specialist.tools.includes('specialist_orchestration'));
assert.ok(CAPABILITY_TOOL_DEFINITIONS.some(tool => tool.name === 'specialist_orchestration'));

const plan = buildSpecialistPlan({ prompt: 'Refactor API handler, update tests, and review the change set.' });
assert.equal(plan.ok, true);
assert.equal(plan.mode, 'multi-specialist');
assert.ok(plan.specialists.some(item => item.id === 'planner'));
assert.ok(plan.specialists.some(item => item.id === 'coding'));
assert.ok(plan.specialists.some(item => item.id === 'testing'));
assert.ok(plan.specialists.some(item => item.id === 'reviewer'));
assert.ok(plan.stages.length >= 4);
assert.equal(plan.coordination.noImplicitCommitOrPush, true);

const handoff = createSpecialistHandoff({ plan, from: 'coding', to: 'testing', evidence: ['edit_file succeeded'], constraints: ['preserve API contract'], artifacts: ['core/api/server.js'] });
assert.equal(handoff.ok, true);
assert.equal(handoff.from, 'coding');
assert.equal(handoff.to, 'testing');

const state = coordinateSpecialists({ plan, completedStages: ['plan', 'evidence', 'implement'], evidence: ['implementation result'] });
assert.equal(state.ok, true);
assert.equal(state.currentStage.id, 'verify');
assert.equal(state.decision, 'continue');

const blocked = coordinateSpecialists({ plan, completedStages: ['plan'], blockers: ['verification dependency changed'] });
assert.equal(blocked.decision, 'replan');

console.log('R8 SPECIALIST ARCHITECTURE CHECK PASSED');
