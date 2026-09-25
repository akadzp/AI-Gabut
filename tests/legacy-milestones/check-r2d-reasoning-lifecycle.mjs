import { establishReasoningLifecycle, summarizeReasoningLifecycle } from '../../core/agent-engine/reasoning/reasoning-lifecycle.js';

const result = establishReasoningLifecycle({
  prompt: 'Perbaiki authentication di backend/auth.js. Jangan ubah API dan jangan commit atau push.',
  conversation: [],
  memories: [],
  sessionId: 'r2d-check'
});

if (!result.ok) throw new Error('R2-D lifecycle should initialize successfully');
const summary = summarizeReasoningLifecycle(result);
if (!summary.steps || !summary.phases) throw new Error('R2-D lifecycle missing integrated plan');
if (!summary.currentPhase) throw new Error('R2-D execution state missing current phase');
if (summary.unresolvedAmbiguities !== 0) throw new Error('Expected no unresolved ambiguities for explicit task');
if (result.context.decision.commitOrPushAllowed !== false) throw new Error('Commit/push boundary must remain disabled');

const ambiguous = establishReasoningLifecycle({ prompt: 'ubah itu', conversation: [], memories: [] });
if (ambiguous.context.decision.readyForPlanning !== false) throw new Error('Ambiguous task should require clarification');
if (ambiguous.context.decision.mutationAllowed !== true) throw new Error('Ambiguity alone should not change mutation policy');

console.log(`R2-D Reasoning Lifecycle: OK (${summary.steps} steps, ${summary.phases} phases, decision=${summary.decision})`);
