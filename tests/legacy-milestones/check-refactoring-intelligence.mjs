import { planRefactoring } from '../../core/workspace/refactoring-intelligence.js';

const result = await planRefactoring({
  task: 'rename runAgent to runAgentV2',
  path: 'core/agent-engine/core/agent.js',
  symbol: 'runAgent',
  newName: 'runAgentV2'
});

if (!result.readOnly) throw new Error('refactoring plan must be read-only');
if (result.kind !== 'rename') throw new Error(`unexpected kind: ${result.kind}`);
if (!Array.isArray(result.affectedFiles)) throw new Error('affectedFiles missing');
if (!Array.isArray(result.verification)) throw new Error('verification missing');
console.log(`Refactoring Intelligence: OK (${result.kind}; ${result.affectedFiles.length} affected files)`);
