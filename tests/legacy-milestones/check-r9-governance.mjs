import assert from 'node:assert/strict';
import { CAPABILITY_TOOL_DEFINITIONS } from '../../core/agent-engine/tools/catalog.js';
import { executeTool } from '../../core/agent-engine/core/tool-registry.js';
import { authorizeTool, issueApproval, getAuditTrail, getGovernancePolicy } from '../../core/security/governance/policy.js';

const policy = getGovernancePolicy();
assert.equal(policy.workspaceIsolation, true);
assert.equal(policy.secretProtection, true);
assert.equal(policy.humanApproval, true);
assert.equal(policy.auditTrail, true);
assert.equal(policy.policyEnforcement, true);

for (const definition of CAPABILITY_TOOL_DEFINITIONS) {
  const sampleInput = definition.name === 'terminal' ? { command: 'pwd' } : {};
  const auth = authorizeTool({ tool: definition.name, definition, input: sampleInput });
  if (definition.permission === 'approval') {
    assert.equal(auth.ok, false);
    assert.equal(auth.requiresApproval, true);
  } else {
    assert.equal(auth.ok, true, `${definition.name} should be governable`);
  }
}

const blockedCommit = await executeTool('git_commit', { message: 'test', approved: true });
assert.equal(blockedCommit.ok, false);
assert.equal(blockedCommit.requiresApproval, true);

const sessionId = 'r9-check-session';
const approval = issueApproval({
  tool: 'git_commit',
  input: { message: 'governance-check' },
  sessionId,
  reason: 'explicit human approval test'
});
assert.ok(approval.token);

const approved = await executeTool('git_commit', { message: 'governance-check', approved: true }, {
  sessionId,
  approvalToken: approval.token
});
assert.notEqual(approved?.error, 'Human approval token wajib diisi');

const replay = await executeTool('git_commit', { message: 'governance-check', approved: true }, {
  sessionId,
  approvalToken: approval.token
});
assert.equal(replay.ok, false);
assert.equal(replay.requiresApproval, true);

const secret = authorizeTool({ tool: 'read_file', definition: { name: 'read_file', permission: 'read', capability: 'core' }, input: { path: '.env' } });
assert.equal(secret.ok, true, 'workspace layer owns .env path protection');

const privateKey = (() => {
  try {
    authorizeTool({ tool: 'write_file', definition: { name: 'write_file', permission: 'write', capability: 'core' }, input: { content: '-----BEGIN PRIVATE KEY-----' } });
    return false;
  } catch {
    return true;
  }
})();
assert.equal(privateKey, true);

assert.ok(getAuditTrail({ limit: 50 }).length >= 5);
console.log('R9 SECURITY & GOVERNANCE CHECK PASSED');
