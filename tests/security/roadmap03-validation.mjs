import assert from "node:assert/strict";
import { getGovernancePolicy, authorizeTool, auditEvent, getAuditPolicy } from "../../core/security/index.js";

const policy = getGovernancePolicy();
assert.equal(policy.policyEnforcement, true);
assert.equal(policy.secretProtection, true);
assert.equal(policy.auditTrail, true);

const unknown = authorizeTool({ tool: "unknown-security-validation-tool", input: {} });
assert.equal(unknown.ok, false);
assert.equal(unknown.status, 403);

const audit = auditEvent({
  actor: "system",
  action: "roadmap03-validation",
  outcome: "completed",
  input: { credential: "sk-validation-secret" }
});
assert.equal(audit.input.credential, "[redacted]");
assert.equal(getAuditPolicy().secretRedaction, true);
assert.equal(Object.isFrozen(audit), true);

console.log("Roadmap 03 security validation: PASS");
