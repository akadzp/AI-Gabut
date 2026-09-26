import assert from "node:assert/strict";
import { auditEvent, getAuditTrail, getAuditMetrics, getAuditPolicy } from "../../core/security/index.js";

const secret = "ghp_SUPERSECRET123456";
const entry = auditEvent({
  actor: "agent",
  action: "security-test",
  tool: "terminal",
  input: { token: secret, command: "echo safe" },
  outcome: "denied",
  principal: { id: "agent-1", secret },
  decisionId: "decision-test",
  executionId: "execution-test",
  sessionId: "session-test",
  meta: { reason: "test", credential: secret }
});

assert.equal(entry.outcome, "denied");
assert.equal(entry.decisionId, "decision-test");
assert.equal(entry.input.token, "[redacted]");
assert.equal(entry.principal.secret, "[redacted]");
assert.equal(entry.meta.credential, "[redacted]");
assert.equal(getAuditTrail({ action: "security-test", executionId: "execution-test" }).length, 1);
const metrics = getAuditMetrics();
assert.ok(metrics.total >= 1);
assert.ok(metrics.byOutcome.denied >= 1);
assert.equal(getAuditPolicy().secretRedaction, true);
assert.equal(Object.isFrozen(entry), true);

console.log("security audit observability: PASS");
