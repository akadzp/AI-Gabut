import assert from "node:assert/strict";
import {
  authorizeTool,
  issueApproval,
  normalizePrincipal,
  normalizeAuthorizationRequest,
  validateAuthorizationRequest
} from "../../core/security/index.js";

const principal = normalizePrincipal({ id: "agent:test", type: "agent", source: "test" }, { sessionId: "security-step04" });
assert.equal(principal.id, "agent:test");
assert.equal(principal.type, "agent");

const request = normalizeAuthorizationRequest({
  principal,
  action: "workspace.read",
  resource: { type: "workspace", id: "workspace", sensitivity: "low" },
  scope: { domain: "workspace", target: "security-step04", allowedActions: ["workspace.read"] },
  context: { sessionId: "security-step04", executionId: "exec-step04" }
});
assert.equal(validateAuthorizationRequest(request), null);

const allowed = authorizeTool({
  tool: "read_file",
  input: { path: "README.md" },
  sessionId: "security-step04",
  principal,
  executionId: "exec-step04"
});
assert.equal(allowed.ok, true);
assert.equal(allowed.decision.decision, "allow");
assert.ok(allowed.decision.decisionId);
assert.equal(allowed.decision.action, "workspace.read");

const denied = authorizeTool({
  tool: "unknown-security-tool",
  input: {},
  sessionId: "security-step04",
  principal
});
assert.equal(denied.ok, false);
assert.equal(denied.decision.decision, "deny");
assert.ok(denied.reasonCode);

const approval = issueApproval({
  tool: "git_commit",
  input: { message: "step04" },
  sessionId: "security-step04",
  principal,
  reason: "security contract test"
});
assert.ok(approval.token);

const approved = authorizeTool({
  tool: "git_commit",
  input: { message: "step04" },
  sessionId: "security-step04",
  principal,
  approvalToken: approval.token
});
assert.equal(approved.ok, true);
assert.equal(approved.decision.decision, "allow");

const replay = authorizeTool({
  tool: "git_commit",
  input: { message: "step04" },
  sessionId: "security-step04",
  principal,
  approvalToken: approval.token
});
assert.equal(replay.ok, false);
assert.equal(replay.reasonCode, "approval-missing");
assert.equal(replay.decision.decision, "approval_required");

console.log("SECURITY AUTHORIZATION CONTRACT CHECK PASSED");
