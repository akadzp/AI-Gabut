import assert from "node:assert/strict";
import { getSecurityCapabilities } from "../../core/security/index.js";

const security = getSecurityCapabilities();

assert.equal(typeof security.authorize, "function");
assert.equal(typeof security.getGovernancePolicy, "function");
assert.equal(typeof security.getAuditTrail, "function");
assert.equal(typeof security.getAuditMetrics, "function");
assert.equal(typeof security.redactSecrets, "function");
assert.equal(typeof security.validateSandboxPath, "function");

const decision = security.authorize({
  principal: { type: "agent", id: "dod-check" },
  action: "workspace.read",
  resource: { type: "workspace", id: "default" },
  scope: { workspace: "default" }
});

assert.ok(decision);
assert.ok(["allow", "deny", "approval_required"].includes(decision.decision));
assert.equal(typeof decision.decisionId, "string");

const redacted = security.redactSecrets("token=sk-test-example");
assert.notEqual(redacted, "token=sk-test-example");

assert.equal(security.validateSandboxPath("notes/test.txt").ok, true);
assert.equal(security.validateSandboxPath("../../etc/passwd").ok, false);

console.log("Roadmap 03 Definition of Done: PASS");
