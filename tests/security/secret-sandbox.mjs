import assert from "node:assert/strict";
import { assertSecretSafe, redactSecrets, sanitizeEnvironment } from "../../core/security/secrets/manager.js";
import { assertSandboxPath, getSandboxPolicy } from "../../core/security/sandbox/policy.js";

assert.throws(() => assertSecretSafe("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"));
assert.match(redactSecrets({ token: "sk-test-secret-value" }).token, /redacted/);
assert.equal(Object.hasOwn(sanitizeEnvironment({ SAFE: "1", API_TOKEN: "x" }), "API_TOKEN"), false);
assert.equal(assertSandboxPath("src/index.js"), "src/index.js");
assert.throws(() => assertSandboxPath("../outside"));
assert.equal(assertSandboxPath(".env"), ".env");
assert.equal(getSandboxPolicy().workspaceOnly, true);
console.log("Security secret/sandbox contract: PASS");
