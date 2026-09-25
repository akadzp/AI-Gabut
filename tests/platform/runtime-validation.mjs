import assert from "node:assert/strict";
import { bootstrap } from "../../core/platform/bootstrap/index.js";
import { registerCoreCapabilities } from "../../core/system/capabilities.js";

let stopped = false;
const runtime = await bootstrap({
  configuration: { port: 3210, host: "127.0.0.1" },
  environment: { mode: "test" },
  start: async ({ registry, health }) => {
    registerCoreCapabilities(registry);
    assert.equal(registry.has("agent-engine"), true);
    assert.equal(registry.has("security-governance"), true);
    assert.equal(health.status().status, "not-ready");
    return { close: callback => callback?.() };
  },
  stop: async () => { stopped = true; }
});

assert.equal(runtime.lifecycle.state, "ready");
assert.equal(runtime.registry.sealed, true);
assert.equal(runtime.health.status().status, "ready");
await runtime.stop();
assert.equal(stopped, true);
assert.equal(runtime.lifecycle.state, "stopped");

console.log("PLATFORM RUNTIME VALIDATION PASS");
