import assert from "node:assert/strict";
import { bootstrap } from "../../core/platform/bootstrap/index.js";

const logs = [];
const runtime = await bootstrap({
  configuration: { port: 0, host: "127.0.0.1" },
  environment: { mode: "test" },
  loggerSink: { log: message => logs.push(message), info: message => logs.push(message), warn: message => logs.push(message), error: message => logs.push(message), debug: message => logs.push(message) },
  start: async ({ identity, diagnostics, health }) => {
    assert.equal(typeof identity.id, "string");
    assert.equal(identity.type, "runtime");
    assert.equal(health.status().status, "not-ready");
    diagnostics.record({ component: "test", message: "foundation check" });
    return { close(callback) { callback?.(); } };
  }
});

assert.equal(runtime.lifecycle.state, "ready");
assert.equal(runtime.health.status().status, "ready");
assert.equal(runtime.registry.has("platform.identity"), true);
assert.equal(runtime.registry.has("platform.diagnostics"), true);
assert.equal(runtime.registry.has("platform.logger"), true);
assert.equal(runtime.diagnostics.list().length >= 2, true);
assert.equal(logs.length >= 2, true);
await runtime.stop();
assert.equal(runtime.lifecycle.state, "stopped");
console.log("FOUNDATION DEFINITION OF DONE PASS");
