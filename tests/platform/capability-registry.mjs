import assert from "node:assert/strict";
import { CapabilityRegistry } from "../../core/platform/registry/index.js";
import { registerCoreCapabilities } from "../../core/system/capabilities.js";

const registry = new CapabilityRegistry();
registerCoreCapabilities(registry);

assert.equal(registry.has("agent-engine"), true);
assert.equal(registry.has("security-governance"), true);
assert.equal(registry.has("workspace"), true);
assert.equal(registry.has("linux-terminal"), true);
assert.equal(registry.has("linux-git"), true);
assert.equal(registry.list().length, 6);
assert.equal(typeof registry.resolve("agent-engine").runAgent, "function");

registry.seal();
assert.throws(() => registry.register("test", {}), /sealed/);

console.log("PLATFORM CAPABILITY REGISTRY PASS");
