import assert from "node:assert/strict";
import { createConnectorRegistry, createConnectorRuntime } from "../../core/connectors/index.js";

const registry = createConnectorRegistry();
let calls = 0;
registry.register(
  { id: "mock", name: "Mock Connector", provider: "test", operations: ["read", "write"], auth: { mode: "token", required: true } },
  { execute: async ({ name, input }) => { calls += 1; return { name, value: input.value }; } }
);

const runtime = createConnectorRuntime({ registry, retries: 0, timeoutMs: 2000 });
const result = await runtime.execute({ connectorId: "mock", name: "read-value", type: "read", input: { value: 42 } });
assert.equal(result.ok, true);
assert.equal(result.result.value, 42);
assert.equal(calls, 1);
assert.equal(registry.list()[0].auth.mode, "token");

registry.seal();
assert.equal(registry.sealed, true);
assert.throws(
  () => registry.register({ id: "late", operations: ["read"] }, { execute: async () => null }),
  /sealed/
);

console.log("Connector registry/runtime contract: PASS");
