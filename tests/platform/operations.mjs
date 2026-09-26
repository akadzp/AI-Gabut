import assert from "node:assert/strict";
import { createOperationsRuntime, OPERATIONS_ERRORS, OperationsError } from "../../core/platform/operations/index.js";

let lifecycleState = "ready";
let healthState = "ready";
const diagnostics = [];

const runtime = createOperationsRuntime({
  lifecycle: { get state() { return lifecycleState; } },
  health: { status: () => ({ status: healthState, state: lifecycleState, dependencies: [] }) },
  diagnostics: { record: event => diagnostics.push(event) },
  identity: { id: "test-runtime", version: "1" },
  configuration: { environment: "test", shutdownTimeoutMs: 1000 },
  processRef: { pid: 123, uptime: () => 4.25 },
  now: () => "2026-01-01T00:00:00.000Z"
});

const snapshot = runtime.snapshot();
assert.equal(snapshot.identity, "test-runtime");
assert.equal(snapshot.lifecycle, "ready");
assert.equal(snapshot.health.status, "ready");
assert.equal(snapshot.pid, 123);

const ready = runtime.readiness();
assert.equal(ready.ready, true);
assert.equal(ready.shuttingDown, false);

await runtime.shutdown(async () => {});
assert.equal(runtime.shuttingDown, true);
assert.equal(runtime.readiness().ready, false);
assert.equal(diagnostics.at(-1).message, "Shutdown completed");

const failing = createOperationsRuntime({
  lifecycle: { state: "ready" },
  health: { status: () => ({ status: "ready", state: "ready", dependencies: [] }) },
  configuration: {},
  processRef: { pid: 1, uptime: () => 1 }
});

await assert.rejects(
  () => failing.shutdown(() => new Promise(() => {}), { timeoutMs: 100 }),
  error => error instanceof OperationsError && error.code === OPERATIONS_ERRORS.SHUTDOWN
);

console.log("Operations runtime contract: PASS");
