import assert from "node:assert/strict";
import { DependencyContainer } from "../../core/platform/dependency/index.js";
import { createHealth } from "../../core/platform/health/index.js";
import { Lifecycle } from "../../core/platform/lifecycle/index.js";

const dependencies = new DependencyContainer();
const value = { name: "test" };
dependencies.register("value", value);
assert.equal(dependencies.resolve("value"), value);
assert.equal(dependencies.has("value"), true);
dependencies.seal();
assert.throws(() => dependencies.register("other", {}), /sealed/);

const lifecycle = new Lifecycle("test");
const health = createHealth({ lifecycle, dependencies });
assert.equal(health.status().status, "not-ready");
await lifecycle.initialize();
await lifecycle.start();
assert.equal(health.status().status, "ready");
assert.equal(health.status().state, "ready");
await lifecycle.stop();
assert.equal(health.status().status, "not-ready");

console.log("PLATFORM DEPENDENCY/HEALTH PASS");
