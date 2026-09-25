import assert from "node:assert/strict";
import {
  PLATFORM_CONTRACT_VERSION,
  PLATFORM_CONTRACTS,
  assertPlatformContracts,
  assertLifecycleContract,
  assertEnvironmentContract,
  assertConfigurationContract,
  assertDependencyContract,
  assertHealthContract,
  assertRegistryContract
} from "../../core/platform/contracts/index.js";
import { Lifecycle } from "../../core/platform/lifecycle/index.js";
import { createEnvironment } from "../../core/platform/environment/index.js";
import { loadConfiguration } from "../../core/platform/config/index.js";
import { DependencyContainer } from "../../core/platform/dependency/index.js";
import { createHealth } from "../../core/platform/health/index.js";
import { CapabilityRegistry } from "../../core/platform/registry/index.js";

assert.equal(PLATFORM_CONTRACT_VERSION, "1.0");
assert.ok(Object.keys(PLATFORM_CONTRACTS).length >= 5);

const lifecycle = new Lifecycle("test");
const environment = createEnvironment({ mode: "test" });
const configuration = loadConfiguration({ PORT: "3001", HOST: "127.0.0.1" });
const dependencies = new DependencyContainer();
const health = createHealth({ lifecycle, dependencies });
const registry = new CapabilityRegistry();

assert.doesNotThrow(() => assertLifecycleContract(lifecycle));
assert.doesNotThrow(() => assertEnvironmentContract(environment));
assert.doesNotThrow(() => assertConfigurationContract(configuration));
assert.doesNotThrow(() => assertDependencyContract(dependencies));
assert.doesNotThrow(() => assertHealthContract(health));
assert.doesNotThrow(() => assertRegistryContract(registry));
assert.doesNotThrow(() => assertPlatformContracts({ lifecycle, environment, configuration, dependencies, health, registry }));

assert.throws(() => assertLifecycleContract({}), /missing member/);
assert.throws(() => assertConfigurationContract({}), /missing member/);

console.log("Platform contracts: PASS");
