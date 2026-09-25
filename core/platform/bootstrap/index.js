import { createEnvironment } from "../environment/index.js";
import { loadConfiguration } from "../config/index.js";
import { DependencyContainer } from "../dependency/index.js";
import { createHealth } from "../health/index.js";
import { Lifecycle } from "../lifecycle/index.js";
import { assertPlatformContracts } from "../contracts/index.js";
import { CapabilityRegistry } from "../registry/index.js";

export async function bootstrap({ start, stop, environment = {}, configuration = {} } = {}) {
  if (typeof start !== "function") throw new TypeError("bootstrap requires a start function");

  const runtime = {
    environment: createEnvironment(environment),
    configuration: loadConfiguration(process.env, configuration),
    lifecycle: new Lifecycle("ai-gabut-runtime")
  };

  runtime.dependencies = new DependencyContainer()
    .register("environment", runtime.environment)
    .register("configuration", runtime.configuration)
    .register("lifecycle", runtime.lifecycle);

  runtime.health = createHealth({ lifecycle: runtime.lifecycle, dependencies: runtime.dependencies });
  runtime.dependencies.register("health", runtime.health);

  runtime.registry = new CapabilityRegistry()
    .register("platform.environment", runtime.environment, { domain: "platform", type: "environment" })
    .register("platform.configuration", runtime.configuration, { domain: "platform", type: "configuration" })
    .register("platform.lifecycle", runtime.lifecycle, { domain: "platform", type: "lifecycle" })
    .register("platform.health", runtime.health, { domain: "platform", type: "health" });

  runtime.dependencies.register("registry", runtime.registry).seal();
  assertPlatformContracts(runtime);

  await runtime.lifecycle.initialize();
  let started;
  await runtime.lifecycle.start(async () => {
    started = await start(runtime);
  });
  runtime.registry.seal();
  runtime.server = started;

  return {
    ...runtime,
    stop: async () => runtime.lifecycle.stop(stop ? () => stop(runtime.server) : undefined)
  };
}
