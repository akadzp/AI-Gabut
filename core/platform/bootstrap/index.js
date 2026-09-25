import { createEnvironment } from "../environment/index.js";
import { loadConfiguration } from "../config/index.js";
import { DependencyContainer } from "../dependency/index.js";
import { createHealth } from "../health/index.js";
import { Lifecycle } from "../lifecycle/index.js";
import { assertPlatformContracts } from "../contracts/index.js";
import { CapabilityRegistry } from "../registry/index.js";
import { createDiagnostics } from "../diagnostics/index.js";
import { createLogger } from "../logging/index.js";
import { createIdentity } from "../identity/index.js";

export async function bootstrap({ start, stop, environment = {}, configuration = {}, loggerSink = console } = {}) {
  if (typeof start !== "function") throw new TypeError("bootstrap requires a start function");
  const runtime = {
    identity: createIdentity(),
    environment: createEnvironment(environment),
    configuration: loadConfiguration(process.env, configuration),
    lifecycle: new Lifecycle("ai-gabut-runtime"),
    logger: createLogger({ sink: loggerSink }),
    diagnostics: null
  };
  runtime.diagnostics = createDiagnostics({ logger: runtime.logger });
  runtime.dependencies = new DependencyContainer()
    .register("identity", runtime.identity)
    .register("environment", runtime.environment)
    .register("configuration", runtime.configuration)
    .register("lifecycle", runtime.lifecycle)
    .register("logger", runtime.logger)
    .register("diagnostics", runtime.diagnostics);
  runtime.health = createHealth({ lifecycle: runtime.lifecycle, dependencies: runtime.dependencies });
  runtime.dependencies.register("health", runtime.health);
  runtime.registry = new CapabilityRegistry()
    .register("platform.identity", runtime.identity, { domain: "platform", type: "identity" })
    .register("platform.environment", runtime.environment, { domain: "platform", type: "environment" })
    .register("platform.configuration", runtime.configuration, { domain: "platform", type: "configuration" })
    .register("platform.lifecycle", runtime.lifecycle, { domain: "platform", type: "lifecycle" })
    .register("platform.logger", runtime.logger, { domain: "platform", type: "logging" })
    .register("platform.diagnostics", runtime.diagnostics, { domain: "platform", type: "diagnostics" })
    .register("platform.health", runtime.health, { domain: "platform", type: "health" });
  runtime.dependencies.register("registry", runtime.registry).seal();
  assertPlatformContracts(runtime);
  await runtime.lifecycle.initialize();
  let started;
  await runtime.lifecycle.start(async () => { started = await start(runtime); });
  runtime.registry.seal();
  runtime.server = started;
  runtime.diagnostics.record({ component: "runtime", message: "Runtime ready", metadata: { identity: runtime.identity.id } });
  return { ...runtime, stop: async () => runtime.lifecycle.stop(stop ? () => stop(runtime.server) : undefined) };
}
