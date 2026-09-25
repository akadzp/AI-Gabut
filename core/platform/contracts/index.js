export const PLATFORM_CONTRACT_VERSION = "1.1";

export const PLATFORM_CONTRACTS = Object.freeze({
  lifecycle: Object.freeze(["component", "state", "initialize", "start", "stop"]),
  environment: Object.freeze(["mode", "platform", "arch", "nodeVersion", "pid", "cwd", "hostname"]),
  configuration: Object.freeze(["port", "host"]),
  dependency: Object.freeze(["register", "resolve", "optional", "has", "names", "seal"]),
  health: Object.freeze(["status"]),
  registry: Object.freeze(["register", "resolve", "has", "list", "seal"]),
  identity: Object.freeze(["id", "type", "name"]),
  diagnostics: Object.freeze(["record", "list", "clear"]),
  logger: Object.freeze(["debug", "info", "warn", "error"])
});

function assertObject(value, name) { if (!value || typeof value !== "object") throw new TypeError(`${name} contract requires an object`); }
function assertMembers(value, name, members) { assertObject(value, name); for (const member of members) if (!(member in value)) throw new TypeError(`${name} contract missing member: ${member}`); return value; }
export const assertLifecycleContract = value => assertMembers(value, "lifecycle", PLATFORM_CONTRACTS.lifecycle);
export const assertEnvironmentContract = value => assertMembers(value, "environment", PLATFORM_CONTRACTS.environment);
export const assertConfigurationContract = value => assertMembers(value, "configuration", PLATFORM_CONTRACTS.configuration);
export const assertDependencyContract = value => assertMembers(value, "dependency", PLATFORM_CONTRACTS.dependency);
export const assertHealthContract = value => assertMembers(value, "health", PLATFORM_CONTRACTS.health);
export const assertRegistryContract = value => assertMembers(value, "registry", PLATFORM_CONTRACTS.registry);
export const assertIdentityContract = value => assertMembers(value, "identity", PLATFORM_CONTRACTS.identity);
export const assertDiagnosticsContract = value => assertMembers(value, "diagnostics", PLATFORM_CONTRACTS.diagnostics);
export const assertLoggerContract = value => assertMembers(value, "logger", PLATFORM_CONTRACTS.logger);
export function assertPlatformContracts({ lifecycle, environment, configuration, dependencies, health, registry, identity, diagnostics, logger } = {}) {
  assertLifecycleContract(lifecycle); assertEnvironmentContract(environment); assertConfigurationContract(configuration); assertDependencyContract(dependencies); assertHealthContract(health); assertRegistryContract(registry); assertIdentityContract(identity); assertDiagnosticsContract(diagnostics); assertLoggerContract(logger); return true;
}
