export const PLATFORM_CONTRACT_VERSION = "1.0";

export const PLATFORM_CONTRACTS = Object.freeze({
  lifecycle: Object.freeze(["component", "state", "initialize", "start", "stop"]),
  environment: Object.freeze(["mode", "platform", "arch", "nodeVersion", "pid", "cwd", "hostname"]),
  configuration: Object.freeze(["port", "host"]),
  dependency: Object.freeze(["register", "resolve", "optional", "has", "names", "seal"]),
  health: Object.freeze(["status"]),
  registry: Object.freeze(["register", "resolve", "has", "list", "seal"])
});

function assertObject(value, name) {
  if (!value || typeof value !== "object") {
    throw new TypeError(`${name} contract requires an object`);
  }
}

function assertMembers(value, name, members) {
  assertObject(value, name);
  for (const member of members) {
    if (!(member in value)) throw new TypeError(`${name} contract missing member: ${member}`);
  }
  return value;
}

export function assertLifecycleContract(value) {
  return assertMembers(value, "lifecycle", PLATFORM_CONTRACTS.lifecycle);
}

export function assertEnvironmentContract(value) {
  return assertMembers(value, "environment", PLATFORM_CONTRACTS.environment);
}

export function assertConfigurationContract(value) {
  return assertMembers(value, "configuration", PLATFORM_CONTRACTS.configuration);
}

export function assertDependencyContract(value) {
  return assertMembers(value, "dependency", PLATFORM_CONTRACTS.dependency);
}

export function assertHealthContract(value) {
  return assertMembers(value, "health", PLATFORM_CONTRACTS.health);
}

export function assertRegistryContract(value) {
  return assertMembers(value, "registry", PLATFORM_CONTRACTS.registry);
}

export function assertPlatformContracts({ lifecycle, environment, configuration, dependencies, health, registry } = {}) {
  assertLifecycleContract(lifecycle);
  assertEnvironmentContract(environment);
  assertConfigurationContract(configuration);
  assertDependencyContract(dependencies);
  assertHealthContract(health);
  assertRegistryContract(registry);
  return true;
}
