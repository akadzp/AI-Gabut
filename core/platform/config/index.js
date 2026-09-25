const DEFAULTS = Object.freeze({
  port: 3000,
  host: "localhost"
});

function parsePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PORT: ${value}`);
  }
  return port;
}

export function loadConfiguration(env = process.env, overrides = {}) {
  const config = {
    ...DEFAULTS,
    port: env.PORT === undefined ? DEFAULTS.port : parsePort(env.PORT),
    host: env.HOST ?? DEFAULTS.host,
    ...overrides
  };
  return Object.freeze(config);
}
