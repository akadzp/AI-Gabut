const DEFAULTS = Object.freeze({
  port: 3000,
  host: "localhost",
  shutdownTimeoutMs: 30_000,
  requestBodyLimit: "2mb"
});

function parsePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PORT: ${value}`);
  }
  return port;
}

function parseDuration(value, fallback) {
  if (value === undefined) return fallback;
  const duration = Number(value);
  if (!Number.isInteger(duration) || duration < 100 || duration > 300_000) {
    throw new Error(`Invalid duration: ${value}`);
  }
  return duration;
}

export function loadConfiguration(env = process.env, overrides = {}) {
  const config = {
    ...DEFAULTS,
    port: env.PORT === undefined ? DEFAULTS.port : parsePort(env.PORT),
    host: env.HOST ?? DEFAULTS.host,
    shutdownTimeoutMs: parseDuration(env.SHUTDOWN_TIMEOUT_MS, DEFAULTS.shutdownTimeoutMs),
    requestBodyLimit: env.REQUEST_BODY_LIMIT ?? DEFAULTS.requestBodyLimit,
    ...overrides
  };
  return Object.freeze(config);
}
