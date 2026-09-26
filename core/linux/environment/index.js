import { sanitizeEnvironment } from "../../security/secrets/manager.js";

const SAFE_VALUE_KEYS = new Set([
  "NODE_ENV", "TZ", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SHELL"
]);

export function getEnvironmentSnapshot({ environment = process.env } = {}) {
  const sanitized = sanitizeEnvironment(environment);
  const values = {};
  for (const key of SAFE_VALUE_KEYS) {
    if (Object.hasOwn(sanitized, key)) values[key] = String(sanitized[key]);
  }
  return Object.freeze({
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    cwd: process.cwd(),
    pid: process.pid,
    values: Object.freeze(values),
    availableKeys: Object.freeze(Object.keys(sanitized).sort())
  });
}
