import os from "node:os";

export function createEnvironment(overrides = {}) {
  return Object.freeze({
    mode: overrides.mode ?? process.env.NODE_ENV ?? "development",
    platform: overrides.platform ?? process.platform,
    arch: overrides.arch ?? process.arch,
    nodeVersion: overrides.nodeVersion ?? process.version,
    pid: overrides.pid ?? process.pid,
    cwd: overrides.cwd ?? process.cwd(),
    hostname: overrides.hostname ?? os.hostname()
  });
}
