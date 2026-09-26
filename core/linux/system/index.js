import os from "node:os";
import { LINUX_ERRORS, LinuxCapabilityError } from "../errors.js";

export function getSystemInfo() {
  return Object.freeze({
    platform: process.platform,
    arch: process.arch,
    release: os.release(),
    version: os.version(),
    hostname: os.hostname(),
    cpus: os.cpus().length,
    endianness: os.endianness(),
    homedir: os.homedir(),
    tmpdir: os.tmpdir(),
    uptimeSeconds: os.uptime()
  });
}

export function getResourceSnapshot() {
  const load = typeof os.loadavg === "function" ? os.loadavg() : [];
  return Object.freeze({
    memory: Object.freeze({
      totalBytes: os.totalmem(),
      freeBytes: os.freemem(),
      usedBytes: Math.max(0, os.totalmem() - os.freemem())
    }),
    cpu: Object.freeze({
      count: os.cpus().length,
      loadAverage: Object.freeze(load.slice(0, 3))
    }),
    process: Object.freeze({
      pid: process.pid,
      uptimeSeconds: process.uptime(),
      heapUsedBytes: process.memoryUsage().heapUsed,
      rssBytes: process.memoryUsage().rss
    })
  });
}

export function getSystemCapabilities() {
  if (process.platform === "win32") {
    return Object.freeze({ filesystem: true, processInspection: true, terminal: true, git: true, packageDiscovery: true, serviceDiscovery: true });
  }
  if (process.platform === "darwin" || process.platform === "linux") {
    return Object.freeze({ filesystem: true, processInspection: true, terminal: true, git: true, packageDiscovery: true, serviceDiscovery: true });
  }
  throw new LinuxCapabilityError(LINUX_ERRORS.NOT_SUPPORTED, `Unsupported platform: ${process.platform}`);
}
