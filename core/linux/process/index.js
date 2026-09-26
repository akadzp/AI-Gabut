import { LINUX_ERRORS, LinuxCapabilityError } from "../errors.js";

function normalizePid(pid = process.pid) {
  const value = Number(pid);
  if (!Number.isInteger(value) || value <= 0) {
    throw new LinuxCapabilityError(LINUX_ERRORS.VALIDATION_ERROR, "PID tidak valid");
  }
  return value;
}

export function getCurrentProcessInfo() {
  const memory = process.memoryUsage();
  return Object.freeze({
    pid: process.pid,
    ppid: process.ppid,
    title: process.title,
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    uptimeSeconds: process.uptime(),
    memory: Object.freeze({ ...memory })
  });
}

export function isProcessAlive(pid) {
  const value = normalizePid(pid);
  try {
    process.kill(value, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw new LinuxCapabilityError(LINUX_ERRORS.EXECUTION_FAILED, "Tidak dapat memeriksa process", { pid: value, cause: error?.message });
  }
}

export function getProcessCapabilities() {
  return Object.freeze({
    inspectCurrentProcess: true,
    checkProcessAlive: true,
    arbitraryProcessControl: false
  });
}
