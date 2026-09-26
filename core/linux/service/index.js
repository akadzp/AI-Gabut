import os from "node:os";

export function getServiceManager() {
  if (process.platform === "win32") return "windows-services";
  if (process.platform === "darwin") return "launchd";
  if (process.platform === "linux") return "systemd-or-init";
  return "unknown";
}

export function getServiceCapabilities() {
  return Object.freeze({
    manager: getServiceManager(),
    discovery: true,
    statusInspection: false,
    start: false,
    stop: false,
    restart: false,
    install: false,
    uninstall: false,
    hostPlatform: os.platform()
  });
}
