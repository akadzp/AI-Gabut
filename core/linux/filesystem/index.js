import fs from "node:fs/promises";
import path from "node:path";
import { resolveWorkspacePath } from "../terminal/workspace.js";
import { assertSandboxPath } from "../../security/sandbox/policy.js";
import { isSensitivePath } from "../../security/secrets/manager.js";
import { LINUX_ERRORS, LinuxCapabilityError } from "../errors.js";

function safePath(relativePath = ".") {
  const normalized = assertSandboxPath(relativePath);
  if (isSensitivePath(normalized)) {
    throw new LinuxCapabilityError(LINUX_ERRORS.PERMISSION_DENIED, "Sensitive filesystem path ditolak");
  }
  return normalized;
}

export async function statWorkspacePath(relativePath = ".") {
  const safe = safePath(relativePath);
  try {
    const stat = await fs.stat(resolveWorkspacePath(safe));
    return Object.freeze({
      path: safe,
      type: stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "other",
      size: stat.size,
      mode: stat.mode,
      modifiedAt: stat.mtime.toISOString()
    });
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw new LinuxCapabilityError(LINUX_ERRORS.EXECUTION_FAILED, "Filesystem stat gagal", { path: safe, cause: error?.message });
  }
}

export async function listWorkspaceDirectory(relativePath = ".") {
  const safe = safePath(relativePath);
  try {
    const entries = await fs.readdir(resolveWorkspacePath(safe), { withFileTypes: true });
    return entries
      .filter(entry => !isSensitivePath(path.posix.join(safe, entry.name)))
      .map(entry => ({
        name: entry.name,
        path: path.posix.join(safe, entry.name),
        type: entry.isDirectory() ? "directory" : entry.isFile() ? "file" : "other"
      }))
      .sort((a, b) => a.path.localeCompare(b.path));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw new LinuxCapabilityError(LINUX_ERRORS.EXECUTION_FAILED, "Filesystem listing gagal", { path: safe, cause: error?.message });
  }
}

export function getFilesystemCapabilities() {
  return Object.freeze({
    workspaceBound: true,
    readOnly: true,
    stat: true,
    list: true,
    write: false,
    delete: false
  });
}
