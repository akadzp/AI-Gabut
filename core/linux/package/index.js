import fs from "node:fs/promises";
import path from "node:path";
import { resolveWorkspacePath } from "../terminal/workspace.js";
import { assertSandboxPath } from "../../security/sandbox/policy.js";
import { LINUX_ERRORS, LinuxCapabilityError } from "../errors.js";

const MANAGERS = Object.freeze([
  { name: "npm", marker: "package-lock.json" },
  { name: "pnpm", marker: "pnpm-lock.yaml" },
  { name: "yarn", marker: "yarn.lock" },
  { name: "bun", marker: "bun.lockb" }
]);

export async function detectPackageManagers({ relativePath = "." } = {}) {
  const safe = assertSandboxPath(relativePath);
  const directory = resolveWorkspacePath(safe);
  const found = [];
  for (const manager of MANAGERS) {
    try {
      await fs.access(path.join(directory, manager.marker));
      found.push(manager.name);
    } catch {}
  }
  return found;
}

export async function readPackageManifest({ relativePath = "package.json" } = {}) {
  const safe = assertSandboxPath(relativePath);
  if (path.posix.basename(safe) !== "package.json") {
    throw new LinuxCapabilityError(LINUX_ERRORS.VALIDATION_ERROR, "Hanya package.json yang dapat dibaca");
  }
  try {
    const content = await fs.readFile(resolveWorkspacePath(safe), "utf8");
    return JSON.parse(content);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    if (error instanceof SyntaxError) throw new LinuxCapabilityError(LINUX_ERRORS.EXECUTION_FAILED, "package.json tidak valid");
    throw new LinuxCapabilityError(LINUX_ERRORS.EXECUTION_FAILED, "Gagal membaca package manifest", { cause: error?.message });
  }
}

export function getPackageCapabilities() {
  return Object.freeze({ discovery: true, manifestRead: true, mutation: false });
}
