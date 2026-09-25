import path from "node:path";

export const WORKSPACE_ROOT = path.resolve(
  process.env.AI_WORKSPACE_ROOT || process.cwd()
);

export function resolveWorkspacePath(relativePath = ".") {
  const resolved = path.resolve(WORKSPACE_ROOT, relativePath);
  const prefix = `${WORKSPACE_ROOT}${path.sep}`;

  if (resolved !== WORKSPACE_ROOT && !resolved.startsWith(prefix)) {
    throw new Error("Path berada di luar workspace");
  }

  return resolved;
}
