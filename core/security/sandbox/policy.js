import path from "node:path";

export function assertSandboxPath(relativePath = ".") {
  if (typeof relativePath !== "string" || !relativePath.trim()) {
    throw new Error("Sandbox path wajib diisi");
  }
  const normalized = relativePath.replaceAll("\\", "/");
  if (normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) {
    throw new Error("Absolute path tidak diizinkan oleh sandbox");
  }
  const resolved = path.posix.normalize(normalized);
  if (resolved === ".." || resolved.startsWith("../") || resolved.includes("/../")) {
    throw new Error("Path traversal tidak diizinkan oleh sandbox");
  }
  return resolved;
}

export function getSandboxPolicy() {
  return {
    enabled: true,
    workspaceOnly: true,
    denyPathTraversal: true,
    denyAbsolutePaths: true,
    denySensitiveFiles: true
  };
}
