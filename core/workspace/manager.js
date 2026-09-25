import fs from "node:fs/promises";
import path from "node:path";
import { resolveWorkspacePath, WORKSPACE_ROOT } from "../linux/terminal/workspace.js";

const MAX_FILE_SIZE = Number(process.env.WORKSPACE_MAX_FILE_SIZE || 1000000);

const IGNORED_NAMES = new Set([
  ".git", "node_modules", ".DS_Store"
]);

const SENSITIVE_NAMES = new Set([
  ".env", ".env.local", ".env.production", ".env.development"
]);

function normalizeRelativePath(input) {
  if (typeof input !== "string" || !input.trim()) {
    throw new Error("Path file wajib diisi");
  }

  const normalized = input.replaceAll("\\", "/");

  if (
    normalized.startsWith("/") ||
    /^[A-Za-z]:\//.test(normalized)
  ) {
    throw new Error("Absolute path tidak diizinkan");
  }

  const parts = normalized.split("/");
  if (parts.includes("..")) {
    throw new Error("Path traversal tidak diizinkan");
  }

  return normalized;
}

function assertSafeFileName(relativePath) {
  const base = path.posix.basename(relativePath);

  if (
    SENSITIVE_NAMES.has(base) ||
    base.startsWith(".env.")
  ) {
    throw new Error("Akses file konfigurasi rahasia ditolak");
  }
}

export async function readWorkspaceFile(relativePath) {
  const safePath = normalizeRelativePath(relativePath);
  assertSafeFileName(safePath);

  const fullPath = resolveWorkspacePath(safePath);
  const stat = await fs.stat(fullPath);

  if (!stat.isFile()) throw new Error("Path bukan file");

  if (stat.size > MAX_FILE_SIZE) {
    throw new Error(`File terlalu besar. Maksimum ${MAX_FILE_SIZE} bytes`);
  }

  return {
    path: safePath,
    content: await fs.readFile(fullPath, "utf8"),
    size: stat.size
  };
}

export async function writeWorkspaceFile(relativePath, content) {
  const safePath = normalizeRelativePath(relativePath);
  assertSafeFileName(safePath);

  if (typeof content !== "string") {
    throw new Error("content harus berupa string");
  }

  const bytes = Buffer.byteLength(content, "utf8");

  if (bytes > MAX_FILE_SIZE) {
    throw new Error(`File terlalu besar. Maksimum ${MAX_FILE_SIZE} bytes`);
  }

  const fullPath = resolveWorkspacePath(safePath);
  await fs.mkdir(path.dirname(fullPath), { recursive: true });
  await fs.writeFile(fullPath, content, "utf8");

  return {
    path: safePath,
    size: bytes
  };
}

async function walk(current, relative = "") {
  const entries = await fs.readdir(current, { withFileTypes: true });
  const result = [];

  for (const entry of entries) {
    if (
      IGNORED_NAMES.has(entry.name) ||
      SENSITIVE_NAMES.has(entry.name) ||
      entry.name.startsWith(".env.")
    ) {
      continue;
    }

    const childRelative = relative
      ? path.join(relative, entry.name)
      : entry.name;

    const childFull = path.join(current, entry.name);

    if (entry.isDirectory()) {
      result.push({
        path: childRelative.replaceAll(path.sep, "/"),
        type: "directory"
      });
      result.push(...await walk(childFull, childRelative));
    } else {
      const stat = await fs.stat(childFull);

      result.push({
        path: childRelative.replaceAll(path.sep, "/"),
        type: "file",
        size: stat.size
      });
    }
  }

  return result;
}

export async function listWorkspaceFiles() {
  await fs.mkdir(WORKSPACE_ROOT, { recursive: true });
  return walk(WORKSPACE_ROOT);
}
