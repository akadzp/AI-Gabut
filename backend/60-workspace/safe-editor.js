import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { resolveWorkspacePath } from "../40-linux/terminal/workspace.js";
import { readWorkspaceFile } from "./manager.js";

const MAX_FILE_SIZE = Number(process.env.WORKSPACE_MAX_FILE_SIZE || 1000000);
const MAX_REPLACEMENTS = 20;

function hashContent(content) {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

function normalizePath(input) {
  if (typeof input !== "string" || !input.trim()) throw new Error("path wajib diisi");
  const normalized = input.replaceAll("\\", "/");
  if (normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) throw new Error("Absolute path tidak diizinkan");
  if (normalized.split("/").includes("..")) throw new Error("Path traversal tidak diizinkan");
  const base = path.posix.basename(normalized);
  if (base === ".env" || base.startsWith(".env.")) throw new Error("Akses file konfigurasi rahasia ditolak");
  return normalized;
}

async function syntaxCheck(relativePath, content) {
  const ext = path.posix.extname(relativePath).toLowerCase();
  if (![".js", ".mjs", ".cjs"].includes(ext)) return { checked: false, type: "not-applicable" };

  const tempPath = path.join(process.cwd(), `.ai-gabut-syntax-${process.pid}-${Date.now()}${ext}`);
  await fs.writeFile(tempPath, content, "utf8");
  try {
    return await new Promise((resolve) => {
      const child = spawn(process.execPath, ["--check", tempPath], { stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.on("data", chunk => { stderr += chunk.toString(); });
      child.on("error", error => resolve({ checked: false, type: "node", error: error.message }));
      child.on("close", code => resolve({ checked: true, type: "node", ok: code === 0, error: code === 0 ? undefined : stderr.trim() }));
    });
  } finally {
    await fs.rm(tempPath, { force: true }).catch(() => {});
  }
}

function applyOperation(content, { operation = "replace", oldText = "", newText = "", count = 1 } = {}) {
  if (typeof newText !== "string") throw new Error("newText harus berupa string");
  if (!["replace", "insert_before", "insert_after", "append"].includes(operation)) throw new Error("operation tidak didukung");

  if (operation === "append") return { content: content + newText, replacements: 1 };
  if (!oldText) throw new Error("oldText wajib diisi untuk operasi ini");

  const maxCount = Math.min(Math.max(Number(count) || 1, 1), MAX_REPLACEMENTS);
  let cursor = 0;
  let replacements = 0;
  let output = "";
  while (replacements < maxCount) {
    const index = content.indexOf(oldText, cursor);
    if (index === -1) break;
    output += content.slice(cursor, index);
    output += operation === "insert_before" ? newText + oldText : operation === "insert_after" ? oldText + newText : newText;
    cursor = index + oldText.length;
    replacements += 1;
  }
  output += content.slice(cursor);

  if (replacements === 0) throw new Error("oldText tidak ditemukan");
  return { content: output, replacements };
}

async function atomicWrite(fullPath, content) {
  const tempPath = `${fullPath}.ai-gabut-tmp-${process.pid}-${Date.now()}`;
  await fs.writeFile(tempPath, content, "utf8");
  try {
    await fs.rename(tempPath, fullPath);
  } catch (error) {
    await fs.rm(tempPath, { force: true }).catch(() => {});
    throw error;
  }
}

export async function safeEditFile({ path: relativePath, expectedHash, operation = "replace", oldText = "", newText = "", count = 1 } = {}) {
  const safePath = normalizePath(relativePath);
  if (typeof expectedHash !== "string" || !/^[a-f0-9]{64}$/i.test(expectedHash)) {
    throw new Error("expectedHash SHA-256 wajib diisi agar edit tidak menimpa perubahan yang terjadi setelah file dibaca");
  }

  const before = await readWorkspaceFile(safePath);
  const beforeHash = hashContent(before.content);
  if (beforeHash !== expectedHash.toLowerCase()) {
    return {
      ok: false,
      conflict: true,
      error: "File berubah sejak terakhir dibaca; edit dibatalkan untuk mencegah lost update.",
      path: safePath,
      expectedHash,
      actualHash: beforeHash
    };
  }

  const applied = applyOperation(before.content, { operation, oldText, newText, count });
  const bytes = Buffer.byteLength(applied.content, "utf8");
  if (bytes > MAX_FILE_SIZE) throw new Error(`File terlalu besar. Maksimum ${MAX_FILE_SIZE} bytes`);
  if (applied.content === before.content) throw new Error("Edit tidak menghasilkan perubahan");

  const syntax = await syntaxCheck(safePath, applied.content);
  if (syntax.checked && !syntax.ok) {
    return {
      ok: false,
      validationFailed: true,
      rolledBack: true,
      error: "Edit dibatalkan karena hasil file gagal syntax check.",
      path: safePath,
      beforeHash,
      validation: syntax
    };
  }

  const fullPath = resolveWorkspacePath(safePath);
  await atomicWrite(fullPath, applied.content);
  const afterHash = hashContent(applied.content);

  return {
    ok: true,
    path: safePath,
    operation,
    replacements: applied.replacements,
    beforeHash,
    afterHash,
    bytes: bytes,
    validation: syntax
  };
}
