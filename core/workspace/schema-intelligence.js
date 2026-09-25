import path from "node:path";
import { listWorkspaceFiles, readWorkspaceFile } from "./manager.js";
import { resolveWorkspacePath } from "../linux/terminal/workspace.js";

const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"]);
const MAX_FILE_BYTES = 512 * 1024;

function normalizePath(filePath) { return filePath.split(path.sep).join("/"); }
function lineOf(source, index) { return source.slice(0, index).split("\n").length; }

function parseTypeScriptSchemas(source, filePath) {
  const schemas = [];
  const interfaceRe = /\b(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)(?:\s+extends\s+([^\{]+))?\s*\{([\s\S]*?)\}/g;
  const typeRe = /\b(?:export\s+)?type\s+([A-Za-z_$][\w$]*)(?:<[^>]+>)?\s*=\s*([^;\n]+(?:\n\s*[^;\n]+)*)/g;
  for (const match of source.matchAll(interfaceRe)) {
    const body = match[3];
    const fields = [...body.matchAll(/(?:^|[;\n])\s*([A-Za-z_$][\w$]*)(\?)?\s*:\s*([^;\n]+)/g)]
      .map(m => ({ name: m[1], optional: Boolean(m[2]), type: m[3].trim() }));
    schemas.push({ kind: "interface", name: match[1], extends: match[2]?.trim() || null, fields, file: normalizePath(filePath), line: lineOf(source, match.index) });
  }
  for (const match of source.matchAll(typeRe)) {
    schemas.push({ kind: "type", name: match[1], definition: match[2].trim().slice(0, 500), file: normalizePath(filePath), line: lineOf(source, match.index) });
  }
  return schemas;
}

function parseRuntimeSchemas(source, filePath) {
  const schemas = [];
  const patterns = [
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*z\.(?:object|array|string|number|boolean|enum|union|record|tuple)\s*\(/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:Joi|yup|yup\.object)\.(?:object|objectSchema|schema)\s*\(/g
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      schemas.push({ kind: "runtime-schema", name: match[1], library: source.slice(match.index, match.index + 80).match(/z\.|Joi|yup/)?.[0]?.replace(".", "") || "unknown", file: normalizePath(filePath), line: lineOf(source, match.index) });
    }
  }
  return schemas;
}

function parseJsonSchema(source, filePath) {
  if (path.extname(filePath).toLowerCase() !== ".json") return [];
  try {
    const value = JSON.parse(source);
    if (!value || typeof value !== "object" || (!value.$schema && !value.type && !value.properties)) return [];
    return [{ kind: "json-schema", name: value.title || path.basename(filePath, ".json"), type: value.type || null, required: Array.isArray(value.required) ? value.required : [], properties: value.properties && typeof value.properties === "object" ? Object.keys(value.properties) : [], file: normalizePath(filePath), line: 1 }];
  } catch { return []; }
}

export async function analyzeSchemas({ paths = [], limit = 150 } = {}) {
  const files = paths?.length ? paths.map(normalizePath) : (await listWorkspaceFiles()).filter(p => SOURCE_EXTENSIONS.has(path.extname(p).toLowerCase()));
  const schemas = [];
  const scannedFiles = [];
  const skippedFiles = [];
  for (const relativePath of files.slice(0, 300)) {
    const ext = path.extname(relativePath).toLowerCase();
    if (!SOURCE_EXTENSIONS.has(ext)) continue;
    const absolute = resolveWorkspacePath(relativePath);
    const stat = await import("node:fs/promises").then(fs => fs.stat(absolute)).catch(() => null);
    if (!stat?.isFile() || stat.size > MAX_FILE_BYTES) { skippedFiles.push({ path: relativePath, reason: stat?.isFile() ? "file-too-large" : "not-a-file" }); continue; }
    const result = await readWorkspaceFile(relativePath);
    scannedFiles.push(relativePath);
    schemas.push(...parseTypeScriptSchemas(result.content, relativePath), ...parseRuntimeSchemas(result.content, relativePath), ...parseJsonSchema(result.content, relativePath));
  }
  return { scannedFiles, skippedFiles, schemas: schemas.slice(0, limit), counts: { files: scannedFiles.length, schemas: schemas.length }, limitations: ["Schema discovery is static and evidence-based.", "Generated schemas, runtime-computed types, advanced conditional TypeScript types, and framework-specific inference may not be detected."] };
}
