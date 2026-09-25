import path from "node:path";
import { listWorkspaceFiles, readWorkspaceFile } from "./manager.js";
import { resolveWorkspacePath } from "../linux/terminal/workspace.js";

const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);
const MAX_FILE_BYTES = 512 * 1024;

function normalizePath(filePath) {
  return filePath.split(path.sep).join("/");
}

function routeEntries(source, filePath) {
  const routes = [];
  const patterns = [
    /\b(?:app|router)\.(get|post|put|patch|delete|options|head|all)\s*\(\s*["'`]([^"'`]+)["'`]/g,
    /\b(?:app|router)\.use\s*\(\s*["'`]([^"'`]+)["'`]/g
  ];

  for (const match of source.matchAll(patterns[0])) {
    routes.push({ method: match[1].toUpperCase(), path: match[2], file: normalizePath(filePath), line: source.slice(0, match.index).split("\n").length });
  }
  for (const match of source.matchAll(patterns[1])) {
    routes.push({ method: "USE", path: match[1], file: normalizePath(filePath), line: source.slice(0, match.index).split("\n").length });
  }
  return routes;
}

function moduleExports(source, filePath) {
  const exports = [];
  const patterns = [
    /\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g,
    /\bexport\s+(?:const|let|var|class)\s+([A-Za-z_$][\w$]*)/g,
    /\bexport\s+default\s+([A-Za-z_$][\w$]*)?/g,
    /\bmodule\.exports\s*=\s*([\s\S]*?)(?:;|$)/g
  ];
  for (const match of source.matchAll(patterns[0])) exports.push({ name: match[1], kind: "named", file: normalizePath(filePath) });
  for (const match of source.matchAll(patterns[1])) exports.push({ name: match[1], kind: "named", file: normalizePath(filePath) });
  for (const match of source.matchAll(patterns[2])) exports.push({ name: match[1] || "default", kind: "default", file: normalizePath(filePath) });
  for (const match of source.matchAll(patterns[3])) exports.push({ name: "module.exports", kind: "commonjs", file: normalizePath(filePath), valuePreview: match[1].trim().slice(0, 180) });
  return exports;
}

function imports(source, filePath) {
  const results = [];
  const pattern = /\bimport\s+([\s\S]*?)\s+from\s+["']([^"']+)["']/g;
  for (const match of source.matchAll(pattern)) {
    results.push({ file: normalizePath(filePath), source: match[2], specifier: match[1].trim().replace(/\s+/g, " ").slice(0, 180) });
  }
  return results;
}

export async function analyzeContracts({ paths = [], limit = 100 } = {}) {
  const files = paths?.length
    ? paths.map(p => normalizePath(p))
    : (await listWorkspaceFiles()).filter(p => SOURCE_EXTENSIONS.has(path.extname(p).toLowerCase()));

  const endpoints = [];
  const exports = [];
  const moduleImports = [];
  const scannedFiles = [];
  const skippedFiles = [];

  for (const relativePath of files.slice(0, 300)) {
    if (!SOURCE_EXTENSIONS.has(path.extname(relativePath).toLowerCase())) continue;
    const absolute = resolveWorkspacePath(relativePath);
    const stat = await import("node:fs/promises").then(fs => fs.stat(absolute)).catch(() => null);
    if (!stat?.isFile() || stat.size > MAX_FILE_BYTES) {
      skippedFiles.push({ path: relativePath, reason: stat?.isFile() ? "file-too-large" : "not-a-file" });
      continue;
    }
    const fileResult = await readWorkspaceFile(relativePath);
    const source = fileResult.content;
    scannedFiles.push(relativePath);
    endpoints.push(...routeEntries(source, relativePath));
    exports.push(...moduleExports(source, relativePath));
    moduleImports.push(...imports(source, relativePath));
  }

  return {
    scannedFiles,
    skippedFiles,
    endpoints: endpoints.slice(0, limit),
    exports: exports.slice(0, limit),
    imports: moduleImports.slice(0, limit),
    counts: { files: scannedFiles.length, endpoints: endpoints.length, exports: exports.length, imports: moduleImports.length },
    limitations: [
      "Contract discovery is lexical and evidence-based; it does not execute the application.",
      "Dynamic routes, generated schemas, runtime middleware, and type-level contracts may not be detected."
    ]
  };
}
