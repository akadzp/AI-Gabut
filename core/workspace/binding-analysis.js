import path from "node:path";
import { getProjectIndex } from "./project-index.js";
import { readWorkspaceFile } from "./manager.js";

let babelParse = null;
try {
  ({ parse: babelParse } = await import("@babel/parser"));
} catch {
  babelParse = null;
}

const EXTENSIONS = ["", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"];
const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);

function normalize(p) {
  return p.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "");
}

function resolveImportTarget(fromPath, source, fileSet) {
  if (!source?.startsWith(".")) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromPath), source));
  for (const suffix of EXTENSIONS) {
    const candidate = normalize(`${base}${suffix}`);
    if (fileSet.has(candidate)) return candidate;
  }
  for (const suffix of EXTENSIONS.filter(Boolean)) {
    const candidate = normalize(`${base}/index${suffix}`);
    if (fileSet.has(candidate)) return candidate;
  }
  return null;
}

function parse(content, extension) {
  if (!babelParse) return null;
  try {
    return babelParse(content, {
      sourceType: "unambiguous",
      errorRecovery: true,
      plugins: ["jsx", "typescript", "classProperties", "classPrivateProperties", "classPrivateMethods", "topLevelAwait", "dynamicImport", "importMeta"]
    });
  } catch {
    return null;
  }
}

function walk(node, visit, parent = null) {
  if (!node || typeof node !== "object") return;
  if (node.type) visit(node, parent);
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "start", "end", "tokens", "comments"].includes(key)) continue;
    if (Array.isArray(value)) for (const child of value) if (child?.type) walk(child, visit, node);
    else if (value?.type) walk(value, visit, node);
  }
}

function lineColumn(node) {
  return node?.loc ? { line: node.loc.start.line, column: node.loc.start.column + 1 } : { line: null, column: null };
}

function declarationFromNode(node) {
  if (!node) return null;
  if (node.type === "FunctionDeclaration" && node.id) return { name: node.id.name, kind: "function", ...lineColumn(node) };
  if (node.type === "ClassDeclaration" && node.id) return { name: node.id.name, kind: "class", ...lineColumn(node) };
  if (node.type === "VariableDeclarator" && node.id?.type === "Identifier") return { name: node.id.name, kind: "variable", ...lineColumn(node) };
  return null;
}

function collectTopLevel(ast) {
  const declarations = new Map();
  const imports = new Map();
  const exports = new Map();
  for (const statement of ast.program?.body || []) {
    const direct = declarationFromNode(statement);
    if (direct) declarations.set(direct.name, direct);
    if (statement.type === "VariableDeclaration") {
      for (const decl of statement.declarations || []) {
        const item = declarationFromNode(decl);
        if (item) declarations.set(item.name, item);
      }
    }
    if (statement.type === "ImportDeclaration") {
      const source = statement.source?.value || "";
      for (const spec of statement.specifiers || []) {
        const local = spec.local?.name;
        if (!local) continue;
        let imported = "default";
        if (spec.type === "ImportSpecifier") imported = spec.imported?.name || spec.imported?.value || "default";
        if (spec.type === "ImportNamespaceSpecifier") imported = "*";
        imports.set(local, { local, imported, source, line: spec.loc?.start.line || null, column: spec.loc?.start.column + 1 || null });
      }
    }
    if (statement.type === "ExportNamedDeclaration") {
      for (const spec of statement.specifiers || []) {
        const local = spec.local?.name || spec.exported?.name;
        const exported = spec.exported?.name || spec.exported?.value || local;
        if (local) exports.set(exported, local);
      }
      const directExport = declarationFromNode(statement.declaration);
      if (directExport) {
        declarations.set(directExport.name, directExport);
        exports.set(directExport.name, directExport.name);
      }
    }
    if (statement.type === "ExportDefaultDeclaration") {
      const directExport = declarationFromNode(statement.declaration);
      if (directExport) {
        declarations.set(directExport.name, directExport);
        exports.set("default", directExport.name);
      }
    }
  }
  return { declarations, imports, exports };
}

function lexicalBindings(content) {
  const declarations = new Map();
  const imports = new Map();
  for (const m of content.matchAll(/\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g)) declarations.set(m[1], { name: m[1], kind: "function", line: content.slice(0, m.index).split(/\n/).length, column: 1 });
  for (const m of content.matchAll(/\b(?:export\s+)?class\s+([A-Za-z_$][\w$]*)/g)) declarations.set(m[1], { name: m[1], kind: "class", line: content.slice(0, m.index).split(/\n/).length, column: 1 });
  for (const m of content.matchAll(/\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g)) declarations.set(m[1], { name: m[1], kind: "variable", line: content.slice(0, m.index).split(/\n/).length, column: 1 });
  for (const m of content.matchAll(/\bimport\s+([^;\n]+?)\s+from\s+["']([^"']+)["']/g)) {
    const clause = m[1].trim();
    const line = content.slice(0, m.index).split(/\n/).length;
    const named = clause.match(/\{([^}]+)\}/);
    if (named) {
      for (const item of named[1].split(",")) {
        const parts = item.trim().split(/\s+as\s+/);
        const imported = parts[0]?.trim();
        const local = (parts[1] || parts[0])?.trim();
        if (/^[A-Za-z_$][\w$]*$/.test(local || "") && /^[A-Za-z_$][\w$]*$/.test(imported || "")) imports.set(local, { local, imported, source: m[2], line, column: 1 });
      }
    }
    const defaultPart = clause.split(",")[0].trim();
    if (/^[A-Za-z_$][\w$]*$/.test(defaultPart)) imports.set(defaultPart, { local: defaultPart, imported: "default", source: m[2], line, column: 1 });
  }
  return { declarations, imports, exports: new Map() };
}

export async function resolveSymbolBinding(name, { sourcePath, refresh = false } = {}) {
  const query = String(name || "").trim();
  if (!/^[A-Za-z_$][\w$]*$/.test(query)) throw new Error("name harus berupa identifier JavaScript/TypeScript");
  const filePath = normalize(String(sourcePath || "").trim());
  if (!filePath) throw new Error("path wajib diisi");
  const index = await getProjectIndex({ refresh });
  const fileSet = new Set(index.files.map(file => file.path));
  if (!fileSet.has(filePath)) return { ok: false, error: `file tidak ditemukan di index: ${filePath}`, bindings: [] };
  const file = index.files.find(item => item.path === filePath);
  const source = await readWorkspaceFile(filePath);
  const ast = parse(source.content, file.extension);
  const scope = ast ? collectTopLevel(ast) : lexicalBindings(source.content);
  const bindings = [];
  const declaration = scope.declarations.get(query);
  if (declaration) bindings.push({ kind: "local-declaration", name: query, path: filePath, ...declaration });
  const imported = scope.imports.get(query);
  if (imported) {
    const target = resolveImportTarget(filePath, imported.source, fileSet);
    const targetFile = target ? index.files.find(item => item.path === target) : null;
    let targetDeclaration = null;
    if (targetFile) {
      try {
        const targetSource = await readWorkspaceFile(target);
        const targetAst = parse(targetSource.content, targetFile.extension);
        const targetScope = targetAst ? collectTopLevel(targetAst) : lexicalBindings(targetSource.content);
        const localName = imported.imported === "default" ? (targetScope.exports.get("default") || "default") : (targetScope.exports.get(imported.imported) || imported.imported);
        targetDeclaration = targetScope.declarations.get(localName) || targetScope.declarations.get(imported.imported) || null;
      } catch {}
    }
    bindings.push({
      kind: "import-binding",
      name: query,
      imported: imported.imported,
      source: imported.source,
      path: filePath,
      line: imported.line,
      column: imported.column,
      target: target ? { path: target, symbol: imported.imported, declaration: targetDeclaration } : null
    });
  }
  return { ok: true, path: filePath, name: query, parser: ast ? "babel" : "lexical-fallback", bindings };
}

async function analyzeFileCalls(file, fileSet) {
  const source = await readWorkspaceFile(file.path);
  const ast = parse(source.content, file.extension);
  if (!ast) {
    const scope = lexicalBindings(source.content);
    const calls = [];
    const lines = source.content.split(/\r?\n/);
    let currentFunction = "<module>";
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const fn = line.match(/\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/);
      if (fn) currentFunction = fn[1];
      for (const match of line.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) {
        const callee = match[1];
        if (["if", "for", "while", "switch", "catch", "with", "function"].includes(callee)) continue;
        const local = scope.declarations.get(callee);
        const imported = scope.imports.get(callee);
        let target = null;
        if (local) target = { path: file.path, symbol: local.name, kind: local.kind };
        if (imported) {
          const resolved = resolveImportTarget(file.path, imported.source, fileSet);
          if (resolved) target = { path: resolved, symbol: imported.imported, kind: "import" };
        }
        calls.push({ caller: currentFunction, callee, line: i + 1, column: match.index + 1, target });
      }
    }
    return { parser: "lexical-fallback", calls };
  }
  const scope = collectTopLevel(ast);
  const calls = [];
  const functions = [];
  walk(ast, node => {
    if (node.type === "FunctionDeclaration" || node.type === "FunctionExpression" || node.type === "ArrowFunctionExpression") {
      functions.push({ node, name: node.id?.name || "<anonymous>", start: node.start ?? 0, end: node.end ?? Number.MAX_SAFE_INTEGER });
    }
  });
  walk(ast, node => {
    if (node.type !== "CallExpression" || node.callee?.type !== "Identifier") return;
    const callee = node.callee.name;
    const local = scope.declarations.get(callee);
    const imported = scope.imports.get(callee);
    let target = null;
    if (local) target = { path: file.path, symbol: local.name, kind: local.kind };
    if (imported) {
      const resolved = resolveImportTarget(file.path, imported.source, fileSet);
      if (resolved) target = { path: resolved, symbol: imported.imported, kind: "import" };
    }
    const containing = functions
      .filter(fn => (node.start ?? 0) >= fn.start && (node.end ?? 0) <= fn.end)
      .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0];
    calls.push({ caller: containing?.name || "<module>", callee, line: node.loc?.start.line || null, column: node.loc?.start.column + 1 || null, target });
  });
  return { parser: "babel", calls };
}

export async function getCallGraph({ sourcePath = null, symbol = null, refresh = false, limit = 100 } = {}) {
  const index = await getProjectIndex({ refresh });
  const fileSet = new Set(index.files.map(file => file.path));
  const candidates = sourcePath ? index.files.filter(file => file.path === normalize(sourcePath)) : index.files;
  const edges = [];
  const parsers = new Set();
  for (const file of candidates) {
    if (!SOURCE_EXTENSIONS.has(file.extension)) continue;
    try {
      const result = await analyzeFileCalls(file, fileSet);
      parsers.add(result.parser);
      for (const call of result.calls) {
        if (symbol && call.callee !== symbol && call.target?.symbol !== symbol) continue;
        edges.push({ from: { path: file.path, symbol: call.caller }, to: call.target || { path: file.path, symbol: call.callee, kind: "unresolved" }, callee: call.callee, line: call.line, column: call.column });
      }
    } catch {}
  }
  return { ok: true, sourcePath: sourcePath ? normalize(sourcePath) : null, symbol: symbol || null, parser: parsers.size === 1 ? [...parsers][0] : "mixed", edges: edges.slice(0, Math.min(200, Math.max(1, Number(limit) || 100))) };
}
