import path from "node:path";
import { WORKSPACE_ROOT } from "../linux/terminal/workspace.js";
import { listWorkspaceFiles, readWorkspaceFile } from "./manager.js";
import { analyzeSourceSemantics } from "./semantic-parser.js";

const TEXT_LIMIT = 240_000;
const MAX_RESULTS = 50;
const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);
const indexCache = new Map();
const RESOLVE_EXTENSIONS = ["", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"];

function relative(filePath) {
  return path.relative(WORKSPACE_ROOT, filePath).replaceAll(path.sep, "/");
}

function extension(filePath) {
  return path.extname(filePath).toLowerCase();
}

function parseImportsExports(content) {
  const imports = [];
  const exports = [];
  const importBindings = [];
  const importRe = /\bimport\s+(?:[\s\S]*?\s+from\s+)?["']([^"']+)["']/g;
  const requireRe = /\brequire\(\s*["']([^"']+)["']\s*\)/g;
  const exportRe = /\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)/g;
  const namedExportRe = /\bexport\s*\{([^}]+)\}/g;

  for (const match of content.matchAll(importRe)) {
    imports.push(match[1]);
    const statement = match[0];
    const beforeFrom = statement.split(/\sfrom\s/)[0].replace(/^import\s+/, "").trim();
    if (beforeFrom && !beforeFrom.startsWith("\"") && !beforeFrom.startsWith("'")) {
      for (const binding of beforeFrom.replace(/[{}]/g, "").split(",")) {
        const name = binding.trim().split(/\s+as\s+/)[0].trim();
        if (/^[A-Za-z_$][\w$]*$/.test(name)) importBindings.push({ local: name, source: match[1] });
      }
    }
  }
  for (const match of content.matchAll(requireRe)) imports.push(match[1]);
  for (const match of content.matchAll(exportRe)) exports.push(match[1]);
  for (const match of content.matchAll(namedExportRe)) {
    for (const name of match[1].split(",")) {
      const cleaned = name.trim().split(/\s+as\s+/)[0];
      if (/^[A-Za-z_$][\w$]*$/.test(cleaned)) exports.push(cleaned);
    }
  }

  return {
    imports: [...new Set(imports)],
    exports: [...new Set(exports)],
    importBindings
  };
}

async function buildIndex() {
  const entries = await listWorkspaceFiles();
  const files = [];
  const directories = [];
  const symbols = [];
  const imports = [];
  let totalBytes = 0;

  for (const entry of entries) {
    if (entry.type === "directory") {
      directories.push(entry.path);
      continue;
    }

    files.push({ path: entry.path, size: entry.size, extension: extension(entry.path) });
    totalBytes += Number(entry.size || 0);

    if (!SOURCE_EXTENSIONS.has(extension(entry.path)) || entry.size > TEXT_LIMIT) continue;

    try {
      const file = await readWorkspaceFile(entry.path);
      const parsed = parseImportsExports(file.content);
      const semantic = analyzeSourceSemantics(file.content, extension(entry.path));
      const semanticSymbols = semantic.symbols.length ? semantic.symbols : parsed.exports.map(name => ({ name, kind: "export", line: null, column: null }));
      for (const symbol of semanticSymbols) symbols.push({ ...symbol, path: entry.path });
      for (const source of parsed.imports) imports.push({ path: entry.path, source });
      for (const binding of parsed.importBindings) imports.push({ path: entry.path, source: binding.source, local: binding.local });
    } catch {
      // The index is best-effort. Sensitive or unreadable files remain absent.
    }
  }

  const packagePath = files.find(file => file.path === "package.json");
  let packageInfo = null;
  if (packagePath) {
    try {
      const pkg = JSON.parse((await readWorkspaceFile("package.json")).content);
      packageInfo = {
        name: pkg.name || null,
        version: pkg.version || null,
        type: pkg.type || null,
        scripts: pkg.scripts || {},
        dependencies: Object.keys(pkg.dependencies || {}),
        devDependencies: Object.keys(pkg.devDependencies || {})
      };
    } catch {
      packageInfo = null;
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    root: relative(WORKSPACE_ROOT),
    fileCount: files.length,
    directoryCount: directories.length,
    totalBytes,
    files,
    directories,
    symbols,
    imports,
    package: packageInfo
  };
}

export async function getProjectIndex({ refresh = false } = {}) {
  const key = WORKSPACE_ROOT;
  if (!refresh && indexCache.has(key)) return indexCache.get(key);
  const index = await buildIndex();
  indexCache.set(key, index);
  return index;
}

export function clearProjectIndex() {
  indexCache.clear();
}

export async function inspectProject({ refresh = false } = {}) {
  const index = await getProjectIndex({ refresh });
  return {
    ok: true,
    generatedAt: index.generatedAt,
    fileCount: index.fileCount,
    directoryCount: index.directoryCount,
    totalBytes: index.totalBytes,
    topLevel: index.files
      .map(file => file.path.split("/")[0])
      .filter((value, index, array) => array.indexOf(value) === index)
      .slice(0, 50),
    package: index.package,
    sourceFiles: index.files.filter(file => SOURCE_EXTENSIONS.has(file.extension)).length,
    symbolCount: index.symbols.length,
    importCount: index.imports.length
  };
}

export async function searchWorkspace(query, { limit = 20, refresh = false } = {}) {
  const text = String(query || "").trim();
  if (!text) throw new Error("query wajib diisi");
  const index = await getProjectIndex({ refresh });
  const terms = text.toLowerCase().split(/[^a-z0-9_$.-]+/).filter(Boolean);
  const results = [];

  for (const file of index.files) {
    const haystack = file.path.toLowerCase();
    const score = terms.reduce((sum, term) => sum + (haystack.includes(term) ? 1 : 0), 0);
    if (score > 0) results.push({ path: file.path, type: "path", score });
  }

  for (const symbol of index.symbols) {
    const haystack = `${symbol.name} ${symbol.path}`.toLowerCase();
    const score = terms.reduce((sum, term) => sum + (haystack.includes(term) ? 1 : 0), 0) + (symbol.name.toLowerCase() === text.toLowerCase() ? 2 : 0);
    if (score > 0) results.push({ path: symbol.path, type: "symbol", symbol: symbol.name, kind: symbol.kind, score });
  }

  return {
    ok: true,
    query: text,
    results: results.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path)).slice(0, Math.min(MAX_RESULTS, Math.max(1, limit)))
  };
}

export async function searchCode(query, { limit = 20, refresh = false, caseSensitive = false, regex = false } = {}) {
  const text = String(query || "").trim();
  if (!text) throw new Error("query wajib diisi");
  const index = await getProjectIndex({ refresh });
  const maxResults = Math.min(MAX_RESULTS, Math.max(1, Number(limit) || 20));
  let matcher;
  try {
    matcher = regex
      ? new RegExp(text, caseSensitive ? "g" : "gi")
      : null;
  } catch (error) {
    throw new Error(`regex tidak valid: ${error instanceof Error ? error.message : "format salah"}`);
  }

  const terms = text.toLowerCase().split(/[^a-z0-9_$.-]+/).filter(Boolean);
  const results = [];

  for (const file of index.files) {
    if (!SOURCE_EXTENSIONS.has(file.extension) || Number(file.size || 0) > TEXT_LIMIT) continue;
    try {
      const source = await readWorkspaceFile(file.path);
      const lines = source.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        const matched = matcher
          ? matcher.test(line)
          : (caseSensitive ? line.includes(text) : line.toLowerCase().includes(text.toLowerCase()));
        matcher?.lastIndex && (matcher.lastIndex = 0);
        if (!matched) continue;

        let score = 1;
        if (!regex && terms.length) {
          const lower = line.toLowerCase();
          score += terms.reduce((sum, term) => sum + (lower.includes(term) ? 1 : 0), 0);
        }
        results.push({
          path: file.path,
          line: i + 1,
          text: line.slice(0, 500),
          score
        });
        if (results.length >= maxResults * 3) break;
      }
    } catch {
      // Best-effort source search; unreadable files remain absent.
    }
    if (results.length >= maxResults * 3) break;
  }

  return {
    ok: true,
    query: text,
    caseSensitive,
    regex,
    results: results
      .sort((a, b) => b.score - a.score || a.path.localeCompare(b.path) || a.line - b.line)
      .slice(0, maxResults)
  };
}


export async function inspectCodeSemantics(sourcePath, { refresh = false, limit = 100 } = {}) {
  const target = String(sourcePath || "").trim();
  if (!target) throw new Error("path wajib diisi");
  const index = await getProjectIndex({ refresh });
  const file = index.files.find(item => item.path === target);
  if (!file || !SOURCE_EXTENSIONS.has(file.extension)) throw new Error(`source file tidak ditemukan: ${target}`);
  const source = await readWorkspaceFile(target);
  const semantic = analyzeSourceSemantics(source.content, file.extension);
  return {
    ok: true,
    path: target,
    parseable: semantic.parseable,
    symbols: semantic.symbols.slice(0, Math.min(MAX_RESULTS, Math.max(1, limit))),
    imports: semantic.imports.slice(0, Math.min(MAX_RESULTS, Math.max(1, limit))),
    referenceCount: semantic.references.length
  };
}

export async function findSemanticReferences(name, { path: sourcePath = null, limit = 30, refresh = false } = {}) {
  const query = String(name || "").trim();
  if (!/^[A-Za-z_$][\w$]*$/.test(query)) throw new Error("name harus berupa identifier JavaScript/TypeScript");
  const index = await getProjectIndex({ refresh });
  const candidates = sourcePath ? index.files.filter(file => file.path === sourcePath) : index.files;
  const results = [];
  for (const file of candidates) {
    if (!SOURCE_EXTENSIONS.has(file.extension) || Number(file.size || 0) > TEXT_LIMIT) continue;
    try {
      const source = await readWorkspaceFile(file.path);
      const semantic = analyzeSourceSemantics(source.content, file.extension);
      for (const ref of semantic.references) {
        if (ref.name !== query) continue;
        results.push({ path: file.path, line: ref.line, column: ref.column, kind: "identifier-reference" });
        if (results.length >= limit * 2) break;
      }
    } catch {}
    if (results.length >= limit * 2) break;
  }
  return { ok: true, name: query, mode: "ast", results: results.slice(0, Math.min(MAX_RESULTS, Math.max(1, limit))) };
}

function normalizePathCandidate(candidate) {
  const normalized = candidate.replaceAll("\\", "/").replace(/^\.\//, "");
  return normalized.replace(/^\//, "");
}

function resolveImportTarget(fromPath, source, fileSet) {
  if (!source?.startsWith(".")) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromPath), source));
  for (const suffix of RESOLVE_EXTENSIONS) {
    const candidate = normalizePathCandidate(`${base}${suffix}`);
    if (fileSet.has(candidate)) return candidate;
  }
  for (const suffix of RESOLVE_EXTENSIONS.filter(Boolean)) {
    const candidate = normalizePathCandidate(`${base}/index${suffix}`);
    if (fileSet.has(candidate)) return candidate;
  }
  return null;
}

export async function findReferences(name, { path: sourcePath = null, limit = 30, refresh = false } = {}) {
  const query = String(name || "").trim();
  if (!query) throw new Error("name wajib diisi");
  if (!/^[A-Za-z_$][\w$]*$/.test(query)) throw new Error("name harus berupa identifier JavaScript/TypeScript");
  const index = await getProjectIndex({ refresh });
  const fileSet = new Set(index.files.map(file => file.path));
  const candidates = sourcePath ? index.files.filter(file => file.path === sourcePath) : index.files;
  const pattern = new RegExp(`\\b${query.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")}\\b`, "g");
  const results = [];

  for (const file of candidates) {
    if (!SOURCE_EXTENSIONS.has(file.extension) || Number(file.size || 0) > TEXT_LIMIT) continue;
    let content;
    try {
      content = (await readWorkspaceFile(file.path)).content;
    } catch {
      continue;
    }
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (!pattern.test(line)) { pattern.lastIndex = 0; continue; }
      pattern.lastIndex = 0;
      const trimmed = line.trim();
      const isDeclaration = new RegExp(`^(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?(?:function|class|const|let|var)\\s+${query}\\b`).test(trimmed);
      const isImport = new RegExp(`^import\\b.*\\b${query}\\b`).test(trimmed);
      const kind = isDeclaration ? "declaration" : isImport ? "import" : "reference";
      results.push({ path: file.path, line: i + 1, kind, text: line.slice(0, 500) });
      if (results.length >= Math.min(MAX_RESULTS, Math.max(1, Number(limit) || 30))) break;
    }
    if (results.length >= Math.min(MAX_RESULTS, Math.max(1, Number(limit) || 30))) break;
  }

  const importEdges = index.imports
    .map(edge => ({ ...edge, target: resolveImportTarget(edge.path, edge.source, fileSet) }))
    .filter(edge => edge.target);
  const relatedFiles = [...new Set(importEdges.filter(edge => edge.local === query || edge.target === sourcePath).map(edge => edge.path))];

  return {
    ok: true,
    name: query,
    sourcePath,
    results,
    relatedFiles,
    imports: importEdges.filter(edge => edge.local === query || edge.target === sourcePath).slice(0, MAX_RESULTS)
  };
}

export async function findReferencesToFile(targetPath, { limit = 30, refresh = false } = {}) {
  const query = normalizePathCandidate(String(targetPath || "").trim());
  if (!query) throw new Error("path wajib diisi");
  const index = await getProjectIndex({ refresh });
  const fileSet = new Set(index.files.map(file => file.path));
  if (!fileSet.has(query)) return { ok: false, error: `file tidak ditemukan di index: ${query}`, results: [] };
  const edges = index.imports
    .map(edge => ({ ...edge, target: resolveImportTarget(edge.path, edge.source, fileSet) }))
    .filter(edge => edge.target === query)
    .slice(0, Math.min(MAX_RESULTS, Math.max(1, Number(limit) || 30)));
  return { ok: true, path: query, results: edges };
}

export async function findSymbol(name, { limit = 20, refresh = false } = {}) {
  const query = String(name || "").trim();
  if (!query) throw new Error("name wajib diisi");
  const index = await getProjectIndex({ refresh });
  const lower = query.toLowerCase();
  const matches = index.symbols
    .filter(symbol => symbol.name.toLowerCase() === lower || symbol.name.toLowerCase().includes(lower))
    .sort((a, b) => (a.name.toLowerCase() === lower ? -1 : 1) - (b.name.toLowerCase() === lower ? -1 : 1) || a.path.localeCompare(b.path))
    .slice(0, Math.min(MAX_RESULTS, Math.max(1, limit)));

  return { ok: true, name: query, results: matches };
}


export async function getDependencyGraph({ refresh = false } = {}) {
  const index = await getProjectIndex({ refresh });
  const fileSet = new Set(index.files.map(file => file.path));
  const edges = index.imports
    .map(edge => ({
      from: edge.path,
      source: edge.source,
      local: edge.local || null,
      to: resolveImportTarget(edge.path, edge.source, fileSet)
    }))
    .filter(edge => edge.to);

  const nodes = index.files.map(file => ({ path: file.path, extension: file.extension, size: file.size }));
  return { ok: true, generatedAt: index.generatedAt, nodes, edges };
}

export async function analyzeImpact(targetPath, { depth = 2, refresh = false } = {}) {
  const query = normalizePathCandidate(String(targetPath || '').trim());
  if (!query) throw new Error('path wajib diisi');
  const graph = await getDependencyGraph({ refresh });
  const known = new Set(graph.nodes.map(node => node.path));
  if (!known.has(query)) return { ok: false, error: `file tidak ditemukan di index: ${query}`, target: query, impacted: [] };

  const maxDepth = Math.min(5, Math.max(1, Number(depth) || 2));
  const reverse = new Map();
  for (const edge of graph.edges) {
    if (!reverse.has(edge.to)) reverse.set(edge.to, []);
    reverse.get(edge.to).push(edge.from);
  }

  const impacted = [];
  const visited = new Set([query]);
  let frontier = [query];
  for (let level = 1; level <= maxDepth; level += 1) {
    const next = [];
    for (const current of frontier) {
      for (const dependent of reverse.get(current) || []) {
        if (visited.has(dependent)) continue;
        visited.add(dependent);
        next.push(dependent);
        impacted.push({ path: dependent, depth: level, dependsOn: current });
      }
    }
    frontier = next;
    if (!frontier.length) break;
  }

  const direct = impacted.filter(item => item.depth === 1).map(item => item.path);
  return {
    ok: true,
    target: query,
    maxDepth,
    directDependents: direct,
    impacted: impacted.sort((a, b) => a.depth - b.depth || a.path.localeCompare(b.path))
  };
}
