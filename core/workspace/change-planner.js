import { getProjectIndex, searchWorkspace, findReferences, findReferencesToFile, analyzeImpact } from "./project-index.js";
import { resolveSymbolBinding, getCallGraph } from "./binding-analysis.js";
import { gitChanges } from "../linux/git/manager.js";

const MAX_FILES = 40;
const MAX_REFERENCES = 30;
const MAX_IMPACT_DEPTH = 3;

function normalizePath(value) {
  return String(value || "").trim().replaceAll("\\", "/").replace(/^\.\//, "");
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function collectCandidatePaths(task, explicitPaths, searchResults) {
  const fromTask = String(task || "").match(/(?:^|\s)([\w./-]+\.(?:js|mjs|cjs|ts|tsx|jsx|json))(?:\s|$)/gi) || [];
  return unique([
    ...explicitPaths.map(normalizePath),
    ...fromTask.map(value => normalizePath(value.trim())),
    ...searchResults.filter(item => item.type === "path").map(item => item.path),
    ...searchResults.filter(item => item.type === "symbol").map(item => item.path)
  ]).slice(0, MAX_FILES);
}

function collectCandidateSymbols(task, explicitSymbols, searchResults) {
  const words = String(task || "").match(/\b[A-Za-z_$][\w$]{2,}\b/g) || [];
  return unique([
    ...explicitSymbols,
    ...searchResults.filter(item => item.type === "symbol").map(item => item.symbol),
    ...words.filter(word => /[A-Z_$]/.test(word[0]) || /[A-Za-z_$]*[A-Z_$][A-Za-z0-9_$]*/.test(word))
  ]).slice(0, 12);
}

export async function planChange({ task, paths = [], symbols = [], depth = MAX_IMPACT_DEPTH, refresh = false } = {}) {
  const goal = String(task || "").trim();
  if (!goal) throw new Error("task wajib diisi");

  const index = await getProjectIndex({ refresh });
  const search = await searchWorkspace(goal, { limit: 20, refresh: false });
  const targetPaths = collectCandidatePaths(goal, paths, search.results || []);
  const targetSymbols = collectCandidateSymbols(goal, symbols, search.results || []);
  const impacts = [];
  const fileReferences = [];
  const symbolReferences = [];
  const bindings = [];
  const callGraphs = [];
  const verification = [];

  for (const target of targetPaths.slice(0, 12)) {
    const impact = await analyzeImpact(target, { depth: Math.min(MAX_IMPACT_DEPTH, Math.max(1, Number(depth) || 2)), refresh: false });
    if (impact.ok) impacts.push(impact);
    const refs = await findReferencesToFile(target, { limit: MAX_REFERENCES, refresh: false });
    if (refs.ok) fileReferences.push(refs);
  }

  for (const symbol of targetSymbols.slice(0, 8)) {
    const refs = await findReferences(symbol, { limit: MAX_REFERENCES, refresh: false });
    if (refs.ok) symbolReferences.push(refs);
  }

  for (const target of targetPaths.filter(path => /\.(js|mjs|cjs|ts|tsx|jsx)$/.test(path)).slice(0, 8)) {
    for (const symbol of targetSymbols.slice(0, 4)) {
      const binding = await resolveSymbolBinding(symbol, { sourcePath: target, refresh: false });
      if (binding?.ok && (binding.declaration || binding.import)) bindings.push(binding);
    }
    const graph = await getCallGraph({ sourcePath: target, limit: 80, refresh: false });
    if (graph.ok && graph.edges.length) callGraphs.push(graph);
  }

  const directImpacted = unique(impacts.flatMap(item => item.directDependents || []));
  const transitiveImpacted = unique(impacts.flatMap(item => (item.impacted || []).map(entry => entry.path)));
  const relatedFiles = unique([
    ...targetPaths,
    ...directImpacted,
    ...transitiveImpacted,
    ...fileReferences.flatMap(item => (item.results || []).map(entry => entry.path)),
    ...symbolReferences.flatMap(item => (item.results || []).map(entry => entry.path))
  ]).slice(0, MAX_FILES);

  const git = await gitChanges();
  const gitTouched = git.ok ? unique([
    ...(git.files?.staged || []),
    ...(git.files?.unstaged || []),
    ...(git.files?.untracked || [])
  ]) : [];

  if (targetPaths.length) verification.push("Baca file target dan referensi langsung sebelum mengedit.");
  if (directImpacted.length) verification.push("Verifikasi semua direct dependents setelah perubahan.");
  if (symbolReferences.length || bindings.length) verification.push("Verifikasi binding dan referensi simbol yang berubah.");
  if (callGraphs.length) verification.push("Jalankan pemeriksaan pada call sites yang teridentifikasi.");
  verification.push("Jalankan test/check yang relevan setelah perubahan.");
  verification.push("Periksa git changes untuk memastikan hanya file yang dimaksud yang berubah.");

  const unresolvedBindings = bindings.filter(item => item.resolution === "unresolved").length;
  const impactCount = directImpacted.length + transitiveImpacted.length;

  return {
    ok: true,
    type: "change_plan",
    generatedAt: new Date().toISOString(),
    task: goal,
    workspace: { fileCount: index.fileCount, sourceFileCount: index.files.filter(file => /\.(js|mjs|cjs|ts|tsx|jsx)$/.test(file.path)).length },
    targets: { paths: targetPaths, symbols: targetSymbols },
    scope: {
      relatedFiles,
      directDependents: directImpacted,
      impactedCount: impactCount,
      unresolvedBindings,
      currentGitChanges: gitTouched
    },
    evidence: {
      fileReferences: fileReferences.flatMap(item => item.results || []).slice(0, MAX_REFERENCES),
      symbolReferences: symbolReferences.flatMap(item => item.results || []).slice(0, MAX_REFERENCES),
      bindings: bindings.slice(0, MAX_REFERENCES),
      callEdges: callGraphs.flatMap(item => item.edges || []).slice(0, 100),
      parsers: unique([
        ...callGraphs.map(item => item.parser),
        ...bindings.map(item => item.parser)
      ])
    },
    readBeforeEdit: relatedFiles.slice(0, 20),
    verification,
    notes: [
      "Rencana ini hanya membaca workspace dan Git; tidak mengubah file, staging, commit, atau push.",
      "Dependency/impact analysis berbasis local import resolution.",
      "Binding dan call graph dapat menggunakan AST Babel atau lexical fallback tergantung environment."
    ]
  };
}
