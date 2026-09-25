import path from "node:path";
import { listWorkspaceFiles } from "./manager.js";
import { WORKSPACE_ROOT } from "../40-linux/terminal/workspace.js";

const MAX_FAILURES = 12;
const MAX_FILES = 10;
const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);

function normalize(value) { return String(value || "").replace(/\\/g, "/"); }
function rel(value) { return normalize(path.relative(WORKSPACE_ROOT, value)); }
function isInsideWorkspace(p) {
  const absolute = path.resolve(WORKSPACE_ROOT, p);
  const relative = path.relative(WORKSPACE_ROOT, absolute);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function outputOf(failure) {
  return [failure?.stderr, failure?.stdout, failure?.error, failure?.message].filter(Boolean).join("\n");
}

function extractPaths(text, workspaceFiles) {
  const found = new Set();
  const normalizedFiles = workspaceFiles.map(normalize);
  const patterns = [
    /(?:at\s+)?(?:file:\/\/)?([^\s()]+\.(?:js|mjs|cjs|ts|tsx|jsx))(?:\:(\d+))?(?:\:(\d+))?/gi,
    /(?:Cannot find module|import|require)\s+['"]([^'"]+)['"]/gi
  ];

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const raw = normalize(match[1]);
      if (!raw || raw.startsWith("node:") || raw.startsWith("http")) continue;
      const candidates = [raw, raw.replace(/^\.\//, "")];
      for (const candidate of candidates) {
        if (normalizedFiles.includes(candidate) && isInsideWorkspace(candidate)) {
          found.add(candidate);
          break;
        }
        const base = path.basename(candidate);
        const matchFile = normalizedFiles.find(file => path.basename(file) === base && SOURCE_EXTENSIONS.has(path.extname(file).toLowerCase()));
        if (matchFile) { found.add(matchFile); break; }
      }
    }
  }
  return [...found].slice(0, MAX_FILES);
}

function classify(text, exitCode, timedOut = false) {
  const lower = text.toLowerCase();
  if (timedOut || /timed? ?out|timeout/.test(lower)) return { category: "timeout", confidence: "high", reason: "Verification exceeded its execution time limit." };
  if (/syntaxerror|unexpected token|unexpected identifier|missing \)/.test(lower)) return { category: "syntax-error", confidence: "high", reason: "Output contains a JavaScript/TypeScript syntax error signature." };
  if (/cannot find module|module not found|err_module_not_found|failed to resolve/.test(lower)) return { category: "module-resolution", confidence: "high", reason: "Output contains a module-resolution failure signature." };
  if (/assertionerror|assert\(|expected .* to (equal|be)|received:|actual:/.test(lower)) return { category: "assertion-failure", confidence: "medium", reason: "Output contains an assertion/test expectation failure signature." };
  if (/enoent|no such file or directory/.test(lower)) return { category: "missing-file", confidence: "high", reason: "Output contains a missing-file error signature." };
  if (/eacces|permission denied|operation not permitted/.test(lower)) return { category: "permission", confidence: "high", reason: "Output contains a filesystem permission failure signature." };
  if (/command not found|is not recognized as an internal or external command/.test(lower)) return { category: "missing-command", confidence: "high", reason: "Output indicates the verification command is unavailable." };
  if (exitCode !== 0) return { category: "nonzero-exit", confidence: "low", reason: "Verification exited non-zero without a more specific deterministic failure signature." };
  return { category: "unknown", confidence: "low", reason: "No deterministic failure category was detected." };
}

function extractLocations(text) {
  const locations = [];
  const regex = /(?:^|\s|\()([^\s()]+\.(?:js|mjs|cjs|ts|tsx|jsx)):(\d+)(?::(\d+))?/g;
  for (const match of text.matchAll(regex)) {
    locations.push({ path: normalize(match[1]), line: Number(match[2]), column: match[3] ? Number(match[3]) : null });
    if (locations.length >= MAX_FILES) break;
  }
  return locations;
}

export async function diagnoseVerificationFailure({ verification = null, failures = [] } = {}) {
  const sourceFailures = Array.isArray(failures) && failures.length ? failures : (Array.isArray(verification?.results) ? verification.results.filter(item => item?.ok === false || item?.exitCode !== 0) : []);
  const bounded = sourceFailures.slice(0, MAX_FAILURES);
  const workspace = await listWorkspaceFiles();
  const workspaceFiles = workspace.map(item => typeof item === "string" ? item : item.path).filter(Boolean);

  const diagnoses = bounded.map((failure, index) => {
    const output = outputOf(failure);
    const classification = classify(output, failure?.exitCode, failure?.timedOut);
    const locations = extractLocations(output);
    const files = [...new Set([...locations.map(item => item.path), ...extractPaths(output, workspaceFiles)])].slice(0, MAX_FILES);
    const suggestedReads = files.filter(file => workspaceFiles.includes(file)).slice(0, MAX_FILES);
    const next = [];
    if (suggestedReads.length) next.push("read-relevant-files");
    if (classification.category === "assertion-failure") next.push("inspect-test-and-source-contract");
    if (["syntax-error", "module-resolution", "missing-file"].includes(classification.category)) next.push("inspect-import-or-source-location");
    if (classification.category === "timeout") next.push("inspect-long-running-path-before-editing");
    if (classification.category === "unknown") next.push("inspect-actual-output-before-editing");
    return {
      failureIndex: index,
      checkId: failure?.id || null,
      check: failure?.label || failure?.name || null,
      category: classification.category,
      confidence: classification.confidence,
      reason: classification.reason,
      exitCode: failure?.exitCode ?? null,
      timedOut: Boolean(failure?.timedOut),
      locations,
      relevantFiles: suggestedReads,
      nextActions: next
    };
  });

  return {
    ok: true,
    analyzedFailures: diagnoses.length,
    diagnoses,
    recommendations: diagnoses.length
      ? ["Use actual verification evidence to read the relevant files before editing.", "If the cause is broad, run plan_change before making a change.", "After a safe edit, rerun the generated verification plan."]
      : ["No failed verification result was supplied; do not infer a failure cause."]
  };
}
