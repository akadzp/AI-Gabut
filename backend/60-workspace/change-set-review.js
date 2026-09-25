import path from "node:path";
import { gitChanges } from "../40-linux/git/manager.js";
import { readWorkspaceFile } from "./manager.js";
import { analyzeImpact } from "./project-index.js";
import { analyzeContracts } from "./contract-intelligence.js";
import { analyzeSchemas } from "./schema-intelligence.js";
import { analyzeFrameworks } from "./framework-intelligence.js";

const MAX_FILES = 60;
const MAX_DIFF_CHARS = 160_000;

function normalize(value) {
  return String(value || "").replaceAll(path.sep, "/");
}

function diffStats(text = "") {
  const lines = String(text).split(/\r?\n/);
  let additions = 0;
  let deletions = 0;
  const hunks = [];
  for (const line of lines) {
    if (line.startsWith("@@")) hunks.push(line.slice(0, 200));
    else if (line.startsWith("+++") || line.startsWith("---")) continue;
    else if (line.startsWith("+")) additions += 1;
    else if (line.startsWith("-")) deletions += 1;
  }
  return { additions, deletions, hunks: hunks.length };
}

function changedPaths(changes) {
  return [...new Set([
    ...(changes.files?.staged || []),
    ...(changes.files?.unstaged || []),
    ...(changes.files?.untracked || [])
  ].map(normalize))].filter(Boolean).slice(0, MAX_FILES);
}

function riskForFile(file) {
  const lower = file.toLowerCase();
  const risks = [];
  if (lower === "package.json" || lower.endsWith("/package.json")) risks.push("dependency-or-script-change");
  if (/(^|\/)(server|app|router|routes?|controller|api)\.[^.]+$/.test(lower)) risks.push("api-or-runtime-boundary");
  if (/schema|model|migration|validation|type/.test(lower)) risks.push("schema-or-type-contract");
  if (/config|\.env|tsconfig|vite|webpack|babel|eslint|prettier/.test(lower)) risks.push("configuration");
  if (/test|spec/.test(lower)) risks.push("test-suite");
  if (/auth|permission|security|secret/.test(lower)) risks.push("security-sensitive");
  return risks;
}

function diffRiskSignals(diffText) {
  const text = String(diffText || "");
  const risks = [];
  if (/\b(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(/.test(text)) risks.push("api-route-change");
  if (/\b(?:export|module\.exports)\b/.test(text)) risks.push("module-contract-change");
  if (/\b(?:interface|type)\s+[A-Za-z_$]/.test(text) || /\b(?:z|Joi|yup)\./.test(text)) risks.push("schema-or-type-change");
  if (/\b(?:import|require)\s*\(?["']/.test(text)) risks.push("dependency-import-change");
  if (/\b(?:password|token|secret|authorization|permission|role)\b/i.test(text)) risks.push("security-sensitive-change");
  if (/\b(?:process\.env|config)\b/.test(text)) risks.push("configuration-change");
  return risks;
}

async function inspectUntracked(paths) {
  const results = [];
  for (const file of paths.slice(0, 30)) {
    try {
      const content = await readWorkspaceFile(file);
      results.push({ path: file, sizeBytes: Buffer.byteLength(content.content || "", "utf8"), lines: String(content.content || "").split(/\r?\n/).length });
    } catch {
      results.push({ path: file, readable: false });
    }
  }
  return results;
}

export async function reviewChangeSet({ paths = [], includeGit = true, depth = 2, limit = 40 } = {}) {
  let gitWarning = null;
  let changes = includeGit ? await gitChanges() : { ok: true, branch: null, files: { staged: [], unstaged: [], untracked: [] }, stagedDiff: "", unstagedDiff: "" };
  if (!changes.ok) {
    gitWarning = changes.error || "Git changes gagal dibaca";
    changes = { ok: true, branch: null, files: { staged: [], unstaged: [], untracked: [] }, stagedDiff: "", unstagedDiff: "" };
  }

  const requested = Array.isArray(paths) ? paths.map(normalize).filter(Boolean) : [];
  const allPaths = requested.length ? requested : changedPaths(changes);
  const staged = String(changes.stagedDiff || "").slice(0, MAX_DIFF_CHARS);
  const unstaged = String(changes.unstagedDiff || "").slice(0, MAX_DIFF_CHARS);
  const combinedDiff = `${staged}\n${unstaged}`;
  const stats = diffStats(combinedDiff);
  const untracked = (changes.files?.untracked || []).map(normalize);
  const selectedUntracked = requested.length ? untracked.filter(file => requested.includes(file)) : untracked;

  const fileReviews = [];
  for (const file of allPaths.slice(0, Math.min(MAX_FILES, Number(limit) || 40))) {
    let impact = null;
    try {
      impact = await analyzeImpact(file, { depth: Math.max(1, Math.min(Number(depth) || 2, 4)), refresh: false });
    } catch {
      impact = null;
    }
    fileReviews.push({
      path: file,
      state: changes.files?.staged?.includes(file) ? "staged" : changes.files?.unstaged?.includes(file) ? "unstaged" : changes.files?.untracked?.includes(file) ? "untracked" : "selected",
      risks: riskForFile(file),
      affectedFiles: impact?.affectedFiles || [],
      impactDepth: impact?.depth ?? null
    });
  }

  const contractResult = await analyzeContracts({ paths: allPaths, limit: 30 });
  const schemaResult = await analyzeSchemas({ paths: allPaths, limit: 30 });
  const frameworkResult = await analyzeFrameworks({ paths: allPaths, limit: 20 });
  const riskSignals = [...new Set([
    ...fileReviews.flatMap(item => item.risks),
    ...diffRiskSignals(combinedDiff)
  ])];

  const findings = [];
  if (gitWarning) findings.push({ severity: "warning", code: "git-unavailable", message: "Git state could not be read; review is limited to explicitly selected paths or workspace evidence." });
  if (!allPaths.length) findings.push({ severity: "info", code: "no-changes", message: "No changed or untracked files were found in the selected scope." });
  if (stats.additions + stats.deletions > 500) findings.push({ severity: "warning", code: "large-change-set", message: "The change set is large; review it in smaller logical groups if possible." });
  if (selectedUntracked.length) findings.push({ severity: "warning", code: "untracked-files", message: "Untracked files are part of the workspace state and are not visible in git diff until staged." });
  if (riskSignals.includes("security-sensitive-change")) findings.push({ severity: "warning", code: "security-sensitive", message: "Security-sensitive terms or files were detected; perform focused review and verification before commit." });
  if (riskSignals.includes("api-route-change") || (contractResult?.counts?.endpoints || 0) > 0) findings.push({ severity: "warning", code: "api-contract", message: "API route/contract evidence is present; verify affected endpoints and consumers." });
  if (riskSignals.includes("schema-or-type-change") || (schemaResult?.counts?.schemas || 0) > 0) findings.push({ severity: "warning", code: "schema-contract", message: "Type/schema evidence is present; verify validation and type consumers." });
  if (riskSignals.includes("configuration-change")) findings.push({ severity: "warning", code: "configuration", message: "Configuration changes were detected; verify environment-specific behavior." });

  const affectedFiles = [...new Set(fileReviews.flatMap(item => item.affectedFiles || []))].slice(0, 80);
  const reviewBeforeCommit = [
    "Inspect the actual diff for every changed file.",
    ...(selectedUntracked.length ? ["Inspect untracked files explicitly; git diff does not include them."] : []),
    ...(affectedFiles.length ? ["Review affected dependent files before committing."] : []),
    ...(contractResult?.counts?.endpoints ? ["Verify API contract behavior for changed routes."] : []),
    ...(schemaResult?.counts?.schemas ? ["Verify schema/type consumers and validation behavior."] : []),
    ...(riskSignals.includes("security-sensitive-change") ? ["Perform focused security review before commit."] : []),
    "Run the verification plan and review the final Git state before commit or push."
  ];

  return {
    ok: true,
    branch: changes.branch,
    scope: allPaths,
    summary: {
      files: allPaths.length,
      staged: changes.files?.staged?.length || 0,
      unstaged: changes.files?.unstaged?.length || 0,
      untracked: changes.files?.untracked?.length || 0,
      additions: stats.additions,
      deletions: stats.deletions,
      hunks: stats.hunks
    },
    files: fileReviews,
    affectedFiles,
    risks: riskSignals,
    findings,
    evidence: {
      contracts: contractResult?.counts || {},
      schemas: schemaResult?.counts || {},
      frameworks: frameworkResult?.frameworks || [],
      diffStats: stats,
      untracked: await inspectUntracked(selectedUntracked)
    },
    reviewBeforeCommit,
    gitWarning,
    limitations: [
      "Review is static and evidence-based; it does not judge business correctness.",
      "Untracked files are inspected separately because git diff does not include them.",
      "Dynamic behavior, generated code, and runtime-only contracts may be missed.",
      "This tool is read-only and does not stage, commit, push, edit, or execute verification commands."
    ]
  };
}
