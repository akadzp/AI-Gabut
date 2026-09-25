import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { listWorkspaceFiles, readWorkspaceFile } from "./manager.js";
import { WORKSPACE_ROOT } from "../linux/terminal/workspace.js";

const execFileAsync = promisify(execFile);
const MAX_FILES = 300;
const MAX_TESTS = 80;
const TEST_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);

function normalize(p) { return p.replace(/\\/g, "/"); }
function rel(abs) { return normalize(path.relative(WORKSPACE_ROOT, abs)); }
function isTestPath(p) {
  const n = normalize(p).toLowerCase();
  const base = path.basename(n);
  return /(^|[/_.-])(test|spec)([/_.-]|$)/.test(n) || base.includes("__tests__");
}
function sourceStem(p) {
  return path.basename(p).replace(/\.(test|spec)\.[^.]+$/i, "").replace(/\.[^.]+$/i, "");
}
function candidateTestForSource(source, test) {
  const s = sourceStem(source).toLowerCase();
  const t = sourceStem(test).toLowerCase();
  return s && t && (s === t || t.includes(s) || s.includes(t));
}

async function packageScripts() {
  try {
    const raw = await readWorkspaceFile("package.json");
    const pkg = JSON.parse(raw.content);
    return pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts : {};
  } catch { return {}; }
}

async function gitChangedFiles() {
  try {
    const { stdout } = await execFileAsync("git", ["status", "--short"], { cwd: WORKSPACE_ROOT, timeout: 5000, maxBuffer: 1024 * 1024 });
    return stdout.split(/\r?\n/).filter(Boolean).map(line => line.slice(3).trim()).filter(Boolean);
  } catch { return []; }
}

export async function analyzeTestIntelligence({ paths = [], includeGit = true, refresh = false } = {}) {
  const all = await listWorkspaceFiles();
  const files = all.map(item => typeof item === "string" ? item : item.path).filter(Boolean).slice(0, MAX_FILES);
  const testFiles = files.filter(isTestPath).filter(p => TEST_EXTENSIONS.has(path.extname(p).toLowerCase())).slice(0, MAX_TESTS);
  const explicit = Array.isArray(paths) ? paths.filter(Boolean) : [];
  const changed = includeGit ? await gitChangedFiles() : [];
  const targets = [...new Set([...explicit, ...changed])].filter(Boolean);
  const scripts = await packageScripts();

  const related = [];
  for (const source of targets) {
    const matches = testFiles.filter(test => candidateTestForSource(source, test)).slice(0, 10);
    for (const test of matches) related.push({ source, test, reason: "filename-convention" });
  }

  const importMatches = [];
  for (const test of testFiles.slice(0, 40)) {
    try {
      const raw = await readWorkspaceFile(test);
      for (const source of targets) {
        const normalizedSource = normalize(source).replace(/\.[^.]+$/, "");
        const sourceBase = path.basename(normalizedSource);
        if (sourceBase && raw.content.includes(sourceBase)) importMatches.push({ source, test, reason: "source-name-reference" });
      }
    } catch {}
  }

  const uniqueRelated = [...new Map([...related, ...importMatches].map(item => [`${item.source}::${item.test}`, item])).values()];
  const verificationScripts = Object.keys(scripts).filter(name => /test|check|lint|type|verify/i.test(name));

  return {
    ok: true,
    targets,
    testFiles,
    relatedTests: uniqueRelated,
    scripts: verificationScripts.map(name => ({ name, command: scripts[name] })),
    recommendations: [
      ...(uniqueRelated.length ? [{ type: "targeted-tests", reason: "Run tests related to changed source files first." }] : []),
      ...(verificationScripts.length ? [{ type: "project-checks", reason: "Project-level test/check scripts are available." }] : []),
      ...(!uniqueRelated.length && !verificationScripts.length ? [{ type: "manual-verification", reason: "No deterministic test mapping or project verification script was detected." }] : [])
    ]
  };
}
