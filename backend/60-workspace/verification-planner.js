import path from "node:path";
import { readWorkspaceFile } from "./manager.js";
import { gitChanges } from "../40-linux/git/manager.js";

const MAX_CHECKS = 12;
const MAX_FILES = 40;

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function changedFiles(git) {
  if (!git?.ok) return [];
  return unique([
    ...(git.files?.staged || []),
    ...(git.files?.unstaged || []),
    ...(git.files?.untracked || [])
  ]).slice(0, MAX_FILES);
}

function packageScriptChecks(scripts, files) {
  const entries = Object.entries(scripts || {});
  const checks = [];
  const sourceChanged = files.some(file => /\.(js|mjs|cjs|ts|tsx|jsx)$/.test(file));
  const testRelated = files.some(file => /(^|[/_.-])(test|tests|spec|__tests__)([/_.-]|$)/i.test(file));

  const preferredNames = testRelated
    ? ["test", "check", "test:unit", "test:integration"]
    : ["check", "lint", "typecheck", "test"];

  for (const name of preferredNames) {
    if (!scripts[name]) continue;
    checks.push({
      id: `npm-${name}`,
      type: "package-script",
      command: `npm run ${name}`,
      reason: testRelated ? "Perubahan menyentuh file test/spec atau area pengujian." : `Script '${name}' tersedia dan relevan untuk verifikasi project.`,
      confidence: name === "check" ? "high" : name === "test" ? "medium" : "medium"
    });
  }

  if (sourceChanged) {
    for (const [name, command] of entries) {
      if (!/^(check|lint|typecheck|test)(:|$)/i.test(name)) continue;
      if (checks.some(item => item.id === `npm-${name}`)) continue;
      checks.push({
        id: `npm-${name}`,
        type: "package-script",
        command: `npm run ${name}`,
        reason: `Script '${name}' cocok untuk perubahan source code.`,
        confidence: "medium"
      });
    }
  }

  return checks;
}

function syntaxChecks(files) {
  return files
    .filter(file => /\.(js|mjs|cjs)$/.test(file))
    .slice(0, 8)
    .map(file => ({
      id: `syntax-${file}`,
      type: "syntax",
      command: `node --check ${file}`,
      reason: "File JavaScript berubah dan dapat diverifikasi tanpa menjalankan aplikasi.",
      confidence: "high",
      path: file
    }));
}

function structuralChecks(files) {
  const checks = [];
  if (files.some(file => file === "package.json")) {
    checks.push({
      id: "package-json",
      type: "metadata",
      command: "node -e \"JSON.parse(require('fs').readFileSync('package.json','utf8')); console.log('package.json: OK')\"",
      reason: "package.json berubah dan perlu diverifikasi sebagai JSON valid.",
      confidence: "high",
      path: "package.json"
    });
  }
  return checks;
}

export async function planVerification({ paths = [], includeGit = true } = {}) {
  const git = includeGit ? await gitChanges() : { ok: false };
  const files = unique([
    ...paths.map(value => String(value || "").trim().replaceAll("\\", "/")),
    ...changedFiles(git)
  ]).slice(0, MAX_FILES);

  let packageJson = null;
  try {
    packageJson = JSON.parse((await readWorkspaceFile("package.json")).content);
  } catch {
    packageJson = null;
  }

  const checks = [
    ...syntaxChecks(files),
    ...structuralChecks(files),
    ...(packageJson ? packageScriptChecks(packageJson.scripts, files) : [])
  ];

  const deduped = [];
  const seen = new Set();
  for (const check of checks) {
    if (seen.has(check.id)) continue;
    seen.add(check.id);
    deduped.push(check);
  }

  const bounded = deduped.slice(0, MAX_CHECKS);
  const warnings = [];
  if (!files.length) warnings.push("Tidak ada file perubahan yang terdeteksi; berikan paths atau buat perubahan terlebih dahulu.");
  if (!packageJson) warnings.push("package.json tidak dapat dibaca/di-parse; package scripts tidak dapat dipetakan.");
  if (deduped.length > MAX_CHECKS) warnings.push(`Daftar verifikasi dibatasi menjadi ${MAX_CHECKS} pemeriksaan.`);

  return {
    ok: true,
    type: "verification_plan",
    generatedAt: new Date().toISOString(),
    files,
    git: git.ok ? {
      branch: git.branch,
      staged: git.files.staged,
      unstaged: git.files.unstaged,
      untracked: git.files.untracked
    } : { ok: false, error: git.error },
    packageScripts: packageJson ? Object.keys(packageJson.scripts || {}) : [],
    checks: bounded,
    warnings,
    execution: {
      performed: false,
      note: "Ini adalah rencana verifikasi. Command belum dijalankan oleh tool ini."
    }
  };
}
