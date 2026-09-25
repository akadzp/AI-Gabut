import path from "node:path";
import { listWorkspaceFiles, readWorkspaceFile } from "./manager.js";

const MAX_FILES = 80;
const FRAMEWORKS = [
  { name: "Next.js", packageNames: ["next"], configs: ["next.config.js", "next.config.mjs", "next.config.ts"] },
  { name: "Nuxt", packageNames: ["nuxt"], configs: ["nuxt.config.ts", "nuxt.config.js"] },
  { name: "React", packageNames: ["react"], configs: [] },
  { name: "Vue", packageNames: ["vue"], configs: ["vite.config.js", "vite.config.ts"] },
  { name: "Angular", packageNames: ["@angular/core"], configs: ["angular.json"] },
  { name: "SvelteKit", packageNames: ["@sveltejs/kit"], configs: ["svelte.config.js", "svelte.config.ts"] },
  { name: "Svelte", packageNames: ["svelte"], configs: ["svelte.config.js", "svelte.config.ts"] },
  { name: "Express", packageNames: ["express"], configs: [] },
  { name: "Fastify", packageNames: ["fastify"], configs: [] },
  { name: "NestJS", packageNames: ["@nestjs/core"], configs: ["nest-cli.json"] },
  { name: "Hono", packageNames: ["hono"], configs: [] },
  { name: "Vite", packageNames: ["vite"], configs: ["vite.config.js", "vite.config.mjs", "vite.config.ts"] },
  { name: "Astro", packageNames: ["astro"], configs: ["astro.config.js", "astro.config.mjs", "astro.config.ts"] },
  { name: "Remix", packageNames: ["@remix-run/node", "@remix-run/react"], configs: ["vite.config.js", "vite.config.ts"] }
];

function normalize(p) { return String(p).replaceAll(path.sep, "/"); }

function packageFiles(entries) {
  return entries.filter(e => e.type === "file" && (e.path === "package.json" || e.path.endsWith("/package.json"))).slice(0, 10);
}

function detectFromPackage(pkg, file) {
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}) };
  const found = [];
  for (const framework of FRAMEWORKS) {
    const packages = framework.packageNames.filter(name => deps[name]);
    if (packages.length) found.push({ name: framework.name, evidence: [{ type: "package", file, packages }] });
  }
  return found;
}

export async function analyzeFrameworks({ paths = [], limit = 30 } = {}) {
  const entries = await listWorkspaceFiles();
  const selected = Array.isArray(paths) && paths.length
    ? entries.filter(e => paths.includes(e.path))
    : entries;
  const packageCandidates = packageFiles(selected.length ? selected : entries);
  const frameworks = new Map();
  const configFiles = [];
  const conventions = [];
  const scannedFiles = [];

  for (const entry of packageCandidates) {
    try {
      const content = await readWorkspaceFile(entry.path);
      const pkg = JSON.parse(content.content);
      for (const detected of detectFromPackage(pkg, entry.path)) {
        const existing = frameworks.get(detected.name) || { name: detected.name, evidence: [] };
        existing.evidence.push(...detected.evidence);
        frameworks.set(detected.name, existing);
      }
      scannedFiles.push(entry.path);
    } catch {
      // Best effort; malformed or inaccessible package manifests are ignored.
    }
  }

  const pathsToInspect = (selected.length ? selected : entries).filter(e => e.type === "file").slice(0, MAX_FILES);
  for (const entry of pathsToInspect) {
    const file = normalize(entry.path);
    const base = path.basename(file);
    for (const framework of FRAMEWORKS) {
      if (framework.configs.includes(base)) {
        configFiles.push({ framework: framework.name, path: file, evidence: "recognized framework configuration filename" });
        const existing = frameworks.get(framework.name) || { name: framework.name, evidence: [] };
        existing.evidence.push({ type: "config", file });
        frameworks.set(framework.name, existing);
      }
    }

    const lower = file.toLowerCase();
    if (/(^|\/)pages\//.test(lower) || /(^|\/)app\//.test(lower)) conventions.push({ path: file, convention: "application/page directory" });
    if (/(^|\/)routes?\//.test(lower)) conventions.push({ path: file, convention: "route directory" });
    if (/(^|\/)components?\//.test(lower)) conventions.push({ path: file, convention: "component directory" });
  }

  const results = [...frameworks.values()].map(item => ({ ...item, evidence: item.evidence.slice(0, 10) }));
  return {
    ok: true,
    frameworks: results.slice(0, Math.max(1, Math.min(Number(limit) || 30, 30))),
    configFiles: configFiles.slice(0, 50),
    conventions: conventions.slice(0, 50),
    scannedFiles,
    counts: { frameworks: results.length, configFiles: configFiles.length, conventions: conventions.length },
    limitations: [
      "Framework detection is static and evidence-based.",
      "A dependency or config filename does not prove how the framework is used at runtime.",
      "Custom framework wrappers, generated files, and unusual project layouts may not be detected."
    ]
  };
}
