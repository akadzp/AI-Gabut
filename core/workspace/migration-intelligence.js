import path from "node:path";
import { listWorkspaceFiles, readWorkspaceFile } from "./manager.js";
import { searchCode } from "./project-index.js";
import { analyzeFrameworks } from "./framework-intelligence.js";
import { analyzeContracts } from "./contract-intelligence.js";
import { analyzeSchemas } from "./schema-intelligence.js";

const MAX_FILES = 80;
const MAX_RESULTS = 60;

function normalize(p) {
  return String(p || "").replaceAll(path.sep, "/");
}

function packageNameFromSpecifier(specifier) {
  const value = String(specifier || "");
  if (!value || value.startsWith(".") || value.startsWith("/") || value.startsWith("node:")) return null;
  const parts = value.split("/");
  return value.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function extractPackages(task = "") {
  const matches = String(task).match(/(?:package|dependency|library|module|framework)\s+[`'\"]?(@?[\w.-]+(?:\/[\w.-]+)?)\s+to\s+[`'\"]?(@?[\w.-]+(?:\/[\w.-]+)?)/gi) || [];
  return matches.map(item => {
    const m = item.match(/(?:package|dependency|library|module|framework)\s+[`'\"]?([^\s`'\"]+)\s+to\s+[`'\"]?([^\s`'\"]+)/i);
    return m ? { from: packageNameFromSpecifier(m[1]), to: packageNameFromSpecifier(m[2]) } : null;
  }).filter(Boolean);
}

function detectMigrationKeywords(task = "") {
  const text = String(task).toLowerCase();
  const kinds = [];
  if (/migrat|upgrade|downgrade|major version|breaking change/.test(text)) kinds.push("dependency-version-migration");
  if (/replace|switch|move from|adopt/.test(text)) kinds.push("library-replacement");
  if (/api|endpoint|route|contract/.test(text)) kinds.push("api-contract-migration");
  if (/schema|type|interface|validation/.test(text)) kinds.push("schema-type-migration");
  if (/config|configuration/.test(text)) kinds.push("configuration-migration");
  return kinds.length ? kinds : ["general-migration"];
}

async function readPackageManifests(entries) {
  const manifests = [];
  for (const entry of entries.filter(e => e.type === "file" && path.basename(e.path) === "package.json").slice(0, 10)) {
    try {
      const result = await readWorkspaceFile(entry.path);
      manifests.push({ path: normalize(entry.path), package: JSON.parse(result.content) });
    } catch {
      // Best effort.
    }
  }
  return manifests;
}

function dependencyEvidence(manifests, packages) {
  const evidence = [];
  for (const { path: file, package: pkg } of manifests) {
    const groups = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
    for (const group of groups) {
      for (const [name, version] of Object.entries(pkg[group] || {})) {
        if (!packages.length || packages.includes(name)) evidence.push({ file, group, name, version });
      }
    }
  }
  return evidence;
}

function inferAffectedFiles({ searchResults = [], frameworkResult, contractResult, schemaResult, entries }) {
  const paths = new Set();
  for (const result of searchResults) if (result?.path) paths.add(normalize(result.path));
  for (const item of frameworkResult?.configFiles || []) if (item.path) paths.add(normalize(item.path));
  for (const item of contractResult?.endpoints || []) if (item.path) paths.add(normalize(item.path));
  for (const item of contractResult?.exports || []) if (item.path) paths.add(normalize(item.path));
  for (const item of schemaResult?.schemas || []) if (item.path) paths.add(normalize(item.path));
  return [...paths].slice(0, MAX_RESULTS).concat(
    entries.filter(e => e.type === "file" && /(^|\/)(package\.json|.*config\.(?:js|mjs|cjs|ts)|tsconfig\.json)$/.test(normalize(e.path)))
      .map(e => normalize(e.path))
      .filter(p => !paths.has(p))
      .slice(0, 20)
  ).slice(0, MAX_RESULTS);
}

export async function planMigration({ task, paths = [], packages = [], limit = 40 } = {}) {
  const entries = await listWorkspaceFiles();
  const manifests = await readPackageManifests(entries);
  const requestedPackages = [...new Set([...(Array.isArray(packages) ? packages : []), ...extractPackages(task).flatMap(item => [item.from, item.to]).filter(Boolean)])];
  const dependencyEvidenceResult = dependencyEvidence(manifests, requestedPackages);
  const selectedPaths = Array.isArray(paths) ? paths.map(normalize).filter(Boolean) : [];
  const sourcePaths = selectedPaths.length
    ? selectedPaths
    : entries.filter(e => e.type === "file").map(e => normalize(e.path));
  const frameworkResult = await analyzeFrameworks({ paths: selectedPaths, limit: 30 });
  const contractResult = await analyzeContracts({ paths: sourcePaths, limit: 40 });
  const schemaResult = await analyzeSchemas({ paths: sourcePaths, limit: 40 });

  const searchQueries = requestedPackages.flatMap(name => name ? [name, `${name}/`] : []);
  const searchResults = [];
  for (const query of searchQueries.slice(0, 8)) {
    const result = await searchCode(query, { limit: 12, refresh: false, caseSensitive: false, regex: false });
    searchResults.push(...(result?.results || []));
  }

  const migrationKinds = detectMigrationKeywords(task);
  const affectedFiles = inferAffectedFiles({ searchResults, frameworkResult, contractResult, schemaResult, entries });
  const targetPaths = Array.isArray(paths) ? paths.map(normalize).filter(Boolean) : [];
  const readBeforeEdit = [...new Set([
    ...targetPaths,
    ...affectedFiles,
    ...dependencyEvidenceResult.map(item => item.file)
  ])].slice(0, Math.max(1, Math.min(Number(limit) || 40, 40)));

  const packageChanges = extractPackages(task);
  const blockers = [];
  const warnings = [];
  if (!requestedPackages.length && migrationKinds.includes("dependency-version-migration")) {
    warnings.push("No explicit package name was found in the migration request; inspect package.json before editing.");
  }
  if (requestedPackages.some(name => !dependencyEvidenceResult.some(item => item.name === name))) {
    warnings.push("One or more requested packages were not found in the inspected package manifests.");
  }
  if ((contractResult?.endpoints?.length || 0) > 0) warnings.push("API routes were detected; migration may require contract compatibility verification.");
  if ((schemaResult?.schemas?.length || 0) > 0) warnings.push("Schemas/types were detected; migration may require type and validation verification.");
  if ((frameworkResult?.frameworks?.length || 0) > 0) warnings.push("Framework conventions were detected; inspect framework-specific configuration before broad edits.");
  if (!affectedFiles.length) blockers.push("No affected source/config evidence was discovered; inspect the target explicitly before editing.");

  const verification = [
    "Re-run syntax/type checks relevant to changed source files.",
    "Run targeted tests identified by Test Intelligence after edits.",
    "Verify API/module contracts if routes or exports changed.",
    "Verify schemas/types if validation or type definitions changed.",
    "Review Git changes before any commit or push."
  ];

  return {
    ok: true,
    task: String(task || ""),
    migrationKinds,
    packageChanges,
    requestedPackages,
    dependencyEvidence: dependencyEvidenceResult.slice(0, MAX_RESULTS),
    affectedFiles,
    readBeforeEdit,
    blockers,
    warnings: [...new Set(warnings)].slice(0, 20),
    verification,
    evidence: {
      frameworks: frameworkResult?.frameworks || [],
      contracts: {
        routes: contractResult?.endpoints?.length || 0,
        exports: contractResult?.exports?.length || 0,
        imports: contractResult?.imports?.length || 0
      },
      schemas: schemaResult?.counts || {},
      sourceMatches: searchResults.slice(0, MAX_RESULTS)
    },
    limitations: [
      "Migration planning is static and evidence-based; it does not infer undocumented upstream breaking changes.",
      "It does not query package registries or external migration guides.",
      "Dynamic imports, generated code, runtime configuration, and undocumented behavior may be missed.",
      "The planner does not edit files or execute verification commands."
    ]
  };
}
