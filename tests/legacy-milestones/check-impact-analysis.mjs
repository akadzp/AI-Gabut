import { getDependencyGraph, analyzeImpact } from "../../core/workspace/project-index.js";

const graph = await getDependencyGraph({ refresh: true });
if (!graph.ok || !Array.isArray(graph.edges)) throw new Error("dependency graph gagal");
if (!graph.edges.some(edge => edge.from === "core/api/server.js" && edge.to === "core/agent-engine/core/agent.js")) {
  throw new Error("expected server.js -> agent.js dependency edge tidak ditemukan");
}

const impact = await analyzeImpact("core/agent-engine/core/agent.js", { depth: 2, refresh: false });
if (!impact.ok) throw new Error("impact analysis gagal");
if (!impact.directDependents.includes("core/api/server.js")) throw new Error("server.js tidak terdeteksi sebagai dependent langsung");

const missing = await analyzeImpact("does-not-exist.js");
if (missing.ok || missing.impacted.length !== 0) throw new Error("missing target handling gagal");

console.log("Dependency graph: OK");
console.log("Impact analysis: OK");
console.log("Impact Analysis: ALL TESTS PASSED");
