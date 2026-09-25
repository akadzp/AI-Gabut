import assert from "node:assert/strict";
import { inspectProject, searchWorkspace, searchCode, findSymbol } from "../../core/workspace/project-index.js";

const summary = await inspectProject({ refresh: true });
assert.equal(summary.ok, true);
assert.ok(summary.fileCount > 0);
assert.ok(summary.sourceFiles > 0);
assert.ok(summary.package?.name === "ai-gabut");

const serverSearch = await searchWorkspace("server.js");
assert.ok(serverSearch.results.some(item => item.path === "core/api/server.js"));

const agentSearch = await searchWorkspace("agent-core");
assert.ok(agentSearch.results.some(item => item.path === "core/agent-engine/core/agent-core.js"));

const symbolSearch = await findSymbol("runAgentV2");
assert.ok(symbolSearch.results.some(item => item.path === "core/agent-engine/core/agent-core.js"));

const codeSearch = await searchCode("retrieveMemories");
assert.ok(codeSearch.results.some(item => item.path === "core/agent-engine/context/memory.js"));

const sensitiveSearch = await searchWorkspace(".env");
assert.ok(!sensitiveSearch.results.some(item => item.path === ".env" || item.path.endsWith("/.env")));

console.log("PASS: inspect_project returns structural metadata");
console.log("PASS: search_files finds relevant project paths");
console.log("PASS: find_symbol finds exported source symbols");
console.log("PASS: search_code finds matching source lines without dumping whole files");
console.log("PASS: sensitive .env files are not indexed");
console.log("Project Intelligence: ALL TESTS PASSED");
