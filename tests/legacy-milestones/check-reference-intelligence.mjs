import assert from "node:assert/strict";
import { getProjectIndex, findReferences, findReferencesToFile } from "../../core/workspace/project-index.js";

const index = await getProjectIndex({ refresh: true });
assert.ok(index.fileCount > 0, "project index should contain files");

const symbol = await findReferences("retrieveMemories", { limit: 20, refresh: false });
assert.equal(symbol.ok, true);
assert.ok(symbol.results.some(result => result.path.endsWith("core/agent-engine/context/memory.js") || result.path.endsWith("core/agent-engine/core/agent-core.js")), "symbol references should include memory/agent-core source");
assert.ok(symbol.results.every(result => Number.isInteger(result.line) && result.line > 0), "references should include line numbers");

const file = await findReferencesToFile("core/agent-engine/context/memory.js", { limit: 20 });
assert.equal(file.ok, true);
assert.ok(file.results.some(result => result.path === "core/agent-engine/core/agent-core.js" || result.path === "core/agent-engine/context/context-intelligence.js"), "file references should resolve relative import");

console.log("PASS: symbol reference lookup");
console.log("PASS: line-numbered reference results");
console.log("PASS: relative import resolution");
console.log("Reference Intelligence: ALL TESTS PASSED");
