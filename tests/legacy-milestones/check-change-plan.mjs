import assert from "node:assert/strict";
import { planChange } from "../../core/workspace/change-planner.js";

const result = await planChange({
  task: "ubah agent core dan cek dampak referensi serta call graph",
  paths: ["core/agent-engine/core/agent-core.js"],
  symbols: ["runAgentV2"],
  depth: 2,
  refresh: true
});

assert.equal(result.ok, true);
assert.equal(result.type, "change_plan");
assert.ok(result.targets.paths.includes("core/agent-engine/core/agent-core.js"));
assert.ok(Array.isArray(result.scope.directDependents));
assert.ok(Array.isArray(result.evidence.callEdges));
assert.ok(Array.isArray(result.readBeforeEdit));
assert.ok(result.verification.length >= 2);
assert.ok(result.notes.some(note => note.includes("tidak mengubah file")));
console.log(`Change Planning Intelligence: OK (${result.scope.relatedFiles.length} related files)`);
