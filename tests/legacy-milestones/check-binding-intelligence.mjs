import assert from "node:assert/strict";
import { resolveSymbolBinding, getCallGraph } from "../../core/workspace/binding-analysis.js";

const local = await resolveSymbolBinding("runAgent", { sourcePath: "core/agent-engine/core/agent.js" });
assert.equal(local.ok, true);
assert.ok(local.bindings.some(item => item.kind === "function" && item.path === "core/agent-engine/core/agent.js"));

const imported = await resolveSymbolBinding("runAgentV2", { sourcePath: "core/agent-engine/core/agent.js" });
assert.equal(imported.ok, true);
const importBinding = imported.bindings.find(item => item.kind === "import-binding");
assert.ok(importBinding);
assert.equal(importBinding.target?.path, "core/agent-engine/core/agent-core.js");

const graph = await getCallGraph({ sourcePath: "core/agent-engine/core/agent.js", symbol: "runAgentV2" });
assert.ok(graph.edges.some(edge => edge.from.symbol === "runAgent" && edge.to.path === "core/agent-engine/core/agent-core.js" && edge.to.symbol === "runAgentV2"));

console.log(`Binding Intelligence: OK (${imported.parser}; ${graph.parser})`);
