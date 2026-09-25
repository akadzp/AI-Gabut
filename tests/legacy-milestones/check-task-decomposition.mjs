import assert from "node:assert/strict";
import { decomposeTask } from "../../core/agent-engine/reasoning/task-decomposition.js";

const result = decomposeTask({
  prompt: "Perbaiki auth di backend/auth.js, pertahankan API, lalu jalankan test. Jangan commit.",
  understanding: {
    taskType: "modification",
    goal: "Perbaiki auth di backend/auth.js, pertahankan API, lalu jalankan test. Jangan commit.",
    actions: ["edit", "test"],
    targets: { files: ["backend/auth.js"] },
    constraints: ["preserve-api", "no-commit-or-push"],
    ambiguity: []
  },
  conversation: [{ role: "user", content: "auth" }]
});

assert.equal(result.ok, true);
assert.ok(result.steps.some(item => item.id === "inspect"));
assert.ok(result.steps.some(item => item.id === "impact"));
assert.ok(result.steps.some(item => item.id === "plan-change"));
assert.ok(result.steps.some(item => item.id === "edit"));
assert.ok(result.steps.some(item => item.id === "verify"));
assert.ok(result.steps.some(item => item.id === "recover"));
assert.equal(result.executionPolicy.noArbitraryCommands, true);
assert.equal(result.executionPolicy.safeEditRequiredForExistingFiles, true);

const readOnly = decomposeTask({
  prompt: "Jelaskan struktur project ini.",
  understanding: { taskType: "analysis", actions: ["inspect"], targets: { files: [] }, constraints: [], ambiguity: [] }
});
assert.ok(!readOnly.steps.some(item => item.id === "edit"));
assert.ok(!readOnly.steps.some(item => item.id === "verify"));

console.log("Task Decomposition: OK");
