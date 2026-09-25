import assert from "node:assert/strict";
import { understandTask } from "../../core/agent-engine/reasoning/task-understanding.js";

const result = understandTask({
  prompt: "Tolong perbaiki auth di backend/auth.js dan jangan ubah API. Jangan commit atau push.",
  conversation: [{ role: "user", content: "Project ini Express." }]
});

assert.equal(result.ok, true);
assert.equal(result.taskType, "modification");
assert.ok(result.actions.includes("edit"));
assert.ok(result.targets.files.includes("backend/auth.js"));
assert.ok(result.constraints.includes("no-commit-or-push"));
assert.ok(result.constraints.includes("preserve-api"));
assert.equal(result.confidence, "high");

const ambiguous = understandTask({ prompt: "tolong perbaiki ini" });
assert.ok(ambiguous.ambiguity.length > 0);
assert.equal(ambiguous.confidence, "partial");

console.log("Task Understanding: OK");
