import assert from "node:assert/strict";
import { TOOL_DEFINITIONS } from "../../core/agent-engine/core/tool-registry.js";
import {
  discoverTools,
  selectTool,
  normalizeToolInput,
  validateToolCall,
  buildToolChain,
  interpretToolResult,
  buildToolIntelligence,
  TOOL_INTELLIGENCE_CAPABILITIES
} from "../../core/agent-engine/core/tool-intelligence.js";

const planning = discoverTools({ query: "ubah API lalu test dan review git", definitions: TOOL_DEFINITIONS });
assert.ok(planning.length > 0);
assert.ok(planning.some(item => item.name === "plan_change"));
assert.ok(planning.some(item => item.name === "plan_verification"));

const selected = selectTool({ query: "fix bug dan verifikasi", definitions: TOOL_DEFINITIONS });
assert.ok(selected.some(item => item.name === "execute_verification"));

const normalized = normalizeToolInput("read_file", { path: " core/api/server.js " });
assert.equal(normalized.path, "core/api/server.js");
assert.equal(validateToolCall({ name: "read_file", input: normalized, definitions: TOOL_DEFINITIONS }).ok, true);
assert.equal(validateToolCall({ name: "git_commit", input: { message: "test" }, definitions: TOOL_DEFINITIONS }).ok, false);
assert.equal(validateToolCall({ name: "git_commit", input: { message: "test", approved: true }, definitions: TOOL_DEFINITIONS }).ok, true);

const chain = buildToolChain({ query: "edit source lalu test", selectedTools: selected });
assert.ok(chain.length > 0);
assert.ok(chain.some(item => item.tool === "plan_change"));

const failure = interpretToolResult({ name: "edit_file", result: { ok: false, error: "stale file hash conflict" } });
assert.equal(failure.ok, false);
assert.equal(failure.recovery.action, "refresh_file");

const intelligence = buildToolIntelligence({ query: "review git changes", definitions: TOOL_DEFINITIONS });
assert.ok(intelligence.discovered.length > 0);
assert.ok(intelligence.selected.length > 0);
assert.ok(TOOL_INTELLIGENCE_CAPABILITIES.includes("tool_failure_handling"));

console.log("R4 TOOL INTELLIGENCE CHECK PASSED");
