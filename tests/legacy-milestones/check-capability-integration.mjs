import assert from "node:assert/strict";
import { CAPABILITY_GROUPS, CAPABILITY_TOOL_DEFINITIONS } from "../../core/agent-engine/tools/catalog.js";
import { TOOL_DEFINITIONS, TOOL_CATALOG } from "../../core/agent-engine/core/tool-registry.js";
import { getIntegrationCatalog } from "../../connectors/registry.js";

assert.ok(CAPABILITY_GROUPS.coding.tools.includes("plan_change"));
assert.ok(CAPABILITY_GROUPS.version_control.tools.includes("git_status"));
assert.equal(CAPABILITY_TOOL_DEFINITIONS.some(tool => tool.name === "github"), false);
assert.equal(TOOL_DEFINITIONS.filter(tool => tool.name === "git_status").length, 1);
assert.deepEqual(TOOL_CATALOG.integrations, []);
const integrations = getIntegrationCatalog();
assert.equal(integrations.length, 1);
assert.equal(integrations[0].name, "github");
assert.equal(integrations[0].status, "scaffold");
console.log("Capability / Integration Architecture: OK");
