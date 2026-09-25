import { CAPABILITY_TOOL_DEFINITIONS, executeCapabilityTool } from "../tools/catalog.js";
import { INTEGRATION_TOOL_DEFINITIONS, executeIntegrationTool, getIntegrationCatalog } from "../../../connectors/registry.js";
import { TOOL_INTELLIGENCE_CAPABILITIES } from "./tool-intelligence.js";
import { authorizeTool, auditEvent } from "../../security/governance/policy.js";

export const TOOL_DEFINITIONS = [...CAPABILITY_TOOL_DEFINITIONS, ...INTEGRATION_TOOL_DEFINITIONS];

export const TOOL_INTELLIGENCE = TOOL_INTELLIGENCE_CAPABILITIES;

export const TOOL_CATALOG = {
  capabilities: CAPABILITY_TOOL_DEFINITIONS,
  integrations: INTEGRATION_TOOL_DEFINITIONS,
  integrationCatalog: getIntegrationCatalog()
};

export async function executeTool(name, input = {}, governance = {}) {
  const definition = TOOL_DEFINITIONS.find(tool => tool.name === name) || null;
  const authorization = authorizeTool({ tool: name, input, definition, sessionId: governance.sessionId, approvalToken: governance.approvalToken });
  if (!authorization.ok) return authorization;

  auditEvent({ actor: "agent", action: "tool-execute-start", tool: name, input, outcome: "started" });
  if (CAPABILITY_TOOL_DEFINITIONS.some(tool => tool.name === name)) {
    const result = await executeCapabilityTool(name, input, governance);
    auditEvent({ actor: "agent", action: "tool-execute-end", tool: name, input, outcome: result?.ok === false ? "error" : "completed" });
    return result;
  }

  if (INTEGRATION_TOOL_DEFINITIONS.some(tool => tool.name === name)) {
    const result = await executeIntegrationTool(name, input);
    auditEvent({ actor: "agent", action: "tool-execute-end", tool: name, input, outcome: result?.ok === false ? "error" : "completed" });
    return result;
  }

  throw new Error(`Tool tidak dikenal: ${name}`);
}
