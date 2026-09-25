import { githubIntegration, githubToolDefinitions, executeGitHubTool } from "./github/index.js";

export const INTEGRATIONS = [githubIntegration];
export const INTEGRATION_TOOL_DEFINITIONS = [...githubToolDefinitions];

export async function executeIntegrationTool(name, input = {}) {
  return executeGitHubTool(name, input);
}

export function getIntegrationCatalog() {
  return INTEGRATIONS.map(({ name, description, status, tools }) => ({ name, description, status, tools }));
}
