export const githubIntegration = {
  name: "github",
  description: "GitHub-hosted repository, issue, pull-request, and remote collaboration operations.",
  status: "scaffold",
  tools: [],
  note: "GitHub API tools are intentionally not implemented in M7.7; local Git remains a version-control capability."
};

export const githubToolDefinitions = [];

export async function executeGitHubTool(name) {
  throw new Error(`GitHub integration tool '${name}' is not registered`);
}
