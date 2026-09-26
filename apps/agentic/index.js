export const AGENTIC_APP = Object.freeze({
  id: "agentic",
  name: "Agentic",
  version: "1.0.0",
  type: "ai-application",
  description: "AI application identity built on the AI-Gabut platform.",
  capabilities: Object.freeze([
    "agent-engine",
    "agent-reliability",
    "security-governance",
    "workspace",
    "task-orchestration",
    "sync-reconciliation",
    "connector-runtime",
    "media-runtime"
  ])
});

export function createAgenticApplication({ platform } = {}) {
  if (!platform || typeof platform.resolve !== "function") {
    throw new TypeError("Agentic application membutuhkan platform capability registry");
  }

  return Object.freeze({
    manifest: AGENTIC_APP,
    platform,
    getCapability(id) {
      return platform.resolve(id);
    }
  });
}
