export const AGENTIC_APP = Object.freeze({
  id: "agentic",
  name: "Agentic",
  version: "1.1.0",
  type: "ai-application",
  description: "AI application identity and runtime built on the AI-Gabut platform.",
  capabilities: Object.freeze([
    "identity",
    "sessions",
    "agent-engine",
    "agent-reliability",
    "security-governance",
    "workspace",
    "task-orchestration",
    "sync-reconciliation",
    "connector-runtime",
    "github-read",
    "media-runtime"
  ])
});

export function createAgenticApplication({ platform } = {}) {
  if (!platform || typeof platform.resolve !== "function") {
    throw new TypeError("Agentic application membutuhkan platform capability registry");
  }
  return Object.freeze({ manifest: AGENTIC_APP, platform, getCapability(id) { return platform.resolve(id); } });
}

export { createAgenticServer } from "./backend/server.js";
export { createAgenticApplication as createLiveAgenticApplication } from "./backend/application.js";
