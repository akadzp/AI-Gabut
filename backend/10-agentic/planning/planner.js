import { chatWithRoutedProvider } from "../models/model-router.js";
import { TOOL_DEFINITIONS } from "../core/tool-registry.js";

const PLANNER_SYSTEM = `
You are the planning component of AI-Gabut.

Create a concise execution plan for the user's development request.
A plan is a sequence of concrete, observable steps.

Rules:
- Do not invent project facts. Unknown facts should be discovered with tools.
- Do not put tool syntax in the plan.
- Each step should have a short id, goal, and suggested tool names.
- Prefer inspection before modification.
- Do not include commit or push unless the user explicitly requests it.
- Return ONLY valid JSON.
`;

export async function createPlan({ prompt, provider, model, conversation = [] }) {
  const toolSummary = TOOL_DEFINITIONS.map(tool =>
    `${tool.name}: ${tool.description}`
  ).join("\n");
  const history = conversation.slice(-12).map(message =>
    `${message.role.toUpperCase()}: ${message.content}`
  ).join("\n\n");

  const response = await chatWithRoutedProvider({
    prompt,
    provider,
    model,
    messages: [
      { role: "system", content: PLANNER_SYSTEM },
      {
        role: "user",
        content:
          `RECENT CONVERSATION:\n${history || "(none)"}\n\n` +
          `CURRENT USER REQUEST:\n${prompt}\n\nAVAILABLE TOOLS:\n${toolSummary}\n\n` +
          `Return JSON in this shape:\n${JSON.stringify({ steps: [{ id: "step-1", goal: "Inspect the project", tools: ["list_files"] }] }, null, 2)}`
      }
    ]
  });

  try {
    const match = response.text.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("Planner did not return JSON");
    const parsed = JSON.parse(match[0]);
    if (!Array.isArray(parsed.steps)) throw new Error("Planner steps missing");

    return parsed.steps.slice(0, 20).map((step, index) => ({
      id: String(step.id || `step-${index + 1}`),
      goal: String(step.goal || "Continue the user's request"),
      tools: Array.isArray(step.tools) ? step.tools : []
    }));
  } catch {
    return [{
      id: "step-1",
      goal: "Understand and execute the user's request using available tools.",
      tools: []
    }];
  }
}
