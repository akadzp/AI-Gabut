import { executeTerminal } from "../../linux/terminal/executor.js";

export const terminalToolDefinition = {
  name: "terminal",
  description: "Execute a limited shell command inside the AI-Gabut workspace.",
  inputSchema: {
    type: "object",
    properties: {
      command: { type: "string" },
      cwd: { type: "string" }
    },
    required: ["command"]
  }
};

export async function runTerminalTool(input) {
  return executeTerminal({
    command: input.command,
    cwd: input.cwd || "."
  });
}
