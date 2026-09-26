import { runAgentV2 } from "./agent-core.js";
import { startExecution, finishExecution, checkpointExecutionState, resumeExecution, withExecutionLock, withTimeout } from "../reliability/runtime.js";

function statusFromResult(result) {
  if (result?.autonomy?.status === "stopped" || /Execution dihentikan secara bounded/i.test(String(result?.text || ""))) return "stopped";
  if (/mencapai batas maksimum/i.test(String(result?.text || ""))) return "max_turns";
  return "completed";
}

export async function runAgent(args = {}) {
  const sessionKey = args.sessionId || "anonymous";
  return withExecutionLock(sessionKey, async () => {
    const execution = args.executionId
      ? await resumeExecution(args.executionId)
      : await startExecution({ id: args.agentExecutionId, sessionId: args.sessionId, prompt: args.prompt });
    const resumeCheckpoint = args.executionId ? execution.checkpoint : null;
    const persistCheckpoint = async checkpoint => {
      await checkpointExecutionState({ id: execution.id, checkpoint, status: checkpoint.status || "running", meta: { sessionId: args.sessionId || null } });
      if (typeof args.onActivity === "function") await args.onActivity({ type: "activity", action: "checkpoint", label: `Checkpoint tersimpan · turn ${checkpoint.turn}`, status: "completed", meta: { executionId: execution.id, turn: checkpoint.turn, steps: checkpoint.steps?.length || 0 } });
    };
    try {
      const result = await withTimeout(runAgentV2({ ...args, resumeCheckpoint, onCheckpoint: persistCheckpoint }), Number(process.env.AI_EXECUTION_TIMEOUT_MS || 600_000), "agent execution");
      const status = statusFromResult(result);
      await finishExecution({ id: execution.id, status, result });
      return { ...result, execution: { id: execution.id, status, resumable: status !== "completed" } };
    } catch (error) {
      await finishExecution({ id: execution.id, status: error?.code === "EXECUTION_CANCELLED" ? "cancelled" : "failed", error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  });
}
