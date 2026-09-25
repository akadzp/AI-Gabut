import { runAgentV2 } from "./agent-core.js";
import { startExecution, finishExecution, checkpointExecutionState, resumeExecution, withExecutionLock, withTimeout } from "../reliability/runtime.js";

export async function runAgent(args = {}) {
  const sessionKey = args.sessionId || "anonymous";
  return withExecutionLock(sessionKey, async () => {
    const execution = args.executionId ? await resumeExecution(args.executionId) : await startExecution({ sessionId: args.sessionId, prompt: args.prompt });
    const resumeCheckpoint = args.executionId ? execution.checkpoint : null;
    const persistCheckpoint = async checkpoint => {
      await checkpointExecutionState({ id: execution.id, checkpoint, status: checkpoint.status || "running", meta: { sessionId: args.sessionId || null } });
      if (typeof args.onActivity === "function") await args.onActivity({ type: "activity", action: "checkpoint", label: `Checkpoint tersimpan · turn ${checkpoint.turn}`, status: "completed", meta: { executionId: execution.id, turn: checkpoint.turn, steps: checkpoint.steps?.length || 0 } });
    };
    try {
      const result = await withTimeout(runAgentV2({ ...args, resumeCheckpoint, onCheckpoint: persistCheckpoint }), Number(process.env.AI_EXECUTION_TIMEOUT_MS || 600_000), "agent execution");
      await finishExecution({ id: execution.id, status: "completed", result });
      return { ...result, execution: { id: execution.id, status: "completed", resumable: false } };
    } catch (error) {
      await finishExecution({ id: execution.id, status: "failed", error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  });
}
