import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const MAX_ITERATIONS = 3;

function classifyFailure(execution, verification) {
  if (verification?.status === "timed_out") return { type: "timeout", source: "verification", message: "Verification timed out", retryable: true };
  if (verification?.status === "failed") return { type: "verification_failure", source: "verification", message: verification.failures?.[0] || verification.stderr || "Verification failed", retryable: true };
  if (execution?.status === "failed") {
    const message = execution.error || execution.result || "Execution failed";
    return { type: /timeout|timed.?out/i.test(String(message)) ? "timeout" : "execution_failure", source: "execution", message: String(message).slice(0, 2000), retryable: true };
  }
  return { type: "unknown", source: "work", message: "Failure tidak memiliki evidence yang dapat diklasifikasikan", retryable: false };
}

function repairPrompt(work, failure, verification, iteration) {
  const evidence = verification
    ? `\nVerification evidence:\nstatus=${verification.status}\nfailures=${JSON.stringify(verification.failures || [])}\nstderr=${String(verification.stderr || "").slice(0, 4000)}`
    : "";
  return `${work.objective}\n\nRepair iteration ${iteration}: perbaiki failure secara bounded. Failure type=${failure.type}; source=${failure.source}; message=${failure.message}.${evidence}\nJangan memperluas scope di luar capability dan authority Work. Setelah repair, hasil harus dapat diverifikasi.`;
}

export function createWorkRepairService({ store, work, planner, execute, verify = null, realtime = null } = {}) {
  if (!store?.putActivity || !store?.listExecutions || !store?.getExecution || !work?.raw || !work?.get || !work?.reopenForRepair || !planner || !execute) {
    throw new TypeError("Work repair membutuhkan store, work, planner, dan execution contract");
  }

  async function checkpoint(ownerId, workId, meta) {
    const checkpoint = {
      id: createId("repair-checkpoint"), workId, executionId: meta.executionId || null,
      iteration: meta.iteration, type: "repair_checkpoint", ...meta, createdAt: new Date().toISOString()
    };
    if (store.putRepairCheckpoint) await store.putRepairCheckpoint(ownerId, checkpoint, { overwrite: false });
    const activity = { id: createId("activity"), workId, executionId: checkpoint.executionId, sessionId: null, type: "repair_checkpoint", action: "repair", status: meta.status || "running", label: meta.label || "Repair checkpoint", meta: checkpoint, createdAt: checkpoint.createdAt };
    await store.putActivity(ownerId, activity, { overwrite: false });
    if (realtime?.publish) await realtime.publish(ownerId, activity);
    return checkpoint;
  }

  async function latestFailure(ownerId, workId) {
    const executions = (await store.listExecutions(ownerId)).filter(item => item.workId === workId).sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    const execution = executions.find(item => item.status === "failed") || executions[0] || null;
    const verifications = store.listVerifications ? (await store.listVerifications(ownerId)).filter(item => item.workId === workId).sort((a, b) => String(b.finishedAt).localeCompare(String(a.finishedAt))) : [];
    const verification = verifications[0] || null;
    return { execution, verification, failure: classifyFailure(execution, verification) };
  }

  async function repair(ownerId, workId, options = {}) {
    const current = await work.raw(ownerId, workId);
    if (current.state !== "failed") throw new AgenticError("WORK_NOT_REPAIRABLE", "Repair hanya dapat dijalankan pada Work yang gagal", 409);
    const maxIterations = Math.max(1, Math.min(Number(options.maxIterations) || 1, MAX_ITERATIONS));
    const history = Array.isArray(current.result?.repair?.history) ? current.result.repair.history : [];
    if (history.length >= maxIterations) throw new AgenticError("REPAIR_LIMIT_REACHED", "Batas repair iteration sudah tercapai", 409, { maxIterations, attempts: history.length });
    const iteration = history.length + 1;
    const { execution, verification, failure } = await latestFailure(ownerId, workId);
    if (!failure.retryable) throw new AgenticError("REPAIR_NOT_SUPPORTED", "Failure tidak berada dalam bounded repair capability", 409, failure);
    const base = { iteration, failure, executionId: execution?.id || null, verificationId: verification?.id || null, startedAt: new Date().toISOString() };
    await checkpoint(ownerId, workId, { ...base, status: "observed", label: `Repair ${iteration} · failure diklasifikasikan` });

    const planned = await planner({ prompt: repairPrompt(current, failure, verification, iteration), provider: options.provider, model: options.model, conversation: Array.isArray(options.conversation) ? options.conversation : [] });
    const steps = Array.isArray(planned) ? planned.slice(0, 20).map((step, index) => ({ id: String(step?.id || `repair-${iteration}-${index + 1}`).slice(0, 120), goal: String(step?.goal || "Repair failure").slice(0, 1000), tools: Array.isArray(step?.tools) ? step.tools.map(String).slice(0, 20) : [], status: "planned" })) : [];
    if (!steps.length) throw new AgenticError("REPAIR_PLAN_EMPTY", "Repair planner tidak menghasilkan langkah", 500);
    const plan = { version: 1, status: "ready", interpretation: { objective: current.objective, summary: `Repair iteration ${iteration}: ${failure.type}` }, steps, currentStepId: null, replanAvailable: iteration < maxIterations, createdAt: new Date().toISOString() };
    await checkpoint(ownerId, workId, { ...base, status: "planned", label: `Repair ${iteration} · plan baru`, plan });

    const reopened = await work.reopenForRepair(ownerId, workId, {
      plan,
      result: { ...(current.result || {}), repair: { status: "running", iteration, maxIterations, history: [...history, { iteration, failure, executionId: execution?.id || null, verificationId: verification?.id || null, plannedAt: new Date().toISOString() }] } }
    });
    await checkpoint(ownerId, workId, { ...base, status: "reopened", label: `Repair ${iteration} · Work dibuka kembali` });

    let runResult;
    try {
      runResult = await execute(ownerId, workId, { provider: options.provider, model: options.model, conversation: options.conversation });
    } catch (error) {
      const failed = await work.raw(ownerId, workId);
      const nextHistory = [...(failed.result?.repair?.history || [])].map(item => item.iteration === iteration ? { ...item, finishedAt: new Date().toISOString(), outcome: "failed", error: error?.message || String(error) } : item);
      await store.putWork(ownerId, { ...failed, result: { ...(failed.result || {}), repair: { status: "failed", iteration, maxIterations, history: nextHistory, replanAvailable: iteration < maxIterations } }, updatedAt: new Date().toISOString() }, { overwrite: true, expectedVersion: failed._storage?.version });
      await checkpoint(ownerId, workId, { ...base, status: "failed", label: `Repair ${iteration} · execution gagal`, error: error?.message || String(error) });
      throw error;
    }

    let verificationResult = null;
    if (verify && runResult?.work?.state === "completed") verificationResult = await verify(ownerId, workId, options.verification || {});
    let finalWork = await work.raw(ownerId, workId);
    const success = finalWork.state === "completed" && (!verificationResult || verificationResult.verification?.status === "passed");
    if (!success && finalWork.state === "completed") {
      finalWork = { ...finalWork, state: "failed", finishedAt: new Date().toISOString(), result: { ...(finalWork.result || {}), status: "failed", message: "Repair verification failed" }, updatedAt: new Date().toISOString() };
      await store.putWork(ownerId, finalWork, { overwrite: true, expectedVersion: finalWork._storage?.version });
    }
    const finished = new Date().toISOString();
    const nextHistory = [...(finalWork.result?.repair?.history || [])].map(item => item.iteration === iteration ? { ...item, finishedAt: finished, outcome: success ? "repaired" : "failed", verificationId: verificationResult?.verification?.id || item.verificationId || null } : item);
    const repairResult = { status: success ? "repaired" : "failed", iteration, maxIterations, history: nextHistory, replanAvailable: !success && iteration < maxIterations };
    await store.putWork(ownerId, { ...finalWork, result: { ...(finalWork.result || {}), repair: repairResult }, updatedAt: finished }, { overwrite: true, expectedVersion: finalWork._storage?.version });
    await checkpoint(ownerId, workId, { ...base, status: success ? "completed" : "failed", label: success ? `Repair ${iteration} · berhasil` : `Repair ${iteration} · failure berlanjut`, verificationId: verificationResult?.verification?.id || null });
    return { work: await work.get(ownerId, workId), execution: runResult.execution, verification: verificationResult, repair: repairResult };
  }

  return Object.freeze({ repair, latestFailure });
}
