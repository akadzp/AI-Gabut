import { executeTerminal } from "../linux/terminal/executor.js";
import { planVerification } from "./verification-planner.js";

const MAX_EXECUTIONS = 12;

function normalizeIds(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(item => String(item || "").trim()).filter(Boolean))];
}

export async function executeVerification({
  paths = [],
  includeGit = true,
  checkIds = [],
  stopOnFailure = false
} = {}) {
  const plan = await planVerification({ paths, includeGit });
  if (!plan.ok) return plan;

  const requestedIds = normalizeIds(checkIds);
  const selected = requestedIds.length
    ? plan.checks.filter(check => requestedIds.includes(check.id))
    : plan.checks;

  const missing = requestedIds.filter(id => !plan.checks.some(check => check.id === id));
  const checks = selected.slice(0, MAX_EXECUTIONS);
  const results = [];

  for (const check of checks) {
    const startedAt = Date.now();
    let result;
    try {
      result = await executeTerminal({ command: check.command, cwd: "." });
    } catch (error) {
      result = {
        command: check.command,
        code: null,
        signal: null,
        timedOut: false,
        outputLimitReached: false,
        stdout: "",
        stderr: error instanceof Error ? error.message : "Verification command failed"
      };
    }

    const passed = result.code === 0 && !result.timedOut && !result.outputLimitReached;
    results.push({
      id: check.id,
      type: check.type,
      command: check.command,
      reason: check.reason,
      confidence: check.confidence,
      path: check.path,
      status: passed ? "passed" : "failed",
      passed,
      startedAt: new Date(startedAt).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      code: result.code,
      signal: result.signal,
      timedOut: result.timedOut,
      outputLimitReached: result.outputLimitReached,
      stdout: result.stdout || "",
      stderr: result.stderr || ""
    });

    if (!passed && stopOnFailure) break;
  }

  const passedCount = results.filter(result => result.passed).length;
  const failedCount = results.length - passedCount;

  return {
    ok: failedCount === 0 && missing.length === 0 && checks.length === selected.length,
    type: "verification_execution",
    generatedAt: new Date().toISOString(),
    plan: {
      files: plan.files,
      packageScripts: plan.packageScripts,
      checks: plan.checks
    },
    selection: {
      requestedIds,
      selectedIds: checks.map(check => check.id),
      missingIds: missing,
      limited: selected.length > MAX_EXECUTIONS
    },
    results,
    summary: {
      total: results.length,
      passed: passedCount,
      failed: failedCount,
      allPassed: results.length > 0 && failedCount === 0,
      stoppedOnFailure: stopOnFailure && results.some(result => !result.passed)
    }
  };
}
