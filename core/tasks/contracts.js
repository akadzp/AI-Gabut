import { TASK_ERRORS, TaskError } from "./errors.js";

export const TASK_STATES = Object.freeze(["queued", "running", "completed", "failed", "cancelled"]);
export const JOB_STATES = Object.freeze(["queued", "leased", "running", "completed", "failed", "cancelled", "retrying"]);
export const EXECUTION_STATES = Object.freeze(["created", "running", "checkpointed", "completed", "failed", "cancelled"]);

const NON_NEGATIVE = Number.isInteger;

export function normalizeRetryPolicy(policy = {}) {
  const maxAttempts = policy.maxAttempts === undefined ? 3 : Number(policy.maxAttempts);
  const backoffMs = policy.backoffMs === undefined ? 1000 : Number(policy.backoffMs);
  const maxBackoffMs = policy.maxBackoffMs === undefined ? 30_000 : Number(policy.maxBackoffMs);
  if (!NON_NEGATIVE(maxAttempts) || maxAttempts < 1 || maxAttempts > 20) throw new TaskError(TASK_ERRORS.VALIDATION, "maxAttempts harus integer 1..20");
  if (!NON_NEGATIVE(backoffMs) || backoffMs < 0) throw new TaskError(TASK_ERRORS.VALIDATION, "backoffMs harus integer >= 0");
  if (!NON_NEGATIVE(maxBackoffMs) || maxBackoffMs < backoffMs) throw new TaskError(TASK_ERRORS.VALIDATION, "maxBackoffMs tidak valid");
  return Object.freeze({ maxAttempts, backoffMs, maxBackoffMs });
}

export function assertState(states, value, label) {
  if (!states.includes(value)) throw new TaskError(TASK_ERRORS.VALIDATION, `${label} state tidak valid: ${value}`);
  return value;
}
