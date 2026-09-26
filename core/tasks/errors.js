export const TASK_ERRORS = Object.freeze({
  VALIDATION: "TASK_VALIDATION",
  NOT_FOUND: "TASK_NOT_FOUND",
  CONFLICT: "TASK_CONFLICT",
  INVALID_STATE: "TASK_INVALID_STATE",
  LEASE_LOST: "TASK_LEASE_LOST",
  RETRY_EXHAUSTED: "TASK_RETRY_EXHAUSTED"
});

export class TaskError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "TaskError";
    this.code = code;
    this.details = details;
  }
}
