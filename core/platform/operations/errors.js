export const OPERATIONS_ERRORS = Object.freeze({
  VALIDATION: "OPERATIONS_VALIDATION",
  NOT_READY: "OPERATIONS_NOT_READY",
  SHUTDOWN: "OPERATIONS_SHUTDOWN",
  STARTUP: "OPERATIONS_STARTUP"
});

export class OperationsError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "OperationsError";
    this.code = code;
    this.details = details;
  }
}
