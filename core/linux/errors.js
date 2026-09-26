export class LinuxCapabilityError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "LinuxCapabilityError";
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export const LINUX_ERRORS = Object.freeze({
  VALIDATION_ERROR: "VALIDATION_ERROR",
  NOT_FOUND: "NOT_FOUND",
  NOT_SUPPORTED: "NOT_SUPPORTED",
  PERMISSION_DENIED: "PERMISSION_DENIED",
  EXECUTION_FAILED: "EXECUTION_FAILED",
  TIMEOUT: "TIMEOUT",
  RESOURCE_LIMIT: "RESOURCE_LIMIT"
});
