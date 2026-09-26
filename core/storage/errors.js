export class StorageError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "StorageError";
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export const STORAGE_ERRORS = Object.freeze({
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",
  VALIDATION_ERROR: "VALIDATION_ERROR",
  ALREADY_EXISTS: "ALREADY_EXISTS",
  STORAGE_UNAVAILABLE: "STORAGE_UNAVAILABLE",
  SERIALIZATION_ERROR: "SERIALIZATION_ERROR"
});
