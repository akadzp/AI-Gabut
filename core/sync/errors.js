export const SYNC_ERRORS = Object.freeze({
  VALIDATION: "SYNC_VALIDATION",
  NOT_FOUND: "SYNC_NOT_FOUND",
  CONFLICT: "SYNC_CONFLICT",
  INVALID_STATE: "SYNC_INVALID_STATE",
  ADAPTER: "SYNC_ADAPTER",
  APPLY_FAILED: "SYNC_APPLY_FAILED"
});

export class SyncError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "SyncError";
    this.code = code;
    this.details = details;
  }
}
