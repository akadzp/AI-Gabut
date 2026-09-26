export const API_ERRORS = Object.freeze({
  VALIDATION: "API_VALIDATION",
  NOT_FOUND: "API_NOT_FOUND",
  METHOD_NOT_ALLOWED: "API_METHOD_NOT_ALLOWED",
  INTERNAL: "API_INTERNAL",
  UNAVAILABLE: "API_UNAVAILABLE"
});

export class ApiError extends Error {
  constructor(code, message, status = 500, details = {}) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function normalizeApiError(error) {
  if (error instanceof ApiError) return error;

  return new ApiError(
    API_ERRORS.INTERNAL,
    error instanceof Error ? error.message : "Internal server error",
    500
  );
}
