import { ApiError, API_ERRORS } from "./errors.js";

const SAFE_METHODS = Object.freeze(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

export const API_VERSION = "v1";
export const API_CONTENT_TYPE = "application/json";

export function normalizeMethod(value) {
  const method = String(value || "").trim().toUpperCase();
  if (!SAFE_METHODS.includes(method)) {
    throw new ApiError(API_ERRORS.METHOD_NOT_ALLOWED, `HTTP method tidak didukung: ${value}`, 405);
  }
  return method;
}

export function normalizePath(value) {
  const path = String(value || "").trim();
  if (!path.startsWith("/")) {
    throw new ApiError(API_ERRORS.VALIDATION, "API path harus diawali '/'", 400);
  }
  return path.replace(/\/{2,}/g, "/");
}

export function createApiContext({ requestId, method, path, query = {}, params = {} } = {}) {
  const normalizedMethod = normalizeMethod(method);
  const normalizedPath = normalizePath(path);

  return Object.freeze({
    requestId: requestId == null ? null : String(requestId),
    version: API_VERSION,
    method: normalizedMethod,
    path: normalizedPath,
    query: query && typeof query === "object" ? { ...query } : {},
    params: params && typeof params === "object" ? { ...params } : {}
  });
}

export function createSuccessResponse(data = {}, meta = {}) {
  return {
    ok: true,
    data,
    meta: meta && typeof meta === "object" ? meta : {}
  };
}

export function createErrorResponse(error, requestId = null) {
  const status = Number(error?.status) >= 400 ? Number(error.status) : 500;
  return {
    ok: false,
    error: {
      code: error?.code || API_ERRORS.INTERNAL,
      message: error?.message || "Internal server error"
    },
    meta: {
      requestId
    },
    status
  };
}
