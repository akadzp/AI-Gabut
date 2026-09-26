import { randomUUID } from "node:crypto";
import { ApiError, API_ERRORS, normalizeApiError } from "./errors.js";
import { createApiContext, createErrorResponse } from "./contracts.js";

export function createApiRouter({ express, basePath = "/api" } = {}) {
  if (!express || typeof express.Router !== "function") {
    throw new ApiError(API_ERRORS.VALIDATION, "Express implementation wajib tersedia", 500);
  }

  const router = express.Router();
  const prefix = String(basePath || "/api").replace(/\/+$/, "") || "/api";

  router.use((req, res, next) => {
    const requestId = req.get("x-request-id") || randomUUID();
    req.api = createApiContext({
      requestId,
      method: req.method,
      path: req.path,
      query: req.query,
      params: req.params
    });
    res.setHeader("x-request-id", requestId);
    next();
  });

  function route(path, methods, handler) {
    const normalizedMethods = Array.isArray(methods) ? methods : [methods];
    for (const method of normalizedMethods) {
      const name = String(method).toLowerCase();
      if (typeof router[name] !== "function") {
        throw new ApiError(API_ERRORS.METHOD_NOT_ALLOWED, `HTTP method tidak tersedia: ${method}`, 405);
      }
      router[name](path, async (req, res, next) => {
        try {
          await handler(req, res);
        } catch (error) {
          next(error);
        }
      });
    }
    return api;
  }

  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const normalized = normalizeApiError(error);
    const response = createErrorResponse(normalized, req.api?.requestId || null);
    res.status(response.status).json(response);
  });

  const api = Object.freeze({
    router,
    prefix,
    route
  });

  return api;
}
