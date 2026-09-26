import assert from "node:assert/strict";
import {
  API_VERSION,
  createApiContext,
  createErrorResponse,
  normalizeMethod,
  normalizePath,
  ApiError
} from "../../core/api/index.js";

assert.equal(API_VERSION, "v1");
assert.equal(normalizeMethod("get"), "GET");
assert.equal(normalizePath("//api//chat"), "/api/chat");

const context = createApiContext({
  requestId: "req-1",
  method: "POST",
  path: "/api/chat",
  query: { q: "test" },
  params: { id: "1" }
});

assert.equal(context.requestId, "req-1");
assert.equal(context.method, "POST");
assert.equal(context.path, "/api/chat");
assert.equal(context.query.q, "test");

const error = createErrorResponse(
  new ApiError("API_VALIDATION", "Invalid request", 400),
  "req-1"
);

assert.equal(error.ok, false);
assert.equal(error.status, 400);
assert.equal(error.error.code, "API_VALIDATION");
assert.equal(error.meta.requestId, "req-1");

assert.throws(() => normalizeMethod("TRACE"), /HTTP method tidak didukung/);
assert.throws(() => normalizePath("api/chat"), /diawali/);

console.log("API contract: PASS");
