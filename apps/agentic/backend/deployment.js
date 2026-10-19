const DEFAULT_BODY_LIMIT = "1mb";
const DEFAULT_ORIGINS = ["http://localhost:3100", "http://127.0.0.1:3100", "http://localhost:5173", "http://127.0.0.1:5173"];
const truthy = value => ["1", "true", "yes", "on"].includes(String(value ?? "").trim().toLowerCase());
const cleanOrigin = value => {
  try {
    const parsed = new URL(String(value));
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) return null;
    return parsed.origin;
  } catch { return null; }
};

export function loadAgenticDeployment(env = process.env, overrides = {}) {
  const rawOrigins = overrides.allowedOrigins ?? env.AGENTIC_ALLOWED_ORIGINS;
  const allowedOrigins = (Array.isArray(rawOrigins) ? rawOrigins : typeof rawOrigins === "string" && rawOrigins.trim() ? rawOrigins.split(",") : DEFAULT_ORIGINS)
    .map(cleanOrigin).filter(Boolean);
  const topology = String(overrides.topology ?? env.AGENTIC_TOPOLOGY ?? "monolith").trim().toLowerCase() === "split" ? "split" : "monolith";
  const configuredLimit = String(overrides.bodyLimit ?? env.AGENTIC_BODY_LIMIT ?? DEFAULT_BODY_LIMIT).trim();
  const bodyLimit = /^(\d{1,4})(b|kb|mb)?$/i.test(configuredLimit) ? configuredLimit : DEFAULT_BODY_LIMIT;
  const port = Number(overrides.port ?? env.AGENTIC_PORT ?? 3100);
  const host = String(overrides.host ?? env.AGENTIC_HOST ?? "127.0.0.1");
  return Object.freeze({
    topology, allowedOrigins: Object.freeze([...new Set(allowedOrigins)]), bodyLimit,
    trustProxy: overrides.trustProxy === true || (overrides.trustProxy === undefined && truthy(env.AGENTIC_TRUST_PROXY)),
    host, port: Number.isInteger(port) && port >= 0 && port <= 65535 ? port : 3100,
    environment: String(env.NODE_ENV || "development")
  });
}

export function assertAllowedOrigin(origin, deployment = {}) {
  const normalized = cleanOrigin(origin);
  if (!normalized) return false;
  const allowed = Array.isArray(deployment.allowedOrigins) ? deployment.allowedOrigins : DEFAULT_ORIGINS;
  return allowed.some(candidate => cleanOrigin(candidate) === normalized);
}

export function getSecurityHeaders({ split = false } = {}) {
  return Object.freeze({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": split ? "cross-origin" : "same-origin",
    "Content-Security-Policy": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
  });
}
