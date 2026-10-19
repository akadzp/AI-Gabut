import { randomBytes, timingSafeEqual } from "node:crypto";

const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MAX_AUDIT_EVENTS = 1000;
const MAX_APPROVAL_TOKENS = 10000;
const approvalTokens = new Map();
const auditEvents = [];

const APPROVAL_REQUIRED = new Set([
  "git_commit", "git_push", "shell", "execute_command", "delete_file", "network_write"
]);

function pruneApprovalTokens(now = Date.now()) {
  for (const [token, grant] of approvalTokens) {
    if (grant.consumed || Date.parse(grant.expiresAt) <= now) approvalTokens.delete(token);
  }
  while (approvalTokens.size >= MAX_APPROVAL_TOKENS) {
    const oldest = approvalTokens.keys().next().value;
    if (oldest === undefined) break;
    approvalTokens.delete(oldest);
  }
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function digest(value) {
  return Buffer.from(canonical(value ?? {}), "utf8").toString("base64url");
}

function tokenEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function getToolPolicy(tool) {
  const name = String(tool ?? "").trim();
  return Object.freeze({
    tool: name,
    requiresApproval: APPROVAL_REQUIRED.has(name),
    approvalTtlMs: DEFAULT_TTL_MS
  });
}

export function issueApproval({ tool, input = {}, sessionId = null, principalId = null, executionId = null, reason = null, ttlMs = DEFAULT_TTL_MS } = {}) {
  const name = String(tool ?? "").trim();
  if (!name) throw new TypeError("Tool approval membutuhkan nama tool");
  const issuedAt = Date.now();
  pruneApprovalTokens(issuedAt);
  const boundedTtl = Math.max(1000, Math.min(Number(ttlMs) || DEFAULT_TTL_MS, 60 * 60 * 1000));
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(issuedAt + boundedTtl).toISOString();
  approvalTokens.set(token, {
    tool: name,
    inputDigest: digest(input),
    sessionId: sessionId == null ? null : String(sessionId).slice(0, 200),
    principalId: principalId == null ? null : String(principalId).slice(0, 200),
    executionId: executionId == null ? null : String(executionId).slice(0, 200),
    reason: reason == null ? null : String(reason).slice(0, 1000),
    expiresAt,
    consumed: false
  });
  return Object.freeze({ token, expiresAt });
}

export function authorizeTool({ tool, input = {}, approvalToken = null, principalId = null, executionId = null } = {}) {
  const name = String(tool ?? "").trim();
  pruneApprovalTokens();
  const policy = getToolPolicy(name);
  if (!policy.requiresApproval) return Object.freeze({ ok: true, requiresApproval: false, error: null, status: 200 });
  if (!approvalToken) return Object.freeze({ ok: false, requiresApproval: true, error: "Human approval is required for this tool", status: 403 });

  let grant = null;
  for (const [token, record] of approvalTokens) {
    if (tokenEqual(token, approvalToken)) { grant = record; break; }
  }
  if (!grant || grant.consumed || Date.parse(grant.expiresAt) <= Date.now() || grant.tool !== name || grant.inputDigest !== digest(input)) {
    return Object.freeze({ ok: false, requiresApproval: false, error: "Approval token is invalid, expired, or does not match the requested action", status: 403 });
  }
  if (grant.principalId !== null && String(principalId ?? "") !== grant.principalId) {
    return Object.freeze({ ok: false, requiresApproval: false, error: "Approval principal mismatch", status: 403 });
  }
  if (grant.executionId !== null && String(executionId ?? "") !== grant.executionId) {
    return Object.freeze({ ok: false, requiresApproval: false, error: "Approval execution mismatch", status: 403 });
  }
  grant.consumed = true;
  return Object.freeze({ ok: true, requiresApproval: false, error: null, status: 200 });
}

export function auditEvent(event = {}) {
  const entry = Object.freeze({
    at: new Date().toISOString(),
    actor: String(event.actor ?? "system").slice(0, 100),
    action: String(event.action ?? "unknown").slice(0, 200),
    outcome: String(event.outcome ?? "unknown").slice(0, 100),
    principal: event.principal && typeof event.principal === "object" ? { userId: event.principal.userId == null ? null : String(event.principal.userId).slice(0, 200) } : null,
    sessionId: event.sessionId == null ? null : String(event.sessionId).slice(0, 200),
    applicationId: event.applicationId == null ? null : String(event.applicationId).slice(0, 100),
    executionId: event.executionId == null ? null : String(event.executionId).slice(0, 200)
  });
  auditEvents.push(entry);
  if (auditEvents.length > MAX_AUDIT_EVENTS) auditEvents.splice(0, auditEvents.length - MAX_AUDIT_EVENTS);
  return entry;
}

export function listAuditEvents({ limit = 100 } = {}) {
  const bounded = Math.max(1, Math.min(Number(limit) || 100, MAX_AUDIT_EVENTS));
  return auditEvents.slice(-bounded).map(event => ({ ...event, principal: event.principal ? { ...event.principal } : null }));
}
