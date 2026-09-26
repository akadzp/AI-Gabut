import crypto from "node:crypto";
import { normalizePrincipal, isKnownPrincipal } from "../identity/principal.js";

const ACTION_PATTERN = /^[a-z][a-z0-9._-]*$/;

export function normalizeAuthorizationRequest({ principal, action, resource, scope, context = {}, inputFingerprint = null, requestedAt = new Date().toISOString() } = {}) {
  const normalizedPrincipal = normalizePrincipal(principal, { sessionId: context.sessionId });
  const normalizedAction = String(action || "").trim().toLowerCase();
  const normalizedResource = normalizeResource(resource);
  const normalizedScope = normalizeScope(scope);

  return {
    principal: normalizedPrincipal,
    action: normalizedAction,
    resource: normalizedResource,
    scope: normalizedScope,
    context: sanitizeContext(context),
    inputFingerprint: inputFingerprint || null,
    requestedAt
  };
}

export function createPolicyDecision({ decision, request, risk = "unknown", reasons = [], policyId = "governance", policyVersion = "1", approval = null } = {}) {
  if (!["allow", "deny", "approval_required"].includes(decision)) throw new TypeError(`Invalid policy decision: ${decision}`);
  return {
    decision,
    decisionId: crypto.randomUUID(),
    principal: request.principal,
    action: request.action,
    resource: request.resource,
    scope: request.scope,
    risk,
    reasons: reasons.map(String),
    policyId,
    policyVersion,
    approval,
    timestamp: new Date().toISOString()
  };
}

export function denyDecision(request, reasonCode, message, options = {}) {
  return createPolicyDecision({
    decision: "deny",
    request,
    risk: options.risk,
    policyId: options.policyId,
    policyVersion: options.policyVersion,
    reasons: [reasonCode, message]
  });
}

export function validateAuthorizationRequest(request) {
  if (!isKnownPrincipal(request?.principal)) return "unknown-principal";
  if (!ACTION_PATTERN.test(request?.action || "")) return "unknown-action";
  if (!request?.resource?.type || !request?.resource?.id) return "unknown-resource";
  if (!request?.scope?.domain || !request?.scope?.target) return "unknown-resource";
  return null;
}

function normalizeResource(resource = {}) {
  if (typeof resource === "string") return { type: resource, id: resource, sensitivity: "unknown" };
  return {
    type: String(resource.type || resource.domain || "unknown").trim().toLowerCase(),
    id: String(resource.id || resource.locator || "unknown").trim(),
    sensitivity: String(resource.sensitivity || "unknown").trim().toLowerCase()
  };
}

function normalizeScope(scope = {}) {
  if (typeof scope === "string") return { domain: "default", target: scope, allowedActions: [] };
  return {
    domain: String(scope.domain || "default").trim().toLowerCase(),
    target: String(scope.target || "default").trim(),
    allowedActions: Array.isArray(scope.allowedActions) ? scope.allowedActions.map(item => String(item).trim().toLowerCase()).filter(Boolean) : [],
    constraints: scope.constraints && typeof scope.constraints === "object" ? { ...scope.constraints } : {}
  };
}

function sanitizeContext(context = {}) {
  return {
    sessionId: context.sessionId || null,
    executionId: context.executionId || null,
    applicationId: context.applicationId || null,
    connectorId: context.connectorId || null,
    environment: context.environment || null,
    requestOrigin: context.requestOrigin || null,
    riskIndicators: Array.isArray(context.riskIndicators) ? context.riskIndicators.slice(0, 20).map(String) : []
  };
}
