import crypto from "node:crypto";
import { redactSecrets } from "../secrets/manager.js";

const MAX_AUDIT_ENTRIES = Number(process.env.GOVERNANCE_AUDIT_MAX || 500);
const audit = [];

function normalizeOutcome(outcome) {
  return String(outcome || "unknown").slice(0, 64);
}

export function auditEvent({
  actor = "system",
  action,
  tool = null,
  input = {},
  outcome,
  meta = {},
  principal = null,
  decisionId = null,
  executionId = null,
  sessionId = null,
  applicationId = null,
  connectorId = null
} = {}) {
  const entry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    actor: String(actor || "system"),
    action: String(action || "unknown"),
    tool: tool ? String(tool) : null,
    outcome: normalizeOutcome(outcome),
    principal: redactSecrets(principal),
    decisionId: decisionId ? String(decisionId) : null,
    executionId: executionId ? String(executionId) : null,
    sessionId: sessionId ? String(sessionId) : null,
    applicationId: applicationId ? String(applicationId) : null,
    connectorId: connectorId ? String(connectorId) : null,
    input: redactSecrets(input),
    meta: redactSecrets(meta)
  };
  audit.push(entry);
  while (audit.length > MAX_AUDIT_ENTRIES) audit.shift();
  return Object.freeze(entry);
}

export function getAuditTrail({ limit = 100, action = null, outcome = null, tool = null, executionId = null } = {}) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 100, MAX_AUDIT_ENTRIES));
  return audit
    .filter(entry => !action || entry.action === action)
    .filter(entry => !outcome || entry.outcome === outcome)
    .filter(entry => !tool || entry.tool === tool)
    .filter(entry => !executionId || entry.executionId === executionId)
    .slice(-safeLimit);
}

export function getAuditMetrics() {
  const metrics = { total: audit.length, byOutcome: {}, byAction: {}, byTool: {} };
  for (const entry of audit) {
    metrics.byOutcome[entry.outcome] = (metrics.byOutcome[entry.outcome] || 0) + 1;
    metrics.byAction[entry.action] = (metrics.byAction[entry.action] || 0) + 1;
    if (entry.tool) metrics.byTool[entry.tool] = (metrics.byTool[entry.tool] || 0) + 1;
  }
  return metrics;
}

export function getAuditPolicy() {
  return {
    enabled: true,
    maxEntries: MAX_AUDIT_ENTRIES,
    secretRedaction: true,
    immutableEntries: true,
    queryFilters: ["action", "outcome", "tool", "executionId"]
  };
}
