import crypto from "node:crypto";
import { classifyCommand } from "../policies/terminal-command.js";

const MAX_AUDIT_ENTRIES = Number(process.env.GOVERNANCE_AUDIT_MAX || 500);
const approvals = new Map();
const audit = [];

const TOOL_POLICY = {
  read_file: { permission: "read", risk: "low", resource: "workspace" },
  list_files: { permission: "read", risk: "low", resource: "workspace" },
  search_files: { permission: "read", risk: "low", resource: "workspace" },
  search_code: { permission: "read", risk: "low", resource: "workspace" },
  find_symbol: { permission: "read", risk: "low", resource: "workspace" },
  inspect_project: { permission: "read", risk: "low", resource: "workspace" },
  inspect_code: { permission: "read", risk: "low", resource: "workspace" },
  find_semantic_references: { permission: "read", risk: "low", resource: "workspace" },
  find_references: { permission: "read", risk: "low", resource: "workspace" },
  find_file_references: { permission: "read", risk: "low", resource: "workspace" },
  dependency_graph: { permission: "read", risk: "low", resource: "workspace" },
  analyze_impact: { permission: "read", risk: "low", resource: "workspace" },
  resolve_symbol: { permission: "read", risk: "low", resource: "workspace" },
  call_graph: { permission: "read", risk: "low", resource: "workspace" },
  plan_change: { permission: "read", risk: "low", resource: "workspace" },
  analyze_tests: { permission: "read", risk: "low", resource: "workspace" },
  diagnose_verification_failure: { permission: "read", risk: "low", resource: "workspace" },
  plan_refactoring: { permission: "read", risk: "low", resource: "workspace" },
  analyze_contracts: { permission: "read", risk: "low", resource: "workspace" },
  analyze_schemas: { permission: "read", risk: "low", resource: "workspace" },
  analyze_frameworks: { permission: "read", risk: "low", resource: "workspace" },
  plan_migration: { permission: "read", risk: "low", resource: "workspace" },
  review_change_set: { permission: "read", risk: "medium", resource: "workspace" },
  plan_verification: { permission: "read", risk: "low", resource: "workspace" },
  git_status: { permission: "read", risk: "low", resource: "git" },
  git_diff: { permission: "read", risk: "low", resource: "git" },
  git_changes: { permission: "read", risk: "low", resource: "git" },
  git_log: { permission: "read", risk: "low", resource: "git" },
  terminal: { permission: "write", risk: "medium", resource: "terminal" },
  write_file: { permission: "write", risk: "medium", resource: "workspace" },
  edit_file: { permission: "write", risk: "medium", resource: "workspace" },
  git_add: { permission: "write", risk: "medium", resource: "git" },
  execute_verification: { permission: "write", risk: "medium", resource: "terminal" },
  git_commit: { permission: "approval", risk: "high", resource: "git" },
  git_push: { permission: "approval", risk: "critical", resource: "git" }
};

const SECRET_KEY = /key|token|secret|password|passwd|credential|authorization|cookie|private/i;
const SECRET_VALUE = /^(?:sk-|ghp_|github_pat_|AIza|xox[baprs]-)/i;

export function getGovernancePolicy() {
  return {
    mode: process.env.AI_GOVERNANCE_MODE || "strict",
    workspaceIsolation: true,
    secretProtection: true,
    humanApproval: true,
    auditTrail: true,
    policyEnforcement: true,
    networkTools: process.env.AI_ALLOW_NETWORK_TOOLS === "true",
    tools: Object.entries(TOOL_POLICY).map(([name, policy]) => ({ name, ...policy }))
  };
}

export function getToolPolicy(name, definition = null) {
  if (TOOL_POLICY[name]) return TOOL_POLICY[name];
  if (definition) {
    const permission = definition.permission === "approval" ? "approval" : definition.permission === "write" ? "write" : "read";
    return { permission, risk: permission === "read" ? "low" : permission === "write" ? "medium" : "high", resource: definition.capability || "agent" };
  }
  return { permission: "deny", risk: "critical", resource: "unknown" };
}

export function sanitizeForAudit(value, depth = 0) {
  if (depth > 4) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 20).map(item => sanitizeForAudit(item, depth + 1));
  if (!value || typeof value !== "object") {
    const text = String(value ?? "");
    return SECRET_VALUE.test(text) ? "[redacted-secret]" : text.slice(0, 1000);
  }
  const output = {};
  for (const [key, item] of Object.entries(value).slice(0, 50)) {
    output[key] = SECRET_KEY.test(key) ? "[redacted]" : sanitizeForAudit(item, depth + 1);
  }
  return output;
}

function fingerprint(tool, input) {
  const normalized = { ...(input || {}) };
  delete normalized.approved;
  delete normalized.approvalToken;
  return crypto.createHash("sha256").update(`${tool}:${JSON.stringify(sanitizeForAudit(normalized))}`).digest("hex");
}

export function issueApproval({ tool, input = {}, sessionId = null, reason = "" } = {}) {
  const policy = getToolPolicy(tool);
  if (policy.permission !== "approval") throw new Error(`Tool '${tool}' tidak memerlukan approval khusus`);
  const token = crypto.randomUUID();
  approvals.set(token, {
    tool,
    sessionId: sessionId || null,
    fingerprint: fingerprint(tool, input),
    reason: String(reason || "").slice(0, 500),
    createdAt: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000,
    used: false
  });
  auditEvent({ actor: "user", action: "approval-issued", tool, input, outcome: "approved", meta: { expiresInMs: 5 * 60 * 1000 } });
  return { token, tool, expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString() };
}

export function consumeApproval({ token, tool, input = {}, sessionId = null } = {}) {
  if (!token) return { ok: false, error: "Human approval token wajib diisi" };
  const record = approvals.get(token);
  if (!record) return { ok: false, error: "Approval token tidak valid" };
  if (record.used) return { ok: false, error: "Approval token sudah digunakan" };
  if (Date.now() > record.expiresAt) return { ok: false, error: "Approval token sudah kedaluwarsa" };
  if (record.tool !== tool) return { ok: false, error: "Approval token tidak cocok dengan tool" };
  if (record.sessionId && record.sessionId !== sessionId) return { ok: false, error: "Approval token tidak cocok dengan session" };
  if (record.fingerprint !== fingerprint(tool, input)) return { ok: false, error: "Approval token tidak cocok dengan parameter tool" };
  record.used = true;
  auditEvent({ actor: "user", action: "approval-consumed", tool, input, outcome: "approved" });
  return { ok: true };
}

export function assertSecretSafeInput(tool, input = {}) {
  const serialized = JSON.stringify(input);
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(serialized)) {
    throw new Error("Secret/private key tidak boleh dikirim ke tool Agent");
  }
  if (tool === "terminal" && /(cat|type|head|tail|grep|print)\s+[^\n]*\.env(?:\.|\s|$)/i.test(serialized)) {
    throw new Error("Akses secret file melalui terminal ditolak");
  }
}

export function authorizeTool({ tool, input = {}, sessionId = null, approvalToken = null, definition = null } = {}) {
  const policy = getToolPolicy(tool, definition);
  assertSecretSafeInput(tool, input);

  if (policy.permission === "deny") {
    auditEvent({ actor: "agent", action: "tool-authorize", tool, input, outcome: "denied", meta: { reason: "unknown-tool" } });
    return { ok: false, status: 403, error: `Tool '${tool}' tidak diizinkan oleh governance policy` };
  }

  if (policy.permission === "approval") {
    const approval = consumeApproval({ token: approvalToken, tool, input, sessionId });
    if (!approval.ok) {
      auditEvent({ actor: "agent", action: "tool-authorize", tool, input, outcome: "blocked", meta: { reason: approval.error } });
      return { ok: false, status: 403, blocked: true, requiresApproval: true, risk: policy.risk, error: approval.error };
    }
  }

  if (tool === "terminal") {
    const commandPolicy = classifyCommand(input.command || "");
    if (!commandPolicy.allowed) {
      auditEvent({ actor: "agent", action: "tool-authorize", tool, input, outcome: "denied", meta: { reason: commandPolicy.reason } });
      return { ok: false, status: 403, error: commandPolicy.reason, risk: commandPolicy.risky ? "high" : policy.risk };
    }
  }

  auditEvent({ actor: "agent", action: "tool-authorize", tool, input, outcome: "allowed", meta: { risk: policy.risk, permission: policy.permission } });
  return { ok: true, policy };
}

export function auditEvent({ actor = "system", action, tool = null, input = {}, outcome, meta = {} } = {}) {
  const entry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    actor,
    action,
    tool,
    input: sanitizeForAudit(input),
    outcome,
    meta: sanitizeForAudit(meta)
  };
  audit.push(entry);
  while (audit.length > MAX_AUDIT_ENTRIES) audit.shift();
  return entry;
}

export function getAuditTrail({ limit = 100 } = {}) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 100, MAX_AUDIT_ENTRIES));
  return audit.slice(-safeLimit);
}
