import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const ARTIFACT = "retention_reconciliation_decision_gate_audit";
const DIGEST = /^[a-f0-9]{64}$/;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item);
  return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RETENTION_DECISION_GATE_AUDIT_OWNER_REQUIRED", "Owner decision-gate audit wajib ditentukan", 400);
  }
}
function validDecision(value) { return typeof value === "string" && value.trim().length >= 1 && value.trim().length <= 120 && !/[\u0000-\u001f\u007f]/.test(value); }

export function createRecoverySloRetentionDecisionGateAuditService({ gateService, retainedEvidenceService, clock = () => new Date().toISOString(), retentionDays = 90 } = {}) {
  if (typeof gateService?.requireRecoverySloRetentionReconciliationAttestationForDecision !== "function"
    || typeof retainedEvidenceService?.retainRecoverySloAnchorEvidence !== "function"
    || typeof retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence !== "function"
    || typeof retainedEvidenceService?.auditRecoverySloRetainedAnchorEvidence !== "function" || typeof clock !== "function") {
    throw new TypeError("Decision-gate audit membutuhkan gate service, retained-evidence service, dan clock");
  }
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) throw new TypeError("Decision-gate audit retentionDays harus 1–3650 hari");
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RETENTION_DECISION_GATE_AUDIT_CLOCK_INVALID", "Clock decision-gate audit tidak valid", 500);
    return new Date(time).toISOString();
  }
  async function writeAudit(ownerId, { decision, attestation, expectedAuditDigest, outcome, error = null, result = null, supersedesDecisionId = null }) {
    const decisionId = `retention-decision-gate-${randomUUID()}`;
    const unsigned = { domain: "agentic-v4-retention-reconciliation-decision-gate-audit", schemaVersion: 1,
      decisionId, ownerId, decision: decision.trim(), checkedAt: now(), outcome,
      attestationDigest: DIGEST.test(attestation?.attestationDigest || "") ? attestation.attestationDigest : null,
      expectedAuditDigest: DIGEST.test(expectedAuditDigest || "") ? expectedAuditDigest : null,
      expectedAuditDigestProvided: expectedAuditDigest != null,
      expectedAuditDigestFingerprint: expectedAuditDigest == null ? null : sha256(String(expectedAuditDigest)),
      errorCode: error?.code ? String(error.code).slice(0, 120) : null,
      supersedesDecisionId: typeof supersedesDecisionId === "string" ? supersedesDecisionId.slice(0, 120) : null,
      findingCodes: Array.isArray(error?.details?.findings) ? error.details.findings.slice(0, 20).map(item => String(item?.code || "UNKNOWN").slice(0, 120)) : [],
      gateResultDigest: result ? sha256(canonical(clean({ allowed: result.allowed, decision: result.decision,
        attestationDigest: result.attestationDigest, issuedAt: result.issuedAt, freshUntil: result.freshUntil }))) : null,
      claims: { decisionGateCalled: true, auditOnly: true, mutationAuthorized: false } };
    const payload = { ...unsigned, digest: digestRecord(unsigned) };
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: ARTIFACT,
      sourceId: decisionId, payload, retentionDays });
    return { decisionId, payload, retention };
  }
  async function evaluate(ownerId, attestation, options = {}) {
    assertOwner(ownerId);
    const decision = options?.decision ?? "unspecified";
    if (!validDecision(decision)) throw new AgenticError("RETENTION_DECISION_GATE_AUDIT_DECISION_INVALID", "Label keputusan wajib 1–120 karakter", 400);
    let result;
    try {
      result = await gateService.requireRecoverySloRetentionReconciliationAttestationForDecision(ownerId, attestation, options);
    } catch (error) {
      try { await writeAudit(ownerId, { decision, attestation, expectedAuditDigest: options.expectedAuditDigest, outcome: "denied", error }); }
      catch (auditError) {
        throw new AgenticError("RETENTION_DECISION_GATE_AUDIT_WRITE_FAILED", "Keputusan ditolak dan bukti audit penolakan gagal disimpan", 503,
          { originalErrorCode: error?.code || "DECISION_GATE_REJECTED", auditErrorCode: auditError?.code || "AUDIT_RETENTION_FAILED" });
      }
      throw error;
    }
    try {
      const audit = await writeAudit(ownerId, { decision, attestation, expectedAuditDigest: options.expectedAuditDigest, outcome: "allowed", result });
      return { ...result, auditEvidence: { decisionId: audit.decisionId, evidenceId: audit.retention?.id || null,
        status: audit.retention?.status || "retained" }, readOnly: true, mutationAllowed: false };
    } catch (error) {
      throw new AgenticError("RETENTION_DECISION_GATE_AUDIT_WRITE_FAILED", "Keputusan tidak dapat diizinkan karena bukti audit tidak berhasil disimpan", 503,
        { auditErrorCode: error?.code || "AUDIT_RETENTION_FAILED" });
    }
  }
  async function recordExternalAnchorFailure(ownerId, { decisionId, attestation, expectedAuditDigest, decision = "unspecified", error = null } = {}) {
    assertOwner(ownerId);
    if (typeof decisionId !== "string" || !decisionId.startsWith("retention-decision-gate-")) {
      throw new AgenticError("RETENTION_DECISION_GATE_AUDIT_SUPERSESSION_INVALID", "Decision ID yang digantikan tidak valid", 400);
    }
    const result = await writeAudit(ownerId, { decision, attestation, expectedAuditDigest, outcome: "denied",
      error: { code: "RETENTION_DECISION_GATE_EXTERNAL_ANCHOR_FAILED", details: { findings: [{ code: error?.code || "ANCHOR_FAILED" }] } },
      supersedesDecisionId: decisionId });
    return { decisionId: result.decisionId, supersedesDecisionId: decisionId, evidenceId: result.retention?.id || null, status: result.retention?.status || "retained" };
  }
  async function list(ownerId, { limit = 100 } = {}) {
    assertOwner(ownerId);
    const bounded = Math.min(500, Math.max(1, Number(limit) || 100));
    const result = await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true });
    const items = result.items.filter(item => item.artifactType === ARTIFACT).slice(0, bounded).map(item => ({ ...item,
      payload: item.status === "retained" ? item.payload : null }));
    return { items, count: items.length, readOnly: true, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [listed, overall] = await Promise.all([
      retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true }),
      retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId)
    ]);
    const records = listed.items.filter(item => item.artifactType === ARTIFACT), findings = [], validPayloads = [];
    let tombstones = 0;
    for (const item of records) {
      if (item.status === "tombstone") { tombstones++; continue; }
      const payload = item.payload;
      if (!payload || payload.domain !== "agentic-v4-retention-reconciliation-decision-gate-audit" || payload.schemaVersion !== 1
        || payload.ownerId !== ownerId || payload.decisionId !== item.sourceId || !validDecision(payload.decision)
        || !Number.isFinite(Date.parse(payload.checkedAt)) || !["allowed", "denied"].includes(payload.outcome)
        || !DIGEST.test(payload.digest || "") || payload.digest !== digestRecord(payload) || item.payloadDigest !== sha256(canonical(payload))
        || (payload.supersedesDecisionId != null && (typeof payload.supersedesDecisionId !== "string" || !payload.supersedesDecisionId.startsWith("retention-decision-gate-")))) {
        findings.push({ code: "RETENTION_DECISION_GATE_AUDIT_RECORD_INVALID", evidenceId: item.id }); continue;
      }
      if (payload.outcome === "allowed" && (!DIGEST.test(payload.attestationDigest || "") || !DIGEST.test(payload.gateResultDigest || ""))) {
        findings.push({ code: "RETENTION_DECISION_GATE_ALLOWED_RECORD_INCOMPLETE", evidenceId: item.id });
      }
      validPayloads.push(payload);
    }
    const superseded = new Set(validPayloads.filter(payload => payload.outcome === "denied" && payload.supersedesDecisionId).map(payload => payload.supersedesDecisionId));
    let allowed = 0, denied = 0;
    for (const payload of validPayloads) {
      if (superseded.has(payload.decisionId)) continue;
      if (payload.outcome === "allowed") allowed++; else denied++;
    }
    if (overall.status !== "healthy") findings.push({ code: "RETENTION_DECISION_GATE_EVIDENCE_STORE_UNHEALTHY" });
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, allowed, denied, superseded: superseded.size, tombstones,
      findings, retainedEvidenceStatus: overall.status, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ evaluateRecoverySloRetentionReconciliationDecisionWithAudit: evaluate,
    listRecoverySloRetentionReconciliationDecisionGateEvidence: list,
    auditRecoverySloRetentionReconciliationDecisionGateEvidence: audit,
    recordRecoverySloRetentionDecisionGateExternalAnchorFailure: recordExternalAnchorFailure,
    retentionDays });
}
