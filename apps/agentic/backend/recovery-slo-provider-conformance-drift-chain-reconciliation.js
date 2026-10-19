import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";

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
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_DRIFT_CHAIN_OWNER_REQUIRED", "Owner drift-retention chain wajib ditentukan", 400);
  }
}

export function createRecoverySloProviderConformanceDriftChainReconciliationService({ driftWatchService, retainedEvidenceChainService } = {}) {
  if (!driftWatchService?.listRecoverySloProviderConformanceDriftEvents || !driftWatchService?.auditRecoverySloProviderConformanceDriftEvents
    || !retainedEvidenceChainService?.auditRecoverySloRetainedEvidenceChain || !retainedEvidenceChainService?.reconcileRecoverySloRetainedEvidenceChainAnchor) {
    throw new TypeError("Drift-retention reconciliation membutuhkan drift watch dan retained-evidence chain service");
  }
  async function inspectDriftEvents(ownerId) {
    const listed = await driftWatchService.listRecoverySloProviderConformanceDriftEvents(ownerId, { limit: 500, includePayload: true });
    const findings = [];
    for (const record of listed.items || []) {
      if (!record || record.ownerId !== ownerId || record.kind !== "recovery-slo-anchor-evidence-retention-record"
        || record.schemaVersion !== 1 || record.artifactType !== "provider_conformance_drift_event"
        || !["retained", "tombstone"].includes(record.status) || !Number.isFinite(Date.parse(record.capturedAt))
        || !Number.isFinite(Date.parse(record.expiresAt)) || !Number.isSafeInteger(record.retentionDays)
        || record.retentionDays < 1 || record.retentionDays > 3650 || !DIGEST.test(record.payloadDigest || "")
        || !DIGEST.test(record.digest || "") || record.digest !== digestRecord(record)) {
        findings.push({ code: "DRIFT_RETENTION_RECORD_INVALID", id: record?.id || null });
        continue;
      }
      if (record.status === "tombstone") {
        if (record.payload !== null || record.tombstone?.payloadDigest !== record.payloadDigest
          || record.tombstone?.reason !== "RETENTION_PERIOD_ELAPSED" || !Number.isFinite(Date.parse(record.tombstone?.expiredAt))) {
          findings.push({ code: "DRIFT_RETENTION_TOMBSTONE_INVALID", id: record.id });
        }
        continue;
      }
      const event = record.payload;
      const eventUnsigned = clean(event || {}); delete eventUnsigned.digest;
      const auditDigest = event?.audit ? sha256(canonical(event.audit)) : null;
      if (!event || event.ownerId !== ownerId || event.domain !== "agentic-v4-provider-conformance-drift-event"
        || event.eventType !== "provider_conformance_drift_detected" || event.eventId !== record.sourceId
        || event.audit?.ownerId !== ownerId || event.audit.status !== "drift_detected"
        || event.auditDigest !== auditDigest || event.digest !== sha256(canonical(eventUnsigned))
        || record.payloadDigest !== sha256(canonical(event)) || !Number.isFinite(Date.parse(event.capturedAt))
        || !validReason(event.reason) || !Number.isSafeInteger(event.retentionDays) || event.retentionDays < 1 || event.retentionDays > 3650) {
        findings.push({ code: "DRIFT_RETENTION_EVENT_BINDING_INVALID", id: record.id });
      }
    }
    return { status: findings.length ? "unhealthy" : "healthy", total: listed.items?.length || 0, findings,
      readOnly: true, mutationAllowed: false };
  }
  async function reconcile(ownerId) {
    assertOwner(ownerId);
    const [driftBefore, chainBefore] = await Promise.all([inspectDriftEvents(ownerId), retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId)]);
    if (driftBefore.status !== "healthy") throw new AgenticError("RECOVERY_SLO_DRIFT_CHAIN_RECORDS_UNHEALTHY",
      "Peristiwa drift-retention tidak sehat; rekonsiliasi ditolak", 409, { findings: driftBefore.findings });
    if (chainBefore.status === "unhealthy" || (chainBefore.findings || []).length) throw new AgenticError("RECOVERY_SLO_DRIFT_CHAIN_LEDGER_UNHEALTHY",
      "Retained-evidence chain ledger atau anchor menunjukkan konflik; rekonsiliasi ditolak", 409,
      { status: chainBefore.status, findings: chainBefore.findings });
    if (chainBefore.status === "not_initialized" && driftBefore.total === 0) {
      return { status: "no_events", driftBefore, chainBefore, chainAfter: chainBefore, readOnly: true, mutationAllowed: false };
    }
    const operation = await retainedEvidenceChainService.reconcileRecoverySloRetainedEvidenceChainAnchor(ownerId);
    if (operation.status === "blocked") throw new AgenticError("RECOVERY_SLO_DRIFT_CHAIN_RECONCILIATION_BLOCKED",
      "External retained-evidence chain tidak dapat direkonsiliasi secara aman", 409, { operation });
    const [driftAfter, chainAfter, driftAuditAfter] = await Promise.all([
      inspectDriftEvents(ownerId), retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId),
      driftWatchService.auditRecoverySloProviderConformanceDriftEvents(ownerId)
    ]);
    if (driftAfter.status !== "healthy" || chainAfter.status === "unhealthy" || (chainAfter.findings || []).length || driftAuditAfter.status !== "healthy") {
      throw new AgenticError("RECOVERY_SLO_DRIFT_CHAIN_POSTCHECK_FAILED", "Pemeriksaan pascarekonsiliasi gagal; chain tidak boleh dianggap sehat", 409,
        { driftFindings: driftAfter.findings, chainStatus: chainAfter.status, chainFindings: chainAfter.findings, driftAuditFindings: driftAuditAfter.findings });
    }
    return { status: chainAfter.status === "healthy" ? "reconciled" : chainAfter.status, operation,
      driftBefore, chainBefore, driftAfter, driftAuditAfter, chainAfter, readOnly: false, mutationAllowed: false };
  }
  return Object.freeze({ reconcileRecoverySloProviderConformanceDriftRetentionChain: reconcile,
    auditRecoverySloProviderConformanceDriftRetentionChain: async ownerId => {
      assertOwner(ownerId);
      const [drift, chain, driftAudit] = await Promise.all([inspectDriftEvents(ownerId),
        retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId),
        driftWatchService.auditRecoverySloProviderConformanceDriftEvents(ownerId)]);
      const healthy = drift.status === "healthy" && chain.status !== "unhealthy" && !(chain.findings || []).length && driftAudit.status === "healthy";
      return { status: healthy ? (chain.status === "local_only" ? "local_only" : chain.status === "degraded" ? "degraded" : "healthy") : "unhealthy",
        ownerId, drift, chain, driftAudit, findings: [...drift.findings, ...(chain.findings || []), ...(driftAudit.findings || [])],
        readOnly: true, mutationAllowed: false };
    } });
}
