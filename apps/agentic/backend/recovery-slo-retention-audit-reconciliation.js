import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";

const DIGEST = /^[a-f0-9]{64}$/;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_RETENTION_RECONCILIATION_OWNER_REQUIRED", "Owner retention reconciliation wajib ditentukan", 400);
  }
}

export function createRecoverySloRetentionAuditReconciliationService({ store, retainedEvidenceService, retainedEvidenceChainService,
  trustPolicyConformanceService = null, providerIdentityAssuranceService = null } = {}) {
  if (!store?.listEvidence || !retainedEvidenceService?.auditRecoverySloRetainedAnchorEvidence
    || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence || !retainedEvidenceChainService?.auditRecoverySloRetainedEvidenceChain
    || !retainedEvidenceChainService?.getRecoverySloRetainedEvidenceChainStatus
    || !retainedEvidenceChainService?.reconcileRecoverySloRetainedEvidenceChainAnchor) {
    throw new TypeError("Retention audit reconciliation membutuhkan store, retained evidence registry, dan evidence chain service");
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [retention, chain, chainStatus, conformance, authority] = await Promise.all([
      retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId),
      retainedEvidenceChainService.auditRecoverySloRetainedEvidenceChain(ownerId),
      retainedEvidenceChainService.getRecoverySloRetainedEvidenceChainStatus(ownerId),
      trustPolicyConformanceService?.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance
        ? trustPolicyConformanceService.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId)
        : Promise.resolve({ status: "not_configured", findings: [], total: 0 }),
      providerIdentityAssuranceService?.auditRecoverySloProviderIdentityPolicyAuthority
        ? providerIdentityAssuranceService.auditRecoverySloProviderIdentityPolicyAuthority(ownerId)
        : Promise.resolve({ status: "not_configured", finding: "POLICY_AUTHORITY_AUDIT_NOT_CONFIGURED" })
    ]);
    const records = (await store.listEvidence(ownerId)).filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record");
    const findings = [];
    const chainCanAdvance = ["behind_local", "anchor_pending"].includes(chainStatus.status) && (chain.findings || []).length === 0;
    const recoverableRetentionAnchorFinding = finding => chainCanAdvance && finding?.code === "RETAINED_EVIDENCE_CHAIN_UNHEALTHY"
      && ["behind_local", "anchor_pending"].includes(finding.status);
    const conformanceChallenges = (await store.listEvidence(ownerId)).filter(item => item?.kind === "recovery-slo-provider-identity-trust-policy-anchor-conformance-challenge");
    const retainedBySource = new Map(records.filter(item => item.artifactType === "provider_conformance")
      .map(item => [`${item.sourceId}:${item.payload?.providerDomain || "tombstone"}`, item]));
    for (const challenge of conformanceChallenges) {
      if (challenge.status !== "completed") continue;
      const report = challenge.report;
      const reportCopy = report && { ...report };
      if (reportCopy) delete reportCopy.reportDigest;
      const validReport = challenge.digest && challenge.digest === digestRecordForReconciliation(challenge)
        && report && report.ownerId === ownerId && report.providerDomain === "provider_identity_trust_policy"
        && DIGEST.test(challenge.reportDigest || "") && report.reportDigest === challenge.reportDigest
        && sha256(canonical(reportCopy)) === challenge.reportDigest;
      if (!validReport) findings.push({ code: "RETENTION_RECONCILIATION_CONFORMANCE_REPORT_INVALID", challengeId: challenge.id });
      const evidence = retainedBySource.get(`${challenge.id}:provider_identity_trust_policy`)
        || [...retainedBySource.values()].find(item => item.sourceId === challenge.id && item.status === "tombstone");
      if (!evidence) findings.push({ code: "RETENTION_RECONCILIATION_CONFORMANCE_EVIDENCE_MISSING", challengeId: challenge.id });
      else if (evidence.status === "retained" && (evidence.payload?.reportDigest !== challenge.reportDigest
        || evidence.payload?.challengeDigest !== challenge.digest || evidence.payload?.providerDomain !== "provider_identity_trust_policy")) {
        findings.push({ code: "RETENTION_RECONCILIATION_CONFORMANCE_BINDING_MISMATCH", challengeId: challenge.id, evidenceId: evidence.id });
      }
    }
    for (const result of [retention, chain, conformance]) {
      for (const finding of result.findings || []) {
        if (result === retention && recoverableRetentionAnchorFinding(finding)) continue;
        findings.push({ code: finding.code || "RETENTION_RECONCILIATION_SOURCE_FINDING", source: result === retention ? "retention" : result === chain ? "chain" : "conformance", detail: finding.id || finding.challengeId || finding.detail || null });
      }
    }
    if (authority.status && !["healthy", "not_configured", "not_initialized"].includes(authority.status)) {
      findings.push({ code: "RETENTION_RECONCILIATION_POLICY_AUTHORITY_UNHEALTHY", status: authority.status, detail: authority.finding || null });
    }
    const retentionOnlyAnchorLag = chainCanAdvance && retention.status === "unhealthy" && (retention.findings || []).length > 0
      && retention.findings.every(recoverableRetentionAnchorFinding);
    const blocking = findings.length > 0 || (retention.status === "unhealthy" && !retentionOnlyAnchorLag)
      || [chain.status, conformance.status, authority.status].some(status => status === "unhealthy" || status === "rollback_detected" || status === "mismatch");
    const degraded = [retentionOnlyAnchorLag ? "degraded" : retention.status, chain.status, chainStatus.status, conformance.status, authority.status].some(status =>
      ["local_only", "not_initialized", "not_configured", "degraded", "behind_local", "anchor_pending", "enrollment_required", "unavailable"].includes(status));
    return { status: blocking ? "unhealthy" : degraded ? "degraded" : "healthy", ownerId,
      sources: { retainedEvidence: retention.status, retainedEvidenceChain: chain.status, chainAnchor: chainStatus.status,
        trustPolicyConformance: conformance.status, policyAuthority: authority.status },
      counts: { retainedRecords: records.length, conformanceChallenges: conformance.total || 0,
        chainSequence: chain.sequence || 0, chainRecordCount: chain.recordCount || 0 },
      findings, reconciliation: { mutationPerformed: false, safeToAdvanceChainAnchor: !blocking && chainCanAdvance, automaticRepairPerformed: false },
      readOnly: true, mutationAllowed: false };
  }
  async function reconcile(ownerId) {
    const before = await audit(ownerId);
    if (before.status === "unhealthy") return { status: "blocked", ownerId, before, after: null,
      finding: "RETENTION_AUDIT_RECONCILIATION_BLOCKED_BY_INTEGRITY_FINDINGS", mutationPerformed: false, readOnly: true, mutationAllowed: false };
    if (!before.reconciliation.safeToAdvanceChainAnchor) return { status: before.status === "degraded" ? "no_action_required_or_unproven" : "already_consistent",
      ownerId, before, after: before, mutationPerformed: false, readOnly: true, mutationAllowed: false };
    const result = await retainedEvidenceChainService.reconcileRecoverySloRetainedEvidenceChainAnchor(ownerId);
    if (!new Set(["anchored", "local_only"]).has(result.status)) return { status: "blocked", ownerId, before, chainReconciliation: result,
      after: null, finding: result.finding || "RETENTION_CHAIN_ANCHOR_RECONCILIATION_FAILED", mutationPerformed: false, readOnly: true, mutationAllowed: false };
    const after = await audit(ownerId);
    return { status: after.status === "healthy" ? "reconciled" : after.status === "degraded" ? "reconciled_with_limitations" : "blocked",
      ownerId, before, chainReconciliation: result, after, mutationPerformed: result.status === "anchored",
      mutatedOnlyExternalChainAnchor: result.status === "anchored", localEvidenceRewritten: false, readOnly: result.status !== "anchored", mutationAllowed: false };
  }
  return Object.freeze({ auditRecoverySloRetentionEvidenceReconciliation: audit,
    reconcileRecoverySloRetentionEvidenceAudit: reconcile });
}
function digestRecordForReconciliation(value) {
  const copy = structuredClone(value); delete copy.digest; delete copy._storage;
  return sha256(canonical(copy));
}
