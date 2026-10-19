import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const BASELINE_KIND = "recovery-slo-provider-conformance-drift-baseline";
const CHALLENGE_KIND = "recovery-slo-provider-conformance-drift-baseline-challenge";
const REPORT_KIND = "recovery-slo-provider-identity-trust-policy-anchor-conformance-challenge";
const DRIFT_EVENT_DOMAIN = "agentic-v4-provider-conformance-drift-event";
const DIGEST = /^[a-f0-9]{64}$/;
const TTL_MS = 10 * 60 * 1000;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = clean(item);
  return result;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
const baselineId = ownerId => `recovery-slo-provider-conformance-drift-baseline-${ownerHash(ownerId)}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_OWNER_REQUIRED", "Owner conformance drift wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function contractSnapshot(provider) {
  const raw = provider?.contractInfo;
  if (!raw || typeof raw !== "object") return null;
  return { contractId: String(raw.contractId || "").slice(0, 100), version: String(raw.version || "").slice(0, 40),
    schemaVersion: Number.isSafeInteger(raw.schemaVersion) ? raw.schemaVersion : null, ownerScope: String(raw.ownerScope || "").slice(0, 80),
    casSemantics: String(raw.casSemantics || "").slice(0, 100),
    capabilities: Array.isArray(raw.capabilities) ? raw.capabilities.slice(0, 30).map(item => String(item).slice(0, 80)) : [] };
}
function liveSnapshot(provider) {
  const identity = typeof provider?.providerIdentity === "string" && provider.providerIdentity.trim()
    ? sha256(provider.providerIdentity.trim()) : null;
  const contract = contractSnapshot(provider);
  return { providerIdentityFingerprint: identity, providerContractDigest: contract ? sha256(canonical(contract)) : null,
    contractId: contract?.contractId || null, version: contract?.version || null };
}
function validReport(challenge, ownerId) {
  const report = challenge?.report;
  if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== REPORT_KIND || challenge.status !== "completed"
    || challenge.digest !== digestRecord(challenge) || !report || report.ownerId !== ownerId || report.providerDomain !== "provider_identity_trust_policy"
    || report.reportDigest !== challenge.reportDigest || !DIGEST.test(report.reportDigest || "")) return false;
  const copy = clean(report); delete copy.reportDigest;
  return sha256(canonical(copy)) === report.reportDigest && DIGEST.test(report.providerIdentityFingerprint || "")
    && DIGEST.test(report.providerContractDigest || "");
}

export function createRecoverySloProviderConformanceDriftWatchService({ store, provider, conformanceService = null, retainedEvidenceService = null, retentionDays = 90, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function") {
    throw new TypeError("Provider conformance drift watch membutuhkan evidence store dan clock");
  }
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) throw new TypeError("Provider conformance drift retentionDays harus 1–3650 hari");
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_CLOCK_INVALID", "Clock conformance drift tidak valid", 500);
    return new Date(value).toISOString();
  }
  async function getBaseline(ownerId) {
    const baseline = await store.getEvidence(ownerId, baselineId(ownerId));
    if (!baseline) return { status: "missing", baseline: null };
    if (baseline.ownerId !== ownerId || baseline.kind !== BASELINE_KIND || baseline.id !== baselineId(ownerId)
      || !Number.isSafeInteger(baseline.revision) || baseline.revision < 1 || !DIGEST.test(baseline.digest || "")
      || baseline.digest !== digestRecord(baseline) || !DIGEST.test(baseline.providerIdentityFingerprint || "")
      || !DIGEST.test(baseline.providerContractDigest || "") || !Number.isFinite(Date.parse(baseline.acceptedAt))) {
      return { status: "unhealthy", baseline: null, finding: "CONFORMANCE_DRIFT_BASELINE_INVALID" };
    }
    return { status: "present", baseline };
  }
  async function prepare(ownerId, { challengeId, reason, rotate = false } = {}) {
    assertOwner(ownerId);
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_REASON_INVALID", "Alasan baseline wajib 12–240 karakter", 400);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!validReport(challenge, ownerId) || challenge.report.conformant !== true) {
      throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_SOURCE_REPORT_INVALID", "Baseline harus bersumber dari laporan conformance valid yang conformant", 409);
    }
    const live = liveSnapshot(provider);
    if (live.providerIdentityFingerprint !== challenge.report.providerIdentityFingerprint
      || live.providerContractDigest !== challenge.report.providerContractDigest) {
      throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_SOURCE_PROVIDER_CHANGED", "Provider berubah sejak laporan conformance; jalankan conformance baru sebelum baseline diterima", 409);
    }
    if (conformanceService?.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance) {
      const sourceAudit = await conformanceService.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId);
      if (sourceAudit.status !== "healthy") throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_CONFORMANCE_AUDIT_UNHEALTHY", "Audit laporan conformance atau retained evidence tidak sehat", 409,
        { status: sourceAudit.status, findings: sourceAudit.findings });
    }
    const current = await getBaseline(ownerId);
    if (current.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_BASELINE_UNHEALTHY", "Baseline lama tidak valid", 409);
    const action = current.status === "missing" ? "enroll" : "rotate";
    if (action === "rotate" && rotate !== true) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_ROTATION_EXPLICIT_REQUIRED", "Rotasi baseline harus diminta secara eksplisit", 409);
    if (action === "enroll" && rotate === true) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_ROTATION_NOT_APPLICABLE", "Belum ada baseline yang dapat dirotasi", 409);
    const createdAt = now(), id = `recovery-slo-provider-conformance-drift-baseline-challenge-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "prepared", action, sourceChallengeId: challenge.id,
      sourceChallengeDigest: challenge.digest, sourceReportDigest: challenge.reportDigest,
      providerIdentityFingerprint: challenge.report.providerIdentityFingerprint, providerContractDigest: challenge.report.providerContractDigest,
      expectedBaselineRevision: current.baseline?.revision ?? 0, expectedBaselineDigest: current.baseline?.digest ?? null,
      reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + TTL_MS).toISOString() };
    const record = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, record, { overwrite: false });
    return { challengeId: id, ownerId, action, sourceChallengeId: challenge.id, sourceReportDigest: challenge.reportDigest,
      expectedBaselineRevision: record.expectedBaselineRevision, expectedBaselineDigest: record.expectedBaselineDigest,
      createdAt, expiresAt: record.expiresAt, challengeDigest: record.digest,
      confirmation: `APPLY CONFORMANCE DRIFT BASELINE ${record.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function apply(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_CHALLENGE_INVALID", "Challenge baseline tidak valid", 409);
    }
    if (challenge.status === "used") throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_REPLAY", "Challenge baseline sudah digunakan", 409);
    if (challenge.status !== "prepared" || Date.parse(challenge.expiresAt) <= Date.parse(now())) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_CHALLENGE_EXPIRED", "Challenge baseline kedaluwarsa", 409);
    if (confirmation !== `APPLY CONFORMANCE DRIFT BASELINE ${challenge.digest.slice(0, 12)}`) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_CONFIRMATION_INVALID", "Konfirmasi baseline tidak cocok", 403);
    const source = await store.getEvidence(ownerId, challenge.sourceChallengeId);
    if (!validReport(source, ownerId) || source.digest !== challenge.sourceChallengeDigest || source.reportDigest !== challenge.sourceReportDigest
      || source.report.providerIdentityFingerprint !== challenge.providerIdentityFingerprint || source.report.providerContractDigest !== challenge.providerContractDigest
      || source.report.conformant !== true) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_SOURCE_STALE", "Laporan sumber berubah atau tidak lagi valid", 409);
    if (conformanceService?.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance) {
      const sourceAudit = await conformanceService.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId);
      if (sourceAudit.status !== "healthy") throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_CONFORMANCE_AUDIT_UNHEALTHY", "Audit conformance berubah setelah challenge dibuat", 409,
        { status: sourceAudit.status, findings: sourceAudit.findings });
    }
    const current = await getBaseline(ownerId);
    if (current.status === "unhealthy" || (current.baseline?.revision ?? 0) !== challenge.expectedBaselineRevision
      || (current.baseline?.digest ?? null) !== challenge.expectedBaselineDigest) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_BASELINE_STALE", "Baseline berubah setelah challenge dibuat", 409);
    if ((challenge.action === "enroll" && current.status !== "missing") || (challenge.action === "rotate" && current.status !== "present")) {
      throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_ACTION_STALE", "Aksi baseline tidak cocok dengan keadaan terkini", 409);
    }
    const at = now(), previous = current.baseline;
    const unsigned = { id: baselineId(ownerId), ownerId, kind: BASELINE_KIND, schemaVersion: 1, revision: (previous?.revision || 0) + 1,
      providerIdentityFingerprint: challenge.providerIdentityFingerprint, providerContractDigest: challenge.providerContractDigest,
      sourceChallengeId: source.id, sourceChallengeDigest: source.digest, sourceReportDigest: source.reportDigest,
      previousBaselineDigest: previous?.digest || null, acceptedAt: at, reason: challenge.reason, historyNotProven: !previous };
    const baseline = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, baseline, previous ? { expectedVersion: previous._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, baseline.id);
    if (!saved || saved.digest !== baseline.digest || saved.digest !== digestRecord(saved)) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_BASELINE_WRITE_INVALID", "Baseline gagal diverifikasi setelah penulisan", 409);
    const used = { ...clean(challenge), status: "used", usedAt: at, appliedBaselineDigest: saved.digest };
    used.digest = digestRecord(used);
    await store.putEvidence(ownerId, used, { expectedVersion: challenge._storage?.version });
    return { status: previous ? "rotated" : "enrolled", ownerId, revision: saved.revision, baselineDigest: saved.digest,
      providerIdentityFingerprint: saved.providerIdentityFingerprint, providerContractDigest: saved.providerContractDigest,
      historyNotProven: saved.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const current = await getBaseline(ownerId);
    if (current.status === "missing") return { status: "baseline_missing", ownerId, finding: "CONFORMANCE_DRIFT_BASELINE_NOT_ENROLLED", readOnly: true, mutationAllowed: false };
    if (current.status === "unhealthy") return { status: "unhealthy", ownerId, finding: current.finding, readOnly: true, mutationAllowed: false };
    const baseline = current.baseline, live = liveSnapshot(provider), findings = [];
    const conformanceAudit = conformanceService?.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance
      ? await conformanceService.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId)
      : { status: "not_configured", findings: [] };
    if (conformanceAudit.status === "unhealthy") findings.push(...(conformanceAudit.findings || []).map(item => ({ code: "CONFORMANCE_EVIDENCE_INTEGRITY_FAILURE", detail: item.code || null })));
    if (live.providerIdentityFingerprint !== baseline.providerIdentityFingerprint) findings.push({ code: "PROVIDER_IDENTITY_DRIFT", expected: baseline.providerIdentityFingerprint, actual: live.providerIdentityFingerprint });
    if (live.providerContractDigest !== baseline.providerContractDigest) findings.push({ code: "PROVIDER_CONTRACT_DRIFT", expected: baseline.providerContractDigest, actual: live.providerContractDigest });
    const reports = (await store.listEvidence(ownerId)).filter(item => item?.kind === REPORT_KIND && item.status === "completed");
    let latestReportAt = null;
    for (const report of reports) {
      if (Date.parse(report.completedAt || 0) <= Date.parse(baseline.acceptedAt)) continue;
      if (!validReport(report, ownerId)) { findings.push({ code: "CONFORMANCE_DRIFT_REPORT_INVALID", challengeId: report.id }); continue; }
      latestReportAt = !latestReportAt || report.completedAt > latestReportAt ? report.completedAt : latestReportAt;
      if (report.report.conformant !== true) findings.push({ code: "PROVIDER_CONFORMANCE_REGRESSION", challengeId: report.id, reportDigest: report.reportDigest });
      if (report.report.providerIdentityFingerprint !== baseline.providerIdentityFingerprint) findings.push({ code: "PROVIDER_IDENTITY_DRIFT_IN_CONFORMANCE_REPORT", challengeId: report.id });
      if (report.report.providerContractDigest !== baseline.providerContractDigest) findings.push({ code: "PROVIDER_CONTRACT_DRIFT_IN_CONFORMANCE_REPORT", challengeId: report.id });
    }
    return { status: findings.length ? "drift_detected" : "healthy", ownerId, baseline: { revision: baseline.revision,
      digest: baseline.digest, acceptedAt: baseline.acceptedAt, sourceReportDigest: baseline.sourceReportDigest,
      providerIdentityFingerprint: baseline.providerIdentityFingerprint, providerContractDigest: baseline.providerContractDigest,
      historyNotProven: baseline.historyNotProven }, current: live, latestReportAt, findings,
      conformanceAudit: { status: conformanceAudit.status, findings: conformanceAudit.findings || [] },
      baselineMutationAuthorized: false, readOnly: true, mutationAllowed: false };
  }
  async function captureDriftEvent(ownerId, { reason, retentionDays: requestedDays = retentionDays } = {}) {
    assertOwner(ownerId);
    if (!retainedEvidenceService?.retainRecoverySloAnchorEvidence || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence) {
      throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_RETENTION_NOT_CONFIGURED", "Retained evidence service belum dikonfigurasi", 503);
    }
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_EVENT_REASON_INVALID", "Alasan event wajib 12–240 karakter", 400);
    if (!Number.isSafeInteger(requestedDays) || requestedDays < 1 || requestedDays > 3650) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_EVENT_RETENTION_INVALID", "Retensi event harus 1–3650 hari", 400);
    const report = await audit(ownerId);
    if (report.status !== "drift_detected") return { status: "no_drift_event", report, readOnly: true, mutationAllowed: false };
    const auditDigest = sha256(canonical(report));
    const eventId = `provider-conformance-drift-${ownerHash(ownerId)}-${auditDigest.slice(0, 24)}`;
    const existing = (await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true })).items
      .find(item => item.artifactType === "provider_conformance_drift_event" && item.sourceId === eventId);
    if (existing) {
      if (existing.status !== "retained" || existing.payload?.digest !== digestRecord(existing.payload)
        || existing.payload?.auditDigest !== auditDigest) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_EVENT_RETENTION_CORRUPT", "Event drift yang sudah tersimpan tidak valid atau sudah dipangkas", 409);
      return { status: "retained", event: existing.payload, retention: { id: existing.id, status: existing.status, expiresAt: existing.expiresAt, idempotent: true }, readOnly: false, mutationAllowed: false };
    }
    const capturedAt = now();
    const unsigned = { domain: DRIFT_EVENT_DOMAIN, schemaVersion: 1, eventId, ownerId, eventType: "provider_conformance_drift_detected",
      capturedAt, reason: reason.trim(), auditDigest, audit: clean(report), retentionDays: requestedDays,
      claims: { driftSnapshotBound: true, baselineMutationAuthorized: false, approvalGranted: false } };
    const event = { ...unsigned, digest: digestRecord(unsigned) };
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, {
      artifactType: "provider_conformance_drift_event", sourceId: eventId, payload: event, retentionDays: requestedDays });
    return { status: "retained", event, retention, readOnly: false, mutationAllowed: false };
  }
  async function listDriftEvents(ownerId, { limit = 100, includePayload = false } = {}) {
    assertOwner(ownerId);
    if (!retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_RETENTION_NOT_CONFIGURED", "Retained evidence service belum dikonfigurasi", 503);
    const bounded = Math.min(500, Math.max(1, Number(limit) || 100));
    const result = await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload });
    const items = result.items.filter(item => item.artifactType === "provider_conformance_drift_event").slice(0, bounded);
    return { ...result, items, count: items.length, readOnly: true, mutationAllowed: false };
  }
  async function auditDriftEvents(ownerId) {
    assertOwner(ownerId);
    if (!retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence || !retainedEvidenceService?.auditRecoverySloRetainedAnchorEvidence) {
      return { status: "not_configured", ownerId, findings: [{ code: "CONFORMANCE_DRIFT_EVENT_RETENTION_NOT_CONFIGURED" }], readOnly: true, mutationAllowed: false };
    }
    const [listed, overall] = await Promise.all([
      retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true }),
      retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId)
    ]);
    const records = listed.items.filter(item => item.artifactType === "provider_conformance_drift_event"), findings = [];
    let active = 0, tombstones = 0, expired = 0;
    for (const record of records) {
      if (record.status === "tombstone") { tombstones++; continue; }
      active++;
      const event = record.payload;
      if (!event || event.ownerId !== ownerId || event.domain !== DRIFT_EVENT_DOMAIN || event.eventType !== "provider_conformance_drift_detected"
        || event.eventId !== record.sourceId || event.audit?.ownerId !== ownerId || event.audit.status !== "drift_detected"
        || event.auditDigest !== sha256(canonical(event.audit)) || event.digest !== digestRecord(event)
        || !Number.isFinite(Date.parse(event.capturedAt)) || !validReason(event.reason)
        || !Number.isSafeInteger(event.retentionDays) || event.retentionDays < 1 || event.retentionDays > 3650
        || !DIGEST.test(event.auditDigest || "")) findings.push({ code: "CONFORMANCE_DRIFT_EVENT_INVALID", evidenceId: record.id });
      if (Date.parse(record.expiresAt) <= Date.parse(now())) expired++;
    }
    if (overall.status !== "healthy") findings.push({ code: "RETAINED_EVIDENCE_STORE_UNHEALTHY", findings: overall.findings?.slice(0, 20) || [] });
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, active, tombstones, expiredRetained: expired,
      retentionDays, findings, readOnly: true, mutationAllowed: false };
  }
  async function pruneDriftEvents(ownerId, { limit = 100 } = {}) {
    assertOwner(ownerId);
    if (!retainedEvidenceService?.pruneExpiredRecoverySloRetainedAnchorEvidence) throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_RETENTION_NOT_CONFIGURED", "Pruning retained evidence belum tersedia", 503);
    const auditResult = await auditDriftEvents(ownerId);
    if (auditResult.status !== "healthy") throw new AgenticError("RECOVERY_SLO_CONFORMANCE_DRIFT_EVENT_AUDIT_UNHEALTHY", "Audit event drift tidak sehat; pruning ditolak", 409, { findings: auditResult.findings });
    return retainedEvidenceService.pruneExpiredRecoverySloRetainedAnchorEvidence(ownerId, { limit, artifactTypes: ["provider_conformance_drift_event"] });
  }
  return Object.freeze({ prepareRecoverySloProviderConformanceDriftBaseline: prepare,
    applyRecoverySloProviderConformanceDriftBaseline: apply, auditRecoverySloProviderConformanceDrift: audit,
    captureRecoverySloProviderConformanceDriftEvent: captureDriftEvent, listRecoverySloProviderConformanceDriftEvents: listDriftEvents,
    auditRecoverySloProviderConformanceDriftEvents: auditDriftEvents, pruneExpiredRecoverySloProviderConformanceDriftEvents: pruneDriftEvents,
    configured: Boolean(provider), retentionDays });
}
