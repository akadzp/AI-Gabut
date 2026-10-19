import { createHash, randomUUID } from "node:crypto";
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
const validReason = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
  && !/[\u0000-\u001f\u007f]/.test(value);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_OWNER_REQUIRED", "Owner checkpoint lintas-domain wajib ditentukan", 400);
}
function normalizeIdentity(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const text = value.trim();
  try { const url = new URL(text); url.hash = ""; url.search = ""; return url.toString().replace(/\/+$/, "").toLowerCase(); }
  catch { return text.toLowerCase(); }
}
function dateMs(value) { const result = Date.parse(String(value ?? "")); return Number.isFinite(result) ? result : null; }

export function createRecoverySloCrossDomainSnapshotAnchorGovernanceService({ store, domains = [], clock = () => new Date().toISOString(),
  maxAgeMs = 86400000, futureSkewMs = 60000, retentionDays = 90 } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function"
    || !Array.isArray(domains) || !domains.length || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 60000 || maxAgeMs > 30 * 86400000
    || !Number.isSafeInteger(futureSkewMs) || futureSkewMs < 0 || futureSkewMs > 600000
    || !Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    throw new TypeError("Governance checkpoint lintas-domain memerlukan store, domain, clock, dan kebijakan freshness/retensi yang valid");
  }
  const registry = new Map();
  for (const item of domains) {
    if (!item || typeof item.domain !== "string" || !/^[a-z0-9_]{3,80}$/.test(item.domain) || registry.has(item.domain)
      || item.service && typeof item.service.getExternalSnapshotCheckpointStatus !== "function") {
      throw new TypeError("Registry checkpoint lintas-domain tidak valid atau memiliki domain duplikat");
    }
    registry.set(item.domain, { ...item, provider: item.provider ?? null, required: Boolean(item.required) });
  }
  const challengeKind = "recovery-slo-cross-domain-snapshot-anchor-conformance-challenge";
  const reportKind = "recovery-slo-cross-domain-snapshot-anchor-conformance-report";
  const sequenceKind = "recovery-slo-cross-domain-snapshot-anchor-conformance-sequence-slot";
  const now = () => {
    const value = dateMs(clock());
    if (value == null) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_CLOCK_INVALID", "Clock checkpoint lintas-domain tidak valid", 500);
    return new Date(value).toISOString();
  };
  const save = async (ownerId, previous, patch) => {
    const unsigned = { ...clean(previous), ...patch, ownerId };
    delete unsigned.digest;
    const record = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, record, previous?._storage?.version != null
      ? { expectedVersion: previous._storage.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, record.id);
    if (!saved || saved.digest !== digestRecord(saved)) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_RECORD_WRITE_FAILED", "Record governance checkpoint gagal diverifikasi", 409);
    return saved;
  };
  async function reserveConformanceSequence(ownerId, domain, challengeId) {
    const rows = await store.listEvidence(ownerId);
    let sequence = Math.max(0, ...rows.filter(row => row?.ownerId === ownerId && row.kind === sequenceKind && row.domain === domain
      && Number.isSafeInteger(row.sequence)).map(row => row.sequence)) + 1;
    for (let attempt = 0; attempt < 100; attempt++, sequence++) {
      const id = `cross-domain-snapshot-conformance-sequence-${sha256(ownerId).slice(0, 24)}-${domain}-${sequence}`;
      const unsigned = { id, ownerId, kind: sequenceKind, schemaVersion: 1, domain, sequence, challengeId, reservedAt: now() };
      const record = { ...unsigned, digest: digestRecord(unsigned) };
      try { await store.putEvidence(ownerId, record, { overwrite: false }); }
      catch {
        const collision = await store.getEvidence(ownerId, id);
        if (collision) continue;
        throw new AgenticError("CROSS_DOMAIN_CONFORMANCE_SEQUENCE_RESERVATION_FAILED", "Sequence conformance tidak dapat direservasi secara atomik", 409);
      }
      const saved = await store.getEvidence(ownerId, id);
      if (!saved || saved.digest !== digestRecord(saved) || saved.challengeId !== challengeId)
        throw new AgenticError("CROSS_DOMAIN_CONFORMANCE_SEQUENCE_RESERVATION_INVALID", "Sequence conformance gagal diverifikasi", 409);
      return sequence;
    }
    throw new AgenticError("CROSS_DOMAIN_CONFORMANCE_SEQUENCE_EXHAUSTED", "Sequence conformance tidak dapat dialokasikan", 409);
  }
  const providerIdentity = item => normalizeIdentity(item.provider?.providerIdentity || item.provider?.baseUrl || item.endpoint || null);
  const fingerprint = identity => identity ? sha256(identity) : null;
  const providerSnapshot = domain => {
    const item = registry.get(domain);
    if (!item) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_DOMAIN_UNKNOWN", "Domain checkpoint tidak dikenal", 404);
    const identity = providerIdentity(item), contract = item.provider?.contractInfo || null;
    const normalizedContract = contract ? { contractId: String(contract.contractId || "").slice(0, 100),
      version: String(contract.version || "").slice(0, 40), schemaVersion: Number.isSafeInteger(contract.schemaVersion) ? contract.schemaVersion : null,
      ownerScope: String(contract.ownerScope || "").slice(0, 80), casSemantics: String(contract.casSemantics || "").slice(0, 100),
      capabilities: Array.isArray(contract.capabilities) ? contract.capabilities.slice(0, 30).map(value => String(value).slice(0, 80)) : [] } : null;
    return { domain, providerConfigured: Boolean(item.provider), providerIdentityFingerprint: fingerprint(identity),
      providerContractDigest: normalizedContract ? sha256(canonical(normalizedContract)) : null,
      contractVersion: normalizedContract?.version || null, contractId: normalizedContract?.contractId || null,
      required: item.required, infrastructureIndependenceProven: false, readOnly: true, mutationAllowed: false };
  };

  async function auditIndependence(ownerId) {
    assertOwner(ownerId);
    const configured = [...registry.values()].filter(item => item.provider);
    const findings = [], identities = new Map(), instances = new Map(), endpoints = new Map();
    const entries = [...registry.values()].map(item => {
      const identity = providerIdentity(item), identityFingerprint = fingerprint(identity);
      if (item.required && !item.provider) findings.push({ code: "CROSS_DOMAIN_REQUIRED_PROVIDER_MISSING", domain: item.domain });
      if (item.provider && !identity) findings.push({ code: "CROSS_DOMAIN_PROVIDER_IDENTITY_UNVERIFIABLE", domain: item.domain });
      if (item.provider) {
        if (instances.has(item.provider)) findings.push({ code: "CROSS_DOMAIN_PROVIDER_INSTANCE_REUSED", domains: [instances.get(item.provider), item.domain] });
        else instances.set(item.provider, item.domain);
        if (identity) {
          if (identities.has(identity)) findings.push({ code: "CROSS_DOMAIN_PROVIDER_IDENTITY_COLLISION", domains: [identities.get(identity), item.domain], identityFingerprint });
          else identities.set(identity, item.domain);
        }
        const endpoint = normalizeIdentity(item.endpoint || item.provider?.baseUrl || null);
        if (endpoint) {
          if (endpoints.has(endpoint)) findings.push({ code: "CROSS_DOMAIN_ENDPOINT_COLLISION", domains: [endpoints.get(endpoint), item.domain], endpointFingerprint: sha256(endpoint) });
          else endpoints.set(endpoint, item.domain);
        }
      }
      return { domain: item.domain, required: item.required, providerConfigured: Boolean(item.provider), identityFingerprint,
        contractVersion: String(item.provider?.contractInfo?.version || "unknown").slice(0, 40), identityObservable: Boolean(identity) };
    });
    const hard = findings.some(item => ["CROSS_DOMAIN_REQUIRED_PROVIDER_MISSING", "CROSS_DOMAIN_PROVIDER_INSTANCE_REUSED", "CROSS_DOMAIN_PROVIDER_IDENTITY_COLLISION", "CROSS_DOMAIN_ENDPOINT_COLLISION"].includes(item.code));
    const unverifiable = findings.some(item => item.code === "CROSS_DOMAIN_PROVIDER_IDENTITY_UNVERIFIABLE");
    return { status: hard ? "unhealthy" : unverifiable ? "unverifiable" : configured.length ? "healthy" : "not_initialized",
      ownerId, domains: entries, findings, configuredProviderCount: configured.length,
      infrastructureIndependenceProven: false, readOnly: true, mutationAllowed: false };
  }

  async function prepareConformance(ownerId, { domain, reason } = {}) {
    assertOwner(ownerId);
    const item = registry.get(domain);
    if (!item) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_DOMAIN_UNKNOWN", "Domain checkpoint tidak dikenal", 404);
    if (!item.provider) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_PROVIDER_REQUIRED", "Provider domain belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_REASON_INVALID", "Alasan conformance wajib 12–240 karakter", 400);
    const createdAt = now(), id = `cross-domain-snapshot-conformance-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: challengeKind, schemaVersion: 1, status: "issued", domain, reason: reason.trim(),
      expectedProviderIdentityFingerprint: fingerprint(providerIdentity(item)), createdAt,
      expiresAt: new Date(Date.parse(createdAt) + 5 * 60_000).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, challengeDigest: challenge.digest, domain, createdAt, expiresAt: challenge.expiresAt,
      confirmation: `RUN ${domain.toUpperCase()} SNAPSHOT ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`,
      writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }

  async function runConformance(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== challengeKind || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_CHALLENGE_INVALID", "Challenge conformance tidak ditemukan atau digest tidak valid", 409);
    if (challenge.status === "completed") return { status: challenge.report.status, report: challenge.report, reportDigest: challenge.reportDigest, idempotent: true };
    const item = registry.get(challenge.domain);
    if (!item?.provider) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_PROVIDER_REQUIRED", "Provider domain belum dikonfigurasi", 503);
    if (challenge.status !== "issued" || Date.parse(now()) >= Date.parse(challenge.expiresAt))
      throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_CHALLENGE_EXPIRED", "Challenge conformance sudah digunakan atau kedaluwarsa", 409);
    if (confirmation !== `RUN ${challenge.domain.toUpperCase()} SNAPSHOT ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_CONFIRMATION_INVALID", "Konfirmasi conformance tidak cocok", 403);
    if (fingerprint(providerIdentity(item)) !== challenge.expectedProviderIdentityFingerprint)
      throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_PROVIDER_DRIFT", "Identitas provider berubah sejak challenge disiapkan", 409);
    const running = await save(ownerId, challenge, { status: "running", startedAt: now() });
    const provider = item.provider, checks = [], findings = [];
    const record = (name, passed, detail = null) => {
      checks.push({ name, passed: Boolean(passed), ...(detail ? { detail: String(detail).slice(0, 140) } : {}) });
      if (!passed) findings.push({ code: `CROSS_DOMAIN_CONFORMANCE_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_FAILED` });
    };
    const scope = `agentic-v4-conformance-${challenge.domain}-${randomUUID()}`;
    const isolatedScope = `${scope}-isolated`;
    const makeAnchor = (sequence, previousAnchorDigest = null, salt = "") => {
      const unsigned = { ownerId: scope, domain: challenge.domain, kind: "cross-domain-snapshot-anchor-conformance", schemaVersion: 1,
        anchorSequence: sequence, revision: sequence, snapshotDigest: sha256(`${challenge.digest}:${sequence}:${salt}`), sourceCount: 1,
        previousAnchorDigest, historyNotProven: false, anchoredAt: now() };
      return { ...unsigned, digest: digestRecord(unsigned) };
    };
    try {
      const identity = providerIdentity(item), contract = provider.contractInfo;
      record("provider_identity_present", Boolean(identity));
      record("contract_metadata", Boolean(contract && contract.contractId === "agentic-v4-trust-anchor-provider"
        && ["1.0.0", "1.1.0"].includes(String(contract.version)) && contract.schemaVersion === 1
        && contract.ownerScope === "ownerId" && contract.casSemantics === "digest-compare-and-set"
        && Array.isArray(contract.capabilities) && ["read", "compareAndSet"].every(cap => contract.capabilities.includes(cap))));
      record("disposable_namespace_empty", await provider.read(scope) == null);
      const first = makeAnchor(1), firstWrite = await provider.compareAndSet(scope, null, first);
      record("genesis_cas", firstWrite?.applied === true);
      record("read_after_write", firstWrite?.applied === true && canonical(await provider.read(scope)) === canonical(first));
      const stale = await provider.compareAndSet(scope, null, makeAnchor(2, first.digest, "stale"));
      record("stale_cas_rejected", stale?.applied === false);
      record("stale_cas_no_mutation", canonical(await provider.read(scope)) === canonical(first));
      const second = makeAnchor(2, first.digest), secondWrite = await provider.compareAndSet(scope, first.digest, second);
      record("monotonic_sequence_and_linkage", secondWrite?.applied === true && canonical(await provider.read(scope)) === canonical(second));
      record("namespace_isolation", await provider.read(isolatedScope) == null);
      const a = makeAnchor(3, second.digest, "concurrent-a"), b = makeAnchor(3, second.digest, "concurrent-b");
      const outcomes = await Promise.allSettled([provider.compareAndSet(scope, second.digest, a), provider.compareAndSet(scope, second.digest, b)]);
      const winners = outcomes.filter(result => result.status === "fulfilled" && result.value?.applied === true).length;
      const after = await provider.read(scope);
      record("concurrent_cas_single_winner", winners === 1 && [a.digest, b.digest].includes(after?.digest));
      record("anchor_digest_integrity", Boolean(after && after.digest === digestRecord(after) && after.ownerId === scope));
    } catch (error) {
      findings.push({ code: error?.code || "CROSS_DOMAIN_PROVIDER_PROBE_EXCEPTION", detail: String(error?.message || "Provider probe failed").slice(0, 140) });
    }
    const identity = providerIdentity(item), contract = provider.contractInfo || null;
    const providerContract = contract ? { contractId: String(contract.contractId || "").slice(0, 100), version: String(contract.version || "").slice(0, 40),
      schemaVersion: Number.isSafeInteger(contract.schemaVersion) ? contract.schemaVersion : null, ownerScope: String(contract.ownerScope || "").slice(0, 80),
      casSemantics: String(contract.casSemantics || "").slice(0, 100), capabilities: Array.isArray(contract.capabilities) ? contract.capabilities.slice(0, 30).map(value => String(value).slice(0, 80)) : [] } : null;
    const conformanceSequence = await reserveConformanceSequence(ownerId, challenge.domain, challenge.id);
    const unsignedReport = { schemaVersion: 1, conformanceSequence, challengeId: challenge.id, ownerId, domain: challenge.domain,
      providerIdentityFingerprint: fingerprint(identity), providerContractDigest: providerContract ? sha256(canonical(providerContract)) : null,
      providerContract, checkedAt: now(), status: findings.length ? "nonconformant" : "conformant", conformant: findings.length === 0,
      checks, findings, writesToProductionNamespace: false, disposableNamespaceUsed: true,
      infrastructureIndependenceProven: false, residualProbeRecordPossible: true };
    const reportDigest = sha256(canonical(unsignedReport)), report = { ...unsignedReport, reportDigest };
    const completed = await save(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest });
    const reportId = `cross-domain-snapshot-report-${challenge.domain}-${challenge.id}`;
    const reportUnsigned = { id: reportId, ownerId, kind: reportKind, schemaVersion: 1, domain: challenge.domain, sourceId: completed.id,
      sourceDigest: completed.digest, report, reportDigest, createdAt: now(), retentionDays };
    const reportRecord = { ...reportUnsigned, digest: digestRecord(reportUnsigned) };
    await store.putEvidence(ownerId, reportRecord, { overwrite: false });
    const savedReport = await store.getEvidence(ownerId, reportId);
    if (!savedReport || savedReport.digest !== digestRecord(savedReport)) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_REPORT_RETENTION_FAILED", "Laporan conformance gagal disimpan secara utuh", 409);
    return { status: report.status, report, reportDigest, reportRecordId: reportId, idempotent: false,
      writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }

  async function auditConformance(ownerId, { domain = null } = {}) {
    assertOwner(ownerId);
    if (domain && !registry.has(domain)) throw new AgenticError("CROSS_DOMAIN_SNAPSHOT_DOMAIN_UNKNOWN", "Domain checkpoint tidak dikenal", 404);
    const rows = await store.listEvidence(ownerId), challenges = rows.filter(row => row?.kind === challengeKind && row.ownerId === ownerId
      && row.status === "completed" && (!domain || row.domain === domain));
    const reports = rows.filter(row => row?.kind === reportKind && row.ownerId === ownerId && (!domain || row.domain === domain));
    const findings = [];
    for (const challenge of challenges) {
      const reportUnsigned = challenge.report && Object.fromEntries(Object.entries(challenge.report).filter(([key]) => key !== "reportDigest"));
      if (challenge.digest !== digestRecord(challenge) || !challenge.report || challenge.reportDigest !== challenge.report.reportDigest
        || challenge.reportDigest !== sha256(canonical(reportUnsigned)) || challenge.report.ownerId !== ownerId || challenge.report.domain !== challenge.domain)
        findings.push({ code: "CROSS_DOMAIN_SNAPSHOT_CONFORMANCE_REPORT_INVALID", challengeId: challenge.id });
      const record = reports.find(item => item.sourceId === challenge.id);
      if (!record) findings.push({ code: "CROSS_DOMAIN_SNAPSHOT_CONFORMANCE_REPORT_MISSING", challengeId: challenge.id });
      else if (record.digest !== digestRecord(record) || record.sourceDigest !== challenge.digest || record.reportDigest !== challenge.reportDigest
        || canonical(record.report) !== canonical(challenge.report)) findings.push({ code: "CROSS_DOMAIN_SNAPSHOT_CONFORMANCE_RETENTION_INVALID", challengeId: challenge.id });
    }
    for (const report of reports) if (report.digest !== digestRecord(report) || !challenges.some(challenge => challenge.id === report.sourceId))
      findings.push({ code: "CROSS_DOMAIN_SNAPSHOT_ORPHANED_REPORT", reportId: report.id });
    const sequenced = new Set();
    const slots = rows.filter(row => row?.ownerId === ownerId && row.kind === sequenceKind);
    for (const report of reports) if (Number.isSafeInteger(report.report?.conformanceSequence)) {
      const sequence = report.report.conformanceSequence, key = `${report.domain}:${sequence}`;
      const slot = slots.find(item => item.domain === report.domain && item.sequence === sequence && item.challengeId === report.report.challengeId);
      if (sequenced.has(key) || !slot || slot.digest !== digestRecord(slot)) findings.push({ code: "CROSS_DOMAIN_SNAPSHOT_CONFORMANCE_SEQUENCE_INVALID", reportId: report.id });
      sequenced.add(key);
    }
    for (const slot of slots) if (slot.digest !== digestRecord(slot) || !Number.isSafeInteger(slot.sequence) || slot.sequence < 1
      || !reports.some(report => report.domain === slot.domain && report.report?.conformanceSequence === slot.sequence && report.report?.challengeId === slot.challengeId)) {
      // A reservation may be left without a report after an interrupted probe; it is retained as an explicit gap, not silently reused.
      if (slot.digest !== digestRecord(slot)) findings.push({ code: "CROSS_DOMAIN_SNAPSHOT_CONFORMANCE_SEQUENCE_SLOT_INVALID", slotId: slot.id });
    }
    const nonconformantCount = challenges.filter(challenge => challenge.report?.status === "nonconformant").length;
    const conformantCount = challenges.filter(challenge => challenge.report?.status === "conformant").length;
    return { status: findings.length ? "unhealthy" : nonconformantCount ? "nonconformant" : challenges.length ? "healthy" : "not_initialized", ownerId, domain,
      challengeCount: challenges.length, reportCount: reports.length, conformantCount, nonconformantCount, findings, readOnly: true, mutationAllowed: false };
  }

  async function auditFreshnessAndRetention(ownerId, { includeAuditAttestations = true } = {}) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId), nowMs = Date.parse(now()), findings = [], checkpoints = [], retention = [];
    const retentionReviewDecisionFor = (recordId, recordDigest) => {
      const approvals = rows.filter(row => row?.ownerId === ownerId && row.kind === "recovery-slo-cross-domain-retention-review-approval"
        && Array.isArray(row.targets) && row.targets.some(target => target.recordId === recordId && target.recordDigest === recordDigest));
      if (!approvals.length) return null;
      for (const approval of approvals) {
        const challenge = rows.find(row => row?.ownerId === ownerId && row.kind === "recovery-slo-cross-domain-retention-review-challenge" && row.id === approval.challengeId);
        const replay = rows.find(row => row?.ownerId === ownerId && row.kind === "recovery-slo-cross-domain-retention-review-replay-guard" && row.id === approval.replayGuardId);
        const valid = approval.digest === digestRecord(approval) && challenge && challenge.digest === digestRecord(challenge)
          && challenge.status === "completed" && challenge.approvalId === approval.id && challenge.approvalDigest === approval.digest
          && challenge.preparedChallengeDigest === approval.challengeDigest && replay && replay.digest === digestRecord(replay)
          && replay.status === "completed" && replay.approvalId === approval.id && replay.approvalDigest === approval.digest
          && replay.challengeId === challenge.id && replay.challengeDigest === approval.challengeDigest
          && replay.replayKey === approval.decisionReplayKey && approval.targetsDigest === sha256(canonical(approval.targets || []));
        if (!valid) return { status: "invalid", approvalId: approval.id };
        return { status: approval.decision, approvalId: approval.id };
      }
      return null;
    };
    const applyRetentionReviewClass = (recordId, recordDigest, overdueClass) => {
      const decision = retentionReviewDecisionFor(recordId, recordDigest);
      if (decision?.status === "invalid") findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_APPROVAL_INVALID", recordId, approvalId: decision.approvalId });
      if (overdueClass !== "retention_overdue_review") return { retentionClass: overdueClass, retentionReviewDecision: decision?.status || null,
        retentionReviewApprovalId: decision?.approvalId || null };
      if (decision?.status === "retain") return { retentionClass: "retention_reviewed_retain", retentionReviewDecision: "retain", retentionReviewApprovalId: decision.approvalId };
      if (decision?.status === "escalate") return { retentionClass: "retention_review_escalated", retentionReviewDecision: "escalate", retentionReviewApprovalId: decision.approvalId };
      return { retentionClass: overdueClass, retentionReviewDecision: null, retentionReviewApprovalId: null };
    };
    for (const item of registry.values()) {
      if (item.auditFreshness === false) continue;
      const state = item.service ? await item.service.getExternalSnapshotCheckpointStatus(ownerId)
        : { status: item.provider ? "status_unavailable" : "not_configured", domain: item.domain, findings: [] };
      let freshnessStatus = "not_anchored", ageMs = null, anchoredAt = null;
      if (state.anchorAnchoredAt || state.anchoredAt) {
        anchoredAt = state.anchorAnchoredAt || state.anchoredAt;
        const stamp = dateMs(anchoredAt);
        if (stamp == null) freshnessStatus = "timestamp_invalid";
        else {
          ageMs = nowMs - stamp;
          freshnessStatus = ageMs < -futureSkewMs ? "future_skew_exceeded" : ageMs < 0 ? "future_within_skew" : ageMs > maxAgeMs ? "stale" : "fresh";
        }
      }
      const hardStatus = ["unhealthy", "rollback_suspected"].includes(state.status) || ["timestamp_invalid", "future_skew_exceeded"].includes(freshnessStatus);
      if (hardStatus) findings.push({ code: "CROSS_DOMAIN_CHECKPOINT_UNTRUSTED", domain: item.domain, checkpointStatus: state.status, freshnessStatus });
      else if (["behind_local", "marker_pending", "enrollment_required", "unavailable", "local_only"].includes(state.status) || freshnessStatus === "stale")
        findings.push({ code: "CROSS_DOMAIN_CHECKPOINT_PENDING_OR_STALE", domain: item.domain, checkpointStatus: state.status, freshnessStatus });
      checkpoints.push({ domain: item.domain, status: state.status, freshnessStatus, ageMs, anchoredAt,
        anchorSequence: state.anchorSequence ?? null, anchorDigest: state.anchorDigest ?? null, historyNotProven: state.historyNotProven ?? null,
        findings: state.findings || [] });
      const markerKind = `${item.kind}-marker`, challengeKindForDomain = `${item.kind}-enrollment-challenge`;
      for (const row of rows.filter(value => value.ownerId === ownerId && [markerKind, challengeKindForDomain].includes(value.kind))) {
        const digestValid = row.digest === digestRecord(row);
        if (!digestValid) findings.push({ code: "CROSS_DOMAIN_CHECKPOINT_LOCAL_RECORD_TAMPERED", domain: item.domain, recordId: row.id });
        const createdAt = row.createdAt || row.updatedAt;
        const stamp = dateMs(createdAt), ageDays = stamp == null ? null : Math.max(0, (nowMs - stamp) / 86400000);
        const challengeExpired = row.kind === challengeKindForDomain && row.status === "prepared" && dateMs(row.expiresAt) != null && dateMs(row.expiresAt) <= nowMs;
        const retentionOverdue = ageDays != null && ageDays > retentionDays && row.kind === challengeKindForDomain;
        const baseClass = row.kind === markerKind ? "protected_current_marker" : retentionOverdue ? "retention_overdue_review" : "retained_challenge";
        const reviewed = applyRetentionReviewClass(row.id, row.digest || null, baseClass);
        retention.push({ domain: item.domain, recordId: row.id, recordKind: row.kind, recordDigest: row.digest || null, digestValid, ageDays,
          retentionClass: reviewed.retentionClass, retentionReviewDecision: reviewed.retentionReviewDecision,
          retentionReviewApprovalId: reviewed.retentionReviewApprovalId, challengeExpired, challengeStatus: row.status || null });
        if (stamp == null) findings.push({ code: "CROSS_DOMAIN_CHECKPOINT_RECORD_TIMESTAMP_INVALID", domain: item.domain, recordId: row.id });
      }
    }
    for (const report of rows.filter(row => row?.kind === reportKind && row.ownerId === ownerId)) {
      const stamp = dateMs(report.createdAt), ageDays = stamp == null ? null : Math.max(0, (nowMs - stamp) / 86400000);
      const digestValid = report.digest === digestRecord(report);
      if (!digestValid) findings.push({ code: "CROSS_DOMAIN_CONFORMANCE_REPORT_TAMPERED", reportId: report.id });
      const baseClass = ageDays != null && ageDays > retentionDays ? "retention_overdue_review" : "retained_conformance_report";
      const reviewed = applyRetentionReviewClass(report.id, report.digest || null, baseClass);
      retention.push({ domain: report.domain, recordId: report.id, recordKind: report.kind, recordDigest: report.digest || null, digestValid, ageDays,
        retentionClass: reviewed.retentionClass, retentionReviewDecision: reviewed.retentionReviewDecision,
        retentionReviewApprovalId: reviewed.retentionReviewApprovalId, challengeExpired: false });
    }
    for (const attestation of (includeAuditAttestations ? rows : []).filter(row => row?.ownerId === ownerId
      && row.kind === "recovery-slo-cross-domain-snapshot-audit-attestation")) {
      const stamp = dateMs(attestation.attestation?.issuedAt || attestation.createdAt);
      const ageDays = stamp == null ? null : Math.max(0, (nowMs - stamp) / 86400000);
      const digestValid = attestation.digest === digestRecord(attestation)
        && attestation.attestation?.attestationId === attestation.id
        && /^[a-f0-9]{64}$/.test(String(attestation.attestation?.attestationDigest || ""));
      if (stamp == null) findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_TIMESTAMP_INVALID", recordId: attestation.id });
      if (!digestValid) findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_RETENTION_RECORD_INVALID", recordId: attestation.id });
      const baseClass = ageDays != null && ageDays > retentionDays ? "retention_overdue_review" : "retained_audit_attestation";
      const reviewed = applyRetentionReviewClass(attestation.id, attestation.digest || null, baseClass);
      retention.push({ domain: "cross_domain_snapshot_audit_attestation", recordId: attestation.id, recordKind: attestation.kind,
        recordDigest: attestation.digest || null, digestValid, ageDays, retentionClass: reviewed.retentionClass,
        retentionReviewDecision: reviewed.retentionReviewDecision, retentionReviewApprovalId: reviewed.retentionReviewApprovalId,
        challengeExpired: false });
    }
    const integrityFailure = findings.some(item => ["CROSS_DOMAIN_CHECKPOINT_UNTRUSTED", "CROSS_DOMAIN_CHECKPOINT_LOCAL_RECORD_TAMPERED",
      "CROSS_DOMAIN_CHECKPOINT_RECORD_TIMESTAMP_INVALID", "CROSS_DOMAIN_CONFORMANCE_REPORT_TAMPERED",
      "CROSS_DOMAIN_AUDIT_ATTESTATION_TIMESTAMP_INVALID", "CROSS_DOMAIN_AUDIT_ATTESTATION_RETENTION_RECORD_INVALID",
      "CROSS_DOMAIN_RETENTION_REVIEW_APPROVAL_INVALID"].includes(item.code));
    const degraded = findings.some(item => item.code === "CROSS_DOMAIN_CHECKPOINT_PENDING_OR_STALE")
      || retention.some(item => item.challengeExpired || item.retentionClass === "retention_overdue_review");
    return { status: integrityFailure ? "unhealthy" : degraded ? "degraded" : checkpoints.some(item => item.status === "not_initialized" || item.status === "not_configured") ? "not_initialized" : "healthy",
      ownerId, checkedAt: now(), policy: { maxAgeMs, futureSkewMs, retentionDays, currentMarkersProtected: true, automaticDeletion: false }, checkpoints, retention, findings,
      readOnly: true, mutationAllowed: false };
  }

  async function auditGovernance(ownerId) {
    const [independence, freshnessRetention, conformance] = await Promise.all([
      auditIndependence(ownerId), auditFreshnessAndRetention(ownerId, { includeAuditAttestations: false }), auditConformance(ownerId)
    ]);
    const statuses = [independence.status, freshnessRetention.status, conformance.status];
    const status = statuses.includes("unhealthy") || statuses.includes("nonconformant") ? "unhealthy"
      : statuses.includes("unverifiable") || statuses.includes("degraded") ? "degraded"
      : statuses.every(value => ["healthy", "not_initialized", "local_only"].includes(value)) ? "healthy" : "not_initialized";
    return { status, ownerId, independence, freshnessRetention, conformance, infrastructureIndependenceProven: false,
      readOnly: true, mutationAllowed: false };
  }

  return Object.freeze({
    auditRecoverySloCrossDomainSnapshotAnchorIndependence: auditIndependence,
    getRecoverySloCrossDomainSnapshotAnchorProviderSnapshot: providerSnapshot,
    prepareRecoverySloCrossDomainSnapshotAnchorConformance: prepareConformance,
    runRecoverySloCrossDomainSnapshotAnchorConformance: runConformance,
    auditRecoverySloCrossDomainSnapshotAnchorConformance: auditConformance,
    auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention: auditFreshnessAndRetention,
    auditRecoverySloCrossDomainSnapshotAnchorGovernance: auditGovernance,
    domains: [...registry.keys()], maxAgeMs, futureSkewMs, retentionDays
  });
}
