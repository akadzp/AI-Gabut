import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const KIND = "recovery-slo-retention-decision-gate-external-anchor";
const MARKER_KIND = "recovery-slo-retention-decision-gate-anchor-marker";
const ENROLLMENT_KIND = "recovery-slo-retention-decision-gate-anchor-enrollment";
const ARTIFACT = "retention_reconciliation_decision_gate_audit";
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
  const out = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item);
  return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
const scopeFor = ownerId => `retention-decision-gate-${ownerHash(ownerId)}`;
const markerId = ownerId => `recovery-slo-retention-decision-gate-anchor-marker-${ownerHash(ownerId)}`;
const enrollmentId = () => `recovery-slo-retention-decision-gate-anchor-enrollment-${randomUUID()}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_OWNER_REQUIRED", "Owner decision-gate anchor wajib ditentukan", 400);
  }
}
function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }
function validRecord(ownerId, record) {
  if (!record || record.ownerId !== ownerId || record.kind !== "recovery-slo-anchor-evidence-retention-record"
    || record.artifactType !== ARTIFACT || !["retained", "tombstone"].includes(record.status)
    || !DIGEST.test(record.payloadDigest || "") || !DIGEST.test(record.digest || "") || record.digest !== digestRecord(record)
    || !Number.isFinite(Date.parse(record.capturedAt))) return false;
  if (record.status === "retained") return record.payload != null && sha256(canonical(record.payload)) === record.payloadDigest && record.tombstone == null;
  return record.payload == null && record.tombstone?.payloadDigest === record.payloadDigest && record.tombstone?.reason === "RETENTION_PERIOD_ELAPSED";
}

export function createRecoverySloRetentionDecisionGateAnchorService({ store, provider = null, decisionGateAuditService,
  retainedEvidenceService, retainedEvidenceChainService, required = false, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence
    || typeof decisionGateAuditService?.auditRecoverySloRetentionReconciliationDecisionGateEvidence !== "function"
    || typeof retainedEvidenceService?.auditRecoverySloRetainedAnchorEvidence !== "function"
    || typeof retainedEvidenceChainService?.getRecoverySloRetainedEvidenceChainHistory !== "function" || typeof clock !== "function"
    || (provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function")) || (required && !provider)) {
    throw new TypeError("Decision-gate external anchor membutuhkan store, audit evidence, chain history, dan provider CAS jika diwajibkan");
  }
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_CLOCK_INVALID", "Clock decision-gate anchor tidak valid", 500);
    return new Date(time).toISOString();
  }
  function validateAnchor(anchor, ownerId) {
    const scope = scopeFor(ownerId);
    if (!anchor || anchor.ownerId !== scope || anchor.sourceOwnerHash !== sha256(ownerId) || anchor.domain !== "retention_decision_gate_audit"
      || anchor.kind !== KIND || anchor.schemaVersion !== 1 || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
      || anchor.revision !== anchor.anchorSequence || !DIGEST.test(anchor.evidenceIdHash || "") || !DIGEST.test(anchor.evidencePayloadDigest || "")
      || !["retained", "tombstone"].includes(anchor.evidenceStatus) || !["retained", "pruned"].includes(anchor.sourceEventType)
      || !Number.isSafeInteger(anchor.sourceEventSequence) || anchor.sourceEventSequence < 1 || !DIGEST.test(anchor.sourceEventDigest || "")
      || !DIGEST.test(anchor.sourceEventRecordDigest || "") || !Number.isFinite(Date.parse(anchor.evidenceCapturedAt))
      || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
      || typeof anchor.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(anchor.anchoredAt))
      || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) return { valid: false, code: "RETENTION_DECISION_GATE_EXTERNAL_ANCHOR_INVALID" };
    if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null) || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) {
      return { valid: false, code: "RETENTION_DECISION_GATE_EXTERNAL_ANCHOR_CHAIN_INVALID" };
    }
    return { valid: true };
  }
  function validateMarker(marker, ownerId) {
    if (!marker || marker.id !== markerId(ownerId) || marker.ownerId !== ownerId || marker.kind !== MARKER_KIND || marker.schemaVersion !== 1
      || !DIGEST.test(marker.anchorDigest || "") || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1
      || !DIGEST.test(marker.evidenceIdHash || "") || !Number.isFinite(Date.parse(marker.updatedAt))
      || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker)) return { valid: false, code: "RETENTION_DECISION_GATE_ANCHOR_MARKER_INVALID" };
    return { valid: true };
  }
  async function sourceEvents(ownerId) {
    const [records, history] = await Promise.all([store.listEvidence(ownerId), retainedEvidenceChainService.getRecoverySloRetainedEvidenceChainHistory(ownerId)]);
    if (history.status === "unhealthy") throw new AgenticError("RETENTION_DECISION_GATE_SOURCE_CHAIN_UNHEALTHY", "Source retained-evidence chain tidak sehat", 409, { findings: history.findings });
    const recordMap = new Map(records.filter(record => record?.kind === "recovery-slo-anchor-evidence-retention-record"
      && record.artifactType === ARTIFACT).map(record => [record.id, record]));
    const events = history.events.filter(event => recordMap.has(event.recordId)).map(event => ({ event, record: recordMap.get(event.recordId) }));
    for (const item of events) {
      if (!validRecord(ownerId, item.record) || !DIGEST.test(item.event.eventDigest || "")
        || !["retained", "pruned"].includes(item.event.eventType) || item.event.payloadDigest !== item.record.payloadDigest
        || !DIGEST.test(item.event.recordDigest || "") || !Number.isSafeInteger(item.event.sequence) || item.event.sequence < 1) {
        throw new AgenticError("RETENTION_DECISION_GATE_SOURCE_EVENT_INVALID", "Source event decision-gate tidak dapat diverifikasi", 409,
          { evidenceId: item.record?.id || null, sourceSequence: item.event?.sequence || null });
      }
    }
    return { events, historyStatus: history.status, historySequence: history.sequence };
  }
  async function readMarker(ownerId) {
    const marker = await store.getEvidence(ownerId, markerId(ownerId));
    if (!marker) return { status: "missing", marker: null };
    const check = validateMarker(marker, ownerId);
    return check.valid ? { status: "present", marker } : { status: "invalid", marker: null, finding: check.code };
  }
  async function saveMarker(ownerId, anchor) {
    const id = markerId(ownerId), old = await store.getEvidence(ownerId, id);
    const unsigned = { id, ownerId, kind: MARKER_KIND, schemaVersion: 1, anchorDigest: anchor.digest,
      anchorSequence: anchor.anchorSequence, evidenceIdHash: anchor.evidenceIdHash, updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, old ? { expectedVersion: old._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!validateMarker(saved, ownerId).valid || saved.anchorDigest !== anchor.digest) {
      throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_MARKER_WRITE_FAILED", "Marker decision-gate anchor gagal diverifikasi", 409);
    }
    return saved;
  }
  async function readRemote(ownerId) {
    if (!provider) return { status: required ? "unavailable" : "local_only", anchor: null, scope: scopeFor(ownerId) };
    const scope = scopeFor(ownerId);
    try {
      const anchor = await provider.read(scope);
      if (!anchor) return { status: "missing", anchor: null, scope };
      const check = validateAnchor(anchor, ownerId);
      return check.valid ? { status: "present", anchor, scope } : { status: "invalid", anchor: null, scope, finding: check.code };
    } catch (error) { return { status: "unavailable", anchor: null, scope, finding: error?.code || "PROVIDER_READ_FAILED" }; }
  }
  async function inspect(ownerId) {
    assertOwner(ownerId);
    const [source, markerState, remote, decisionAudit] = await Promise.all([sourceEvents(ownerId), readMarker(ownerId), readRemote(ownerId),
      decisionGateAuditService.auditRecoverySloRetentionReconciliationDecisionGateEvidence(ownerId)]);
    const all = source.events, findings = [];
    if (decisionAudit.status !== "healthy") findings.push({ code: "RETENTION_DECISION_GATE_EVIDENCE_AUDIT_UNHEALTHY" });
    if (markerState.status === "invalid") findings.push({ code: markerState.finding });
    if (remote.status === "local_only") return { status: required ? "unavailable" : findings.length ? "unhealthy" : "local_only", ownerId, total: all.length,
      anchorSequence: null, anchorDigest: null, historyNotProven: null, findings, providerConfigured: false, sourceChainStatus: source.historyStatus,
      readOnly: true, mutationAllowed: false };
    if (remote.status === "unavailable" || remote.status === "invalid") return { status: "unhealthy", ownerId, total: all.length,
      anchorSequence: null, anchorDigest: null, historyNotProven: null, findings: [...findings, { code: remote.finding || remote.status }],
      sourceChainStatus: source.historyStatus, readOnly: true, mutationAllowed: false };
    if (remote.status === "missing") {
      if (markerState.status === "present") findings.push({ code: "RETENTION_DECISION_GATE_ANCHOR_MISSING_AFTER_ENROLLMENT" });
      const status = markerState.status === "present" ? "rollback_suspected" : all.length === 0 ? "not_initialized" : all.length === 1 ? "anchor_pending" : "enrollment_required";
      return { status: findings.length ? "unhealthy" : status, ownerId, total: all.length, anchorSequence: null, anchorDigest: null,
        historyNotProven: null, findings, sourceChainStatus: source.historyStatus, readOnly: true, mutationAllowed: false };
    }
    if (markerState.status !== "present") findings.push({ code: "RETENTION_DECISION_GATE_ANCHOR_MARKER_MISSING" });
    const anchor = remote.anchor;
    const index = all.findIndex(item => item.event.eventDigest === anchor.sourceEventDigest);
    if (index < 0) findings.push({ code: "RETENTION_DECISION_GATE_ANCHOR_SOURCE_EVENT_MISSING" });
    else {
      const { event, record } = all[index];
      if (anchor.anchorSequence !== index + 1 || anchor.sourceEventSequence !== event.sequence
        || anchor.sourceEventRecordDigest !== event.recordDigest || anchor.evidenceIdHash !== sha256(record.id)
        || anchor.evidencePayloadDigest !== event.payloadDigest || anchor.evidenceStatus !== event.status
        || anchor.sourceEventType !== event.eventType || anchor.evidenceCapturedAt !== record.capturedAt) {
        findings.push({ code: "RETENTION_DECISION_GATE_ANCHOR_SOURCE_EVENT_MISMATCH" });
      }
    }
    if (markerState.status === "present") {
      const marker = markerState.marker;
      if (marker.anchorSequence > anchor.anchorSequence) findings.push({ code: "RETENTION_DECISION_GATE_ANCHOR_ROLLBACK_SUSPECTED" });
      else if (marker.anchorSequence === anchor.anchorSequence && marker.anchorDigest !== anchor.digest) findings.push({ code: "RETENTION_DECISION_GATE_ANCHOR_MARKER_MISMATCH" });
      else if (marker.anchorSequence < anchor.anchorSequence && !(marker.anchorSequence + 1 === anchor.anchorSequence
        && anchor.previousAnchorDigest === marker.anchorDigest)) findings.push({ code: "RETENTION_DECISION_GATE_ANCHOR_MARKER_DISCONTINUITY" });
    }
    if (anchor.anchorSequence > all.length) findings.push({ code: "RETENTION_DECISION_GATE_EXTERNAL_ANCHOR_AHEAD_OF_LOCAL_EVIDENCE" });
    const status = findings.length ? "unhealthy" : anchor.anchorSequence === all.length ? "anchored" : "behind_local";
    return { status, ownerId, total: all.length, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      anchoredSourceEventDigest: anchor.sourceEventDigest, historyNotProven: anchor.historyNotProven, findings,
      sourceChainStatus: source.historyStatus, readOnly: true, mutationAllowed: false };
  }
  async function append(ownerId, item, previous, historyNotProven = false) {
    const { event, record } = item, scope = scopeFor(ownerId), anchorSequence = previous ? previous.anchorSequence + 1 : 1;
    const unsigned = { ownerId: scope, sourceOwnerHash: sha256(ownerId), domain: "retention_decision_gate_audit", kind: KIND,
      schemaVersion: 1, anchorSequence, revision: anchorSequence, evidenceIdHash: sha256(record.id), evidencePayloadDigest: event.payloadDigest,
      evidenceStatus: event.status, evidenceCapturedAt: record.capturedAt, sourceEventSequence: event.sequence,
      sourceEventDigest: event.eventDigest, sourceEventRecordDigest: event.recordDigest, sourceEventType: event.eventType,
      previousAnchorDigest: previous?.digest || null, historyNotProven: Boolean(historyNotProven || previous?.historyNotProven), anchoredAt: now() };
    const candidate = { ...unsigned, digest: digestRecord(unsigned) };
    let result;
    try { result = await provider.compareAndSet(scope, previous?.digest ?? null, candidate); }
    catch (error) { throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_WRITE_FAILED", "External decision-gate anchor gagal ditulis", 503, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
    if (!result?.applied) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_CAS_CONFLICT", "External decision-gate anchor berubah bersamaan", 409);
    const reread = await readRemote(ownerId);
    if (reread.status !== "present" || reread.anchor.digest !== candidate.digest) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_VERIFY_FAILED", "External decision-gate anchor gagal diverifikasi setelah penulisan", 409);
    await saveMarker(ownerId, candidate);
    return candidate;
  }
  async function anchorPending(ownerId) {
    assertOwner(ownerId);
    if (!provider) {
      if (required) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_REQUIRED", "External decision-gate evidence anchor diwajibkan", 503);
      return { status: "local_only", anchored: 0, readOnly: false, mutationAllowed: false };
    }
    const audit = await decisionGateAuditService.auditRecoverySloRetentionReconciliationDecisionGateEvidence(ownerId);
    if (audit.status !== "healthy") throw new AgenticError("RETENTION_DECISION_GATE_EVIDENCE_UNHEALTHY", "Decision-gate evidence tidak sehat; external anchoring ditolak", 409, { findings: audit.findings });
    const source = await sourceEvents(ownerId), all = source.events;
    const remote = await readRemote(ownerId), markerState = await readMarker(ownerId);
    if (remote.status === "unavailable" || remote.status === "invalid" || markerState.status === "invalid") {
      throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_UNHEALTHY", "External decision-gate anchor tidak sehat", 409, { status: remote.status, finding: remote.finding || markerState.finding });
    }
    if (remote.status === "missing") {
      if (markerState.status === "present") throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_ROLLBACK_SUSPECTED", "External anchor hilang setelah enrollment", 409);
      if (all.length === 0) return { status: "not_initialized", anchored: 0, readOnly: false, mutationAllowed: false };
      if (all.length > 1) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_ENROLLMENT_REQUIRED", "Evidence historis memerlukan enrollment eksplisit", 409, { count: all.length });
      const candidate = await append(ownerId, all[0], null, false);
      return { status: "anchored", anchored: 1, anchorSequence: candidate.anchorSequence, anchorDigest: candidate.digest, historyNotProven: false, readOnly: false, mutationAllowed: false };
    }
    if (markerState.status !== "present") throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_MARKER_MISSING", "Marker lokal hilang; external anchor tidak dapat dipercaya secara otomatis", 409);
    let previous = remote.anchor;
    const index = all.findIndex(item => item.event.eventDigest === previous.sourceEventDigest);
    if (index < 0 || all[index].event.sequence !== previous.sourceEventSequence || all[index].event.recordDigest !== previous.sourceEventRecordDigest
      || all[index].event.payloadDigest !== previous.evidencePayloadDigest || previous.anchorSequence !== index + 1 || previous.anchorSequence > all.length) {
      throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_MISMATCH", "External anchor tidak cocok dengan histori source event", 409);
    }
    const marker = markerState.marker;
    if (marker.anchorSequence > previous.anchorSequence || marker.anchorSequence === previous.anchorSequence && marker.anchorDigest !== previous.digest
      || marker.anchorSequence < previous.anchorSequence && !(marker.anchorSequence + 1 === previous.anchorSequence && previous.previousAnchorDigest === marker.anchorDigest)) {
      throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_ROLLBACK_SUSPECTED", "Local marker menunjukkan rollback atau diskontinuitas", 409);
    }
    if (marker.anchorSequence < previous.anchorSequence) await saveMarker(ownerId, previous);
    let count = 0;
    for (const item of all.slice(index + 1)) { previous = await append(ownerId, item, previous); count++; }
    return { status: count ? "anchored" : "already_anchored", anchored: count, anchorSequence: previous.anchorSequence,
      anchorDigest: previous.digest, historyNotProven: previous.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function prepareEnrollment(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!provider) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_NOT_CONFIGURED", "External decision-gate anchor belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const state = await inspect(ownerId);
    if (state.status !== "enrollment_required") throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_ENROLLMENT_BLOCKED", "Enrollment hanya berlaku untuk histori lokal yang belum di-anchor", 409, { status: state.status });
    const createdAt = now(), id = enrollmentId(), expiresAt = new Date(Date.parse(createdAt) + TTL_MS).toISOString();
    const unsigned = { id, ownerId, kind: ENROLLMENT_KIND, schemaVersion: 1, status: "prepared", expectedEventCount: state.total,
      reason: reason.trim(), createdAt, expiresAt };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, ownerId, expectedEventCount: state.total, challengeDigest: challenge.digest, createdAt, expiresAt,
      confirmation: `ENROLL DECISION GATE ANCHOR ${challenge.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function applyEnrollment(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    const unsigned = clean(challenge || {}); delete unsigned.digest;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== ENROLLMENT_KIND || challenge.status !== "prepared"
      || challenge.digest !== digestRecord(unsigned) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `ENROLL DECISION GATE ANCHOR ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_ENROLLMENT_INVALID", "Challenge enrollment tidak valid, kedaluwarsa, atau konfirmasinya tidak cocok", 409);
    }
    const audit = await decisionGateAuditService.auditRecoverySloRetentionReconciliationDecisionGateEvidence(ownerId);
    if (audit.status !== "healthy") throw new AgenticError("RETENTION_DECISION_GATE_EVIDENCE_UNHEALTHY", "Evidence tidak sehat; legacy enrollment ditolak", 409);
    const source = await sourceEvents(ownerId), all = source.events;
    if (all.length !== challenge.expectedEventCount || all.length === 0) throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_ENROLLMENT_STALE", "Evidence berubah sejak enrollment disiapkan", 409);
    const remote = await readRemote(ownerId), marker = await readMarker(ownerId);
    if (remote.status !== "missing" || marker.status !== "missing") throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_ENROLLMENT_BLOCKED", "Remote anchor atau marker sudah ada; enrollment ditolak", 409);
    let previous = null;
    for (const item of all) previous = await append(ownerId, item, previous, true);
    const completedUnsigned = { ...clean(challenge), status: "completed", completedAt: now(), resultAnchorDigest: previous.digest };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version });
    return { status: "enrolled", anchorSequence: previous.anchorSequence, anchorDigest: previous.digest, historyNotProven: true, readOnly: false, mutationAllowed: false };
  }
  async function reconcile(ownerId) {
    const state = await inspect(ownerId);
    if (["local_only", "not_initialized", "anchored"].includes(state.status)) return { ...state, reconciled: false, readOnly: false, mutationAllowed: false };
    if (state.status === "behind_local") return { ...(await anchorPending(ownerId)), reconciled: true, readOnly: false, mutationAllowed: false };
    throw new AgenticError("RETENTION_DECISION_GATE_ANCHOR_RECONCILIATION_BLOCKED", "Decision-gate anchor tidak dapat direkonsiliasi secara aman", 409, { status: state.status, findings: state.findings });
  }
  return Object.freeze({ getRecoverySloRetentionDecisionGateAnchorStatus: inspect,
    anchorPendingRecoverySloRetentionDecisionGateEvidence: anchorPending,
    prepareRecoverySloRetentionDecisionGateAnchorEnrollment: prepareEnrollment,
    applyRecoverySloRetentionDecisionGateAnchorEnrollment: applyEnrollment,
    reconcileRecoverySloRetentionDecisionGateAnchor: reconcile, configured: Boolean(provider), required });
}
