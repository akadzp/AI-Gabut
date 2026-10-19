import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const ARTIFACT = "root_trust_baseline_checkpoint_continuity_proof";
const LIFECYCLE_ARTIFACT = "root_trust_conformance_baseline_lifecycle";
const REVOCATION_CHALLENGE_KIND = "root-trust-baseline-continuity-proof-revocation-challenge";
const REVOCATION_STATE_KIND = "root-trust-baseline-continuity-proof-revocation-state";
const REVOCATION_ARTIFACT = "root_trust_baseline_continuity_proof_revocation";
const REVOCATION_TTL_MS = 10 * 60_000;
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
  const out = {}; for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item); return out;
};
const recordDigest = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_OWNER_REQUIRED", "Owner continuity proof wajib ditentukan", 400);
}
export function createRecoverySloRootTrustBaselineCheckpointContinuityService({ store, lifecycleService, lifecycleAnchorService,
  baselineService, retainedEvidenceService, clock = () => new Date().toISOString() } = {}) {
  if (!store?.listEvidence || typeof lifecycleService?.auditRecoverySloRootTrustConformanceBaselineLifecycle !== "function"
    || typeof lifecycleAnchorService?.getRecoverySloRootTrustBaselineLifecycleAnchorStatus !== "function"
    || typeof baselineService?.getRecoverySloRootTrustConformanceCurrentBaseline !== "function"
    || !retainedEvidenceService?.retainRecoverySloAnchorEvidence || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence || typeof clock !== "function") {
    throw new TypeError("Baseline checkpoint continuity membutuhkan lifecycle, external anchor, baseline, dan retained-evidence service");
  }
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_CLOCK_INVALID", "Clock continuity proof tidak valid", 500);
    return new Date(ms).toISOString();
  }
  async function source(ownerId) {
    const [audit, all] = await Promise.all([lifecycleService.auditRecoverySloRootTrustConformanceBaselineLifecycle(ownerId), store.listEvidence(ownerId)]);
    if (audit.status !== "healthy") throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_SOURCE_UNHEALTHY", "Baseline lifecycle tidak sehat", 409, { findings: audit.findings });
    const records = all.filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record" && item.artifactType === LIFECYCLE_ARTIFACT && item.status === "retained")
      .sort((a, b) => Number(a.payload?.sequence || 0) - Number(b.payload?.sequence || 0));
    const events = [];
    for (let i = 0; i < records.length; i++) {
      const record = records[i], event = record.payload;
      if (record.ownerId !== ownerId || record.digest !== recordDigest(record) || record.payloadDigest !== sha256(canonical(event))
        || record.sourceId !== event?.eventDigest || event?.ownerId !== ownerId || event.sequence !== i + 1
        || !DIGEST.test(event.eventDigest || "") || event.eventDigest !== sha256(canonical(Object.fromEntries(Object.entries(event).filter(([key]) => key !== "eventDigest"))))
        || event.previousEventDigest !== (i ? events[i - 1].eventDigest : null)) {
        throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_EVENT_INVALID", "Event baseline lifecycle tidak dapat diverifikasi", 409, { sequence: event?.sequence ?? null });
      }
      events.push({ sequence: event.sequence, eventDigest: event.eventDigest, recordDigest: record.digest, baselineDigest: event.baselineDigest });
    }
    if (records.length !== audit.lifecycleEvents) throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_HISTORY_INCOMPLETE", "Jumlah event tidak cocok dengan audit lifecycle", 409);
    return { audit, records, events, historyDigest: sha256(canonical(events)) };
  }
  const revocationStateId = (ownerId, proofDigest) => `root-trust-baseline-continuity-proof-revocation-${sha256(`${ownerId}:${proofDigest}`).slice(0, 40)}`;
  function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }
  async function sourceTrust(ownerId) {
    const [lifecycleAuditResult, anchorResult, baselineResult] = await Promise.allSettled([
      lifecycleService.auditRecoverySloRootTrustConformanceBaselineLifecycle(ownerId),
      lifecycleAnchorService.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(ownerId),
      baselineService.getRecoverySloRootTrustConformanceCurrentBaseline(ownerId)
    ]);
    const lifecycleAudit = lifecycleAuditResult.status === "fulfilled" ? lifecycleAuditResult.value : { status: "unhealthy", findings: [{ code: lifecycleAuditResult.reason?.code || "ROOT_TRUST_BASELINE_LIFECYCLE_AUDIT_FAILED" }] };
    const anchor = anchorResult.status === "fulfilled" ? anchorResult.value : { status: "unhealthy", findings: [{ code: anchorResult.reason?.code || "ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_STATUS_FAILED" }] };
    const baseline = baselineResult.status === "fulfilled" ? baselineResult.value : { status: "unhealthy", findings: [{ code: baselineResult.reason?.code || "ROOT_TRUST_BASELINE_CURRENT_STATUS_FAILED" }] };
    const findings = [...(lifecycleAudit.findings || []), ...(anchor.findings || []), ...(baseline.findings || [])];
    const lifecycleRecords = (await store.listEvidence(ownerId)).filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record"
      && item.artifactType === LIFECYCLE_ARTIFACT).map(item => ({ id: item.id, storedDigest: item.digest || null,
        computedDigest: recordDigest(item), payloadDigest: item.payloadDigest || null,
        computedPayloadDigest: item.payload == null ? null : sha256(canonical(item.payload)), status: item.status || null }))
      .sort((a, b) => String(a.id).localeCompare(String(b.id)));
    const hardFinding = findings.some(item => /ROLLBACK|MISMATCH|EVENT_MISSING|EVENT_INVALID|HISTORY_INCOMPLETE|MARKER_INVALID|DISCONTINUITY|DIGEST_INVALID|LEDGER_INVALID/.test(String(item.code || "")));
    const transientUnavailable = findings.some(item => /UNAVAILABLE|PROVIDER_READ_FAILED|TIMEOUT|CONNECTION_REFUSED/.test(String(item.code || "")));
    const lost = lifecycleAudit.status === "unhealthy" || hardFinding || ["rollback_suspected", "mismatch", "continuity_unproven"].includes(anchor.status)
      || anchor.status === "unhealthy" && !transientUnavailable || ["unhealthy", "invalid", "corrupt"].includes(baseline.status);
    const snapshot = { lifecycleStatus: lifecycleAudit.status, anchorStatus: anchor.status, anchorSequence: anchor.anchorSequence ?? null,
      anchorDigest: anchor.anchorDigest ?? null, baselineStatus: baseline.status, baselineDigest: baseline.currentBaselineDigest ?? null,
      findings: findings.map(item => ({ code: item.code, sequence: item.sequence ?? null })).sort((a, b) => String(a.code).localeCompare(String(b.code))), lifecycleRecords };
    return { lost, snapshot, findings, digest: sha256(canonical(snapshot)) };
  }
  async function readRevocation(ownerId, proofDigest) {
    const id = revocationStateId(ownerId, proofDigest), state = await store.getEvidence(ownerId, id);
    if (!state) return { status: "not_revoked", state: null, findings: [] };
    if (state.id !== id || state.ownerId !== ownerId || state.kind !== REVOCATION_STATE_KIND || state.schemaVersion !== 1
      || state.proofDigest !== proofDigest || state.status !== "revoked" || state.revision !== 1 || !Array.isArray(state.events) || state.events.length !== 1
      || state.digest !== recordDigest(state)) return { status: "unhealthy", state: null, findings: [{ code: "ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_STATE_INVALID" }] };
    const event = state.events[0], unsigned = clean(event || {}); delete unsigned.eventDigest;
    if (event?.sequence !== 1 || event.previousEventDigest !== null || event.proofDigest !== proofDigest || !DIGEST.test(event.eventDigest || "")
      || sha256(canonical(unsigned)) !== event.eventDigest || !validReason(event.reason) || !Number.isFinite(Date.parse(event.revokedAt))
      || !DIGEST.test(event.sourceTrustDigest || "")) return { status: "unhealthy", state: null, findings: [{ code: "ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_EVENT_INVALID" }] };
    return { status: "revoked", state, findings: [] };
  }
  async function create(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240 || /[\u0000-\u001f\u007f]/.test(reason))
      throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REASON_INVALID", "Alasan continuity proof wajib 12–240 karakter", 400);
    const [sourceState, anchor, baseline] = await Promise.all([source(ownerId), lifecycleAnchorService.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(ownerId),
      baselineService.getRecoverySloRootTrustConformanceCurrentBaseline(ownerId)]);
    if (anchor.status !== "anchored" || anchor.anchorSequence !== sourceState.events.length || !DIGEST.test(anchor.anchorDigest || "")
      || baseline.status !== "current" || !baseline.currentBaselineDigest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_NOT_PROVABLE", "Continuity proof memerlukan lifecycle sehat, external checkpoint terkini, dan baseline aktif", 409,
        { anchorStatus: anchor.status, anchorSequence: anchor.anchorSequence, lifecycleEvents: sourceState.events.length, baselineStatus: baseline.status });
    }
    const unsigned = { domain: "agentic-v4-root-trust-baseline-checkpoint-continuity", schemaVersion: 1,
      proofId: `root-trust-baseline-continuity-${randomUUID()}`, ownerId, reason: reason.trim(), createdAt: now(),
      anchor: { status: anchor.status, sequence: anchor.anchorSequence, digest: anchor.anchorDigest, historyNotProven: anchor.historyNotProven ?? true },
      lifecycle: { eventCount: sourceState.events.length, historyDigest: sourceState.historyDigest, latestEventDigest: sourceState.events.at(-1)?.eventDigest || null },
      baseline: { revision: baseline.revision, digest: baseline.currentBaselineDigest } };
    const proof = { ...unsigned, digest: sha256(canonical(unsigned)) };
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: ARTIFACT, sourceId: proof.digest, payload: proof, retentionDays: 3650 });
    return { status: "proof_created", proof, retention, readOnly: false, mutationAllowed: false };
  }
  async function verify(ownerId, proof) {
    assertOwner(ownerId);
    const unsigned = clean(proof || {}); delete unsigned.digest;
    const digestValid = Boolean(proof?.digest && sha256(canonical(unsigned)) === proof.digest && proof.domain === "agentic-v4-root-trust-baseline-checkpoint-continuity"
      && proof.schemaVersion === 1 && proof.ownerId === ownerId && DIGEST.test(proof.lifecycle?.historyDigest || "") && DIGEST.test(proof.anchor?.digest || "")
      && DIGEST.test(proof.baseline?.digest || ""));
    const listed = await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true });
    const record = listed.items.find(item => item?.artifactType === ARTIFACT && item.sourceId === proof?.digest);
    const retained = Boolean(record && record.status === "retained" && record.digest === recordDigest(record)
      && record.payloadDigest === sha256(canonical(proof)) && canonical(record.payload) === canonical(proof));
    const revocation = await readRevocation(ownerId, proof?.digest || "");
    const findings = [...revocation.findings];
    if (!digestValid) findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_PROOF_DIGEST_INVALID" });
    if (!retained) findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_PROOF_NOT_RETAINED" });
    if (revocation.status === "revoked") findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_PROOF_REVOKED", revokedAt: revocation.state.events[0].revokedAt });
    let current = false;
    try {
      const [sourceState, anchor, baseline] = await Promise.all([source(ownerId), lifecycleAnchorService.getRecoverySloRootTrustBaselineLifecycleAnchorStatus(ownerId),
        baselineService.getRecoverySloRootTrustConformanceCurrentBaseline(ownerId)]);
      current = anchor.status === "anchored" && anchor.anchorDigest === proof?.anchor?.digest && anchor.anchorSequence === proof?.anchor?.sequence
        && sourceState.historyDigest === proof?.lifecycle?.historyDigest && baseline.status === "current" && baseline.currentBaselineDigest === proof?.baseline?.digest;
    } catch { current = false; }
    const historicallyValid = digestValid && retained;
    return { valid: historicallyValid && revocation.status === "not_revoked", historicallyValid, current,
      revoked: revocation.status === "revoked", revocationStatus: revocation.status,
      usableAsTrustedEvidence: historicallyValid && revocation.status === "not_revoked", findings, readOnly: true, mutationAllowed: false };
  }
  async function prepareRevocation(ownerId, { proof = null, proofDigest = null, reason } = {}) {
    assertOwner(ownerId);
    if (!validReason(reason)) throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_REASON_INVALID", "Alasan pencabutan wajib 12–240 karakter", 400);
    if (!proof && DIGEST.test(proofDigest || "")) {
      const listedProofs = await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true });
      proof = listedProofs.items.find(item => item?.artifactType === ARTIFACT && item.sourceId === proofDigest && item.status === "retained")?.payload || null;
    }
    const verification = await verify(ownerId, proof);
    if (!verification.historicallyValid) throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_PROOF_INVALID", "Proof historis tidak valid atau tidak tersimpan", 409);
    const existing = await readRevocation(ownerId, proof.digest);
    if (existing.status === "revoked") throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_PROOF_ALREADY_REVOKED", "Continuity proof sudah dicabut", 409);
    if (existing.status === "unhealthy") throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_STATE_UNHEALTHY", "Histori pencabutan tidak sehat", 409);
    const trust = await sourceTrust(ownerId);
    if (!trust.lost) throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_SOURCE_STILL_TRUSTED", "Pencabutan hanya diizinkan ketika integritas sumber tidak lagi dapat dipercaya", 409,
      { lifecycleStatus: trust.snapshot.lifecycleStatus, anchorStatus: trust.snapshot.anchorStatus });
    const createdAt = now(), id = `root-trust-baseline-continuity-revocation-challenge-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: REVOCATION_CHALLENGE_KIND, schemaVersion: 1, status: "prepared", proofDigest: proof.digest,
      sourceTrustDigest: trust.digest, sourceTrustSnapshot: trust.snapshot, reason: reason.trim(), createdAt,
      expiresAt: new Date(Date.parse(createdAt) + REVOCATION_TTL_MS).toISOString() };
    const challenge = { ...unsigned, digest: sha256(canonical(unsigned)) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, proofDigest: proof.digest, sourceTrustDigest: trust.digest, createdAt, expiresAt: challenge.expiresAt,
      challengeDigest: challenge.digest, confirmation: `REVOKE ROOT TRUST BASELINE CONTINUITY PROOF ${challenge.digest.slice(0, 12)}`,
      readOnly: false, mutationAllowed: false };
  }
  async function applyRevocation(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id), unsignedChallenge = clean(challenge || {}); delete unsignedChallenge.digest;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== REVOCATION_CHALLENGE_KIND || challenge.status !== "prepared"
      || challenge.digest !== sha256(canonical(unsignedChallenge)) || !Number.isFinite(Date.parse(challenge.expiresAt))
      || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `REVOKE ROOT TRUST BASELINE CONTINUITY PROOF ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_CHALLENGE_INVALID", "Challenge pencabutan tidak valid, kedaluwarsa, atau konfirmasi tidak cocok", 409);
    }
    const existing = await readRevocation(ownerId, challenge.proofDigest);
    if (existing.status !== "not_revoked") throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_ALREADY_APPLIED", "Pencabutan sudah diterapkan atau statusnya tidak dapat dipercaya", 409);
    const trust = await sourceTrust(ownerId);
    if (!trust.lost || trust.digest !== challenge.sourceTrustDigest) throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_SOURCE_CHANGED", "Kondisi trust sumber berubah sejak challenge dibuat", 409);
    const listed = await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true });
    const proofRecord = listed.items.find(item => item?.artifactType === ARTIFACT && item.sourceId === challenge.proofDigest);
    if (!proofRecord || proofRecord.status !== "retained" || proofRecord.digest !== recordDigest(proofRecord)
      || proofRecord.payloadDigest !== sha256(canonical(proofRecord.payload)) || proofRecord.payload?.digest !== challenge.proofDigest)
      throw new AgenticError("ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_PROOF_MISSING", "Proof sumber tidak lagi dapat diverifikasi", 409);
    const revokedAt = now(), eventUnsigned = { domain: "agentic-v4-root-trust-baseline-continuity-proof-revocation", schemaVersion: 1,
      ownerId, proofDigest: challenge.proofDigest, sequence: 1, previousEventDigest: null, reason: challenge.reason,
      sourceTrustStatus: trust.snapshot.anchorStatus, sourceTrustDigest: trust.digest, sourceTrustFindings: trust.snapshot.findings, revokedAt };
    const event = { ...eventUnsigned, eventDigest: sha256(canonical(eventUnsigned)) };
    const stateUnsigned = { id: revocationStateId(ownerId, challenge.proofDigest), ownerId, kind: REVOCATION_STATE_KIND, schemaVersion: 1,
      status: "revoked", proofDigest: challenge.proofDigest, revision: 1, events: [event], updatedAt: revokedAt };
    const state = { ...stateUnsigned, digest: recordDigest(stateUnsigned) };
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: REVOCATION_ARTIFACT,
      sourceId: challenge.proofDigest, payload: state, retentionDays: 3650 });
    await store.putEvidence(ownerId, state, { overwrite: false });
    const completedUnsigned = { ...clean(challenge), status: "applied", appliedAt: revokedAt, revocationDigest: state.digest, retentionId: retention?.id || null };
    delete completedUnsigned.digest;
    await store.putEvidence(ownerId, { ...completedUnsigned, digest: sha256(canonical(completedUnsigned)) }, { expectedVersion: challenge._storage?.version });
    return { status: "revoked", proofDigest: challenge.proofDigest, revocationDigest: state.digest, revokedAt,
      sourceTrustStatus: trust.snapshot.anchorStatus, retention, readOnly: false, mutationAllowed: false };
  }
  async function auditRevocations(ownerId) {
    assertOwner(ownerId);
    const [rows, retained] = await Promise.all([store.listEvidence(ownerId), retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true })]);
    const states = rows.filter(item => item?.kind === REVOCATION_STATE_KIND && item.ownerId === ownerId), findings = [];
    for (const state of states) {
      const checked = await readRevocation(ownerId, state.proofDigest);
      if (checked.status !== "revoked") findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_INVALID", proofDigest: state.proofDigest });
      const evidence = retained.items.find(item => item?.artifactType === REVOCATION_ARTIFACT && item.sourceId === state.proofDigest);
      const cleanState = clean(state), expectedPayloadDigest = sha256(canonical(cleanState));
      const retainedMatch = evidence?.status === "retained" && evidence.payloadDigest === expectedPayloadDigest
        && canonical(evidence.payload) === canonical(cleanState);
      const tombstoneMatch = evidence?.status === "tombstone" && evidence.payload == null
        && evidence.payloadDigest === expectedPayloadDigest && evidence.tombstone?.payloadDigest === expectedPayloadDigest
        && evidence.tombstone?.reason === "RETENTION_PERIOD_ELAPSED";
      if (!evidence || (!retainedMatch && !tombstoneMatch))
        findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_NOT_RETAINED", proofDigest: state.proofDigest });
    }
    const orphaned = retained.items.filter(item => item?.artifactType === REVOCATION_ARTIFACT && item.status === "retained"
      && !states.some(state => state.proofDigest === item.sourceId));
    for (const item of orphaned) findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_ORPHANED_EVIDENCE", evidenceId: item.id });
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: states.length, findings, readOnly: true, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [listed, overall] = await Promise.all([retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true }),
      retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId)]);
    const records = listed.items.filter(item => item?.artifactType === ARTIFACT), findings = []; let valid = 0, current = 0, revoked = 0, tombstones = 0;
    for (const record of records) {
      if (record.status === "tombstone") { tombstones++; continue; }
      const result = await verify(ownerId, record.payload);
      if (!result.historicallyValid) findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_PROOF_INVALID", evidenceId: record.id, findings: result.findings });
      else { valid++; if (result.current) current++; if (result.revoked) revoked++; }
      if (result.revocationStatus === "unhealthy") findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_STATE_UNHEALTHY", evidenceId: record.id });
    }
    const revocationAudit = await auditRevocations(ownerId);
    if (overall.status !== "healthy") findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_RETENTION_AUDIT_UNHEALTHY" });
    if (revocationAudit.status !== "healthy") findings.push({ code: "ROOT_TRUST_BASELINE_CONTINUITY_REVOCATION_AUDIT_UNHEALTHY", findings: revocationAudit.findings });
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, valid, current, revoked, tombstones,
      revocationAudit, findings, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ createRecoverySloRootTrustBaselineCheckpointContinuityProof: create,
    verifyRecoverySloRootTrustBaselineCheckpointContinuityProof: verify,
    auditRecoverySloRootTrustBaselineCheckpointContinuityProofs: audit,
    prepareRecoverySloRootTrustBaselineContinuityProofRevocation: prepareRevocation,
    applyRecoverySloRootTrustBaselineContinuityProofRevocation: applyRevocation,
    auditRecoverySloRootTrustBaselineContinuityProofRevocations: auditRevocations });
}
