import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const POINTER_KIND = "recovery-slo-root-trust-conformance-baseline-current";
const CHALLENGE_KIND = "recovery-slo-root-trust-conformance-baseline-rotation-challenge";
const LIFECYCLE_ARTIFACT = "root_trust_conformance_baseline_lifecycle";
const SOURCE_KIND = "recovery-slo-root-recovery-trust-anchor-conformance-challenge";
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
const pointerId = ownerId => `recovery-slo-root-trust-baseline-current-${sha256(ownerId).slice(0, 40)}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_OWNER_REQUIRED", "Owner baseline lifecycle wajib ditentukan", 400);
  }
}
function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }

export function createRecoverySloRootTrustConformanceBaselineLifecycleService({ store, baselineAttestationService, retainedEvidenceService,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence
    || typeof baselineAttestationService?.attestRecoverySloRootTrustConformanceBaseline !== "function"
    || typeof baselineAttestationService?.verifyRecoverySloRootTrustConformanceBaselineAttestation !== "function"
    || typeof retainedEvidenceService?.retainRecoverySloAnchorEvidence !== "function" || typeof retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence !== "function"
    || typeof clock !== "function") throw new TypeError("Root-trust baseline lifecycle membutuhkan store, attestation service, retained evidence, dan clock");
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_CLOCK_INVALID", "Clock baseline lifecycle tidak valid", 500);
    return new Date(time).toISOString();
  }
  async function sourceReport(ownerId, challengeId) {
    const challenge = await store.getEvidence(ownerId, challengeId);
    const report = challenge?.report ? clean(challenge.report) : null;
    if (report) delete report.reportDigest;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== SOURCE_KIND || challenge.status !== "completed"
      || !DIGEST.test(challenge.digest || "") || challenge.digest !== digestRecord(challenge)
      || !challenge.report || challenge.report.ownerId !== ownerId || challenge.report.providerDomain !== "root_recovery_trust"
      || challenge.report.status !== "conformant" || challenge.report.conformant !== true || !DIGEST.test(challenge.reportDigest || "")
      || challenge.report.reportDigest !== challenge.reportDigest || sha256(canonical(report)) !== challenge.reportDigest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_SOURCE_INVALID", "Rotasi memerlukan laporan root-trust conformance yang completed dan conformant", 409);
    }
    return challenge;
  }
  function validatePointer(ownerId, pointer) {
    if (!pointer || pointer.id !== pointerId(ownerId) || pointer.ownerId !== ownerId || pointer.kind !== POINTER_KIND || pointer.schemaVersion !== 1
      || !Number.isSafeInteger(pointer.revision) || pointer.revision < 1 || !DIGEST.test(pointer.activeAttestationDigest || "")
      || typeof pointer.activeEvidenceId !== "string" || !pointer.activeEvidenceId
      || (pointer.previousBaselineDigest !== null && !DIGEST.test(pointer.previousBaselineDigest || ""))
      || !DIGEST.test(pointer.lifecycleEventDigest || "") || !Number.isFinite(Date.parse(pointer.updatedAt))
      || typeof pointer.historyNotProven !== "boolean" || !DIGEST.test(pointer.digest || "") || pointer.digest !== digestRecord(pointer)) {
      return { valid: false, code: "ROOT_TRUST_BASELINE_CURRENT_POINTER_INVALID" };
    }
    return { valid: true };
  }
  async function readPointer(ownerId) {
    const pointer = await store.getEvidence(ownerId, pointerId(ownerId));
    if (!pointer) return { status: "missing", pointer: null };
    const check = validatePointer(ownerId, pointer);
    return check.valid ? { status: "present", pointer } : { status: "invalid", pointer: null, finding: check.code };
  }
  async function lifecycleRecords(ownerId) {
    return (await store.listEvidence(ownerId)).filter(record => record?.kind === "recovery-slo-anchor-evidence-retention-record"
      && record.artifactType === LIFECYCLE_ARTIFACT).sort((a, b) => Number(a.payload?.sequence || 0) - Number(b.payload?.sequence || 0));
  }
  function validateLifecycleEvent(ownerId, record) {
    const event = record?.payload;
    if (!record || record.ownerId !== ownerId || record.kind !== "recovery-slo-anchor-evidence-retention-record"
      || record.artifactType !== LIFECYCLE_ARTIFACT || record.status !== "retained" || !DIGEST.test(record.digest || "")
      || record.digest !== digestRecord(record) || record.sourceId !== event?.eventDigest || record.payloadDigest !== sha256(canonical(event))
      || event?.domain !== "agentic-v4-root-trust-conformance-baseline-lifecycle" || event.schemaVersion !== 1 || event.ownerId !== ownerId
      || !Number.isSafeInteger(event.sequence) || event.sequence < 1 || !["enrolled", "rotated"].includes(event.action)
      || (event.previousEventDigest !== null && !DIGEST.test(event.previousEventDigest || ""))
      || (event.previousBaselineDigest !== null && !DIGEST.test(event.previousBaselineDigest || ""))
      || !DIGEST.test(event.baselineDigest || "") || !DIGEST.test(event.challengeDigest || "") || !DIGEST.test(event.reportDigest || "")
      || !Number.isFinite(Date.parse(event.createdAt)) || event.historyNotProven !== true
      || !DIGEST.test(event.eventDigest || "")) return { valid: false, code: "ROOT_TRUST_BASELINE_LIFECYCLE_EVENT_INVALID" };
    const unsigned = clean(event); delete unsigned.eventDigest;
    if (sha256(canonical(unsigned)) !== event.eventDigest) return { valid: false, code: "ROOT_TRUST_BASELINE_LIFECYCLE_EVENT_DIGEST_INVALID" };
    return { valid: true, event };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [pointerState, records, retainedAudit] = await Promise.all([readPointer(ownerId), lifecycleRecords(ownerId),
      retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId)]);
    const findings = [], ordered = [];
    if (retainedAudit.status !== "healthy") findings.push({ code: "ROOT_TRUST_BASELINE_RETAINED_EVIDENCE_UNHEALTHY", status: retainedAudit.status });
    if (pointerState.status === "invalid") findings.push({ code: pointerState.finding });
    for (const record of records) {
      const checked = validateLifecycleEvent(ownerId, record);
      if (!checked.valid) { findings.push({ code: checked.code, evidenceId: record.id }); continue; }
      ordered.push({ record, event: checked.event });
    }
    if (records.length !== ordered.length) findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_HISTORY_INCOMPLETE" });
    for (let index = 0; index < ordered.length; index++) {
      const event = ordered[index].event;
      if (event.sequence !== index + 1 || event.previousEventDigest !== (index ? ordered[index - 1].event.eventDigest : null)) {
        findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_CONTINUITY_INVALID", sequence: event.sequence });
      }
      if (index && event.previousBaselineDigest !== ordered[index - 1].event.baselineDigest) {
        findings.push({ code: "ROOT_TRUST_BASELINE_ROTATION_PREVIOUS_DIGEST_MISMATCH", sequence: event.sequence });
      }
    }
    const latest = ordered.at(-1)?.event || null, pointer = pointerState.pointer;
    if (pointer && (!latest || pointer.revision !== latest.sequence || pointer.activeAttestationDigest !== latest.baselineDigest
      || pointer.previousBaselineDigest !== latest.previousBaselineDigest || pointer.lifecycleEventDigest !== latest.eventDigest)) {
      findings.push({ code: "ROOT_TRUST_BASELINE_CURRENT_POINTER_HISTORY_MISMATCH" });
    }
    if (!pointer && records.length) findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_POINTER_MISSING" });
    return { status: findings.length ? "unhealthy" : pointer ? "healthy" : "not_initialized", ownerId,
      revision: pointer?.revision ?? 0, currentBaselineDigest: pointer?.activeAttestationDigest || null,
      previousBaselineDigest: pointer?.previousBaselineDigest ?? null, lifecycleEvents: records.length, findings,
      historyNotProven: pointer?.historyNotProven ?? true, readOnly: true, mutationAllowed: false };
  }
  async function findAttestation(ownerId, pointer) {
    const record = await store.getEvidence(ownerId, pointer.activeEvidenceId);
    if (!record || record.kind !== "recovery-slo-anchor-evidence-retention-record" || record.artifactType !== "root_trust_conformance_baseline_attestation"
      || record.status !== "retained" || record.sourceId !== pointer.activeAttestationDigest || record.payloadDigest !== sha256(canonical(record.payload))
      || record.payload?.attestationDigest !== pointer.activeAttestationDigest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_CURRENT_EVIDENCE_MISSING", "Attestation baseline aktif tidak tersedia sebagai retained evidence", 409);
    }
    return record.payload;
  }
  async function prepare(ownerId, { challengeId, reason } = {}) {
    assertOwner(ownerId);
    if (!validReason(reason)) throw new AgenticError("ROOT_TRUST_BASELINE_ROTATION_REASON_INVALID", "Alasan rotasi wajib 12–240 karakter", 400);
    const source = await sourceReport(ownerId, challengeId);
    const [pointerState, auditState] = await Promise.all([readPointer(ownerId), audit(ownerId)]);
    if (pointerState.status === "invalid" || auditState.status === "unhealthy") throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_UNHEALTHY", "Histori baseline tidak sehat; rotasi ditolak", 409, { findings: auditState.findings });
    const current = pointerState.pointer;
    if (current) {
      const previous = await findAttestation(ownerId, current);
      const verified = await baselineAttestationService.verifyRecoverySloRootTrustConformanceBaselineAttestation(ownerId, previous);
      if (!verified.historicallyValid) throw new AgenticError("ROOT_TRUST_BASELINE_PREVIOUS_ATTESTATION_INVALID", "Baseline sebelumnya tidak dapat diverifikasi secara historis", 409);
    }
    const createdAt = now(), id = `root-trust-baseline-rotation-${randomUUID()}`, expiresAt = new Date(Date.parse(createdAt) + TTL_MS).toISOString();
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "prepared", intent: current ? "rotate" : "enroll",
      expectedRevision: current?.revision ?? 0, expectedBaselineDigest: current?.activeAttestationDigest ?? null,
      challengeId: source.id, sourceChallengeDigest: source.digest, reportDigest: source.reportDigest,
      reason: reason.trim(), createdAt, expiresAt };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, intent: challenge.intent, expectedRevision: challenge.expectedRevision,
      expectedBaselineDigest: challenge.expectedBaselineDigest, sourceReportDigest: challenge.reportDigest,
      challengeDigest: challenge.digest, createdAt, expiresAt,
      confirmation: `${challenge.intent === "enroll" ? "ENROLL" : "ROTATE"} ROOT TRUST BASELINE ${challenge.digest.slice(0, 12)}`,
      readOnly: false, mutationAllowed: false };
  }
  async function apply(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.status !== "prepared"
      || challenge.digest !== digestRecord(challenge) || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `${challenge.intent === "enroll" ? "ENROLL" : "ROTATE"} ROOT TRUST BASELINE ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("ROOT_TRUST_BASELINE_ROTATION_CHALLENGE_INVALID", "Challenge rotasi tidak valid, kedaluwarsa, atau konfirmasinya tidak cocok", 409);
    }
    const source = await sourceReport(ownerId, challenge.challengeId);
    if (source.digest !== challenge.sourceChallengeDigest || source.reportDigest !== challenge.reportDigest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_ROTATION_SOURCE_CHANGED", "Laporan conformance berubah sejak challenge disiapkan", 409);
    }
    const currentState = await readPointer(ownerId);
    if (currentState.status === "invalid" || (currentState.pointer?.revision ?? 0) !== challenge.expectedRevision
      || (currentState.pointer?.activeAttestationDigest ?? null) !== challenge.expectedBaselineDigest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_ROTATION_STALE", "Baseline aktif berubah sejak challenge disiapkan", 409);
    }
    const previousDigest = currentState.pointer?.activeAttestationDigest ?? null;
    const issued = await baselineAttestationService.attestRecoverySloRootTrustConformanceBaseline(ownerId, {
      challengeId: challenge.challengeId, reason: challenge.reason
    });
    const sequence = (currentState.pointer?.revision ?? 0) + 1;
    const events = await lifecycleRecords(ownerId);
    const priorEvent = events.map(record => record.payload).filter(event => DIGEST.test(event?.eventDigest || ""))
      .sort((a, b) => a.sequence - b.sequence).at(-1) || null;
    const eventUnsigned = { domain: "agentic-v4-root-trust-conformance-baseline-lifecycle", schemaVersion: 1, ownerId,
      sequence, action: previousDigest ? "rotated" : "enrolled", previousEventDigest: priorEvent?.eventDigest || null,
      previousBaselineDigest: previousDigest, baselineDigest: issued.attestation.attestationDigest,
      challengeDigest: challenge.digest, reportDigest: challenge.reportDigest, createdAt: now(), historyNotProven: true };
    const event = { ...eventUnsigned, eventDigest: sha256(canonical(eventUnsigned)) };
    const retainedEvent = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: LIFECYCLE_ARTIFACT,
      sourceId: event.eventDigest, payload: event, retentionDays: 3650 });
    const pointerIdValue = pointerId(ownerId), old = currentState.pointer;
    const pointerUnsigned = { id: pointerIdValue, ownerId, kind: POINTER_KIND, schemaVersion: 1, revision: sequence,
      activeAttestationDigest: issued.attestation.attestationDigest, activeEvidenceId: issued.retention.id,
      previousBaselineDigest: previousDigest, lifecycleEventDigest: event.eventDigest, updatedAt: now(), historyNotProven: true };
    const pointer = { ...pointerUnsigned, digest: digestRecord(pointerUnsigned) };
    await store.putEvidence(ownerId, pointer, old ? { expectedVersion: old._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, pointerIdValue);
    if (!validatePointer(ownerId, saved).valid || saved.activeAttestationDigest !== issued.attestation.attestationDigest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_ROTATION_WRITE_VERIFY_FAILED", "Current baseline pointer gagal diverifikasi setelah penulisan", 409);
    }
    const lifecycleAudit = await audit(ownerId);
    if (lifecycleAudit.status !== "healthy") throw new AgenticError("ROOT_TRUST_BASELINE_ROTATION_POSTCHECK_FAILED", "Audit histori baseline gagal setelah rotasi", 409, { findings: lifecycleAudit.findings });
    return { status: previousDigest ? "rotated" : "enrolled", revision: sequence, attestation: issued.attestation,
      attestationRetention: issued.retention, lifecycleRetention: retainedEvent, currentBaselineDigest: pointer.activeAttestationDigest,
      previousBaselineDigest: pointer.previousBaselineDigest, historyNotProven: true, audit: lifecycleAudit, readOnly: false, mutationAllowed: false };
  }
  async function current(ownerId) {
    assertOwner(ownerId);
    const state = await audit(ownerId), pointerState = await readPointer(ownerId);
    if (state.status === "unhealthy" || pointerState.status === "invalid") return { status: "unhealthy", ownerId, findings: state.findings, readOnly: true, mutationAllowed: false };
    if (!pointerState.pointer) return { status: "not_initialized", ownerId, revision: 0, currentBaselineDigest: null, readOnly: true, mutationAllowed: false };
    const attestation = await findAttestation(ownerId, pointerState.pointer);
    const verification = await baselineAttestationService.verifyRecoverySloRootTrustConformanceBaselineAttestation(ownerId, attestation);
    return { status: verification.usableAsCurrentBaseline ? "current" : "revalidation_required", ownerId,
      revision: pointerState.pointer.revision, currentBaselineDigest: pointerState.pointer.activeAttestationDigest,
      previousBaselineDigest: pointerState.pointer.previousBaselineDigest, verification, historyNotProven: true,
      readOnly: true, mutationAllowed: false };
  }
  async function revalidate(ownerId) {
    const result = await current(ownerId);
    if (result.status !== "current") throw new AgenticError("ROOT_TRUST_BASELINE_REVALIDATION_FAILED", "Baseline aktif tidak dapat direvalidasi; jalankan conformance baru dan rotasi eksplisit", 409,
      { status: result.status, findings: result.findings || result.verification?.findings || [] });
    return { ...result, revalidatedAt: now(), revalidated: true, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ prepareRecoverySloRootTrustConformanceBaselineRotation: prepare,
    applyRecoverySloRootTrustConformanceBaselineRotation: apply,
    getRecoverySloRootTrustConformanceCurrentBaseline: current,
    revalidateRecoverySloRootTrustConformanceCurrentBaseline: revalidate,
    auditRecoverySloRootTrustConformanceBaselineLifecycle: audit, configured: true });
}
