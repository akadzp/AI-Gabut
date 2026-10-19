import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const TRANSITION_LEDGER_KIND = "recovery-slo-cross-domain-recovery-intent-status-transition-ledger";
const TRANSITION_EVENT_KIND = "recovery-slo-cross-domain-recovery-intent-status-transition";
const TRANSITION_ATTESTATION_KIND = "recovery-slo-cross-domain-recovery-intent-status-transition-attestation";
const DISPOSITION_LEDGER_KIND = "recovery-slo-cross-domain-recovery-intent-orphan-disposition-ledger";
const DISPOSITION_EVENT_KIND = "recovery-slo-cross-domain-recovery-intent-orphan-disposition";
const DISPOSITION_ATTESTATION_KIND = "recovery-slo-cross-domain-recovery-intent-orphan-disposition-attestation";
const DISPOSITION_CHALLENGE_KIND = "recovery-slo-cross-domain-recovery-intent-orphan-disposition-challenge";
const CHECKPOINT_RECOVERY_LEDGER_KIND = "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-recovery-ledger";
const CHECKPOINT_RECOVERY_EVENT_KIND = "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-recovery-event";
const CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND = "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-marker-recovery-ledger";
const CHECKPOINT_MARKER_RECOVERY_EVENT_KIND = "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-marker-recovery-event";
const CHECKPOINT_MARKER_RECOVERY_ATTESTATION_KIND = "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-marker-recovery-attestation";
const CHECKPOINT_FRESHNESS_ATTESTATION_KIND = "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-freshness-attestation";
const CHECKPOINT_FRESHNESS_LIFECYCLE_CHALLENGE_KIND = "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-freshness-lifecycle-challenge";
const MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND = "recovery-slo-cross-domain-recovery-intent-closure-marker-recovery-journal-attestation";
const MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND = "marker-journal-attestation-lifecycle-challenge";
const MARKER_RECOVERY_JOURNAL_LIFECYCLE_INTENT_EVENT_TYPE = "marker_recovery_journal_attestation_lifecycle_recovery_intent";
const MARKER_RECOVERY_JOURNAL_LIFECYCLE_FINALIZATION_EVENT_TYPE = "marker_recovery_journal_attestation_lifecycle_finalization";
const MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_KIND = "marker-journal-attestation-lifecycle-recovery-disposition-challenge";
const MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE = "marker_recovery_journal_attestation_lifecycle_recovery_intent_disposition";
const MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE = "marker_recovery_journal_attestation_lifecycle_recovery_intent_disposition_finalization";
const MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_SNAPSHOT_KIND = "marker-recovery-journal-lifecycle-disposition-ledger-snapshot";
const MARKER_JOURNAL_LIFECYCLE_DISPOSITIONS = new Set(["quarantine", "mark_unrecoverable"]);
const LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND = "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-challenge";
const LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_KIND = "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-event";
const LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_KIND = "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-finalization";
const LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND = "recovery-intent-closure-lifecycle-disposition-checkpoint-rollback-attestation";
const LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_LEDGER_KIND = "recovery-intent-closure-lifecycle-disposition-rollback-continuity-ledger";
const LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_EVENT_KIND = "recovery-intent-closure-lifecycle-disposition-rollback-continuity-event";
const LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KIND = "recovery-intent-closure-lifecycle-disposition-rollback-revalidation-attestation";
const LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHALLENGE_KIND = "recovery-intent-closure-lifecycle-disposition-rollback-revalidation-lifecycle-challenge";
const LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_INTENT_EVENT_TYPE = "lifecycle_disposition_checkpoint_rollback_revalidation_lifecycle_intent";
const LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_APPLIED_EVENT_TYPE = "lifecycle_disposition_checkpoint_rollback_revalidation_lifecycle_applied";
const LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_FINALIZATION_EVENT_TYPE = "lifecycle_disposition_checkpoint_rollback_revalidation_lifecycle_finalized";
const LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_EVENT_TYPES = new Set([
  LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_INTENT_EVENT_TYPE,
  LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_APPLIED_EVENT_TYPE,
  LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_FINALIZATION_EVENT_TYPE
]);
const LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN = "cross_domain_recovery_intent_closure_revalidation_lifecycle";
const REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE = "revalidation_lifecycle_checkpoint_freshness_attested";
const REVALIDATION_LIFECYCLE_DRIFT_OBSERVED_EVENT_TYPE = "revalidation_lifecycle_checkpoint_drift_observed";
const REVALIDATION_LIFECYCLE_DRIFT_RESOLVED_EVENT_TYPE = "revalidation_lifecycle_checkpoint_drift_resolved";
const REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_EVENT_TYPE = "revalidation_lifecycle_drift_resolution_continuity_receipt";
const REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_EVENT_TYPE = "revalidation_lifecycle_freshness_attestation_superseded";
const REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_EVENT_TYPE = "revalidation_lifecycle_recovery_gate_proof";
const REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_KIND = "recovery-slo-cross-domain-revalidation-lifecycle-freshness-attestation";
const REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_ATTESTATION_KIND = "recovery-slo-cross-domain-revalidation-lifecycle-freshness-supersession";
const REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_KIND = "recovery-slo-cross-domain-revalidation-lifecycle-recovery-gate-proof";
const REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_LEDGER_KIND = "recovery-slo-cross-domain-revalidation-lifecycle-recovery-gate-proof-ledger";
const REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_RECORD_KIND = "recovery-slo-cross-domain-revalidation-lifecycle-drift-evidence";
const LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES = Object.freeze([
  "challenge_prepared", "rollback_event_recorded", "external_intent_receipt_anchored",
  "finalization_receipt_recorded", "external_finalization_receipt_anchored", "challenge_finalized"
]);
const LIFECYCLE_DISPOSITION_ROLLBACK_ACTIONS = new Set(["quarantine", "mark_unrecoverable"]);
const DIGEST = /^[a-f0-9]{64}$/;
const INTENT_STATUSES = new Set(["prepared", "recovery_required", "completed"]);
const DISPOSITIONS = new Set(["quarantine", "mark_unrecoverable"]);

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
const payloadDigest = value => { const copy = clean(value); for (const key of ["digest", "attestation"]) delete copy[key]; return sha256(canonical(copy)); };
const eventBaseDigest = value => { const copy = clean(value); for (const key of ["digest", "attestation", "payloadBindingDigest"]) delete copy[key]; return sha256(canonical(copy)); };
const isoNow = clock => new Date(Date.parse(String(clock()))).toISOString();

function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("RECOVERY_INTENT_CLOSURE_OWNER_REQUIRED", "Owner recovery-intent closure wajib ditentukan", 400);
}
function ledgerId(prefix, ownerId) { return `${prefix}-${sha256(ownerId).slice(0, 32)}`; }

export function createRecoverySloCrossDomainRecoveryIntentClosureService({
  store, clock = () => new Date().toISOString(), intentKind, strictAttestation = false,
  getCurrentKeyBinding, getIntentRows, getLifecycleEvents, getIntentCheckpointAudit,
  getOrphanCandidates, getStrictCheckpointState, createAttestation, verifyAttestation,
  getTransitionCheckpointState = async () => ({ enabled: false, required: false, usableForCurrentDecision: true, status: "not_configured" }),
  getDispositionCheckpointState = async () => ({ enabled: false, required: false, usableForCurrentDecision: true, status: "not_configured" }),
  advanceTransitionCheckpoint = async () => ({ status: "not_configured" }),
  advanceDispositionCheckpoint = async () => ({ status: "not_configured" }),
  getRecoveryReceiptCheckpointState = async () => ({ enabled: false, required: false, usableForCurrentDecision: true, status: "not_configured" }),
  advanceRecoveryReceiptCheckpoint = async () => ({ status: "not_configured" }),
  getMarkerRecoveryJournalCheckpointState = async () => ({ enabled: false, required: false, usableForCurrentDecision: true, status: "not_configured" }),
  advanceMarkerRecoveryJournalCheckpoint = async () => ({ status: "not_configured" }),
  getMarkerRecoveryJournalLifecycleDispositionCheckpointState = async () => ({ enabled: false, required: false, usableForCurrentDecision: true, status: "not_configured" }),
  advanceMarkerRecoveryJournalLifecycleDispositionCheckpoint = async () => ({ status: "not_configured" }),
  inspectMarkerRecoveryJournalLifecycleDispositionCheckpointRecovery = async () => ({ status: "not_configured", recoverable: false, findings: [] }),
  getRevalidationLifecycleCheckpointState = async () => ({ enabled: false, required: false, usableForCurrentDecision: true, status: "not_configured", findings: [] }),
  advanceRevalidationLifecycleCheckpoint = async () => ({ status: "not_configured", usableForCurrentDecision: true }),
  reconcileRevalidationLifecycleCheckpoint = async () => ({ status: "not_configured", usableForCurrentDecision: true }),
  requireFreshnessAttestation = false, freshnessAttestationMaxAgeMs = 300000,
  requireMarkerRecoveryJournalAttestation = false, requireRevalidationLifecycleFreshnessAttestation = false,
  revalidationLifecycleFreshnessAttestationMaxAgeMs = 300000
} = {}) {
  if (!store?.getEvidence || !store?.listEvidence || !store?.putEvidence || typeof intentKind !== "string"
    || typeof getCurrentKeyBinding !== "function" || typeof getIntentRows !== "function"
    || typeof getLifecycleEvents !== "function" || typeof getIntentCheckpointAudit !== "function"
    || typeof getOrphanCandidates !== "function" || typeof getStrictCheckpointState !== "function"
    || typeof createAttestation !== "function" || typeof verifyAttestation !== "function"
    || typeof getTransitionCheckpointState !== "function" || typeof getDispositionCheckpointState !== "function"
    || typeof advanceTransitionCheckpoint !== "function" || typeof advanceDispositionCheckpoint !== "function"
    || typeof getRecoveryReceiptCheckpointState !== "function" || typeof advanceRecoveryReceiptCheckpoint !== "function"
    || typeof getMarkerRecoveryJournalCheckpointState !== "function" || typeof advanceMarkerRecoveryJournalCheckpoint !== "function"
    || typeof getMarkerRecoveryJournalLifecycleDispositionCheckpointState !== "function"
    || typeof advanceMarkerRecoveryJournalLifecycleDispositionCheckpoint !== "function"
    || typeof inspectMarkerRecoveryJournalLifecycleDispositionCheckpointRecovery !== "function")
    throw new TypeError("Recovery-intent closure membutuhkan store, lifecycle readers, key binding, dan attestation signer/verifier");

  const transitionLedgerId = ownerId => ledgerId("recovery-intent-status-transitions", ownerId);
  const dispositionLedgerId = ownerId => ledgerId("recovery-intent-orphan-dispositions", ownerId);
  const checkpointRecoveryLedgerId = ownerId => ledgerId("recovery-intent-closure-checkpoint-recovery", ownerId);
  const checkpointMarkerRecoveryLedgerId = ownerId => ledgerId("recovery-intent-closure-checkpoint-marker-recovery", ownerId);
  const lifecycleDispositionRollbackContinuityLedgerId = ownerId => ledgerId("lifecycle-disposition-rollback-continuity", ownerId);
  const CHECKPOINTS = new Set(["status_transition", "orphan_disposition", "lifecycle_disposition"]);
  const maxFreshnessAgeMs = Number.isSafeInteger(freshnessAttestationMaxAgeMs) && freshnessAttestationMaxAgeMs >= 1000
    ? Math.min(freshnessAttestationMaxAgeMs, 3600000) : 300000;
  const maxRevalidationLifecycleFreshnessAgeMs = Number.isSafeInteger(revalidationLifecycleFreshnessAttestationMaxAgeMs)
    && revalidationLifecycleFreshnessAttestationMaxAgeMs >= 1000 ? Math.min(revalidationLifecycleFreshnessAttestationMaxAgeMs, 3600000) : 300000;

  async function readLedger(ownerId, { kind, id, eventKind }) {
    const record = await store.getEvidence(ownerId, id(ownerId));
    const events = Array.isArray(record?.events) ? record.events : [];
    const findings = [];
    if (record && (record.ownerId !== ownerId || record.kind !== kind || record.schemaVersion !== 1
      || record.digest !== digestRecord(record) || record.eventCount !== events.length
      || (record.headDigest || null) !== (events.at(-1)?.digest || null)))
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_LEDGER_INVALID", ledgerKind: kind });
    let previous = null;
    const seen = new Set();
    for (let index = 0; index < events.length; index++) {
      const event = events[index];
      if (!event || event.ownerId !== ownerId || event.kind !== eventKind || event.sequence !== index + 1
        || (event.previousEventDigest || null) !== (previous?.digest || null) || !event.id || seen.has(event.id)
        || event.digest !== digestRecord(event) || !DIGEST.test(event.payloadBindingDigest || "")
        || event.payloadBindingDigest !== eventBaseDigest(event)) {
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_EVENT_CHAIN_INVALID", ledgerKind: kind, sequence: index + 1, eventId: event?.id || null });
      }
      seen.add(event?.id);
      previous = event;
    }
    const snapshot = { schemaVersion: 1, kind, events: clean(events) };
    return { status: findings.length ? "unhealthy" : events.length ? "healthy" : "not_initialized", ownerId,
      ledgerId: id(ownerId), record, events, count: events.length, headDigest: events.at(-1)?.digest || null,
      snapshotDigest: sha256(canonical(snapshot)), findings, snapshot, readOnly: true, mutationAllowed: false };
  }

  async function readCheckpointMarkerRecoveryLedger(ownerId) {
    return readLedger(ownerId, { kind: CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND,
      id: checkpointMarkerRecoveryLedgerId, eventKind: CHECKPOINT_MARKER_RECOVERY_EVENT_KIND });
  }

  async function getCheckpointMarkerRecoverySnapshot(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointMarkerRecoveryLedger(ownerId);
    return { status: ledger.status, ownerId, snapshot: ledger.snapshot, digest: ledger.snapshotDigest, count: ledger.count,
      findings: ledger.findings, historyNotProven: false, readOnly: true, mutationAllowed: false };
  }

  async function advanceRecoveryReceiptCheckpointAfterAppend(ownerId, operationId) {
    const initial = await getRecoveryReceiptCheckpointState(ownerId);
    if (!initial.enabled) return { status: "not_configured", usableForCurrentDecision: true };
    let lastError = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      const before = await getRecoveryReceiptCheckpointState(ownerId);
      if (before.usableForCurrentDecision === true) return { ...before, idempotent: attempt > 0 || initial.usableForCurrentDecision === true };
      try {
        await advanceRecoveryReceiptCheckpoint(ownerId, { operationId, retry: attempt });
        const after = await getRecoveryReceiptCheckpointState(ownerId);
        if (after.usableForCurrentDecision === true) return { ...after, idempotent: attempt > 0 };
        lastError = new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT",
          "Recovery receipt tersimpan tetapi external checkpoint belum current", 409,
          { status: after.status || "unavailable", findings: after.findings || [] });
      } catch (error) {
        lastError = error;
        // Another concurrent writer may have won external CAS and be finalizing the local marker.
        // Re-read before failing, and retry only through the same idempotent one-event continuity gate.
        const afterFailure = await getRecoveryReceiptCheckpointState(ownerId);
        if (afterFailure.usableForCurrentDecision === true)
          return { ...afterFailure, idempotent: true, recoveredConcurrentCheckpointAdvance: true };
      }
    }
    throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING",
      "Recovery receipt tersimpan secara lokal tetapi external checkpoint belum dapat difinalisasi", 409,
      { operationId, attempts: 3, cause: lastError?.code || lastError?.name || "CHECKPOINT_ADVANCE_FAILED" });
  }

  async function advanceMarkerRecoveryJournalCheckpointAfterAppend(ownerId, operationId) {
    const initial = await getMarkerRecoveryJournalCheckpointState(ownerId);
    if (!initial.enabled) return { status: "not_configured", usableForCurrentDecision: true };
    let lastError = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      const before = await getMarkerRecoveryJournalCheckpointState(ownerId);
      if (before.usableForCurrentDecision === true)
        return { ...before, idempotent: attempt > 0 || initial.usableForCurrentDecision === true };
      try {
        await advanceMarkerRecoveryJournalCheckpoint(ownerId, { operationId, retry: attempt });
        const after = await getMarkerRecoveryJournalCheckpointState(ownerId);
        if (after.usableForCurrentDecision === true) return { ...after, idempotent: attempt > 0 };
        lastError = new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_CHECKPOINT_NOT_CURRENT",
          "Marker-recovery journal tersimpan tetapi external checkpoint belum current", 409,
          { status: after.status || "unavailable", findings: after.findings || [] });
      } catch (error) {
        lastError = error;
        const afterFailure = await getMarkerRecoveryJournalCheckpointState(ownerId);
        if (afterFailure.usableForCurrentDecision === true)
          return { ...afterFailure, idempotent: true, recoveredConcurrentCheckpointAdvance: true };
      }
    }
    throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_CHECKPOINT_ADVANCE_PENDING",
      "Marker-recovery journal tersimpan secara lokal tetapi external checkpoint belum dapat difinalisasi", 409,
      { operationId, attempts: 3, cause: lastError?.code || lastError?.name || "CHECKPOINT_ADVANCE_FAILED" });
  }

  async function advanceMarkerRecoveryJournalLifecycleDispositionCheckpointAfterAppend(ownerId, operationId) {
    const initial = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
    if (!initial.enabled) return { status: "not_configured", usableForCurrentDecision: true };
    let lastError = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      const before = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
      if (before.usableForCurrentDecision === true)
        return { ...before, idempotent: attempt > 0 || initial.usableForCurrentDecision === true };
      try {
        await advanceMarkerRecoveryJournalLifecycleDispositionCheckpoint(ownerId, { operationId, retry: attempt });
        const after = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
        if (after.usableForCurrentDecision === true) return { ...after, idempotent: attempt > 0 };
        lastError = new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_NOT_CURRENT",
          "Lifecycle disposition ledger tersimpan tetapi external checkpoint belum current", 409,
          { status: after.status || "unavailable", findings: after.findings || [] });
      } catch (error) {
        lastError = error;
        const afterFailure = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
        if (afterFailure.usableForCurrentDecision === true)
          return { ...afterFailure, idempotent: true, recoveredConcurrentCheckpointAdvance: true };
      }
    }
    throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_ADVANCE_PENDING",
      "Lifecycle disposition tersimpan secara lokal tetapi external checkpoint belum dapat difinalisasi", 409,
      { operationId, attempts: 3, cause: lastError?.code || lastError?.name || "CHECKPOINT_ADVANCE_FAILED" });
  }

  async function advanceRollbackRevalidationLifecycleCheckpointAfterAppend(ownerId, operationId) {
    const initial = await getRevalidationLifecycleCheckpointState(ownerId);
    if (!initial.enabled) return { status: "not_configured", usableForCurrentDecision: true };
    if (initial.usableForCurrentDecision === true) return { ...initial, idempotent: true };
    if (["unhealthy", "rollback_suspected", "policy_drift", "unavailable", "enrollment_required", "not_initialized", "anchor_missing", "continuity_unproven"]
      .includes(initial.status))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_NOT_CURRENT",
        "Revalidation lifecycle ledger belum current; operasi baru ditolak sampai checkpoint direkonsiliasi secara aman", 409,
        { status: initial.status, findings: initial.findings || [], operationId });
    let lastError = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await advanceRevalidationLifecycleCheckpoint(ownerId, { operationId, retry: attempt });
        const after = await getRevalidationLifecycleCheckpointState(ownerId);
        if (after.usableForCurrentDecision === true) return { ...after, idempotent: attempt > 0 };
        lastError = new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_NOT_CURRENT",
          "Revalidation lifecycle ledger tersimpan tetapi external checkpoint belum current", 409,
          { status: after.status || "unavailable", findings: after.findings || [] });
        if (["unhealthy", "rollback_suspected", "policy_drift", "unavailable"].includes(after.status)) break;
      } catch (error) {
        lastError = error;
        const afterFailure = await getRevalidationLifecycleCheckpointState(ownerId);
        if (afterFailure.usableForCurrentDecision === true)
          return { ...afterFailure, idempotent: true, recoveredConcurrentCheckpointAdvance: true };
        if (["unhealthy", "rollback_suspected", "policy_drift", "unavailable"].includes(afterFailure.status)) break;
      }
    }
    throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_ADVANCE_PENDING",
      "Revalidation lifecycle event tersimpan tetapi external checkpoint belum dapat difinalisasi", 409,
      { operationId, attempts: 3, status: (await getRevalidationLifecycleCheckpointState(ownerId)).status,
        cause: lastError?.code || lastError?.name || "CHECKPOINT_ADVANCE_FAILED" });
  }

  async function appendSignedEvent(ownerId, { ledgerKind, ledgerIdForOwner, eventKind, attestationKind, eventBase, requireSignature = strictAttestation }) {
    assertOwner(ownerId);
    for (let attempt = 0; attempt < 4; attempt++) {
      const current = await readLedger(ownerId, { kind: ledgerKind, id: ledgerIdForOwner, eventKind });
      if (current.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_LEDGER_UNHEALTHY",
        "Closure ledger tidak sehat; penulisan baru ditolak", 409, { findings: current.findings });
      const existing = current.events.find(item => item.operationId === eventBase.operationId);
      if (existing) {
        const bindingMatches = Object.entries(clean(eventBase)).every(([key, value]) => canonical(existing[key]) === canonical(value));
        if (!bindingMatches || existing.payloadBindingDigest !== eventBaseDigest(existing))
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_OPERATION_CONFLICT", "Operation ID sudah digunakan dengan binding berbeda atau payload tidak valid", 409);
        if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND) await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, eventBase.operationId);
        if (ledgerKind === CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND)
          await advanceMarkerRecoveryJournalCheckpointAfterAppend(ownerId, eventBase.operationId);
        if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && [MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE,
          MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE].includes(eventBase.eventType))
          await advanceMarkerRecoveryJournalLifecycleDispositionCheckpointAfterAppend(ownerId, eventBase.operationId);
        if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_EVENT_TYPES.has(eventBase.eventType))
          await advanceRollbackRevalidationLifecycleCheckpointAfterAppend(ownerId, eventBase.operationId);
        return { event: existing, idempotent: true, ledger: current };
      }
      if (ledgerKind === CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND) {
        const markerJournalCheckpoint = await getMarkerRecoveryJournalCheckpointState(ownerId);
        if (markerJournalCheckpoint.enabled && markerJournalCheckpoint.usableForCurrentDecision !== true)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_CHECKPOINT_NOT_CURRENT",
            "Penulisan marker-recovery journal diblokir sampai external journal checkpoint current", 409,
            { status: markerJournalCheckpoint.status || "unavailable", findings: markerJournalCheckpoint.findings || [] });
      }
      let receiptCheckpointBefore = null;
      if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND) {
        receiptCheckpointBefore = await getRecoveryReceiptCheckpointState(ownerId);
        if (receiptCheckpointBefore.enabled && receiptCheckpointBefore.usableForCurrentDecision !== true)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT",
            "Penulisan recovery receipt diblokir sampai external checkpoint sehat dan current", 409,
            { status: receiptCheckpointBefore.status || "unavailable", findings: receiptCheckpointBefore.findings || [] });
      }
      if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && [MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE,
        MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE].includes(eventBase.eventType)) {
        const dispositionCheckpoint = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
        if (dispositionCheckpoint.enabled && dispositionCheckpoint.usableForCurrentDecision !== true)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_NOT_CURRENT",
            "Penulisan lifecycle disposition diblokir sampai dedicated external checkpoint current", 409,
            { status: dispositionCheckpoint.status || "unavailable", findings: dispositionCheckpoint.findings || [] });
      }
      if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_EVENT_TYPES.has(eventBase.eventType)) {
        const lifecycleCheckpoint = await getRevalidationLifecycleCheckpointState(ownerId);
        if (lifecycleCheckpoint.enabled && lifecycleCheckpoint.usableForCurrentDecision !== true)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_NOT_CURRENT",
            "Lifecycle event baru diblokir sampai independent revalidation lifecycle checkpoint current", 409,
            { status: lifecycleCheckpoint.status || "unavailable", findings: lifecycleCheckpoint.findings || [] });
      }
      const keyBinding = await getCurrentKeyBinding(ownerId);
      const base = { ...clean(eventBase), ownerId, kind: eventKind, schemaVersion: 1,
        sequence: current.count + 1, previousEventDigest: current.headDigest || null,
        keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
        occurredAt: eventBase.occurredAt || isoNow(clock) };
      if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && ["checkpoint_freshness_attestation", REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE,
        REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_EVENT_TYPE, REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_EVENT_TYPE].includes(eventBase.eventType)) {
        base.recoveryReceiptCheckpointSourceCountAtIssue = current.count + 1;
        base.recoveryReceiptCheckpointPriorAnchorSequence = Number.isSafeInteger(receiptCheckpointBefore?.anchorSequence)
          ? receiptCheckpointBefore.anchorSequence : null;
        base.recoveryReceiptCheckpointPriorAnchorDigest = receiptCheckpointBefore?.anchorDigest || null;
      }
      const bindingDigest = payloadDigest(base);
      const signable = { ...base, payloadBindingDigest: bindingDigest };
      const attestation = await createAttestation(ownerId, signable, { attestationKind, keyLifecycleBinding: keyBinding,
        required: requireSignature, attestationIdSuffix: eventBase.operationId });
      const eventUnsigned = { ...signable, attestation: attestation || null };
      const event = { ...eventUnsigned, digest: digestRecord(eventUnsigned) };
      const events = [...current.events, event];
      const ledgerUnsigned = { id: ledgerIdForOwner(ownerId), ownerId, kind: ledgerKind, schemaVersion: 1,
        events, eventCount: events.length, headDigest: event.digest, updatedAt: isoNow(clock) };
      const candidate = { ...ledgerUnsigned, digest: digestRecord(ledgerUnsigned) };
      try {
        if (current.record) await store.putEvidence(ownerId, candidate, { expectedVersion: current.record._storage?.version });
        else await store.putEvidence(ownerId, candidate, { overwrite: false });
      } catch {
        const concurrent = await readLedger(ownerId, { kind: ledgerKind, id: ledgerIdForOwner, eventKind });
        const matched = concurrent.events.find(item => item.operationId === eventBase.operationId);
        if (matched) {
          const bindingMatches = Object.entries(clean(eventBase)).every(([key, value]) => canonical(matched[key]) === canonical(value));
          if (!bindingMatches || matched.payloadBindingDigest !== eventBaseDigest(matched))
            throw new AgenticError("RECOVERY_INTENT_CLOSURE_OPERATION_CONFLICT", "Operation ID mengalami konflik CAS dengan binding berbeda", 409);
          if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND) await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, eventBase.operationId);
          if (ledgerKind === CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND)
            await advanceMarkerRecoveryJournalCheckpointAfterAppend(ownerId, eventBase.operationId);
          if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && [MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE,
            MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE].includes(eventBase.eventType))
            await advanceMarkerRecoveryJournalLifecycleDispositionCheckpointAfterAppend(ownerId, eventBase.operationId);
          if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_EVENT_TYPES.has(eventBase.eventType))
            await advanceRollbackRevalidationLifecycleCheckpointAfterAppend(ownerId, eventBase.operationId);
          return { event: matched, idempotent: true, ledger: concurrent };
        }
        if (attempt === 3) throw new AgenticError("RECOVERY_INTENT_CLOSURE_CAS_RETRY_EXHAUSTED",
          "CAS closure ledger gagal setelah retry terbatas", 409);
        continue;
      }
      const post = await readLedger(ownerId, { kind: ledgerKind, id: ledgerIdForOwner, eventKind });
      const saved = post.events.find(item => item.operationId === eventBase.operationId);
      if (post.status === "unhealthy" || !saved) throw new AgenticError("RECOVERY_INTENT_CLOSURE_POSTCONDITION_FAILED",
        "Closure event gagal diverifikasi setelah penulisan", 409, { findings: post.findings });
      if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND) await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, eventBase.operationId);
      if (ledgerKind === CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND)
        await advanceMarkerRecoveryJournalCheckpointAfterAppend(ownerId, eventBase.operationId);
      if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && [MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE,
        MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE].includes(eventBase.eventType))
        await advanceMarkerRecoveryJournalLifecycleDispositionCheckpointAfterAppend(ownerId, eventBase.operationId);
      if (ledgerKind === CHECKPOINT_RECOVERY_LEDGER_KIND && LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_EVENT_TYPES.has(eventBase.eventType))
        await advanceRollbackRevalidationLifecycleCheckpointAfterAppend(ownerId, eventBase.operationId);
      return { event: saved, idempotent: false, ledger: post };
    }
    throw new AgenticError("RECOVERY_INTENT_CLOSURE_CAS_RETRY_EXHAUSTED", "CAS closure ledger gagal", 409);
  }

  async function recordStatusTransition(ownerId, intent, fromStatus, fromIntentDigest, { observedLegacyState = false } = {}) {
    assertOwner(ownerId);
    if (!intent || intent.ownerId !== ownerId || intent.kind !== intentKind || intent.digest !== digestRecord(intent)
      || !INTENT_STATUSES.has(intent.status) || !DIGEST.test(intent.recoveryIntentDigest || "") || !DIGEST.test(intent.intentEventDigest || ""))
      throw new AgenticError("RECOVERY_INTENT_TRANSITION_SOURCE_INVALID", "Status transition membutuhkan recovery intent yang valid", 409);
    if (fromStatus === intent.status && fromIntentDigest === intent.digest) return { status: "not_required", idempotent: true };
    const operationId = sha256(canonical({ ownerId, intentId: intent.id, fromStatus: fromStatus ?? null,
      toStatus: intent.status, fromIntentDigest: fromIntentDigest || null, toIntentDigest: intent.digest }));
    const checkpointBefore = await getTransitionCheckpointState(ownerId);
    const ledgerBefore = await readLedger(ownerId, { kind: TRANSITION_LEDGER_KIND, id: transitionLedgerId, eventKind: TRANSITION_EVENT_KIND });
    const existingOperation = ledgerBefore.events.some(item => item.operationId === operationId);
    if (checkpointBefore.enabled && checkpointBefore.usableForCurrentDecision !== true && !existingOperation)
      throw new AgenticError("RECOVERY_INTENT_TRANSITION_CHECKPOINT_NOT_CURRENT",
        "Status transition diblokir sampai external closure checkpoint current", 409,
        { status: checkpointBefore.status || "unavailable", findings: checkpointBefore.findings || [] });
    const eventBase = { id: `ritrans-${operationId.slice(0, 32)}`, operationId, eventType: "status_transition",
      intentId: intent.id, recoveryIntentDigest: intent.recoveryIntentDigest, intentEventDigest: intent.intentEventDigest,
      fromStatus: fromStatus ?? null, toStatus: intent.status, fromIntentDigest: fromIntentDigest || null,
      toIntentDigest: intent.digest, observedLegacyState: Boolean(observedLegacyState),
      reasonCode: observedLegacyState ? "LEGACY_STATE_OBSERVED_NOT_PROVEN" : fromStatus == null ? "INTENT_CREATED" : "INTENT_STATUS_CHANGED" };
    const result = await appendSignedEvent(ownerId, { ledgerKind: TRANSITION_LEDGER_KIND, ledgerIdForOwner: transitionLedgerId,
      eventKind: TRANSITION_EVENT_KIND, attestationKind: TRANSITION_ATTESTATION_KIND, eventBase, requireSignature: strictAttestation });
    if (checkpointBefore.enabled) {
      try { result.externalCheckpoint = await advanceTransitionCheckpoint(ownerId, { operationId, idempotent: result.idempotent === true }); }
      catch (error) { throw new AgenticError("RECOVERY_INTENT_TRANSITION_CHECKPOINT_ADVANCE_PENDING",
        "Transition tersimpan secara lokal tetapi external checkpoint belum dapat difinalisasi", 409,
        { operationId, cause: error?.code || error?.name || "CHECKPOINT_ADVANCE_FAILED" }); }
    }
    return result;
  }

  async function getStatusTransitionSnapshot(ownerId) {
    assertOwner(ownerId);
    const ledger = await readLedger(ownerId, { kind: TRANSITION_LEDGER_KIND, id: transitionLedgerId, eventKind: TRANSITION_EVENT_KIND });
    return { status: ledger.status, ownerId, snapshot: ledger.snapshot, count: ledger.count, digest: ledger.snapshotDigest,
      findings: ledger.findings, historyNotProven: false };
  }

  async function auditStatusTransitions(ownerId, { skipCheckpoint = false } = {}) {
    assertOwner(ownerId);
    const [ledger, intents, keyBinding, transitionCheckpoint] = await Promise.all([
      readLedger(ownerId, { kind: TRANSITION_LEDGER_KIND, id: transitionLedgerId, eventKind: TRANSITION_EVENT_KIND }),
      getIntentRows(ownerId), getCurrentKeyBinding(ownerId),
      skipCheckpoint ? Promise.resolve({ enabled: false, usableForCurrentDecision: true, status: "skipped" }) : getTransitionCheckpointState(ownerId)
    ]);
    const findings = [...ledger.findings];
    const rows = intents.filter(item => item?.ownerId === ownerId && item.kind === intentKind);
    const latestIntent = [...rows].sort((a, b) => (a.sequence || 0) - (b.sequence || 0) || String(a.createdAt).localeCompare(String(b.createdAt))).at(-1) || null;
    const byIntent = new Map();
    const verified = new Map();
    for (const event of ledger.events) {
      if (!event.intentId || !DIGEST.test(event.recoveryIntentDigest || "") || !DIGEST.test(event.intentEventDigest || "")
        || !INTENT_STATUSES.has(event.toStatus) || event.fromStatus !== null && !INTENT_STATUSES.has(event.fromStatus)
        || event.toIntentDigest !== event.digestOfTarget && !DIGEST.test(event.toIntentDigest || "")) {
        findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_BINDING_INVALID", eventId: event.id });
      }
      const list = byIntent.get(event.intentId) || []; list.push(event); byIntent.set(event.intentId, list);
    }
    let historyNotProven = false, stale = false;
    for (const intent of rows) {
      const events = byIntent.get(intent.id) || [];
      if (!events.length) {
        historyNotProven = true;
        findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_HISTORY_NOT_PROVEN", intentId: intent.id, status: intent.status });
        continue;
      }
      events.sort((a, b) => a.sequence - b.sequence);
      let previous = null;
      for (const event of events) {
        if (event.recoveryIntentDigest !== intent.recoveryIntentDigest || event.intentEventDigest !== intent.intentEventDigest)
          findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_IMMUTABLE_BINDING_INVALID", intentId: intent.id, eventId: event.id });
        if (previous && (event.fromStatus !== previous.toStatus || event.fromIntentDigest !== previous.toIntentDigest))
          findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_SEQUENCE_INVALID", intentId: intent.id, eventId: event.id });
        if (!previous && (event.fromStatus !== null || event.fromIntentDigest !== null) && !event.observedLegacyState)
          findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_INITIAL_STATE_INVALID", intentId: intent.id, eventId: event.id });
        if (event.observedLegacyState) historyNotProven = true;
        previous = event;
      }
      const last = events.at(-1);
      if (last.toStatus !== intent.status || last.toIntentDigest !== intent.digest
        || last.recoveryIntentDigest !== intent.recoveryIntentDigest || last.intentEventDigest !== intent.intentEventDigest)
        findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_CURRENT_POINTER_INVALID", intentId: intent.id, eventId: last.id });
    }
    const transitionEvents = ledger.events;
    const lastByIntent = new Map();
    for (const event of transitionEvents) lastByIntent.set(event.intentId, event);
    for (const event of transitionEvents) {
      const currentForIntent = lastByIntent.get(event.intentId)?.id === event.id;
      const currentIntent = latestIntent?.id === event.intentId && currentForIntent;
      let verification = { status: "not_present", historicallyValid: false, usableForCurrentDecision: false };
      if (event.attestation) {
        try { verification = await verifyAttestation(ownerId, event, { attestationKind: TRANSITION_ATTESTATION_KIND,
          required: strictAttestation, checkCurrent: currentIntent }); }
        catch { verification = { status: "unhealthy", historicallyValid: false, usableForCurrentDecision: false, reasonCode: "VERIFIER_FAILED" }; }
      }
      verified.set(event.id, verification);
      if (event.attestation && !verification.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_ATTESTATION_INVALID", eventId: event.id,
          reasonCode: verification.reasonCode || null });
      else if (strictAttestation && !event.attestation)
        findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_ATTESTATION_MISSING", eventId: event.id });
      else if (currentIntent && event.attestation && verification.status !== "verified_current") {
        stale = true;
        findings.push({ code: "RECOVERY_INTENT_STATUS_TRANSITION_ATTESTATION_NOT_CURRENT", eventId: event.id,
          status: verification.status, staleReasons: verification.staleReasons || [] });
      }
    }
    if (transitionCheckpoint.enabled && transitionCheckpoint.usableForCurrentDecision !== true) {
      const checkpointHard = ["unhealthy", "rollback_suspected", "policy_drift", "invalid"].includes(transitionCheckpoint.status);
      findings.push({ code: checkpointHard ? "RECOVERY_INTENT_STATUS_TRANSITION_CHECKPOINT_UNHEALTHY"
        : "RECOVERY_INTENT_STATUS_TRANSITION_CHECKPOINT_NOT_CURRENT", status: transitionCheckpoint.status || "unavailable",
        findings: transitionCheckpoint.findings || [] });
      if (checkpointHard) stale = false;
      else stale = true;
    }
    const invalid = findings.some(item => /INVALID|UNHEALTHY|CONFLICT|SEQUENCE/.test(item.code || ""));
    const status = invalid ? "unhealthy" : stale ? "stale" : historyNotProven ? "history_unproven"
      : strictAttestation && transitionEvents.some(item => !item.attestation) ? "unhealthy"
        : transitionEvents.length ? "healthy" : rows.length ? "history_unproven" : "not_initialized";
    return { status, ownerId, ledgerId: ledger.ledgerId, transitionCount: ledger.count, latestTransition: ledger.events.at(-1) || null,
      transitions: ledger.events.map(event => ({ ...event, verification: verified.get(event.id) || null })), snapshotDigest: ledger.snapshotDigest,
      intentCount: rows.length, latestIntentId: latestIntent?.id || null, currentKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      historyNotProven, transitionCheckpoint, findings, usableForCurrentDecision: status === "healthy" && (!strictAttestation
        || Boolean(latestIntent && lastByIntent.get(latestIntent.id)?.toStatus === latestIntent.status
          && verified.get(lastByIntent.get(latestIntent.id)?.id)?.status === "verified_current")),
      readOnly: true, mutationAllowed: false, deletionPerformed: false, compactionPerformed: false };
  }

  async function readDispositionLedger(ownerId) {
    return readLedger(ownerId, { kind: DISPOSITION_LEDGER_KIND, id: dispositionLedgerId, eventKind: DISPOSITION_EVENT_KIND });
  }

  async function getOrphanDispositionSnapshot(ownerId) {
    assertOwner(ownerId);
    const ledger = await readDispositionLedger(ownerId);
    return { status: ledger.status, ownerId, snapshot: ledger.snapshot, count: ledger.count, digest: ledger.snapshotDigest,
      findings: ledger.findings, historyNotProven: false };
  }

  async function prepareOrphanDisposition(ownerId, intentId, { disposition, reason } = {}) {
    assertOwner(ownerId);
    if (typeof intentId !== "string" || !intentId.trim() || intentId.length > 200)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_TARGET_INVALID", "Recovery intent target tidak valid", 400);
    if (!DISPOSITIONS.has(disposition)) throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_INVALID", "Disposition harus quarantine atau mark_unrecoverable", 400);
    if (typeof reason !== "string" || reason.trim() !== reason || reason.length < 12 || reason.length > 240)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_REASON_INVALID", "Alasan disposition wajib 12–240 karakter", 400);
    const intent = await store.getEvidence(ownerId, intentId);
    if (!intent || intent.ownerId !== ownerId || intent.kind !== intentKind || intent.digest !== digestRecord(intent))
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_TARGET_MISSING", "Recovery intent target tidak ditemukan atau tidak valid", 404);
    const orphans = await getOrphanCandidates(ownerId);
    const orphan = orphans.find(item => item.intentId === intentId && item.intentDigest === intent.digest);
    if (!orphan) throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_NOT_ORPHANED", "Disposition hanya boleh diterapkan pada orphan yang terverifikasi", 409);
    const existingClosure = await auditClosure(ownerId);
    if (existingClosure.dispositionedIntents.some(item => item.intentId === intentId && item.intentDigest === intent.digest))
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_ALREADY_RECORDED", "Orphan sudah memiliki disposition untuk digest ini", 409);
    if (existingClosure.transitionAudit?.status !== "healthy")
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_TRANSITION_HISTORY_UNPROVEN",
        "Disposition memerlukan status-transition history yang sehat dan terattestasi", 409,
        { status: existingClosure.transitionAudit?.status || "unavailable" });
    const checkpoint = await getStrictCheckpointState(ownerId);
    if (checkpoint.required && checkpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHECKPOINT_NOT_CURRENT", "Disposition diblokir sampai checkpoint wajib current", 409,
        { status: checkpoint.status || "unavailable" });
    const [transitionCheckpoint, dispositionCheckpoint] = await Promise.all([
      getTransitionCheckpointState(ownerId), getDispositionCheckpointState(ownerId)
    ]);
    for (const [label, state] of [["transition", transitionCheckpoint], ["disposition", dispositionCheckpoint]]) {
      if (state.enabled && state.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CLOSURE_CHECKPOINT_NOT_CURRENT",
          `Disposition diblokir sampai ${label} closure checkpoint current`, 409,
          { checkpoint: label, status: state.status || "unavailable", findings: state.findings || [] });
    }
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const transitions = await auditStatusTransitions(ownerId);
    const lifecycleEvents = await getLifecycleEvents(ownerId);
    const lifecycleEventsDigest = sha256(canonical(lifecycleEvents));
    const dispositions = await readDispositionLedger(ownerId);
    const createdAt = isoNow(clock), expiresAt = new Date(Date.parse(createdAt) + 10 * 60 * 1000).toISOString();
    const id = `riodc-${randomUUID().replaceAll("-", "")}`;
    const confirmationPhrase = `DISPOSITION ORPHANED RECOVERY INTENT ${sha256(`${ownerId}\0${id}\0${intent.digest}`).slice(0, 12)}`;
    const unsigned = { id, ownerId, kind: DISPOSITION_CHALLENGE_KIND, schemaVersion: 1, status: "prepared", intentId,
      intentDigest: intent.digest, intentEventDigest: intent.intentEventDigest, recoveryIntentDigest: intent.recoveryIntentDigest,
      orphanReason: orphan.reason, disposition, reason, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      intentCheckpointDigest: checkpoint.snapshotDigest || null, transitionLedgerDigest: transitions.snapshotDigest || null,
      lifecycleEventsDigest, dispositionLedgerDigest: dispositions.snapshotDigest || null, confirmationPhrase, createdAt, expiresAt };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { status: "prepared", challengeId: id, intentId, intentDigest: intent.digest, disposition,
      confirmation: confirmationPhrase, expiresAt, readOnly: false, mutationAllowed: false };
  }

  async function applyOrphanDisposition(ownerId, challengeId, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== DISPOSITION_CHALLENGE_KIND || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHALLENGE_INVALID", "Orphan disposition challenge tidak valid", 409);
    const dispositions = await readDispositionLedger(ownerId);
    const prior = dispositions.events.find(item => item.challengeId === challenge.id);
    if (prior && challenge.status === "completed") return { status: "completed", disposition: prior, idempotent: true,
      closure: await auditClosure(ownerId), readOnly: true, mutationAllowed: false };
    if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(String(clock()))
      || confirmation !== challenge.confirmationPhrase)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHALLENGE_EXPIRED_OR_UNCONFIRMED", "Challenge kedaluwarsa atau konfirmasi tidak cocok", 409);
    const intent = await store.getEvidence(ownerId, challenge.intentId);
    if (!intent || intent.ownerId !== ownerId || intent.digest !== challenge.intentDigest || intent.kind !== intentKind
      || intent.intentEventDigest !== challenge.intentEventDigest || intent.recoveryIntentDigest !== challenge.recoveryIntentDigest)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_TARGET_CHANGED", "Recovery intent berubah sejak challenge dibuat", 409);
    const keyBinding = await getCurrentKeyBinding(ownerId);
    if ((keyBinding?.bindingDigest || null) !== (challenge.keyLifecycleBindingDigest || null))
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_KEY_CUTOFF", "Signing-key lifecycle berubah sejak challenge dibuat", 409);
    const orphan = (await getOrphanCandidates(ownerId)).find(item => item.intentId === intent.id && item.intentDigest === intent.digest);
    if (!orphan || orphan.reason !== challenge.orphanReason)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_SOURCE_CHANGED", "Kondisi orphan berubah sejak challenge dibuat", 409);
    const checkpoint = await getStrictCheckpointState(ownerId);
    if (checkpoint.required && checkpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHECKPOINT_NOT_CURRENT", "Disposition diblokir sampai checkpoint wajib current", 409,
        { status: checkpoint.status || "unavailable" });
    if ((checkpoint.snapshotDigest || null) !== (challenge.intentCheckpointDigest || null))
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHECKPOINT_CHANGED", "Intent checkpoint berubah sejak challenge dibuat", 409);
    const operationId = sha256(canonical({ ownerId, challengeId, intentId: intent.id, intentDigest: intent.digest,
      disposition: challenge.disposition, reason: challenge.reason }));
    const transitions = await auditStatusTransitions(ownerId);
    const lifecycleEvents = await getLifecycleEvents(ownerId);
    const lifecycleEventsDigest = sha256(canonical(lifecycleEvents));
    const dispositionsNow = await readDispositionLedger(ownerId);
    if (transitions.status !== "healthy" || transitions.snapshotDigest !== challenge.transitionLedgerDigest
      || lifecycleEventsDigest !== challenge.lifecycleEventsDigest)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_SNAPSHOT_CHANGED", "Closure atau lifecycle ledger berubah sejak challenge dibuat", 409);
    const priorOperation = dispositionsNow.events.find(item => item.operationId === operationId);
    if (priorOperation) {
      if (priorOperation.challengeDigest !== challenge.digest || priorOperation.intentDigest !== intent.digest
        || priorOperation.disposition !== challenge.disposition || priorOperation.reason !== challenge.reason
        || priorOperation.transitionLedgerDigest !== transitions.snapshotDigest
        || priorOperation.lifecycleEventsDigest !== lifecycleEventsDigest)
        throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_REPLAY_CONFLICT", "Disposition receipt yang tersimpan tidak cocok dengan challenge asli", 409);
      let verification;
      try { verification = await verifyAttestation(ownerId, priorOperation, { attestationKind: DISPOSITION_ATTESTATION_KIND,
        required: true, checkCurrent: true }); }
      catch { verification = { status: "unhealthy", historicallyValid: false }; }
      if (!verification?.historicallyValid || verification.status !== "verified_current")
        throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_RECOVERY_ATTESTATION_NOT_CURRENT",
          "Disposition receipt yang tertunda tidak dapat dipulihkan karena attestation tidak current", 409,
          { status: verification?.status || "unavailable" });
      const transitionCheckpointState = await getTransitionCheckpointState(ownerId);
      if (transitionCheckpointState.enabled && transitionCheckpointState.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_TRANSITION_CHECKPOINT_NOT_CURRENT",
          "Pemulihan disposition diblokir karena transition checkpoint tidak current", 409,
          { status: transitionCheckpointState.status || "unavailable" });
      const dispositionCheckpointState = await getDispositionCheckpointState(ownerId);
      if (dispositionCheckpointState.enabled && dispositionCheckpointState.usableForCurrentDecision !== true) {
        try { await advanceDispositionCheckpoint(ownerId, { operationId, idempotent: true }); }
        catch (error) { throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHECKPOINT_ADVANCE_PENDING",
          "Disposition receipt tersimpan tetapi checkpoint belum dapat dipulihkan", 409,
          { operationId, cause: error?.code || error?.name || "CHECKPOINT_ADVANCE_FAILED" }); }
      }
      const completedUnsigned = { ...clean(challenge), status: "completed", dispositionEventId: priorOperation.id,
        dispositionEventDigest: priorOperation.digest, completedAt: isoNow(clock) };
      delete completedUnsigned.digest;
      const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
      try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, challengeId);
        if (!concurrent || concurrent.status !== "completed" || concurrent.dispositionEventDigest !== priorOperation.digest)
          throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_FINALIZE_CONFLICT", "Disposition receipt dipulihkan tetapi challenge belum dapat difinalisasi", 409);
      }
      return { status: "completed", disposition: priorOperation, idempotent: true,
        closure: await auditClosure(ownerId), readOnly: true, mutationAllowed: false };
    }
    if (dispositionsNow.snapshotDigest !== challenge.dispositionLedgerDigest)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_SNAPSHOT_CHANGED", "Disposition ledger berubah sejak challenge dibuat", 409);
    const eventBase = { id: `riod-${operationId.slice(0, 32)}`, operationId, eventType: "orphan_disposition",
      challengeId, challengeDigest: challenge.digest, intentId: intent.id, intentDigest: intent.digest,
      intentEventDigest: intent.intentEventDigest, recoveryIntentDigest: intent.recoveryIntentDigest,
      orphanReason: orphan.reason, disposition: challenge.disposition, reason: challenge.reason,
      transitionLedgerDigest: transitions.snapshotDigest, lifecycleEventsDigest, intentCheckpointDigest: checkpoint.snapshotDigest || null };
    const [transitionCheckpointBefore, dispositionCheckpointBefore] = await Promise.all([
      getTransitionCheckpointState(ownerId), getDispositionCheckpointState(ownerId)
    ]);
    if (transitionCheckpointBefore.enabled && transitionCheckpointBefore.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_TRANSITION_CHECKPOINT_NOT_CURRENT",
        "Disposition diblokir karena transition checkpoint tidak current", 409,
        { status: transitionCheckpointBefore.status || "unavailable" });
    if (dispositionCheckpointBefore.enabled && dispositionCheckpointBefore.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHECKPOINT_NOT_CURRENT",
        "Disposition diblokir sampai disposition checkpoint current", 409,
        { status: dispositionCheckpointBefore.status || "unavailable" });
    const result = await appendSignedEvent(ownerId, { ledgerKind: DISPOSITION_LEDGER_KIND, ledgerIdForOwner: dispositionLedgerId,
      eventKind: DISPOSITION_EVENT_KIND, attestationKind: DISPOSITION_ATTESTATION_KIND, eventBase, requireSignature: true });
    if (dispositionCheckpointBefore.enabled) {
      try { result.externalCheckpoint = await advanceDispositionCheckpoint(ownerId, { operationId, idempotent: result.idempotent === true }); }
      catch (error) { throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_CHECKPOINT_ADVANCE_PENDING",
        "Disposition receipt tersimpan secara lokal tetapi external checkpoint belum dapat difinalisasi", 409,
        { operationId, cause: error?.code || error?.name || "CHECKPOINT_ADVANCE_FAILED" }); }
    }
    const completedUnsigned = { ...clean(challenge), status: "completed", dispositionEventId: result.event.id,
      dispositionEventDigest: result.event.digest, completedAt: isoNow(clock) };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, challengeId);
      if (!concurrent || concurrent.status !== "completed" || concurrent.dispositionEventDigest !== result.event.digest)
        throw new AgenticError("RECOVERY_INTENT_ORPHAN_DISPOSITION_FINALIZE_CONFLICT", "Disposition tersimpan tetapi challenge belum dapat difinalisasi", 409);
    }
    return { status: "completed", disposition: result.event, idempotent: result.idempotent,
      closure: await auditClosure(ownerId), readOnly: true, mutationAllowed: false };
  }

  async function getCheckpointRecoverySnapshot(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    return { status: ledger.status, ownerId, snapshot: ledger.snapshot, digest: ledger.snapshotDigest, count: ledger.count,
      findings: ledger.findings, historyNotProven: false, readOnly: true, mutationAllowed: false };
  }

  async function getMarkerRecoveryJournalLifecycleDispositionSnapshot(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const events = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE
      || event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE).map(clean);
    const snapshot = { schemaVersion: 1, kind: MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_SNAPSHOT_KIND, events };
    return { status: ledger.status === "unhealthy" ? "unhealthy" : "healthy", ownerId, snapshot,
      digest: sha256(canonical(snapshot)), count: events.length, findings: ledger.findings,
      historyNotProven: false, readOnly: true, mutationAllowed: false };
  }

  async function auditMarkerRecoveryJournalLifecycleDispositionLedger(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const events = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE
      || event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE);
    const findings = [...ledger.findings];
    const seen = new Map();
    for (const event of events) {
      const prior = seen.get(event.operationId);
      if (!event.operationId || prior) findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_OPERATION_DUPLICATE",
        operationId: event.operationId || null, eventIds: [prior?.id, event.id].filter(Boolean) });
      else seen.set(event.operationId, event);
      let verification;
      try { verification = await verifyAttestation(ownerId, event, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false }); }
      catch { verification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
      if (!verification?.historicallyValid || verification.status === "unhealthy") findings.push({
        code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_ATTESTATION_INVALID",
        eventId: event.id, reasonCode: verification?.reasonCode || null });
    }
    const snapshot = { schemaVersion: 1, kind: MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_SNAPSHOT_KIND, events: events.map(clean) };
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, count: events.length,
      digest: sha256(canonical(snapshot)), snapshot, findings, readOnly: true, mutationAllowed: false };
  }

  async function readCheckpointRecoveryLedger(ownerId) {
    return readLedger(ownerId, { kind: CHECKPOINT_RECOVERY_LEDGER_KIND, id: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND });
  }

  async function appendLifecycleDispositionRollbackRecoveryReceipt(ownerId, record, phase) {
    const isFinalization = phase === "finalization";
    const baseOperationId = isFinalization && String(record.operationId || "").endsWith(":finalize")
      ? record.operationId.slice(0, -":finalize".length) : record.operationId;
    const receiptOperationId = `lifecycle-disposition-checkpoint-rollback:${baseOperationId}:${phase}`;
    const eventType = isFinalization ? "lifecycle_disposition_checkpoint_rollback_finalized"
      : "lifecycle_disposition_checkpoint_rollback_recovery_intent";
    const eventId = `${checkpointRecoveryLedgerId(ownerId)}-${sha256(receiptOperationId).slice(0, 24)}`;
    const eventBase = { id: eventId, operationId: receiptOperationId, eventType, checkpointName: "lifecycle_disposition",
      rollbackOperationId: baseOperationId, rollbackChallengeId: record.challengeId,
      rollbackChallengeDigest: record.challengeDigest, rollbackEventId: isFinalization ? record.rollbackEventId : record.id,
      rollbackEventDigest: isFinalization ? record.rollbackEventDigest : record.digest,
      disposition: record.disposition, checkpointFingerprint: record.checkpointFingerprint || record.observedCheckpointFingerprint || null,
      ...(isFinalization ? { observedCheckpointFingerprint: record.observedCheckpointFingerprint || null,
        observedCheckpointStatus: record.observedCheckpointStatus || null, keyCutoffDetected: Boolean(record.keyCutoffDetected),
        revalidatedAfterExternalRecovery: Boolean(record.revalidatedAfterExternalRecovery), finalizedAt: record.finalizedAt }
        : { reason: record.reason, preparedKeyLifecycleBindingDigest: record.preparedKeyLifecycleBindingDigest || null,
          createdAt: record.createdAt, mutationOfExternalAnchor: false }) };
    const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true });
    return appended.event;
  }

  function compactCheckpointState(state = {}) {
    return { enabled: Boolean(state.enabled), required: Boolean(state.required), status: state.status || "unavailable",
      anchorSequence: Number.isSafeInteger(state.anchorSequence) ? state.anchorSequence : null,
      anchorDigest: state.anchorDigest || null, sourceDigest: state.sourceDigest || null,
      sourceCount: Number.isSafeInteger(state.sourceCount) ? state.sourceCount : null,
      freshnessStatus: state.freshnessStatus || null, policyDigest: state.currentPolicyDigest || state.policyDigest || null,
      historyNotProven: Boolean(state.historyNotProven), policyDrift: Boolean(state.policyDrift),
      usableForCurrentDecision: state.usableForCurrentDecision === true };
  }

  async function getCheckpointFreshnessSnapshot(ownerId) {
    assertOwner(ownerId);
    const [transition, disposition, markerRecoveryJournal, keyBinding] = await Promise.all([
      getTransitionCheckpointState(ownerId), getDispositionCheckpointState(ownerId),
      getMarkerRecoveryJournalCheckpointState(ownerId), getCurrentKeyBinding(ownerId)
    ]);
    const checkpoints = { status_transition: compactCheckpointState(transition), orphan_disposition: compactCheckpointState(disposition),
      marker_recovery_journal: compactCheckpointState(markerRecoveryJournal) };
    const snapshotDigest = sha256(canonical({ schemaVersion: 2, checkpoints }));
    const blockers = Object.entries(checkpoints).filter(([, state]) => state.enabled && state.usableForCurrentDecision !== true)
      .map(([name, state]) => ({ code: `RECOVERY_INTENT_CLOSURE_${name.toUpperCase()}_CHECKPOINT_NOT_CURRENT`, status: state.status }));
    return { ownerId, checkpoints, snapshotDigest, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      keyLifecycleSequence: keyBinding?.sequence ?? null, keyLifecycleKeyId: keyBinding?.activeKeyId || keyBinding?.keyId || null,
      usableForCurrentDecision: blockers.length === 0, findings: blockers, observedAt: isoNow(clock), readOnly: true, mutationAllowed: false };
  }

  async function getMarkerRecoveryJournalAttestationSnapshot(ownerId) {
    assertOwner(ownerId);
    const [freshness, journal, receiptCheckpoint] = await Promise.all([
      getCheckpointFreshnessSnapshot(ownerId), getCheckpointMarkerRecoverySnapshot(ownerId), getRecoveryReceiptCheckpointState(ownerId)
    ]);
    // Only stable configuration belongs in the attested digest: the recovery-receipt anchor advances
    // when this attestation is appended, so anchoring its own sequence here would be self-referential.
    const receiptState = { enabled: Boolean(receiptCheckpoint.enabled), required: Boolean(receiptCheckpoint.required) };
    const snapshot = { schemaVersion: 1, closureFreshnessSnapshotDigest: freshness.snapshotDigest,
      checkpoints: freshness.checkpoints, markerRecoveryJournalDigest: journal.digest || null,
      markerRecoveryJournalCount: journal.count ?? null, markerRecoveryJournalStatus: journal.status,
      recoveryReceiptCheckpoint: receiptState };
    const snapshotDigest = sha256(canonical(snapshot));
    const findings = [...(freshness.findings || [])];
    const markerJournalCheckpoint = freshness.checkpoints.marker_recovery_journal;
    if (!markerJournalCheckpoint.enabled) findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_CHECKPOINT_REQUIRED" });
    if (journal.status === "unhealthy") findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_UNHEALTHY",
      journalFindings: journal.findings || [] });
    if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT", status: receiptCheckpoint.status || "unavailable" });
    const keyBinding = await getCurrentKeyBinding(ownerId);
    return { ownerId, snapshot, snapshotDigest, journalSnapshotDigest: journal.digest || null,
      journalEventCount: journal.count ?? null, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      keyLifecycleSequence: keyBinding?.sequence ?? null, keyLifecycleKeyId: keyBinding?.activeKeyId || keyBinding?.keyId || null,
      usableForCurrentDecision: freshness.usableForCurrentDecision && markerJournalCheckpoint.enabled === true
        && journal.status !== "unhealthy" && (!receiptCheckpoint.enabled || receiptCheckpoint.usableForCurrentDecision === true), findings,
      observedAt: isoNow(clock), readOnly: true, mutationAllowed: false };
  }

  async function prepareRecoveryReceiptCheckpointMarkerRecoveryIntent(ownerId, inspection) {
    assertOwner(ownerId);
    if (!inspection || typeof inspection !== "object" || inspection.domain !== "cross_domain_recovery_intent_closure_recovery_receipts")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_INPUT_INVALID",
        "Inspeksi recovery-receipt checkpoint tidak valid", 400);
    if (inspection.status === "not_required") {
      const ledger = await readCheckpointMarkerRecoveryLedger(ownerId);
      const pending = ledger.events.find(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_intent"
        && event.expectedAnchorSequence === inspection.anchorSequence && event.expectedAnchorDigest === inspection.anchorDigest
        && event.expectedSourceDigest === inspection.sourceDigest && event.expectedSourceCount === inspection.sourceCount
        && !ledger.events.some(item => item.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized" && item.intentEventId === event.id));
      if (pending) {
        await advanceMarkerRecoveryJournalCheckpointAfterAppend(ownerId, pending.operationId);
        return { status: "prepared", intent: pending, idempotent: true, markerAlreadyCurrent: true };
      }
      return { status: "not_required", readOnly: true, mutationAllowed: false };
    }
    if (inspection.status !== "recoverable" || inspection.recoverable !== true || !Number.isSafeInteger(inspection.expectedAnchorSequence)
      || inspection.expectedAnchorSequence < 1 || !DIGEST.test(inspection.anchorDigest || "")
      || !DIGEST.test(inspection.expectedSourceDigest || "") || !Number.isSafeInteger(inspection.expectedSourceCount)
      || inspection.expectedSourceCount < 0 || (inspection.previousAnchorDigest !== null && inspection.previousAnchorDigest !== undefined
        && !DIGEST.test(inspection.previousAnchorDigest || ""))
      || (inspection.policyDigest !== null && inspection.policyDigest !== undefined && !DIGEST.test(inspection.policyDigest))
      || !DIGEST.test(inspection.recoveryIntentDigest || ""))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_NOT_PROVEN",
        "External anchor tidak membuktikan pemulihan marker recovery receipt yang aman", 409,
        { status: inspection.status || "unavailable", findings: inspection.findings || [] });
    const ledger = await readCheckpointMarkerRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_LEDGER_UNHEALTHY",
      "Ledger pemulihan marker recovery receipt tidak sehat", 409, { findings: ledger.findings });
    const binding = { schemaVersion: 1, checkpointName: "recovery_receipts", domain: inspection.domain,
      expectedAnchorSequence: inspection.expectedAnchorSequence, expectedAnchorDigest: inspection.anchorDigest,
      expectedSourceDigest: inspection.expectedSourceDigest, expectedSourceCount: inspection.expectedSourceCount,
      previousAnchorDigest: inspection.previousAnchorDigest ?? null, policyDigest: inspection.policyDigest,
      recoveryIntentDigest: inspection.recoveryIntentDigest, historyNotProven: Boolean(inspection.historyNotProven) };
    const operationId = `recovery-receipt-marker-recovery:${binding.recoveryIntentDigest}`;
    const existing = ledger.events.find(event => event.operationId === operationId);
    if (existing) {
      if (Object.entries(binding).some(([key, value]) => canonical(existing[key]) !== canonical(value)))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_CONFLICT",
          "Recovery intent yang sama memiliki binding berbeda", 409);
      await advanceMarkerRecoveryJournalCheckpointAfterAppend(ownerId, existing.operationId);
      return { status: "prepared", intent: existing, idempotent: true };
    }
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const eventBase = { id: `${checkpointMarkerRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`,
      operationId, eventType: "recovery_receipt_checkpoint_marker_recovery_intent", ...binding,
      preparedKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null, preparedAt: isoNow(clock) };
    const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointMarkerRecoveryLedgerId, eventKind: CHECKPOINT_MARKER_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_MARKER_RECOVERY_ATTESTATION_KIND, eventBase, requireSignature: true });
    if (appended.event.keyLifecycleBindingDigest !== (keyBinding?.bindingDigest || null))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_KEY_CUTOFF",
        "Signing-key lifecycle berubah ketika recovery intent disimpan", 409,
        { intentId: appended.event.id, preparedKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
          persistedKeyLifecycleBindingDigest: appended.event.keyLifecycleBindingDigest || null });
    return { status: "prepared", intent: appended.event, idempotent: appended.idempotent === true };
  }

  async function finalizeRecoveryReceiptCheckpointMarkerRecoveryIntent(ownerId, intentEventId, recoveryResult) {
    assertOwner(ownerId);
    const ledger = await readCheckpointMarkerRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_LEDGER_UNHEALTHY",
      "Ledger pemulihan marker recovery receipt tidak sehat", 409, { findings: ledger.findings });
    const intent = ledger.events.find(event => event.id === intentEventId && event.eventType === "recovery_receipt_checkpoint_marker_recovery_intent");
    if (!intent || intent.ownerId !== ownerId || intent.checkpointName !== "recovery_receipts" || !DIGEST.test(intent.payloadBindingDigest || ""))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_INTENT_MISSING",
        "Recovery intent marker recovery receipt tidak ditemukan", 409);
    const existing = ledger.events.find(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized" && event.intentEventId === intent.id);
    if (existing) {
      if (existing.resultAnchorDigest !== intent.expectedAnchorDigest || existing.resultAnchorSequence !== intent.expectedAnchorSequence)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_FINALIZATION_CONFLICT",
          "Finalization receipt tidak cocok dengan recovery intent", 409);
      await advanceMarkerRecoveryJournalCheckpointAfterAppend(ownerId, existing.operationId);
      return { status: "finalized", receipt: existing, idempotent: true };
    }
    if (!recoveryResult || !["marker_recovered", "marker_already_current"].includes(recoveryResult.status)
      || recoveryResult.domain !== intent.domain || recoveryResult.anchorDigest !== intent.expectedAnchorDigest
      || recoveryResult.anchorSequence !== intent.expectedAnchorSequence)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_RESULT_MISMATCH",
        "Hasil marker recovery tidak cocok dengan intent persisten", 409);
    const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (checkpoint.status !== "anchored" || checkpoint.usableForCurrentDecision !== true
      || checkpoint.anchorDigest !== intent.expectedAnchorDigest || checkpoint.anchorSequence !== intent.expectedAnchorSequence)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_CHECKPOINT_NOT_CURRENT",
        "Marker pulih tetapi external checkpoint belum current", 409,
        { status: checkpoint.status || "unavailable", findings: checkpoint.findings || [] });
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const keyCutoffDetected = (intent.keyLifecycleBindingDigest || null) !== (keyBinding?.bindingDigest || null);
    const operationId = `recovery-receipt-marker-recovery-finalized:${intent.id}`;
    const eventBase = { id: `${checkpointMarkerRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`,
      operationId, eventType: "recovery_receipt_checkpoint_marker_recovery_finalized", checkpointName: intent.checkpointName,
      domain: intent.domain, intentEventId: intent.id, intentEventDigest: intent.digest,
      recoveryIntentDigest: intent.recoveryIntentDigest, resultStatus: recoveryResult.status,
      resultAnchorDigest: recoveryResult.anchorDigest, resultAnchorSequence: recoveryResult.anchorSequence,
      resultSourceDigest: intent.expectedSourceDigest, resultSourceCount: intent.expectedSourceCount,
      preparedKeyLifecycleBindingDigest: intent.keyLifecycleBindingDigest || null,
      finalizedKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      finalizedKeyLifecycleSequence: keyBinding?.sequence ?? null, finalizedKeyLifecycleKeyId: keyBinding?.activeKeyId || keyBinding?.keyId || null,
      keyCutoffDetected, finalizedAt: isoNow(clock) };
    const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_MARKER_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointMarkerRecoveryLedgerId, eventKind: CHECKPOINT_MARKER_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_MARKER_RECOVERY_ATTESTATION_KIND, eventBase, requireSignature: true });
    return { status: "finalized", receipt: appended.event, idempotent: appended.idempotent === true,
      keyCutoffDetected, usableForCurrentDecision: !keyCutoffDetected };
  }

  async function auditRecoveryReceiptCheckpointMarkerRecovery(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointMarkerRecoveryLedger(ownerId);
    const findings = [...ledger.findings];
    if (ledger.status === "unhealthy") return { status: "unhealthy", ownerId, eventCount: ledger.count,
      pendingCount: 0, usableForCurrentDecision: false, events: ledger.events, findings, readOnly: true, mutationAllowed: false };
    const intents = ledger.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_intent");
    const finals = ledger.events.filter(event => event.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized");
    const finalizedIntentIds = new Set();
    const operationIds = new Set();
    let staleCount = 0;
    for (const event of ledger.events) {
      if (operationIds.has(event.operationId)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_REPLAY", operationId: event.operationId });
      operationIds.add(event.operationId);
      let verification;
      try { verification = await verifyAttestation(ownerId, event, { attestationKind: CHECKPOINT_MARKER_RECOVERY_ATTESTATION_KIND,
        required: true, checkCurrent: event.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized" }); }
      catch { verification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
      if (!verification?.historicallyValid || verification.status === "unhealthy") findings.push({
        code: "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_ATTESTATION_INVALID", eventId: event.id,
        reasonCode: verification?.reasonCode || null });
      if (event.eventType === "recovery_receipt_checkpoint_marker_recovery_finalized") {
        const intent = intents.find(item => item.id === event.intentEventId);
        if (!intent || event.intentEventDigest !== intent.digest || event.recoveryIntentDigest !== intent.recoveryIntentDigest
          || event.resultAnchorDigest !== intent.expectedAnchorDigest || event.resultAnchorSequence !== intent.expectedAnchorSequence
          || event.resultSourceDigest !== intent.expectedSourceDigest || event.resultSourceCount !== intent.expectedSourceCount
          || finalizedIntentIds.has(event.intentEventId)) {
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_FINALIZATION_BINDING_INVALID", eventId: event.id });
        }
        finalizedIntentIds.add(event.intentEventId);
        if (event.keyCutoffDetected || event.finalizedKeyLifecycleBindingDigest !== event.keyLifecycleBindingDigest
          || verification.status !== "verified_current") {
          staleCount++; findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_KEY_CUTOFF", eventId: event.id,
            keyCutoffDetected: Boolean(event.keyCutoffDetected), verificationStatus: verification.status || "unverified" });
        }
      } else if (event.eventType !== "recovery_receipt_checkpoint_marker_recovery_intent") {
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_EVENT_TYPE_INVALID", eventId: event.id });
      }
    }
    const pending = intents.filter(event => !finalizedIntentIds.has(event.id));
    if (pending.length) findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_PENDING", count: pending.length,
      intentIds: pending.map(event => event.id) });
    const [checkpoint, journalCheckpoint] = await Promise.all([
      getRecoveryReceiptCheckpointState(ownerId), getMarkerRecoveryJournalCheckpointState(ownerId)
    ]);
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECEIPT_MARKER_RECOVERY_CHECKPOINT_NOT_CURRENT", status: checkpoint.status || "unavailable" });
    if (journalCheckpoint.enabled && journalCheckpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_CHECKPOINT_NOT_CURRENT", status: journalCheckpoint.status || "unavailable",
        checkpointFindings: journalCheckpoint.findings || [] });
    const hard = findings.some(item => /LEDGER_INVALID|CHAIN_INVALID|ATTESTATION_INVALID|BINDING_INVALID|EVENT_TYPE_INVALID|REPLAY/.test(item.code || ""));
    const status = hard ? "unhealthy" : staleCount ? "stale" : pending.length ? "recovery_required"
      : journalCheckpoint.enabled && journalCheckpoint.usableForCurrentDecision !== true ? "checkpoint_not_current"
        : checkpoint.enabled && checkpoint.usableForCurrentDecision !== true ? "checkpoint_not_current" : ledger.count ? "healthy" : "not_initialized";
    return { status, ownerId, ledgerId: ledger.ledgerId, eventCount: ledger.count, headDigest: ledger.headDigest,
      pendingCount: pending.length, pendingIntents: pending.map(event => ({ id: event.id, digest: event.digest,
        expectedAnchorSequence: event.expectedAnchorSequence, expectedAnchorDigest: event.expectedAnchorDigest, preparedAt: event.preparedAt })),
      events: ledger.events, currentKeyLifecycleBindingDigest: (await getCurrentKeyBinding(ownerId))?.bindingDigest || null,
      checkpoint, journalCheckpoint, findings, usableForCurrentDecision: ["healthy", "not_initialized"].includes(status)
        && pending.length === 0 && (!checkpoint.enabled || checkpoint.usableForCurrentDecision === true)
        && (!journalCheckpoint.enabled || journalCheckpoint.usableForCurrentDecision === true),
      readOnly: true, mutationAllowed: false };
  }

  async function prepareCheckpointRecoveryIntent(ownerId, checkpointName, inspection) {
    assertOwner(ownerId);
    if (!CHECKPOINTS.has(checkpointName) || !inspection || typeof inspection !== "object")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_CHECKPOINT_RECOVERY_INPUT_INVALID", "Target atau inspeksi checkpoint recovery tidak valid", 400);
    const counterpartStates = checkpointName === "status_transition" ? [["orphan_disposition", await getDispositionCheckpointState(ownerId)]]
      : checkpointName === "orphan_disposition" ? [["status_transition", await getTransitionCheckpointState(ownerId)]]
        : [["status_transition", await getTransitionCheckpointState(ownerId)], ["orphan_disposition", await getDispositionCheckpointState(ownerId)]];
    const staleCounterpart = counterpartStates.find(([, state]) => state.enabled && state.usableForCurrentDecision !== true);
    if (staleCounterpart)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_COUNTERPART_CHECKPOINT_NOT_CURRENT",
        "Pemulihan checkpoint ditolak karena checkpoint lintas-domain lainnya tidak current", 409,
        { checkpointName, counterpartCheckpoint: staleCounterpart[0], counterpartStatus: staleCounterpart[1].status || "unavailable" });
    if (!["recoverable", "not_required"].includes(inspection.status))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_CHECKPOINT_NOT_RECOVERABLE",
        "Inspeksi external anchor tidak membuktikan marker recovery yang aman", 409,
        { checkpointName, status: inspection.status, findings: inspection.findings || [] });
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_LEDGER_UNHEALTHY",
      "Ledger recovery closure tidak sehat", 409, { findings: ledger.findings });
    const pending = ledger.events.filter(event => event.eventType === "checkpoint_recovery_intent"
      && event.checkpointName === checkpointName
      && !ledger.events.some(finalized => finalized.eventType === "checkpoint_recovery_finalized" && finalized.intentEventId === event.id));
    const anchorSequence = inspection.expectedAnchorSequence ?? inspection.anchorSequence;
    const anchorDigest = inspection.anchorDigest || null;
    const sourceDigest = inspection.expectedSourceDigest || inspection.sourceDigest || null;
    const sourceCount = inspection.expectedSourceCount ?? inspection.sourceCount;
    const matchingPending = pending.find(event => event.expectedAnchorSequence === anchorSequence
      && event.expectedAnchorDigest === anchorDigest && event.expectedSourceDigest === sourceDigest
      && event.expectedSourceCount === sourceCount);
    if (inspection.status === "not_required") {
      if (matchingPending) return { status: "prepared", intent: matchingPending, idempotent: true, resumedAfterMarkerCommit: true };
      return { status: "not_required", checkpointName, readOnly: true, mutationAllowed: false };
    }
    if (!Number.isSafeInteger(anchorSequence) || anchorSequence < 1 || !DIGEST.test(anchorDigest || "")
      || !DIGEST.test(sourceDigest || "") || !Number.isSafeInteger(sourceCount) || sourceCount < 0
      || (inspection.previousAnchorDigest !== null && inspection.previousAnchorDigest !== undefined && !DIGEST.test(inspection.previousAnchorDigest)))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_CHECKPOINT_RECOVERY_BINDING_INVALID", "Binding external anchor untuk recovery tidak valid", 409);
    // A target checkpoint may report a non-current marker precisely because it is the checkpoint being recovered.
    // The read-only external-anchor inspection above is the authority for whether that marker recovery is safe.
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const recoveryBinding = { schemaVersion: 1, checkpointName, expectedAnchorSequence: anchorSequence,
      expectedAnchorDigest: anchorDigest, expectedSourceDigest: sourceDigest, expectedSourceCount: sourceCount,
      previousAnchorDigest: inspection.previousAnchorDigest ?? null, policyDigest: inspection.policyDigest ?? null,
      recoveryIntentDigest: inspection.recoveryIntentDigest || sha256(canonical({ checkpointName, anchorSequence, anchorDigest, sourceDigest, sourceCount,
        previousAnchorDigest: inspection.previousAnchorDigest ?? null, policyDigest: inspection.policyDigest ?? null })),
      counterpartCheckpointDigest: sha256(canonical(counterpartStates.map(([name, state]) => ({ name, state: compactCheckpointState(state) })))) };
    const operationId = `checkpoint-recovery-intent:${checkpointName}:${recoveryBinding.recoveryIntentDigest}`;
    const existing = ledger.events.find(event => event.operationId === operationId);
    if (existing) {
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, operationId);
      return { status: "prepared", intent: existing, idempotent: true };
    }
    const result = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND, ledgerIdForOwner: checkpointRecoveryLedgerId,
      eventKind: CHECKPOINT_RECOVERY_EVENT_KIND, attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      eventBase: { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`, operationId,
        eventType: "checkpoint_recovery_intent", checkpointName, ...recoveryBinding,
        preparedKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null, preparedAt: isoNow(clock) }, requireSignature: true });
    return { status: "prepared", intent: result.event, idempotent: result.idempotent === true };
  }

  async function finalizeCheckpointRecoveryIntent(ownerId, intentEventId, recoveryResult) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_LEDGER_UNHEALTHY",
      "Ledger recovery closure tidak sehat", 409, { findings: ledger.findings });
    const intent = ledger.events.find(event => event.id === intentEventId && event.eventType === "checkpoint_recovery_intent");
    if (!intent || intent.ownerId !== ownerId || !DIGEST.test(intent.payloadBindingDigest || ""))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_INTENT_MISSING", "Recovery intent closure tidak ditemukan", 409);
    const existing = ledger.events.find(event => event.eventType === "checkpoint_recovery_finalized" && event.intentEventId === intent.id);
    if (existing) {
      if (existing.resultAnchorDigest !== recoveryResult?.anchorDigest || existing.resultAnchorSequence !== recoveryResult?.anchorSequence)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_FINALIZATION_CONFLICT", "Finalization receipt yang ada tidak cocok dengan hasil recovery", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, existing.operationId);
      return { status: "finalized", receipt: existing, idempotent: true };
    }
    if (!recoveryResult || !["marker_recovered", "marker_already_current"].includes(recoveryResult.status)
      || recoveryResult.domain !== (intent.checkpointName === "status_transition" ? "cross_domain_recovery_intent_status_transitions"
        : intent.checkpointName === "orphan_disposition" ? "cross_domain_recovery_intent_orphan_dispositions"
          : "cross_domain_recovery_intent_closure_lifecycle_dispositions")
      || recoveryResult.anchorDigest !== intent.expectedAnchorDigest || recoveryResult.anchorSequence !== intent.expectedAnchorSequence)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RESULT_MISMATCH", "Hasil marker recovery tidak cocok dengan intent yang tersimpan", 409);
    const currentState = intent.checkpointName === "status_transition" ? await getTransitionCheckpointState(ownerId)
      : intent.checkpointName === "orphan_disposition" ? await getDispositionCheckpointState(ownerId)
        : await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
    if (currentState.status !== "anchored" || currentState.usableForCurrentDecision !== true
      || currentState.anchorDigest !== intent.expectedAnchorDigest || currentState.anchorSequence !== intent.expectedAnchorSequence)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_CHECKPOINT_NOT_CURRENT",
        "Marker dipulihkan tetapi checkpoint belum memenuhi syarat currentness", 409,
        { status: currentState.status, findings: currentState.findings || [] });
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const keyCutoffDetected = (intent.preparedKeyLifecycleBindingDigest || null) !== (keyBinding?.bindingDigest || null);
    const operationId = `checkpoint-recovery-finalized:${intent.id}`;
    const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND, ledgerIdForOwner: checkpointRecoveryLedgerId,
      eventKind: CHECKPOINT_RECOVERY_EVENT_KIND, attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      eventBase: { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`, operationId,
        eventType: "checkpoint_recovery_finalized", checkpointName: intent.checkpointName, intentEventId: intent.id,
        intentEventDigest: intent.digest, recoveryIntentDigest: intent.recoveryIntentDigest,
        resultStatus: recoveryResult.status, resultAnchorDigest: recoveryResult.anchorDigest,
        resultAnchorSequence: recoveryResult.anchorSequence, resultSourceDigest: intent.expectedSourceDigest,
        resultSourceCount: intent.expectedSourceCount, finalizedKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
        keyCutoffDetected, finalizedAt: isoNow(clock) }, requireSignature: true });
    return { status: "finalized", receipt: appended.event, idempotent: appended.idempotent === true, keyCutoffDetected };
  }

  async function auditCheckpointRecoveryReceipts(ownerId, { skipCheckpoint = false } = {}) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const markerRecoveryAudit = await auditRecoveryReceiptCheckpointMarkerRecovery(ownerId);
    const markerJournalLifecycleRecoveryAudit = await auditMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(ownerId);
    const findings = [...ledger.findings, ...markerRecoveryAudit.findings, ...markerJournalLifecycleRecoveryAudit.findings];
    const finalizedIds = new Set(ledger.events.filter(event => event.eventType === "checkpoint_recovery_finalized").map(event => event.intentEventId));
    const intents = ledger.events.filter(event => event.eventType === "checkpoint_recovery_intent");
    const pendingIntents = intents.filter(event => !finalizedIds.has(event.id));
    const keyBinding = await getCurrentKeyBinding(ownerId);
    let staleCount = 0;
    for (const event of ledger.events) {
      let verification;
      const eventAttestationKind = event.eventType === "checkpoint_freshness_attestation"
        ? CHECKPOINT_FRESHNESS_ATTESTATION_KIND
        : event.eventType === "marker_recovery_journal_checkpoint_attestation"
          ? MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
      try { verification = await verifyAttestation(ownerId, event, { attestationKind: eventAttestationKind, required: true,
        checkCurrent: event.eventType === "checkpoint_recovery_finalized"
          || event.eventType === "marker_recovery_journal_checkpoint_attestation" }); }
      catch { verification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
      if (!verification?.historicallyValid || verification.status === "unhealthy") findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_EVENT_ATTESTATION_INVALID",
        eventId: event.id, reasonCode: verification?.reasonCode || null });
      if (event.eventType === "checkpoint_recovery_finalized" && verification?.status !== "verified_current") {
        staleCount++; findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_FINALIZATION_ATTESTATION_STALE", eventId: event.id,
          status: verification?.status || "unverified" });
      }
      if (event.eventType === "checkpoint_recovery_finalized" && event.keyCutoffDetected)
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_KEY_CUTOFF_REVALIDATED", eventId: event.id,
          preparedKeyLifecycleBindingDigest: intents.find(item => item.id === event.intentEventId)?.preparedKeyLifecycleBindingDigest || null,
          finalizedKeyLifecycleBindingDigest: event.finalizedKeyLifecycleBindingDigest || null });
    }
    if (pendingIntents.length) findings.push({ code: "RECOVERY_INTENT_CLOSURE_CHECKPOINT_RECOVERY_PENDING", count: pendingIntents.length,
      intentIds: pendingIntents.map(event => event.id) });
    const markerRecoveryJournalAttestationAudit = await auditMarkerRecoveryJournalCheckpointAttestation(ownerId);
    if (requireMarkerRecoveryJournalAttestation && markerRecoveryJournalAttestationAudit.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_ATTESTATION_NOT_CURRENT",
        status: markerRecoveryJournalAttestationAudit.status || "unavailable", attestationFindings: markerRecoveryJournalAttestationAudit.findings || [] });
    const recoveryReceiptCheckpoint = skipCheckpoint
      ? { enabled: false, required: false, status: "skipped", usableForCurrentDecision: true }
      : await getRecoveryReceiptCheckpointState(ownerId);
    let continuityAudit = { status: "local_only", usableForCurrentDecision: !recoveryReceiptCheckpoint.enabled, findings: [] };
    if (!skipCheckpoint && recoveryReceiptCheckpoint.enabled) {
      const state = recoveryReceiptCheckpoint;
      if (["unhealthy", "rollback_suspected", "policy_drift", "invalid"].includes(state.status)) {
        continuityAudit = { status: "unhealthy", usableForCurrentDecision: false,
          findings: [{ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CONTINUITY_UNHEALTHY", checkpointStatus: state.status }] };
      } else if (state.status === "anchored" && state.freshnessStatus === "fresh" && !state.historyNotProven && !state.policyDrift
        && state.sourceCount === ledger.count && state.sourceDigest === ledger.snapshotDigest) {
        continuityAudit = { status: "verified_current", usableForCurrentDecision: true, findings: [],
          sourceCount: ledger.count, sourceDigest: ledger.snapshotDigest, anchorSequence: state.anchorSequence, anchorDigest: state.anchorDigest };
      } else if (state.status === "behind_local" && Number.isSafeInteger(state.anchoredSourceCount)
        && ledger.count === state.anchoredSourceCount + 1 && DIGEST.test(state.anchoredSourceDigest || "")) {
        const matchingEventIds = [];
        for (const event of ledger.events) {
          const candidate = structuredClone(ledger.snapshot);
          candidate.events = candidate.events.filter(item => item.id !== event.id);
          if (candidate.events.length === state.anchoredSourceCount && sha256(canonical(candidate)) === state.anchoredSourceDigest) matchingEventIds.push(event.id);
        }
        continuityAudit = matchingEventIds.length === 1
          ? { status: "single_event_pending", usableForCurrentDecision: false, matchingEventIds,
            findings: [{ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_SINGLE_EVENT_PENDING", eventId: matchingEventIds[0] }] }
          : { status: "continuity_unproven", usableForCurrentDecision: false, matchingEventIds,
            findings: [{ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CONTINUITY_UNPROVEN", matchingEventIds }] };
      } else {
        continuityAudit = { status: state.status === "anchored" && state.freshnessStatus !== "fresh" ? "stale" : "continuity_unproven",
          usableForCurrentDecision: false, findings: [{ code: "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CONTINUITY_NOT_PROVEN",
            checkpointStatus: state.status || "unavailable", freshnessStatus: state.freshnessStatus || null,
            sourceCount: ledger.count, anchoredSourceCount: state.anchoredSourceCount ?? null }] };
      }
      findings.push(...continuityAudit.findings);
    }
    if (!skipCheckpoint && recoveryReceiptCheckpoint.enabled && recoveryReceiptCheckpoint.usableForCurrentDecision !== true)
      findings.push({ code: ["unhealthy", "rollback_suspected", "policy_drift", "invalid"].includes(recoveryReceiptCheckpoint.status)
        ? "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_UNHEALTHY"
        : "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT",
        status: recoveryReceiptCheckpoint.status || "unavailable", findings: recoveryReceiptCheckpoint.findings || [] });
    const hard = markerRecoveryAudit.status === "unhealthy" || markerRecoveryJournalAttestationAudit.status === "unhealthy"
      || findings.some(item => /LEDGER_INVALID|CHAIN_INVALID|ATTESTATION_INVALID|CHECKPOINT_UNHEALTHY|CONTINUITY_UNHEALTHY/.test(item.code || ""));
    const status = hard ? "unhealthy" : staleCount || markerRecoveryAudit.status === "stale"
      || markerJournalLifecycleRecoveryAudit.status === "stale"
      || (requireMarkerRecoveryJournalAttestation && markerRecoveryJournalAttestationAudit.usableForCurrentDecision !== true) ? "stale"
      : recoveryReceiptCheckpoint.enabled && recoveryReceiptCheckpoint.usableForCurrentDecision !== true ? "external_checkpoint_pending"
        : pendingIntents.length || markerRecoveryAudit.pendingCount > 0 || markerJournalLifecycleRecoveryAudit.pendingCount > 0
          ? "recovery_required" : ledger.count ? "healthy" : "not_initialized";
    return { status, ownerId, ledgerId: ledger.ledgerId, eventCount: ledger.count, headDigest: ledger.headDigest,
      pendingCount: pendingIntents.length, lifecycleRecoveryPendingCount: markerJournalLifecycleRecoveryAudit.pendingCount || 0,
      pendingIntents: pendingIntents.map(event => ({ id: event.id, checkpointName: event.checkpointName,
        expectedAnchorSequence: event.expectedAnchorSequence, expectedAnchorDigest: event.expectedAnchorDigest,
        preparedAt: event.preparedAt })), markerRecoveryAudit, markerRecoveryPendingCount: markerRecoveryAudit.pendingCount || 0,
      markerJournalLifecycleRecoveryAudit, events: ledger.events, currentKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      recoveryReceiptCheckpoint, continuityAudit, markerRecoveryJournalAttestationAudit, findings,
      usableForCurrentDecision: ["healthy", "not_initialized"].includes(status) && pendingIntents.length === 0
        && markerRecoveryAudit.usableForCurrentDecision === true
        && markerJournalLifecycleRecoveryAudit.usableForCurrentDecision === true
        && (!requireMarkerRecoveryJournalAttestation || markerRecoveryJournalAttestationAudit.usableForCurrentDecision === true)
        && (!recoveryReceiptCheckpoint.enabled || recoveryReceiptCheckpoint.usableForCurrentDecision === true), readOnly: true, mutationAllowed: false };
  }

  async function auditCheckpointRecoveryReceiptContinuity(ownerId) {
    const audit = await auditCheckpointRecoveryReceipts(ownerId);
    return { ...audit.continuityAudit, ownerId, recoveryReceiptAudit: audit, readOnly: true, mutationAllowed: false };
  }

  async function createCheckpointFreshnessAttestation(ownerId, { operationId = null, lifecycle = null } = {}) {
    assertOwner(ownerId);
    const snapshot = await getCheckpointFreshnessSnapshot(ownerId);
    if (!snapshot.usableForCurrentDecision) throw new AgenticError("RECOVERY_INTENT_CLOSURE_CHECKPOINT_FRESHNESS_NOT_CURRENT",
      "Tidak dapat menerbitkan freshness attestation karena salah satu checkpoint tidak current", 409, { findings: snapshot.findings });
    const recoveryAudit = await auditCheckpointRecoveryReceipts(ownerId);
    if (recoveryAudit.status === "unhealthy" || recoveryAudit.pendingCount > 0 || recoveryAudit.lifecycleRecoveryPendingCount > 0
      || recoveryAudit.status === "stale" || recoveryAudit.status === "external_checkpoint_pending" || recoveryAudit.status === "recovery_required")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPTS_NOT_CURRENT",
        "Freshness attestation ditolak karena recovery receipt ledger belum sehat/current", 409, { status: recoveryAudit.status, findings: recoveryAudit.findings });
    const createdAt = lifecycle?.createdAt || isoNow(clock);
    const expiresAt = lifecycle?.attestationExpiresAt || new Date(Date.parse(createdAt) + maxFreshnessAgeMs).toISOString();
    const finalOperationId = operationId || `checkpoint-freshness:${snapshot.snapshotDigest}:${snapshot.keyLifecycleBindingDigest}:${randomUUID()}`;
    const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(finalOperationId).slice(0, 24)}`,
      operationId: finalOperationId, eventType: "checkpoint_freshness_attestation", checkpointSnapshotDigest: snapshot.snapshotDigest,
      checkpointStates: snapshot.checkpoints, keyLifecycleBindingDigest: snapshot.keyLifecycleBindingDigest,
      keyLifecycleSequence: snapshot.keyLifecycleSequence, keyLifecycleKeyId: snapshot.keyLifecycleKeyId,
      createdAt, expiresAt, ...(lifecycle ? { lifecycleAction: "renew", lifecycleChallengeId: lifecycle.challengeId,
        lifecycleChallengeDigest: lifecycle.challengeDigest, priorAttestationEventId: lifecycle.targetAttestationEventId,
        priorAttestationEventDigest: lifecycle.targetAttestationEventDigest, lifecycleReason: lifecycle.reason } : {}) };
    const result = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND, ledgerIdForOwner: checkpointRecoveryLedgerId,
      eventKind: CHECKPOINT_RECOVERY_EVENT_KIND, attestationKind: CHECKPOINT_FRESHNESS_ATTESTATION_KIND,
      eventBase, requireSignature: true });
    return { status: "attested", attestation: result.event, snapshotDigest: snapshot.snapshotDigest,
      expiresAt, idempotent: result.idempotent === true, readOnly: false, mutationAllowed: false };
  }

  async function attestCheckpointFreshness(ownerId) {
    return createCheckpointFreshnessAttestation(ownerId);
  }

  async function prepareCheckpointFreshnessAttestationLifecycle(ownerId, { action, eventId = null, reason } = {}) {
    assertOwner(ownerId);
    if (!new Set(["renew", "revoke"]).has(action) || typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_INPUT_INVALID",
        "Action renewal/revocation dan alasan minimal 12 karakter wajib diberikan", 400);
    const audit = await auditCheckpointFreshnessAttestation(ownerId, eventId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const target = ledger.events.find(item => item.id === (eventId || audit.eventId) && item.eventType === "checkpoint_freshness_attestation");
    if (!target || !audit.verification?.historicallyValid || audit.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_TARGET_INVALID",
        "Freshness attestation target tidak dapat diverifikasi secara historis", 409, { status: audit.status, findings: audit.findings || [] });
    if (action === "revoke" && audit.revoked)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_ALREADY_REVOKED", "Freshness attestation sudah dicabut", 409);
    if (action === "renew" && audit.revoked)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_REVOKED", "Attestation yang dicabut tidak dapat diperpanjang; terbitkan attestation baru melalui jalur attest", 409);
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT",
        "Lifecycle freshness diblokir sampai recovery receipt checkpoint current", 409,
        { status: receiptCheckpoint.status || "unavailable", findings: receiptCheckpoint.findings || [] });
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const snapshot = await getCheckpointFreshnessSnapshot(ownerId);
    const createdAt = isoNow(clock);
    const challengeLifetimeMs = Math.max(1000, Math.min(10 * 60_000, maxFreshnessAgeMs - 1000));
    const expiresAt = new Date(Date.parse(createdAt) + challengeLifetimeMs).toISOString();
    const attestationExpiresAt = new Date(Date.parse(createdAt) + maxFreshnessAgeMs).toISOString();
    const challengeId = `${CHECKPOINT_FRESHNESS_LIFECYCLE_CHALLENGE_KIND}-${randomUUID()}`;
    const unsigned = { id: challengeId, ownerId, kind: CHECKPOINT_FRESHNESS_LIFECYCLE_CHALLENGE_KIND, schemaVersion: 1,
      status: "prepared", action, reason: reason.trim(), targetAttestationEventId: target.id, targetAttestationEventDigest: target.digest,
      targetSnapshotDigest: target.checkpointSnapshotDigest, observedFreshnessStatus: audit.status,
      closureCheckpointSnapshotDigest: snapshot.snapshotDigest, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      recoveryReceiptCheckpointAnchorDigest: receiptCheckpoint.anchorDigest || null,
      recoveryReceiptCheckpointAnchorSequence: receiptCheckpoint.anchorSequence ?? null,
      recoveryReceiptLedgerHeadDigest: ledger.headDigest || null, createdAt, expiresAt, attestationExpiresAt };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { status: "prepared", challengeId, challengeDigest: challenge.digest, action, targetAttestationEventId: target.id,
      targetAttestationEventDigest: target.digest, expiresAt,
      confirmation: `${action.toUpperCase()} CLOSURE FRESHNESS ATTESTATION ${challenge.digest.slice(0, 12)}`,
      readOnly: false, mutationAllowed: false };
  }

  async function applyCheckpointFreshnessAttestationLifecycle(ownerId, challengeId, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    const unsigned = clean(challenge || {}); delete unsigned.digest;
    const expectedConfirmation = challenge ? `${challenge.action.toUpperCase()} CLOSURE FRESHNESS ATTESTATION ${challenge.digest?.slice(0, 12)}` : null;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHECKPOINT_FRESHNESS_LIFECYCLE_CHALLENGE_KIND
      || !["renew", "revoke"].includes(challenge.action) || challenge.digest !== digestRecord(unsigned)
      || !["prepared", "completed"].includes(challenge.status) || !Number.isFinite(Date.parse(challenge.expiresAt))
      || typeof expectedConfirmation !== "string" || confirmation !== expectedConfirmation)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_CHALLENGE_INVALID",
        "Challenge freshness lifecycle tidak valid, kedaluwarsa, atau konfirmasinya tidak cocok", 409);
    if (challenge.status === "completed") {
      const priorLedger = await readCheckpointRecoveryLedger(ownerId);
      const prior = priorLedger.events.find(item => item.operationId === `checkpoint-freshness-lifecycle:${challenge.id}`);
      const bindingMatches = prior && (challenge.action === "renew"
        ? prior.eventType === "checkpoint_freshness_attestation" && prior.lifecycleChallengeId === challenge.id
          && prior.lifecycleChallengeDigest === challenge.digest && prior.priorAttestationEventId === challenge.targetAttestationEventId
          && prior.priorAttestationEventDigest === challenge.targetAttestationEventDigest
        : prior.eventType === "checkpoint_freshness_attestation_revoked" && prior.challengeId === challenge.id
          && prior.challengeDigest === challenge.digest && prior.targetAttestationEventId === challenge.targetAttestationEventId
          && prior.targetAttestationEventDigest === challenge.targetAttestationEventDigest);
      if (!bindingMatches) throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_RECEIPT_MISSING",
        "Lifecycle receipt yang sudah difinalisasi hilang atau binding-nya tidak cocok", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, prior.operationId);
      const currentKeyBinding = await getCurrentKeyBinding(ownerId);
      const attestationKind = prior.eventType === "checkpoint_freshness_attestation"
        ? CHECKPOINT_FRESHNESS_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
      const currentVerification = await verifyAttestation(ownerId, prior, { attestationKind, required: true, checkCurrent: true });
      const keyCutoffDetected = (prior.keyLifecycleBindingDigest || null) !== (currentKeyBinding?.bindingDigest || null)
        || currentVerification?.status !== "verified_current";
      return { status: "completed", action: challenge.action, event: prior, idempotent: true, keyCutoffDetected,
        lifecycleReceiptCurrent: !keyCutoffDetected, audit: await auditCheckpointFreshnessAttestation(ownerId),
        readOnly: true, mutationAllowed: false };
    }
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const operationId = `checkpoint-freshness-lifecycle:${challenge.id}`;
    const alreadyAppended = ledger.events.find(item => item.operationId === operationId);
    if (alreadyAppended) {
      const bindingMatches = challenge.action === "renew"
        ? alreadyAppended.eventType === "checkpoint_freshness_attestation" && alreadyAppended.lifecycleChallengeId === challenge.id
          && alreadyAppended.lifecycleChallengeDigest === challenge.digest && alreadyAppended.priorAttestationEventId === challenge.targetAttestationEventId
          && alreadyAppended.priorAttestationEventDigest === challenge.targetAttestationEventDigest
        : alreadyAppended.eventType === "checkpoint_freshness_attestation_revoked" && alreadyAppended.challengeId === challenge.id
          && alreadyAppended.challengeDigest === challenge.digest && alreadyAppended.targetAttestationEventId === challenge.targetAttestationEventId
          && alreadyAppended.targetAttestationEventDigest === challenge.targetAttestationEventDigest;
      if (!bindingMatches) throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_OPERATION_CONFLICT",
        "Lifecycle operation ID sudah digunakan dengan binding berbeda", 409);
      const attestationKind = alreadyAppended.eventType === "checkpoint_freshness_attestation"
        ? CHECKPOINT_FRESHNESS_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
      const historicalVerification = await verifyAttestation(ownerId, alreadyAppended, { attestationKind, required: true, checkCurrent: false });
      if (!historicalVerification?.historicallyValid || historicalVerification.status === "unhealthy")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_EVENT_INVALID",
          "Lifecycle event tersimpan tetapi signature historis tidak valid", 409,
          { reasonCode: historicalVerification?.reasonCode || null });
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, operationId);
      const currentKeyBinding = await getCurrentKeyBinding(ownerId);
      const currentVerification = await verifyAttestation(ownerId, alreadyAppended, { attestationKind, required: true, checkCurrent: true });
      const keyCutoffDetected = (alreadyAppended.keyLifecycleBindingDigest || null) !== (currentKeyBinding?.bindingDigest || null)
        || currentVerification?.status !== "verified_current";
      const completedUnsigned = { ...clean(challenge), status: "completed", lifecycleEventId: alreadyAppended.id,
        lifecycleEventDigest: alreadyAppended.digest, finalizedKeyLifecycleBindingDigest: currentKeyBinding?.bindingDigest || null,
        finalizedKeyLifecycleSequence: currentKeyBinding?.sequence ?? null, keyCutoffDetected,
        lifecycleReceiptCurrent: !keyCutoffDetected, completedAt: isoNow(clock) };
      delete completedUnsigned.digest;
      const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
      try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, challengeId);
        if (!concurrent || concurrent.status !== "completed" || concurrent.lifecycleEventDigest !== alreadyAppended.digest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_FINALIZE_CONFLICT",
            "Lifecycle event tersimpan tetapi challenge belum dapat difinalisasi", 409);
      }
      return { status: "completed", action: challenge.action, event: alreadyAppended, idempotent: true, keyCutoffDetected,
        lifecycleReceiptCurrent: !keyCutoffDetected, audit: await auditCheckpointFreshnessAttestation(ownerId),
        readOnly: true, mutationAllowed: false };
    }
    if (Date.parse(challenge.expiresAt) <= Date.parse(isoNow(clock)))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_CHALLENGE_EXPIRED",
        "Challenge kedaluwarsa sebelum lifecycle event tersimpan; operasi baru ditolak", 409);
    const target = ledger.events.find(item => item.id === challenge.targetAttestationEventId && item.eventType === "checkpoint_freshness_attestation");
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const snapshot = await getCheckpointFreshnessSnapshot(ownerId);
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (!target || target.digest !== challenge.targetAttestationEventDigest || ledger.headDigest !== (challenge.recoveryReceiptLedgerHeadDigest || null)
      || snapshot.snapshotDigest !== challenge.closureCheckpointSnapshotDigest
      || (keyBinding?.bindingDigest || null) !== (challenge.keyLifecycleBindingDigest || null)
      || (receiptCheckpoint.anchorDigest || null) !== (challenge.recoveryReceiptCheckpointAnchorDigest || null)
      || (receiptCheckpoint.anchorSequence ?? null) !== (challenge.recoveryReceiptCheckpointAnchorSequence ?? null)
      || receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_STALE", "Evidence berubah sejak challenge freshness lifecycle dibuat", 409,
        { snapshotMatches: snapshot.snapshotDigest === challenge.closureCheckpointSnapshotDigest,
          keyBindingMatches: (keyBinding?.bindingDigest || null) === (challenge.keyLifecycleBindingDigest || null),
          checkpointStatus: receiptCheckpoint.status || "unavailable" });
    const currentAudit = await auditCheckpointFreshnessAttestation(ownerId, target.id);
    if (!currentAudit.verification?.historicallyValid || currentAudit.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_TARGET_INVALID", "Attestation target tidak lagi valid", 409,
        { status: currentAudit.status, findings: currentAudit.findings || [] });
    let result;
    if (challenge.action === "renew") {
      result = await createCheckpointFreshnessAttestation(ownerId, { operationId, lifecycle: { challengeId: challenge.id,
        challengeDigest: challenge.digest, targetAttestationEventId: target.id, targetAttestationEventDigest: target.digest,
        reason: challenge.reason, createdAt: challenge.createdAt, attestationExpiresAt: challenge.attestationExpiresAt } });
    } else {
      const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`, operationId,
        eventType: "checkpoint_freshness_attestation_revoked", targetAttestationEventId: target.id,
        targetAttestationEventDigest: target.digest, challengeId: challenge.id, challengeDigest: challenge.digest,
        reason: challenge.reason, checkpointSnapshotDigest: challenge.closureCheckpointSnapshotDigest,
        keyLifecycleBindingDigest: keyBinding?.bindingDigest || null, revokedAt: challenge.createdAt };
      const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND, ledgerIdForOwner: checkpointRecoveryLedgerId,
        eventKind: CHECKPOINT_RECOVERY_EVENT_KIND, attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true });
      result = { status: "revoked", event: appended.event, idempotent: appended.idempotent === true };
    }
    const finalizedEvent = result.attestation || result.event;
    const finalizedAttestationKind = result.attestation ? CHECKPOINT_FRESHNESS_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
    const currentKeyBinding = await getCurrentKeyBinding(ownerId);
    const currentVerification = await verifyAttestation(ownerId, finalizedEvent, { attestationKind: finalizedAttestationKind, required: true, checkCurrent: true });
    const keyCutoffDetected = (finalizedEvent.keyLifecycleBindingDigest || null) !== (currentKeyBinding?.bindingDigest || null)
      || currentVerification?.status !== "verified_current";
    const completedUnsigned = { ...clean(challenge), status: "completed", lifecycleEventId: finalizedEvent.id,
      lifecycleEventDigest: finalizedEvent.digest, finalizedKeyLifecycleBindingDigest: currentKeyBinding?.bindingDigest || null,
      finalizedKeyLifecycleSequence: currentKeyBinding?.sequence ?? null, keyCutoffDetected,
      lifecycleReceiptCurrent: !keyCutoffDetected, completedAt: isoNow(clock) };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, challengeId);
      if (!concurrent || concurrent.status !== "completed" || concurrent.lifecycleEventDigest !== completed.lifecycleEventDigest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_FINALIZE_CONFLICT",
          "Lifecycle event tersimpan tetapi challenge belum dapat difinalisasi", 409);
    }
    return { status: "completed", action: challenge.action, event: finalizedEvent,
      idempotent: result.idempotent === true, keyCutoffDetected, lifecycleReceiptCurrent: !keyCutoffDetected,
      audit: await auditCheckpointFreshnessAttestation(ownerId), readOnly: true, mutationAllowed: false };
  }

  async function auditCheckpointFreshnessAttestation(ownerId, eventId = null) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") return { status: "unhealthy", usableForCurrentDecision: false, findings: ledger.findings, readOnly: true, mutationAllowed: false };
    const events = ledger.events.filter(event => event.eventType === "checkpoint_freshness_attestation");
    const event = eventId ? events.find(item => item.id === eventId) : events.at(-1);
    if (!event) return { status: "missing", usableForCurrentDecision: !requireFreshnessAttestation,
      required: requireFreshnessAttestation, findings: requireFreshnessAttestation ? [{ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_REQUIRED" }] : [],
      readOnly: true, mutationAllowed: false };
    let verification;
    try { verification = await verifyAttestation(ownerId, event, { attestationKind: CHECKPOINT_FRESHNESS_ATTESTATION_KIND, required: true, checkCurrent: true }); }
    catch { verification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
    const current = await getCheckpointFreshnessSnapshot(ownerId);
    const nowMs = Date.parse(isoNow(clock)), createdMs = Date.parse(event.createdAt), expiryMs = Date.parse(event.expiresAt);
    const timeValid = Number.isFinite(createdMs) && Number.isFinite(expiryMs) && createdMs <= nowMs + 60000
      && expiryMs > nowMs && expiryMs - createdMs <= maxFreshnessAgeMs && nowMs - createdMs <= maxFreshnessAgeMs;
    const snapshotMatches = event.checkpointSnapshotDigest === current.snapshotDigest
      && event.keyLifecycleBindingDigest === current.keyLifecycleBindingDigest;
    const revocation = ledger.events.find(item => item.eventType === "checkpoint_freshness_attestation_revoked"
      && item.targetAttestationEventId === event.id && item.targetAttestationEventDigest === event.digest);
    let revocationVerification = null;
    if (revocation) {
      try { revocationVerification = await verifyAttestation(ownerId, revocation, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false }); }
      catch { revocationVerification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
    }
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    const receiptCheckpointMatches = !receiptCheckpoint.enabled || (receiptCheckpoint.usableForCurrentDecision === true
      && receiptCheckpoint.sourceCount === event.recoveryReceiptCheckpointSourceCountAtIssue
      && Number.isSafeInteger(event.recoveryReceiptCheckpointPriorAnchorSequence)
      && receiptCheckpoint.anchorSequence === event.recoveryReceiptCheckpointPriorAnchorSequence + 1);
    const findings = [];
    if (!verification?.historicallyValid || verification.status === "unhealthy") findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_INVALID",
      reasonCode: verification?.reasonCode || null });
    if (verification?.status !== "verified_current") findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_KEY_CUTOFF",
      status: verification?.status || "unverified" });
    if (!timeValid) findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_EXPIRED" });
    if (!snapshotMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_BINDING_CHANGED" });
    if (!current.usableForCurrentDecision) findings.push(...current.findings);
    if (receiptCheckpoint.enabled && !receiptCheckpointMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_RECEIPT_CHECKPOINT_CHANGED",
      status: receiptCheckpoint.status || "unavailable", expectedSourceCount: event.recoveryReceiptCheckpointSourceCountAtIssue ?? null,
      currentSourceCount: receiptCheckpoint.sourceCount ?? null });
    if (revocation && (!revocationVerification?.historicallyValid || revocationVerification.status === "unhealthy"))
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_REVOCATION_ATTESTATION_INVALID", revocationEventId: revocation.id,
        reasonCode: revocationVerification?.reasonCode || null });
    if (revocation) findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_REVOKED", revocationEventId: revocation.id,
      revokedAt: revocation.revokedAt || revocation.occurredAt || null });
    const hard = findings.some(item => /_INVALID|UNHEALTHY/.test(item.code || ""));
    const status = hard ? "unhealthy" : revocation ? "revoked" : findings.length ? "stale" : "verified_current";
    return { status, eventId: event.id, checkpointSnapshotDigest: event.checkpointSnapshotDigest,
      currentSnapshotDigest: current.snapshotDigest, createdAt: event.createdAt, expiresAt: event.expiresAt,
      verification, revoked: Boolean(revocation), revocationEventId: revocation?.id || null, receiptCheckpoint, findings, required: requireFreshnessAttestation, usableForCurrentDecision: status === "verified_current",
      readOnly: true, mutationAllowed: false };
  }

  async function createMarkerRecoveryJournalCheckpointAttestation(ownerId, { operationId = null, lifecycle = null } = {}) {
    assertOwner(ownerId);
    let snapshot = await getMarkerRecoveryJournalAttestationSnapshot(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_LEDGER_UNHEALTHY",
      "Recovery receipt ledger tidak sehat; marker-journal attestation ditolak", 409, { findings: ledger.findings });
    const nowMs = Date.parse(isoNow(clock));
    const currentKey = snapshot.keyLifecycleBindingDigest || null;
    const isRevoked = event => ledger.events.some(item => item.eventType === "marker_recovery_journal_checkpoint_attestation_revoked"
      && item.targetAttestationEventId === event.id && item.targetAttestationEventDigest === event.digest);
    const existingByOperation = operationId ? ledger.events.find(item => item.operationId === operationId) : null;
    if (existingByOperation) {
      const lifecycleMatches = !lifecycle || (existingByOperation.lifecycleAction === "renew"
        && existingByOperation.lifecycleChallengeId === lifecycle.challengeId
        && existingByOperation.lifecycleChallengeDigest === lifecycle.challengeDigest
        && existingByOperation.priorAttestationEventId === lifecycle.targetAttestationEventId
        && existingByOperation.priorAttestationEventDigest === lifecycle.targetAttestationEventDigest);
      if (existingByOperation.eventType !== "marker_recovery_journal_checkpoint_attestation"
        || existingByOperation.checkpointSnapshotDigest !== snapshot.snapshotDigest
        || existingByOperation.journalSnapshotDigest !== snapshot.journalSnapshotDigest
        || existingByOperation.keyLifecycleBindingDigest !== currentKey || !lifecycleMatches)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_OPERATION_CONFLICT",
          "Operation marker-journal attestation sudah digunakan dengan binding berbeda", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, existingByOperation.operationId);
      return { status: "attested", attestation: existingByOperation, snapshotDigest: snapshot.snapshotDigest,
        expiresAt: existingByOperation.expiresAt, idempotent: true, readOnly: false, mutationAllowed: false };
    }
    if (!lifecycle) {
      const reusable = [...ledger.events].reverse().find(event => event.eventType === "marker_recovery_journal_checkpoint_attestation"
        && event.checkpointSnapshotDigest === snapshot.snapshotDigest && event.journalSnapshotDigest === snapshot.journalSnapshotDigest
        && event.keyLifecycleBindingDigest === currentKey && !isRevoked(event));
      if (reusable) {
        await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, reusable.operationId);
        const audit = await auditMarkerRecoveryJournalCheckpointAttestation(ownerId, reusable.id);
        if (audit.usableForCurrentDecision) return { status: "attested", attestation: reusable,
          snapshotDigest: snapshot.snapshotDigest, expiresAt: reusable.expiresAt, idempotent: true,
          readOnly: false, mutationAllowed: false };
        // A pending external commit may have been recovered even though its old attestation expired.
        // Re-read the now-current snapshot before issuing a replacement generation.
        snapshot = await getMarkerRecoveryJournalAttestationSnapshot(ownerId);
      }
    }
    if (!snapshot.usableForCurrentDecision) throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_SNAPSHOT_NOT_CURRENT",
      "Marker-recovery journal attestation memerlukan seluruh checkpoint sumber yang current", 409, { findings: snapshot.findings });
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT",
        "Marker-journal attestation ditolak sampai recovery receipt checkpoint current", 409,
        { status: receiptCheckpoint.status || "unavailable", findings: receiptCheckpoint.findings || [] });
    const createdAt = lifecycle?.createdAt || isoNow(clock);
    const expiresAt = lifecycle?.attestationExpiresAt || new Date(Date.parse(createdAt) + maxFreshnessAgeMs).toISOString();
    const finalOperationId = operationId || `marker-recovery-journal-attestation:${snapshot.snapshotDigest}:${currentKey || "no-key"}:${ledger.headDigest || "genesis"}`;
    const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(finalOperationId).slice(0, 24)}`,
      operationId: finalOperationId, eventType: "marker_recovery_journal_checkpoint_attestation",
      checkpointSnapshotDigest: snapshot.snapshotDigest, checkpointStates: snapshot.snapshot.checkpoints,
      journalSnapshotDigest: snapshot.journalSnapshotDigest, journalEventCount: snapshot.journalEventCount,
      keyLifecycleBindingDigest: currentKey, keyLifecycleSequence: snapshot.keyLifecycleSequence,
      keyLifecycleKeyId: snapshot.keyLifecycleKeyId, createdAt, expiresAt,
      ...(lifecycle ? { lifecycleAction: "renew", lifecycleChallengeId: lifecycle.challengeId,
        lifecycleChallengeDigest: lifecycle.challengeDigest, priorAttestationEventId: lifecycle.targetAttestationEventId,
        priorAttestationEventDigest: lifecycle.targetAttestationEventDigest, lifecycleReason: lifecycle.reason,
        lifecycleRecoveryIntentEventId: lifecycle.recoveryIntentEventId || null,
        lifecycleRecoveryIntentEventDigest: lifecycle.recoveryIntentEventDigest || null } : {}) };
    const result = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND, eventBase, requireSignature: true });
    if (result.event.keyLifecycleBindingDigest !== currentKey)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_KEY_CUTOFF",
        "Signing-key lifecycle berubah saat marker-journal attestation diterbitkan", 409,
        { eventId: result.event.id, preparedKeyLifecycleBindingDigest: currentKey,
          persistedKeyLifecycleBindingDigest: result.event.keyLifecycleBindingDigest || null });
    return { status: "attested", attestation: result.event, snapshotDigest: snapshot.snapshotDigest,
      expiresAt, idempotent: result.idempotent === true, readOnly: false, mutationAllowed: false };
  }

  async function attestMarkerRecoveryJournalCheckpoint(ownerId, options = {}) {
    return createMarkerRecoveryJournalCheckpointAttestation(ownerId, options);
  }

  async function auditMarkerRecoveryJournalCheckpointAttestation(ownerId, eventId = null) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") return { status: "unhealthy", eventId: eventId || null,
      usableForCurrentDecision: false, required: requireMarkerRecoveryJournalAttestation, findings: ledger.findings,
      readOnly: true, mutationAllowed: false };
    const events = ledger.events.filter(event => event.eventType === "marker_recovery_journal_checkpoint_attestation");
    const event = eventId ? events.find(item => item.id === eventId) : events.at(-1);
    if (!event) return { status: "missing", usableForCurrentDecision: !requireMarkerRecoveryJournalAttestation,
      required: requireMarkerRecoveryJournalAttestation,
      findings: requireMarkerRecoveryJournalAttestation ? [{ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_REQUIRED" }] : [],
      readOnly: true, mutationAllowed: false };
    let verification;
    try { verification = await verifyAttestation(ownerId, event, { attestationKind: MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND,
      required: true, checkCurrent: true }); }
    catch { verification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
    const snapshot = await getMarkerRecoveryJournalAttestationSnapshot(ownerId);
    const nowMs = Date.parse(isoNow(clock)), createdMs = Date.parse(event.createdAt), expiryMs = Date.parse(event.expiresAt);
    const timeValid = Number.isFinite(createdMs) && Number.isFinite(expiryMs) && createdMs <= nowMs + 60000
      && expiryMs > nowMs && expiryMs - createdMs <= maxFreshnessAgeMs && nowMs - createdMs <= maxFreshnessAgeMs;
    const snapshotMatches = event.checkpointSnapshotDigest === snapshot.snapshotDigest
      && event.journalSnapshotDigest === snapshot.journalSnapshotDigest
      && event.journalEventCount === snapshot.journalEventCount
      && event.keyLifecycleBindingDigest === snapshot.keyLifecycleBindingDigest;
    const revocation = ledger.events.find(item => item.eventType === "marker_recovery_journal_checkpoint_attestation_revoked"
      && item.targetAttestationEventId === event.id && item.targetAttestationEventDigest === event.digest);
    const superseding = ledger.events.find(item => item.eventType === "marker_recovery_journal_checkpoint_attestation"
      && item.lifecycleAction === "renew" && item.priorAttestationEventId === event.id
      && item.priorAttestationEventDigest === event.digest);
    let revocationVerification = null;
    if (revocation) {
      try { revocationVerification = await verifyAttestation(ownerId, revocation, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false }); }
      catch { revocationVerification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
    }
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    const findings = [];
    if (!verification?.historicallyValid || verification.status === "unhealthy") findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_INVALID",
      reasonCode: verification?.reasonCode || null });
    if (verification?.status !== "verified_current") findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_KEY_CUTOFF",
      status: verification?.status || "unverified" });
    if (!timeValid) findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_EXPIRED" });
    if (!snapshotMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_BINDING_CHANGED" });
    if (!snapshot.usableForCurrentDecision) findings.push(...snapshot.findings);
    if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_RECEIPT_CHECKPOINT_NOT_CURRENT",
        status: receiptCheckpoint.status || "unavailable", checkpointFindings: receiptCheckpoint.findings || [] });
    if (revocation && (!revocationVerification?.historicallyValid || revocationVerification.status === "unhealthy"))
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_REVOCATION_INVALID", eventId: revocation.id,
        reasonCode: revocationVerification?.reasonCode || null });
    if (revocation) findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_REVOKED", eventId: revocation.id,
      revokedAt: revocation.revokedAt || revocation.occurredAt || null });
    if (superseding) findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_SUPERSEDED",
      supersededByEventId: superseding.id, supersededByEventDigest: superseding.digest });
    const hard = findings.some(item => /_INVALID|_UNHEALTHY/.test(item.code || ""));
    const status = hard ? "unhealthy" : revocation ? "revoked" : findings.length ? "stale" : "verified_current";
    return { status, eventId: event.id, checkpointSnapshotDigest: event.checkpointSnapshotDigest,
      currentSnapshotDigest: snapshot.snapshotDigest, journalSnapshotDigest: event.journalSnapshotDigest,
      currentJournalSnapshotDigest: snapshot.journalSnapshotDigest, createdAt: event.createdAt, expiresAt: event.expiresAt,
      verification, revoked: Boolean(revocation), revocationEventId: revocation?.id || null,
      supersededBy: superseding ? { eventId: superseding.id, eventDigest: superseding.digest } : null, receiptCheckpoint,
      required: requireMarkerRecoveryJournalAttestation, findings, usableForCurrentDecision: status === "verified_current",
      readOnly: true, mutationAllowed: false };
  }

  async function prepareMarkerRecoveryJournalAttestationLifecycle(ownerId, { action, eventId = null, reason } = {}) {
    assertOwner(ownerId);
    if (!new Set(["renew", "revoke"]).has(action) || typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INPUT_INVALID",
        "Action renewal/revocation dan alasan minimal 12 karakter wajib diberikan", 400);
    const audit = await auditMarkerRecoveryJournalCheckpointAttestation(ownerId, eventId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const target = ledger.events.find(item => item.id === (eventId || audit.eventId)
      && item.eventType === "marker_recovery_journal_checkpoint_attestation");
    if (!target || !audit.verification?.historicallyValid || audit.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_TARGET_INVALID",
        "Marker-journal attestation target tidak dapat diverifikasi secara historis", 409,
        { status: audit.status, findings: audit.findings || [] });
    if (audit.revoked) throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_REVOKED",
      "Attestation yang sudah dicabut tidak dapat diperpanjang atau dicabut kembali", 409);
    if (audit.supersededBy) throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_ATTESTATION_SUPERSEDED",
      "Attestation lama sudah digantikan; lifecycle harus menargetkan attestation terbaru", 409,
      { supersededBy: audit.supersededBy });
    const snapshot = await getMarkerRecoveryJournalAttestationSnapshot(ownerId);
    if (!snapshot.usableForCurrentDecision) throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_SNAPSHOT_NOT_CURRENT",
      "Lifecycle marker-journal memerlukan checkpoint sumber yang current", 409, { findings: snapshot.findings });
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT",
        "Lifecycle marker-journal diblokir sampai recovery receipt checkpoint current", 409,
        { status: receiptCheckpoint.status || "unavailable", findings: receiptCheckpoint.findings || [] });
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const createdAt = isoNow(clock);
    const challengeLifetimeMs = Math.max(1000, Math.min(10 * 60_000, maxFreshnessAgeMs - 1000));
    const expiresAt = new Date(Date.parse(createdAt) + challengeLifetimeMs).toISOString();
    const attestationExpiresAt = new Date(Date.parse(createdAt) + maxFreshnessAgeMs).toISOString();
    const challengeId = `${MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND}-${randomUUID()}`;
    const unsigned = { id: challengeId, ownerId, kind: MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND, schemaVersion: 1,
      status: "prepared", action, reason: reason.trim(), targetAttestationEventId: target.id, targetAttestationEventDigest: target.digest,
      targetSnapshotDigest: target.checkpointSnapshotDigest, closureCheckpointSnapshotDigest: snapshot.snapshotDigest,
      journalSnapshotDigest: snapshot.journalSnapshotDigest, journalEventCount: snapshot.journalEventCount,
      keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      recoveryReceiptCheckpointAnchorDigest: receiptCheckpoint.anchorDigest || null,
      recoveryReceiptCheckpointAnchorSequence: receiptCheckpoint.anchorSequence ?? null,
      recoveryReceiptLedgerHeadDigest: ledger.headDigest || null, createdAt, expiresAt, attestationExpiresAt,
      confirmation: `${action.toUpperCase()} MARKER-RECOVERY JOURNAL ATTESTATION ${sha256(challengeId).slice(0, 12)}` };
    const challengeDigest = digestRecord(unsigned);
    const challenge = { ...unsigned, challengeDigest, digest: digestRecord({ ...unsigned, challengeDigest }) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { status: "prepared", challengeId, challengeDigest: challenge.challengeDigest, action,
      targetAttestationEventId: target.id, targetAttestationEventDigest: target.digest, expiresAt,
      confirmation: challenge.confirmation,
      readOnly: false, mutationAllowed: false };
  }

  function markerJournalLifecycleOperationIds(challengeId) {
    return {
      intentOperationId: `marker-recovery-journal-attestation-lifecycle-intent:${challengeId}`,
      lifecycleOperationId: `marker-recovery-journal-attestation-lifecycle:${challengeId}`,
      finalizationOperationId: `marker-recovery-journal-attestation-lifecycle-finalization:${challengeId}`
    };
  }

  function markerJournalLifecycleIntentEventBase(ownerId, challenge, { legacyIntentReconstructed = false } = {}) {
    const { intentOperationId } = markerJournalLifecycleOperationIds(challenge.id);
    return { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(intentOperationId).slice(0, 24)}`,
      operationId: intentOperationId, eventType: MARKER_RECOVERY_JOURNAL_LIFECYCLE_INTENT_EVENT_TYPE,
      challengeId: challenge.id, challengeDigest: challenge.challengeDigest || challenge.digest,
      action: challenge.action, reason: challenge.reason,
      targetAttestationEventId: challenge.targetAttestationEventId,
      targetAttestationEventDigest: challenge.targetAttestationEventDigest,
      targetSnapshotDigest: challenge.targetSnapshotDigest,
      closureCheckpointSnapshotDigest: challenge.closureCheckpointSnapshotDigest,
      journalSnapshotDigest: challenge.journalSnapshotDigest, journalEventCount: challenge.journalEventCount,
      preparedKeyLifecycleBindingDigest: challenge.keyLifecycleBindingDigest || null,
      preparedRecoveryReceiptCheckpointAnchorDigest: challenge.recoveryReceiptCheckpointAnchorDigest || null,
      preparedRecoveryReceiptCheckpointAnchorSequence: challenge.recoveryReceiptCheckpointAnchorSequence ?? null,
      expectedPriorRecoveryReceiptLedgerHeadDigest: challenge.recoveryReceiptLedgerHeadDigest || null,
      challengeCreatedAt: challenge.createdAt, challengeExpiresAt: challenge.expiresAt,
      legacyIntentReconstructed: Boolean(legacyIntentReconstructed) };
  }

  function markerJournalLifecycleFinalizationBinding(challenge) {
    return { challengeId: challenge.id, challengeDigest: challenge.challengeDigest || null, action: challenge.action,
      recoveryIntentEventId: challenge.lifecycleRecoveryIntentEventId || null,
      recoveryIntentEventDigest: challenge.lifecycleRecoveryIntentEventDigest || null,
      lifecycleEventId: challenge.lifecycleEventId || null, lifecycleEventDigest: challenge.lifecycleEventDigest || null,
      finalizationEventId: challenge.lifecycleFinalizationEventId || null,
      finalizationEventDigest: challenge.lifecycleFinalizationEventDigest || null,
      checkpointAnchorDigest: challenge.finalizedRecoveryReceiptCheckpointAnchorDigest || null,
      checkpointAnchorSequence: challenge.finalizedRecoveryReceiptCheckpointAnchorSequence ?? null,
      checkpointSourceDigest: challenge.finalizedRecoveryReceiptCheckpointSourceDigest || null,
      checkpointSourceCount: challenge.finalizedRecoveryReceiptCheckpointSourceCount ?? null,
      finalizedKeyLifecycleBindingDigest: challenge.finalizedKeyLifecycleBindingDigest || null,
      keyCutoffDetected: Boolean(challenge.keyCutoffDetected) };
  }

  async function finalizeMarkerJournalLifecycleChallenge(ownerId, challenge, recoveryIntentEvent, lifecycleEvent, finalizationEvent) {
    const { finalizationOperationId } = markerJournalLifecycleOperationIds(challenge.id);
    await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, finalizationOperationId);
    const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CHECKPOINT_PENDING",
        "Lifecycle event sudah tersimpan tetapi recovery-receipt checkpoint belum current", 409,
        { status: checkpoint.status || "unavailable", findings: checkpoint.findings || [] });
    const currentKey = await getCurrentKeyBinding(ownerId);
    const currentKeyDigest = currentKey?.bindingDigest || null;
    const keyCutoffDetected = (recoveryIntentEvent.keyLifecycleBindingDigest || null) !== currentKeyDigest
      || (lifecycleEvent.keyLifecycleBindingDigest || null) !== currentKeyDigest
      || (finalizationEvent.keyLifecycleBindingDigest || null) !== currentKeyDigest
      || Boolean(finalizationEvent.keyCutoffDetected);
    const completedUnsigned = { ...clean(challenge), status: "completed",
      lifecycleRecoveryIntentEventId: recoveryIntentEvent.id, lifecycleRecoveryIntentEventDigest: recoveryIntentEvent.digest,
      lifecycleEventId: lifecycleEvent.id, lifecycleEventDigest: lifecycleEvent.digest,
      lifecycleFinalizationEventId: finalizationEvent.id, lifecycleFinalizationEventDigest: finalizationEvent.digest,
      finalizedRecoveryReceiptCheckpointAnchorDigest: checkpoint.anchorDigest || null,
      finalizedRecoveryReceiptCheckpointAnchorSequence: checkpoint.anchorSequence ?? null,
      finalizedRecoveryReceiptCheckpointSourceDigest: checkpoint.sourceDigest || null,
      finalizedRecoveryReceiptCheckpointSourceCount: checkpoint.sourceCount ?? null,
      finalizedRecoveryReceiptLedgerHeadDigest: finalizationEvent.digest,
      finalizedKeyLifecycleBindingDigest: currentKeyDigest, finalizedKeyLifecycleSequence: currentKey?.sequence ?? null,
      keyCutoffDetected, completedAt: isoNow(clock) };
    delete completedUnsigned.digest;
    completedUnsigned.lifecycleFinalizationBindingDigest = sha256(canonical(markerJournalLifecycleFinalizationBinding(completedUnsigned)));
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    const challengeWasCompleted = challenge.status === "completed";
    if (challengeWasCompleted) {
      const unsigned = clean(challenge); delete unsigned.digest;
      const expectedBinding = sha256(canonical(markerJournalLifecycleFinalizationBinding(challenge)));
      if (challenge.digest !== digestRecord(unsigned) || challenge.lifecycleFinalizationBindingDigest !== expectedBinding
        || challenge.lifecycleRecoveryIntentEventDigest !== recoveryIntentEvent.digest
        || challenge.lifecycleEventDigest !== lifecycleEvent.digest
        || challenge.lifecycleFinalizationEventDigest !== finalizationEvent.digest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_INVALID",
          "Lifecycle challenge selesai tetapi finalization binding tidak valid", 409);
    } else {
      try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, challenge.id);
        if (!concurrent || concurrent.status !== "completed"
          || concurrent.lifecycleFinalizationBindingDigest !== completed.lifecycleFinalizationBindingDigest
          || concurrent.lifecycleFinalizationEventDigest !== finalizationEvent.digest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZE_CONFLICT",
            "Lifecycle event tersimpan tetapi challenge belum dapat difinalisasi secara CAS", 409);
      }
    }
    const currentVerification = await verifyAttestation(ownerId, lifecycleEvent, { attestationKind:
      challenge.action === "renew" ? MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND,
      required: true, checkCurrent: true });
    const finalizationCurrent = await verifyAttestation(ownerId, finalizationEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      required: true, checkCurrent: true });
    const cutoff = keyCutoffDetected || (challenge.action === "renew" && currentVerification?.status !== "verified_current")
      || finalizationCurrent?.status !== "verified_current";
    return { status: "completed", action: challenge.action, event: lifecycleEvent, recoveryIntentEvent,
      finalizationReceipt: finalizationEvent, idempotent: challengeWasCompleted, keyCutoffDetected: cutoff,
      lifecycleReceiptCurrent: !cutoff, audit: await auditMarkerRecoveryJournalCheckpointAttestation(ownerId),
      lifecycleRecoveryAudit: await auditMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(ownerId),
      readOnly: true, mutationAllowed: false };
  }

  async function applyMarkerRecoveryJournalAttestationLifecycle(ownerId, challengeId, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    const unsigned = clean(challenge || {}); delete unsigned.digest;
    const expectedConfirmation = challenge?.confirmation || null;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND
      || !["renew", "revoke"].includes(challenge.action) || challenge.digest !== digestRecord(unsigned)
      || !["prepared", "completed"].includes(challenge.status) || !Number.isFinite(Date.parse(challenge.expiresAt))
      || typeof expectedConfirmation !== "string" || confirmation !== expectedConfirmation)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CHALLENGE_INVALID",
        "Challenge marker-journal lifecycle tidak valid atau konfirmasinya tidak cocok", 409);

    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const { intentOperationId, lifecycleOperationId, finalizationOperationId } = markerJournalLifecycleOperationIds(challenge.id);
    let recoveryIntentEvent = ledger.events.find(item => item.operationId === intentOperationId);
    let lifecycleEvent = ledger.events.find(item => item.operationId === lifecycleOperationId);
    let finalizationEvent = ledger.events.find(item => item.operationId === finalizationOperationId);
    const challengeDigest = challenge.challengeDigest || challenge.digest;
    const lifecycleBindingMatches = event => event && (challenge.action === "renew"
      ? event.eventType === "marker_recovery_journal_checkpoint_attestation" && event.lifecycleAction === "renew"
        && event.lifecycleChallengeId === challenge.id && event.lifecycleChallengeDigest === challengeDigest
        && event.priorAttestationEventId === challenge.targetAttestationEventId
        && event.priorAttestationEventDigest === challenge.targetAttestationEventDigest
        && (!event.lifecycleRecoveryIntentEventId || event.lifecycleRecoveryIntentEventId === recoveryIntentEvent?.id)
        && (!event.lifecycleRecoveryIntentEventDigest || event.lifecycleRecoveryIntentEventDigest === recoveryIntentEvent?.digest)
      : event.eventType === "marker_recovery_journal_checkpoint_attestation_revoked" && event.challengeId === challenge.id
        && event.challengeDigest === challengeDigest && event.targetAttestationEventId === challenge.targetAttestationEventId
        && event.targetAttestationEventDigest === challenge.targetAttestationEventDigest
        && (!event.lifecycleRecoveryIntentEventId || event.lifecycleRecoveryIntentEventId === recoveryIntentEvent?.id)
        && (!event.lifecycleRecoveryIntentEventDigest || event.lifecycleRecoveryIntentEventDigest === recoveryIntentEvent?.digest));

    if (ledger.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_LEDGER_UNHEALTHY",
      "Recovery-receipt ledger tidak sehat; lifecycle recovery ditolak", 409, { findings: ledger.findings });

    // A finalization receipt or lifecycle event means the operation crossed its durable intent boundary.
    // Resume it even after challenge expiry, but never create a second lifecycle event.
    if (challenge.status === "completed" || lifecycleEvent || finalizationEvent) {
      if (!lifecycleEvent || !lifecycleBindingMatches(lifecycleEvent))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_RECEIPT_MISSING",
          "Lifecycle receipt tersimpan hilang atau binding-nya tidak cocok", 409);
      if (!recoveryIntentEvent) {
        // Compatibility path for a pre-Batch-194 event interrupted before its intent record was added.
        const intentBase = markerJournalLifecycleIntentEventBase(ownerId, challenge, { legacyIntentReconstructed: true });
        const appendedIntent = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
          ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
          attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase: intentBase, requireSignature: true });
        recoveryIntentEvent = appendedIntent.event;
      }
      const intentVerification = await verifyAttestation(ownerId, recoveryIntentEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false });
      if (!intentVerification?.historicallyValid || intentVerification.status === "unhealthy"
        || recoveryIntentEvent.challengeId !== challenge.id || recoveryIntentEvent.challengeDigest !== challengeDigest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_INVALID",
          "Recovery intent lifecycle tidak dapat diverifikasi secara historis", 409,
          { reasonCode: intentVerification?.reasonCode || null });
      const lifecycleAttestationKind = challenge.action === "renew" ? MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
      const lifecycleVerification = await verifyAttestation(ownerId, lifecycleEvent, { attestationKind: lifecycleAttestationKind,
        required: true, checkCurrent: false });
      if (!lifecycleVerification?.historicallyValid || lifecycleVerification.status === "unhealthy")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_EVENT_INVALID",
          "Lifecycle event tersimpan tetapi signature historis tidak valid", 409,
          { reasonCode: lifecycleVerification?.reasonCode || null });
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, lifecycleOperationId);
      if (!finalizationEvent) {
        const currentKey = await getCurrentKeyBinding(ownerId);
        const lifecycleCurrent = await verifyAttestation(ownerId, lifecycleEvent, { attestationKind: lifecycleAttestationKind,
          required: true, checkCurrent: true });
        const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(finalizationOperationId).slice(0, 24)}`,
          operationId: finalizationOperationId, eventType: MARKER_RECOVERY_JOURNAL_LIFECYCLE_FINALIZATION_EVENT_TYPE,
          challengeId: challenge.id, challengeDigest, action: challenge.action,
          targetAttestationEventId: challenge.targetAttestationEventId, targetAttestationEventDigest: challenge.targetAttestationEventDigest,
          recoveryIntentEventId: recoveryIntentEvent.id, recoveryIntentEventDigest: recoveryIntentEvent.digest,
          lifecycleEventId: lifecycleEvent.id, lifecycleEventDigest: lifecycleEvent.digest,
          finalizedKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
          keyCutoffDetected: (recoveryIntentEvent.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)
            || (lifecycleEvent.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)
            || (challenge.action === "renew" && lifecycleCurrent?.status !== "verified_current"),
          finalizedAt: isoNow(clock) };
        finalizationEvent = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
          ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
          attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true })).event;
      }
      if (finalizationEvent.eventType !== MARKER_RECOVERY_JOURNAL_LIFECYCLE_FINALIZATION_EVENT_TYPE
        || finalizationEvent.challengeId !== challenge.id || finalizationEvent.challengeDigest !== challengeDigest
        || finalizationEvent.recoveryIntentEventId !== recoveryIntentEvent.id
        || finalizationEvent.recoveryIntentEventDigest !== recoveryIntentEvent.digest
        || finalizationEvent.lifecycleEventId !== lifecycleEvent.id || finalizationEvent.lifecycleEventDigest !== lifecycleEvent.digest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_CONFLICT",
          "Finalization receipt memiliki binding yang berbeda dari lifecycle event", 409);
      return finalizeMarkerJournalLifecycleChallenge(ownerId, challenge, recoveryIntentEvent, lifecycleEvent, finalizationEvent);
    }

    if (Date.parse(challenge.expiresAt) <= Date.parse(isoNow(clock)))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CHALLENGE_EXPIRED",
        "Challenge kedaluwarsa sebelum recovery intent tersimpan; operasi baru ditolak", 409);

    const target = ledger.events.find(item => item.id === challenge.targetAttestationEventId
      && item.eventType === "marker_recovery_journal_checkpoint_attestation");
    let snapshot = await getMarkerRecoveryJournalAttestationSnapshot(ownerId);
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const keyDigest = keyBinding?.bindingDigest || null;

    if (!recoveryIntentEvent) {
      if (!target || target.digest !== challenge.targetAttestationEventDigest
        || ledger.headDigest !== (challenge.recoveryReceiptLedgerHeadDigest || null)
        || snapshot.snapshotDigest !== challenge.closureCheckpointSnapshotDigest
        || snapshot.journalSnapshotDigest !== challenge.journalSnapshotDigest
        || snapshot.journalEventCount !== challenge.journalEventCount
        || keyDigest !== (challenge.keyLifecycleBindingDigest || null)
        || (receiptCheckpoint.anchorDigest || null) !== (challenge.recoveryReceiptCheckpointAnchorDigest || null)
        || (receiptCheckpoint.anchorSequence ?? null) !== (challenge.recoveryReceiptCheckpointAnchorSequence ?? null)
        || receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true
        || !snapshot.usableForCurrentDecision)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_STALE",
          "Evidence berubah sejak marker-journal lifecycle challenge dibuat", 409,
          { snapshotMatches: snapshot.snapshotDigest === challenge.closureCheckpointSnapshotDigest,
            keyBindingMatches: keyDigest === (challenge.keyLifecycleBindingDigest || null),
            checkpointStatus: receiptCheckpoint.status || "unavailable" });
      const targetAudit = await auditMarkerRecoveryJournalCheckpointAttestation(ownerId, target.id);
      if (!targetAudit.verification?.historicallyValid || targetAudit.status === "unhealthy" || targetAudit.revoked || targetAudit.supersededBy)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_TARGET_INVALID",
          "Attestation target tidak lagi valid untuk lifecycle", 409, { status: targetAudit.status, findings: targetAudit.findings || [] });
      const intentBase = markerJournalLifecycleIntentEventBase(ownerId, challenge);
      recoveryIntentEvent = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase: intentBase, requireSignature: true })).event;
    } else {
      const intentMatches = recoveryIntentEvent.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_INTENT_EVENT_TYPE
        && recoveryIntentEvent.challengeId === challenge.id && recoveryIntentEvent.challengeDigest === challengeDigest
        && recoveryIntentEvent.action === challenge.action
        && recoveryIntentEvent.targetAttestationEventId === challenge.targetAttestationEventId
        && recoveryIntentEvent.targetAttestationEventDigest === challenge.targetAttestationEventDigest
        && recoveryIntentEvent.closureCheckpointSnapshotDigest === challenge.closureCheckpointSnapshotDigest
        && recoveryIntentEvent.journalSnapshotDigest === challenge.journalSnapshotDigest
        && recoveryIntentEvent.preparedKeyLifecycleBindingDigest === (challenge.keyLifecycleBindingDigest || null)
        && recoveryIntentEvent.preparedRecoveryReceiptCheckpointAnchorDigest === (challenge.recoveryReceiptCheckpointAnchorDigest || null)
        && recoveryIntentEvent.preparedRecoveryReceiptCheckpointAnchorSequence === (challenge.recoveryReceiptCheckpointAnchorSequence ?? null);
      const intentVerification = await verifyAttestation(ownerId, recoveryIntentEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false });
      if (!intentMatches || !intentVerification?.historicallyValid || intentVerification.status === "unhealthy")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_INVALID",
          "Recovery intent lifecycle tidak valid atau tidak cocok dengan challenge", 409,
          { reasonCode: intentVerification?.reasonCode || null });
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, intentOperationId);
      const afterIntentCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
      if (afterIntentCheckpoint.enabled && afterIntentCheckpoint.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_CHECKPOINT_PENDING",
          "Recovery intent tersimpan tetapi belum ter-anchor secara current", 409,
          { status: afterIntentCheckpoint.status || "unavailable" });
      snapshot = await getMarkerRecoveryJournalAttestationSnapshot(ownerId);
      if (keyDigest !== (challenge.keyLifecycleBindingDigest || null)
        || (recoveryIntentEvent.keyLifecycleBindingDigest || null) !== (challenge.keyLifecycleBindingDigest || null))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_KEY_CUTOFF",
          "Signing-key lifecycle berubah setelah recovery intent tersimpan; challenge lama tidak dapat melanjutkan mutasi", 409,
          { preparedKeyLifecycleBindingDigest: challenge.keyLifecycleBindingDigest || null,
            currentKeyLifecycleBindingDigest: keyDigest });
      if (Date.parse(recoveryIntentEvent.occurredAt) > Date.parse(challenge.expiresAt))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_EXPIRED",
          "Recovery intent dibuat setelah challenge kedaluwarsa", 409);
      if (!target || target.digest !== challenge.targetAttestationEventDigest
        || snapshot.snapshotDigest !== challenge.closureCheckpointSnapshotDigest
        || snapshot.journalSnapshotDigest !== challenge.journalSnapshotDigest
        || snapshot.journalEventCount !== challenge.journalEventCount || !snapshot.usableForCurrentDecision)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_STALE",
          "Snapshot target berubah setelah recovery intent dibuat", 409, { snapshotMatches: snapshot.snapshotDigest === challenge.closureCheckpointSnapshotDigest,
            journalSnapshotMatches: snapshot.journalSnapshotDigest === challenge.journalSnapshotDigest,
            journalCountMatches: snapshot.journalEventCount === challenge.journalEventCount,
            snapshotUsable: snapshot.usableForCurrentDecision, findings: snapshot.findings || [] });
      const targetAudit = await auditMarkerRecoveryJournalCheckpointAttestation(ownerId, target.id);
      if (!targetAudit.verification?.historicallyValid || targetAudit.status === "unhealthy" || targetAudit.revoked || targetAudit.supersededBy)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_TARGET_INVALID",
          "Attestation target tidak lagi valid untuk lifecycle", 409, { status: targetAudit.status, findings: targetAudit.findings || [] });
    }

    // The durable, signed intent is now anchored. An identical retry resumes from it.
    const intentVerification = await verifyAttestation(ownerId, recoveryIntentEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      required: true, checkCurrent: false });
    if (!intentVerification?.historicallyValid || intentVerification.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_INVALID",
        "Recovery intent lifecycle signature tidak valid", 409);
    const lifecycle = challenge.action === "renew" ? await createMarkerRecoveryJournalCheckpointAttestation(ownerId, {
      operationId: lifecycleOperationId, lifecycle: { challengeId: challenge.id, challengeDigest,
        targetAttestationEventId: challenge.targetAttestationEventId,
        targetAttestationEventDigest: challenge.targetAttestationEventDigest, reason: challenge.reason,
        createdAt: isoNow(clock), attestationExpiresAt: challenge.attestationExpiresAt,
        recoveryIntentEventId: recoveryIntentEvent.id, recoveryIntentEventDigest: recoveryIntentEvent.digest }
    }) : null;
    if (challenge.action === "renew") lifecycleEvent = lifecycle.attestation;
    else {
      const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(lifecycleOperationId).slice(0, 24)}`,
        operationId: lifecycleOperationId, eventType: "marker_recovery_journal_checkpoint_attestation_revoked",
        challengeId: challenge.id, challengeDigest, targetAttestationEventId: challenge.targetAttestationEventId,
        targetAttestationEventDigest: challenge.targetAttestationEventDigest,
        lifecycleRecoveryIntentEventId: recoveryIntentEvent.id, lifecycleRecoveryIntentEventDigest: recoveryIntentEvent.digest,
        checkpointSnapshotDigest: snapshot.snapshotDigest, journalSnapshotDigest: snapshot.journalSnapshotDigest,
        journalEventCount: snapshot.journalEventCount, keyLifecycleBindingDigest: keyDigest,
        reason: challenge.reason, revokedAt: isoNow(clock) };
      lifecycleEvent = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true })).event;
    }
    if (!lifecycleBindingMatches(lifecycleEvent))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_EVENT_CONFLICT",
        "Lifecycle event tidak mengikat recovery intent yang persisten", 409);
    await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, lifecycleOperationId);
    const currentKey = await getCurrentKeyBinding(ownerId);
    const lifecycleAttestationKind = challenge.action === "renew" ? MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
    const currentVerification = await verifyAttestation(ownerId, lifecycleEvent, { attestationKind: lifecycleAttestationKind,
      required: true, checkCurrent: true });
    const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(finalizationOperationId).slice(0, 24)}`,
      operationId: finalizationOperationId, eventType: MARKER_RECOVERY_JOURNAL_LIFECYCLE_FINALIZATION_EVENT_TYPE,
      challengeId: challenge.id, challengeDigest, action: challenge.action,
      targetAttestationEventId: challenge.targetAttestationEventId, targetAttestationEventDigest: challenge.targetAttestationEventDigest,
      recoveryIntentEventId: recoveryIntentEvent.id, recoveryIntentEventDigest: recoveryIntentEvent.digest,
      lifecycleEventId: lifecycleEvent.id, lifecycleEventDigest: lifecycleEvent.digest,
      finalizedKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
      keyCutoffDetected: (recoveryIntentEvent.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)
        || (lifecycleEvent.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)
        || (challenge.action === "renew" && currentVerification?.status !== "verified_current"),
      finalizedAt: isoNow(clock) };
    finalizationEvent = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true })).event;
    return finalizeMarkerJournalLifecycleChallenge(ownerId, challenge, recoveryIntentEvent, lifecycleEvent, finalizationEvent);
  }

  function markerJournalLifecycleDispositionOperationIds(targetLifecycleChallengeId) {
    return {
      dispositionOperationId: `marker-recovery-journal-attestation-lifecycle-disposition:${targetLifecycleChallengeId}`,
      finalizationOperationId: `marker-recovery-journal-attestation-lifecycle-disposition-finalization:${targetLifecycleChallengeId}`
    };
  }

  function markerJournalLifecycleDispositionFinalizationBinding(challenge) {
    return { challengeId: challenge.id, challengeDigest: challenge.challengeDigest || null,
      targetLifecycleChallengeId: challenge.targetLifecycleChallengeId || null,
      targetIntentEventId: challenge.targetIntentEventId || null, targetIntentEventDigest: challenge.targetIntentEventDigest || null,
      dispositionEventId: challenge.dispositionEventId || null, dispositionEventDigest: challenge.dispositionEventDigest || null,
      finalizationEventId: challenge.finalizationEventId || null, finalizationEventDigest: challenge.finalizationEventDigest || null,
      disposition: challenge.disposition || null, keyCutoffDetected: Boolean(challenge.keyCutoffDetected),
      finalizedKeyLifecycleBindingDigest: challenge.finalizedKeyLifecycleBindingDigest || null,
      finalizedCheckpointAnchorDigest: challenge.finalizedCheckpointAnchorDigest || null,
      finalizedCheckpointAnchorSequence: challenge.finalizedCheckpointAnchorSequence ?? null,
      finalizedDispositionCheckpointAnchorDigest: challenge.finalizedDispositionCheckpointAnchorDigest || null,
      finalizedDispositionCheckpointAnchorSequence: challenge.finalizedDispositionCheckpointAnchorSequence ?? null };
  }

  async function auditMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const rows = (await store.listEvidence(ownerId)).filter(row => row?.ownerId === ownerId);
    const lifecycleChallenges = rows.filter(row => row.kind === MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND);
    const dispositionChallenges = rows.filter(row => row.kind === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_KIND);
    const byChallengeId = new Map(lifecycleChallenges.map(row => [row.id, row]));
    const byDispositionChallengeId = new Map(dispositionChallenges.map(row => [row.id, row]));
    const intentEvents = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_INTENT_EVENT_TYPE);
    const lifecycleEvents = ledger.events.filter(event =>
      (event.eventType === "marker_recovery_journal_checkpoint_attestation" && event.lifecycleChallengeId)
      || (event.eventType === "marker_recovery_journal_checkpoint_attestation_revoked" && event.challengeId));
    const finalizationEvents = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_FINALIZATION_EVENT_TYPE);
    const dispositionEvents = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE);
    const dispositionFinalizations = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE);
    const currentKey = await getCurrentKeyBinding(ownerId);
    const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
    const lifecycleDispositionCheckpoint = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
    const findings = [...ledger.findings];
    const chains = [];
    const validDispositionChallengeIds = new Set();
    let pendingCount = 0, pendingDispositionCount = 0, staleCount = 0, dispositionedCount = 0;
    if (lifecycleDispositionCheckpoint.enabled && lifecycleDispositionCheckpoint.usableForCurrentDecision !== true) {
      staleCount++;
      const unhealthy = ["unhealthy", "rollback_suspected", "policy_drift", "invalid"].includes(lifecycleDispositionCheckpoint.status)
        || (lifecycleDispositionCheckpoint.findings || []).some(item => item.code === "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ANCHOR_PROVIDER_REUSED");
      findings.push({ code: unhealthy ? "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_UNHEALTHY"
        : "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_NOT_CURRENT",
        status: lifecycleDispositionCheckpoint.status || "unavailable", checkpointFindings: lifecycleDispositionCheckpoint.findings || [] });
    }
    const verifyHistorical = async (event, attestationKind, code) => {
      let verification;
      try { verification = await verifyAttestation(ownerId, event, { attestationKind, required: true, checkCurrent: false }); }
      catch { verification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
      if (!verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code, eventId: event?.id || null, reasonCode: verification?.reasonCode || null });
      return verification;
    };
    const eventByOperation = new Map();
    for (const event of ledger.events) {
      if (!event.operationId) continue;
      const prior = eventByOperation.get(event.operationId);
      if (prior) findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_OPERATION_ID_DUPLICATE",
        operationId: event.operationId, eventIds: [prior.id, event.id] });
      else eventByOperation.set(event.operationId, event);
    }

    for (const challenge of lifecycleChallenges) {
      const unsignedChallenge = clean(challenge); delete unsignedChallenge.digest;
      if (challenge.digest !== digestRecord(unsignedChallenge)) {
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CHALLENGE_INVALID", challengeId: challenge.id });
        continue;
      }
      const intents = intentEvents.filter(event => event.challengeId === challenge.id);
      const lifecycles = lifecycleEvents.filter(event => (event.lifecycleChallengeId || event.challengeId) === challenge.id);
      const finalizations = finalizationEvents.filter(event => event.challengeId === challenge.id);
      const dispositions = dispositionEvents.filter(event => event.targetLifecycleChallengeId === challenge.id);
      const dispositionFinals = dispositionFinalizations.filter(event => event.targetLifecycleChallengeId === challenge.id);
      if (intents.length > 1 || lifecycles.length > 1 || finalizations.length > 1 || dispositions.length > 1 || dispositionFinals.length > 1)
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CHAIN_DUPLICATE", challengeId: challenge.id,
          intentCount: intents.length, lifecycleCount: lifecycles.length, finalizationCount: finalizations.length,
          dispositionCount: dispositions.length, dispositionFinalizationCount: dispositionFinals.length });
      const intent = intents[0] || null, lifecycle = lifecycles[0] || null, finalization = finalizations[0] || null;
      let intentVerification = null, lifecycleVerification = null, finalizationVerification = null;
      if (intent) {
        intentVerification = await verifyHistorical(intent, CHECKPOINT_RECOVERY_EVENT_KIND,
          "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_ATTESTATION_INVALID");
        if (intent.challengeDigest !== (challenge.challengeDigest || challenge.digest) || intent.action !== challenge.action
          || intent.targetAttestationEventId !== challenge.targetAttestationEventId
          || intent.targetAttestationEventDigest !== challenge.targetAttestationEventDigest
          || intent.closureCheckpointSnapshotDigest !== challenge.closureCheckpointSnapshotDigest
          || intent.journalSnapshotDigest !== challenge.journalSnapshotDigest
          || intent.journalEventCount !== challenge.journalEventCount)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_BINDING_INVALID", challengeId: challenge.id });
      } else if (challenge.status === "completed") {
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_MISSING", challengeId: challenge.id });
      }
      if (lifecycle) {
        const lifecycleKind = challenge.action === "renew" ? MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
        lifecycleVerification = await verifyHistorical(lifecycle, lifecycleKind,
          "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_EVENT_ATTESTATION_INVALID");
        if (!intent || lifecycle.lifecycleRecoveryIntentEventId !== intent.id
          || lifecycle.lifecycleRecoveryIntentEventDigest !== intent.digest)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_BINDING_INVALID", challengeId: challenge.id,
            lifecycleEventId: lifecycle.id });
      }
      if (finalization) {
        finalizationVerification = await verifyHistorical(finalization, CHECKPOINT_RECOVERY_EVENT_KIND,
          "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_ATTESTATION_INVALID");
        if (!intent || !lifecycle || finalization.challengeDigest !== (challenge.challengeDigest || challenge.digest)
          || finalization.recoveryIntentEventId !== intent.id || finalization.recoveryIntentEventDigest !== intent.digest
          || finalization.lifecycleEventId !== lifecycle.id || finalization.lifecycleEventDigest !== lifecycle.digest)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_BINDING_INVALID",
            challengeId: challenge.id, finalizationEventId: finalization.id });
      }
      if (intent && lifecycle && lifecycle.sequence <= intent.sequence)
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_SEQUENCE_INVALID", challengeId: challenge.id,
          intentSequence: intent.sequence, lifecycleSequence: lifecycle.sequence });
      if (lifecycle && finalization && finalization.sequence <= lifecycle.sequence)
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_SEQUENCE_INVALID", challengeId: challenge.id,
          lifecycleSequence: lifecycle.sequence, finalizationSequence: finalization.sequence });

      const validDisposition = dispositions.length === 1 && dispositionFinals.length === 1
        && dispositionChallenges.some(item => {
          const unsigned = clean(item); delete unsigned.digest;
          return item.targetLifecycleChallengeId === challenge.id && item.status === "completed"
            && item.digest === digestRecord(unsigned) && item.dispositionEventId === dispositions[0].id
            && item.dispositionEventDigest === dispositions[0].digest && item.finalizationEventId === dispositionFinals[0].id
            && item.finalizationEventDigest === dispositionFinals[0].digest
            && item.finalizationBindingDigest === sha256(canonical(markerJournalLifecycleDispositionFinalizationBinding(item)))
            && dispositions[0].challengeId === item.id && dispositionFinals[0].challengeId === item.id
            && dispositions[0].challengeDigest === (item.challengeDigest || item.digest)
            && dispositions[0].targetLifecycleChallengeDigest === challenge.digest;
        });
      if (!validDisposition && dispositions.length && dispositionChallenges.some(item => item.targetLifecycleChallengeId === challenge.id && item.status === "completed"))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_BINDING_INVALID",
          challengeId: challenge.id, dispositionEventId: dispositions[0]?.id || null, finalizationEventId: dispositionFinals[0]?.id || null });
      if (validDisposition) {
        const disposition = dispositions[0], dispositionFinal = dispositionFinals[0];
        await verifyHistorical(disposition, CHECKPOINT_RECOVERY_EVENT_KIND,
          "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_ATTESTATION_INVALID");
        await verifyHistorical(dispositionFinal, CHECKPOINT_RECOVERY_EVENT_KIND,
          "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_ATTESTATION_INVALID");
        if (disposition.targetIntentEventId !== intent?.id || disposition.targetIntentEventDigest !== intent?.digest
          || dispositionFinal.dispositionEventId !== disposition.id || dispositionFinal.dispositionEventDigest !== disposition.digest
          || dispositionFinal.challengeDigest !== dispositionChallenges.find(item => item.targetLifecycleChallengeId === challenge.id)?.challengeDigest
          || dispositionFinal.targetIntentEventId !== intent?.id || dispositionFinal.targetIntentEventDigest !== intent?.digest
          || dispositionFinal.disposition !== disposition.disposition || disposition.sequence >= dispositionFinal.sequence)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_BINDING_INVALID",
            challengeId: challenge.id, dispositionEventId: disposition.id });
        else {
          validDispositionChallengeIds.add(challenge.id);
          dispositionedCount++;
          staleCount++;
        }
      } else if (dispositions.length || dispositionFinals.length) {
        pendingDispositionCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_PENDING", challengeId: challenge.id,
          dispositionEventId: dispositions[0]?.id || null, finalizationEventId: dispositionFinals[0]?.id || null });
      }

      const incomplete = !intent || !lifecycle || !finalization || challenge.status !== "completed";
      if (incomplete && !validDisposition) {
        pendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_RECOVERY_PENDING", challengeId: challenge.id,
          intentEventId: intent?.id || null, lifecycleEventId: lifecycle?.id || null, finalizationEventId: finalization?.id || null,
          challengeStatus: challenge.status });
      }
      const cutoff = Boolean(challenge.keyCutoffDetected)
        || (intent && (intent.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null))
        || (lifecycle && (lifecycle.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null))
        || (finalization && ((finalization.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)
          || (finalization.finalizedKeyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)))
        || dispositions.some(item => item.keyCutoffDetected === true)
        || dispositionFinals.some(item => item.keyCutoffDetected === true);
      if (cutoff) {
        staleCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_KEY_CUTOFF", challengeId: challenge.id,
          intentKeyBindingDigest: intent?.keyLifecycleBindingDigest || null,
          currentKeyLifecycleBindingDigest: currentKey?.bindingDigest || null });
      }
      if (challenge.status === "completed" && !validDisposition) {
        const expected = sha256(canonical(markerJournalLifecycleFinalizationBinding(challenge)));
        if (!intent || !lifecycle || !finalization || challenge.lifecycleRecoveryIntentEventId !== intent.id
          || challenge.lifecycleRecoveryIntentEventDigest !== intent.digest || challenge.lifecycleEventId !== lifecycle.id
          || challenge.lifecycleEventDigest !== lifecycle.digest || challenge.lifecycleFinalizationEventId !== finalization.id
          || challenge.lifecycleFinalizationEventDigest !== finalization.digest || challenge.lifecycleFinalizationBindingDigest !== expected)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_BINDING_INVALID", challengeId: challenge.id });
      }
      chains.push({ challengeId: challenge.id, status: validDisposition ? "dispositioned" : incomplete ? "pending" : cutoff ? "stale" : "verified_current",
        intentEventId: intent?.id || null, lifecycleEventId: lifecycle?.id || null, finalizationEventId: finalization?.id || null,
        dispositionEventId: dispositions[0]?.id || null, dispositionFinalizationEventId: dispositionFinals[0]?.id || null,
        keyCutoffDetected: cutoff, sequence: { intent: intent?.sequence ?? null, lifecycle: lifecycle?.sequence ?? null,
          finalization: finalization?.sequence ?? null } });
    }

    for (const challenge of dispositionChallenges) {
      const unsigned = clean(challenge); delete unsigned.digest;
      if (challenge.digest !== digestRecord(unsigned))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_INVALID", challengeId: challenge.id });
      if (challenge.status === "completed" && (!dispositionEvents.some(event => event.id === challenge.dispositionEventId
        && event.digest === challenge.dispositionEventDigest)
        || !dispositionFinalizations.some(event => event.id === challenge.finalizationEventId
          && event.digest === challenge.finalizationEventDigest)))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_RECEIPT_MISSING", challengeId: challenge.id });
    }
    for (const event of [...lifecycleEvents, ...finalizationEvents, ...dispositionEvents, ...dispositionFinalizations]) {
      const isDispositionEvent = event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE
        || event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE;
      const challengeId = event.lifecycleChallengeId || (isDispositionEvent ? event.targetLifecycleChallengeId : event.challengeId);
      if (challengeId && !byChallengeId.has(challengeId))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_EVENT_ORPHANED", eventId: event.id, challengeId });
    }
    for (const event of finalizationEvents) {
      if (!intentEvents.some(item => item.id === event.recoveryIntentEventId && item.digest === event.recoveryIntentEventDigest))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_INTENT_MISSING", eventId: event.id });
    }
    for (const event of dispositionFinalizations) {
      if (!dispositionEvents.some(item => item.id === event.dispositionEventId && item.digest === event.dispositionEventDigest))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_MISSING", eventId: event.id });
    }
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true) {
      staleCount++;
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CHECKPOINT_NOT_CURRENT",
        status: checkpoint.status || "unavailable", checkpointFindings: checkpoint.findings || [] });
    }
    const hard = findings.some(item => /_INVALID|_MISSING|_ORPHANED|_DUPLICATE|_UNHEALTHY|SEQUENCE_INVALID|LEDGER_INVALID|CHAIN_INVALID/.test(item.code || ""));
    const status = hard ? "unhealthy" : staleCount || dispositionedCount ? "stale" : pendingCount || pendingDispositionCount ? "recovery_required"
      : intentEvents.length ? "verified_current" : "not_initialized";
    return { status, ownerId, intentCount: intentEvents.length, lifecycleEventCount: lifecycleEvents.length,
      finalizationCount: finalizationEvents.length, pendingCount, pendingDispositionCount, dispositionedCount, staleCount, chains,
      dispositionedChallengeIds: [...validDispositionChallengeIds], currentKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
      recoveryReceiptCheckpoint: checkpoint, lifecycleDispositionCheckpoint, findings,
      usableForCurrentDecision: !hard && staleCount === 0 && pendingCount === 0
        && pendingDispositionCount === 0 && dispositionedCount === 0
        && (!checkpoint.enabled || checkpoint.usableForCurrentDecision === true)
        && (!lifecycleDispositionCheckpoint.enabled || lifecycleDispositionCheckpoint.usableForCurrentDecision === true),
      readOnly: true, mutationAllowed: false };
  }

  async function prepareMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(ownerId, targetChallengeId, { disposition, reason } = {}) {
    assertOwner(ownerId);
    if (typeof targetChallengeId !== "string" || !targetChallengeId.trim() || targetChallengeId.length > 240)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_TARGET_INVALID", "Lifecycle challenge target tidak valid", 400);
    if (!MARKER_JOURNAL_LIFECYCLE_DISPOSITIONS.has(disposition))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_INVALID", "Disposition harus quarantine atau mark_unrecoverable", 400);
    if (typeof reason !== "string" || reason.trim() !== reason || reason.length < 12 || reason.length > 240)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_REASON_INVALID", "Alasan disposition wajib 12–240 karakter", 400);
    const targetChallenge = await store.getEvidence(ownerId, targetChallengeId);
    if (!targetChallenge || targetChallenge.ownerId !== ownerId || targetChallenge.kind !== MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND
      || targetChallenge.digest !== digestRecord(targetChallenge))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_TARGET_MISSING", "Lifecycle challenge tidak ditemukan atau tidak valid", 404);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    if (ledger.status === "unhealthy") throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_LEDGER_UNHEALTHY",
      "Lifecycle ledger tidak sehat; disposition ditolak", 409, { findings: ledger.findings });
    const intentEvents = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_INTENT_EVENT_TYPE
      && event.challengeId === targetChallenge.id);
    if (intentEvents.length !== 1) throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_INTENT_NOT_UNIQUE",
      "Disposition memerlukan tepat satu recovery intent persisten", 409, { intentCount: intentEvents.length });
    const continuity = await auditMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(ownerId);
    const chain = continuity.chains.find(item => item.challengeId === targetChallenge.id);
    if (continuity.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CONTINUITY_UNHEALTHY",
        "Continuity ledger tidak sehat; disposition tidak dapat digunakan untuk menyamarkan evidence yang rusak", 409,
        { findings: continuity.findings });
    const currentKey = await getCurrentKeyBinding(ownerId);
    const unresolved = targetChallenge.status !== "completed" || !chain || chain.status !== "verified_current"
      || targetChallenge.keyCutoffDetected === true
      || (intentEvents[0].keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null);
    if (!unresolved) throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_NOT_REQUIRED",
      "Lifecycle intent yang current dan terfinalisasi tidak memerlukan disposition", 409);
    if (continuity.dispositionedChallengeIds.includes(targetChallenge.id))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_ALREADY_RECORDED", "Lifecycle intent sudah memiliki disposition", 409);
    const existingDispositionEvent = ledger.events.find(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE
      && event.targetLifecycleChallengeId === targetChallenge.id);
    if (existingDispositionEvent)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_RECOVERY_PENDING",
        "Disposition event sudah tersimpan; lanjutkan challenge asal, jangan membuat disposition baru", 409,
        { dispositionChallengeId: existingDispositionEvent.challengeId, dispositionEventId: existingDispositionEvent.id });
    const existingPreparedDisposition = (await store.listEvidence(ownerId)).find(item => item?.ownerId === ownerId
      && item.kind === MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_KIND
      && item.targetLifecycleChallengeId === targetChallenge.id && item.status === "prepared"
      && Number.isFinite(Date.parse(item.expiresAt)) && Date.parse(item.expiresAt) > Date.parse(isoNow(clock)));
    if (existingPreparedDisposition)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_ALREADY_PREPARED",
        "Disposition challenge masih aktif; gunakan challenge yang sudah ada", 409,
        { challengeId: existingPreparedDisposition.id });
    const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_NOT_CURRENT",
        "Disposition memerlukan recovery-receipt checkpoint current; rekonsiliasi checkpoint terlebih dahulu", 409,
        { status: checkpoint.status || "unavailable", findings: checkpoint.findings || [] });
    const lifecycleDispositionCheckpoint = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
    if (lifecycleDispositionCheckpoint.enabled && lifecycleDispositionCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_NOT_CURRENT",
        "Disposition memerlukan dedicated lifecycle-disposition checkpoint yang current", 409,
        { status: lifecycleDispositionCheckpoint.status || "unavailable", findings: lifecycleDispositionCheckpoint.findings || [] });
    const intent = intentEvents[0];
    const intentVerification = await verifyAttestation(ownerId, intent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      required: true, checkCurrent: false });
    if (!intentVerification?.historicallyValid || intentVerification.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_INTENT_INVALID",
        "Signature recovery intent tidak valid; disposition otomatis ditolak", 409);
    const createdAt = isoNow(clock), expiresAt = new Date(Date.parse(createdAt) + 10 * 60 * 1000).toISOString();
    const challengeId = `${MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_KIND}-${randomUUID()}`;
    const unsigned = { id: challengeId, ownerId, kind: MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_KIND, schemaVersion: 1,
      status: "prepared", targetLifecycleChallengeId: targetChallenge.id, targetLifecycleChallengeDigest: targetChallenge.digest,
      targetIntentEventId: intent.id, targetIntentEventDigest: intent.digest,
      targetLifecycleEventId: chain?.lifecycleEventId || null, targetFinalizationEventId: chain?.finalizationEventId || null,
      targetLedgerSnapshotDigest: ledger.snapshotDigest, targetLedgerHeadDigest: ledger.headDigest, targetLedgerCount: ledger.count,
      currentKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
      recoveryReceiptCheckpointAnchorDigest: checkpoint.anchorDigest || null,
      recoveryReceiptCheckpointAnchorSequence: checkpoint.anchorSequence ?? null,
      lifecycleDispositionCheckpointAnchorDigest: lifecycleDispositionCheckpoint.anchorDigest || null,
      lifecycleDispositionCheckpointAnchorSequence: lifecycleDispositionCheckpoint.anchorSequence ?? null,
      lifecycleDispositionCheckpointSnapshotDigest: lifecycleDispositionCheckpoint.snapshotDigest || null,
      disposition, reason, createdAt, expiresAt,
      confirmationPhrase: `DISPOSITION MARKER-JOURNAL LIFECYCLE INTENT ${sha256(`${ownerId}\0${challengeId}\0${intent.digest}\0${disposition}`).slice(0, 12)}` };
    const challengeDigest = digestRecord(unsigned);
    const challenge = { ...unsigned, challengeDigest, digest: digestRecord({ ...unsigned, challengeDigest }) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { status: "prepared", challengeId, targetLifecycleChallengeId: targetChallenge.id, targetIntentEventId: intent.id,
      disposition, expiresAt, confirmation: challenge.confirmationPhrase, readOnly: false, mutationAllowed: false };
  }

  async function applyMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(ownerId, challengeId, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    const challengeUnsigned = clean(challenge || {}); delete challengeUnsigned.digest;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_KIND
      || challenge.digest !== digestRecord(challengeUnsigned) || !MARKER_JOURNAL_LIFECYCLE_DISPOSITIONS.has(challenge.disposition))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_INVALID", "Disposition challenge tidak valid", 409);
    if (confirmation !== challenge.confirmationPhrase)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_UNCONFIRMED", "Konfirmasi disposition tidak cocok", 409);
    const ids = markerJournalLifecycleDispositionOperationIds(challenge.targetLifecycleChallengeId);
    let ledger = await readCheckpointRecoveryLedger(ownerId);
    let dispositionEvent = ledger.events.find(event => event.operationId === ids.dispositionOperationId) || null;
    let finalizationEvent = ledger.events.find(event => event.operationId === ids.finalizationOperationId) || null;
    const hadDurableDispositionEvent = Boolean(dispositionEvent);
    const hadDurableFinalizationEvent = Boolean(finalizationEvent);
    const currentKey = await getCurrentKeyBinding(ownerId);
    const keyCutoffDetected = (challenge.currentKeyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null);
    if (!dispositionEvent) {
      if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt))
        || Date.parse(challenge.expiresAt) <= Date.parse(isoNow(clock)))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_EXPIRED", "Disposition challenge kedaluwarsa atau tidak lagi prepared", 409);
      if (keyCutoffDetected) throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_KEY_CUTOFF",
        "Signing-key lifecycle berubah sejak disposition disiapkan; siapkan challenge baru", 409);
      const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
      if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_NOT_CURRENT",
          "Disposition diblokir sampai recovery-receipt checkpoint current", 409, { status: checkpoint.status || "unavailable" });
      const lifecycleDispositionCheckpoint = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
      if (lifecycleDispositionCheckpoint.enabled && (lifecycleDispositionCheckpoint.usableForCurrentDecision !== true
        || (challenge.lifecycleDispositionCheckpointAnchorDigest || null) !== (lifecycleDispositionCheckpoint.anchorDigest || null)
        || (challenge.lifecycleDispositionCheckpointAnchorSequence ?? null) !== (lifecycleDispositionCheckpoint.anchorSequence ?? null)
        || (challenge.lifecycleDispositionCheckpointSnapshotDigest || null) !== (lifecycleDispositionCheckpoint.snapshotDigest || null)))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_SNAPSHOT_CHANGED",
          "Dedicated lifecycle-disposition checkpoint berubah sejak challenge dibuat", 409,
          { status: lifecycleDispositionCheckpoint.status || "unavailable" });
      if (ledger.snapshotDigest !== challenge.targetLedgerSnapshotDigest || ledger.headDigest !== challenge.targetLedgerHeadDigest
        || ledger.count !== challenge.targetLedgerCount)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_SNAPSHOT_CHANGED",
          "Lifecycle ledger berubah sejak disposition challenge dibuat", 409);
      const targetChallenge = await store.getEvidence(ownerId, challenge.targetLifecycleChallengeId);
      if (!targetChallenge || targetChallenge.digest !== challenge.targetLifecycleChallengeDigest
        || targetChallenge.kind !== MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_TARGET_CHANGED", "Lifecycle challenge target berubah", 409);
      const intent = ledger.events.find(event => event.id === challenge.targetIntentEventId && event.digest === challenge.targetIntentEventDigest
        && event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_INTENT_EVENT_TYPE);
      if (!intent || intent.challengeId !== targetChallenge.id)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_INTENT_CHANGED", "Recovery intent target berubah", 409);
      const continuity = await auditMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(ownerId);
      const chain = continuity.chains.find(item => item.challengeId === targetChallenge.id);
      if (!chain || (chain.status === "verified_current" && targetChallenge.status === "completed"))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_NOT_REQUIRED",
          "Lifecycle intent tidak lagi membutuhkan disposition", 409);
      const operationId = ids.dispositionOperationId;
      const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`,
        operationId, eventType: MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_TYPE,
        challengeId: challenge.id, challengeDigest: challenge.challengeDigest, targetLifecycleChallengeId: targetChallenge.id,
        targetLifecycleChallengeDigest: targetChallenge.digest, targetIntentEventId: intent.id, targetIntentEventDigest: intent.digest,
        targetLifecycleEventId: challenge.targetLifecycleEventId || null, targetFinalizationEventId: challenge.targetFinalizationEventId || null,
        disposition: challenge.disposition, reason: challenge.reason, observedLedgerHeadDigest: ledger.headDigest || null,
        observedLedgerCount: ledger.count, preparedKeyLifecycleBindingDigest: challenge.currentKeyLifecycleBindingDigest || null,
        keyCutoffDetected: (intent.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)
          || Boolean(targetChallenge.keyCutoffDetected), occurredAt: isoNow(clock) };
      dispositionEvent = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true })).event;
      ledger = await readCheckpointRecoveryLedger(ownerId);
    } else {
      const verification = await verifyAttestation(ownerId, dispositionEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false });
      if (dispositionEvent.challengeDigest !== challenge.challengeDigest || dispositionEvent.targetIntentEventId !== challenge.targetIntentEventId
        || dispositionEvent.targetIntentEventDigest !== challenge.targetIntentEventDigest || dispositionEvent.disposition !== challenge.disposition
        || !verification?.historicallyValid || verification.status === "unhealthy")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_EVENT_INVALID", "Disposition event tersimpan tidak cocok dengan challenge", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, ids.dispositionOperationId);
      await advanceMarkerRecoveryJournalLifecycleDispositionCheckpointAfterAppend(ownerId, ids.dispositionOperationId);
    }
    const checkpointAfterDisposition = await getRecoveryReceiptCheckpointState(ownerId);
    const lifecycleDispositionCheckpointAfterDisposition = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
    if (lifecycleDispositionCheckpointAfterDisposition.enabled && lifecycleDispositionCheckpointAfterDisposition.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_PENDING",
        "Disposition event tersimpan tetapi dedicated external checkpoint belum current", 409,
        { status: lifecycleDispositionCheckpointAfterDisposition.status || "unavailable", findings: lifecycleDispositionCheckpointAfterDisposition.findings || [] });
    if (checkpointAfterDisposition.enabled && checkpointAfterDisposition.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHECKPOINT_PENDING",
        "Disposition event tersimpan tetapi external checkpoint belum current", 409,
        { status: checkpointAfterDisposition.status || "unavailable", findings: checkpointAfterDisposition.findings || [] });
    if (!finalizationEvent) {
      const finalizationOperationId = ids.finalizationOperationId;
      const targetChallenge = await store.getEvidence(ownerId, challenge.targetLifecycleChallengeId);
      const targetIntent = ledger.events.find(event => event.id === challenge.targetIntentEventId && event.digest === challenge.targetIntentEventDigest);
      const currentKeyNow = await getCurrentKeyBinding(ownerId);
      const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(finalizationOperationId).slice(0, 24)}`,
        operationId: finalizationOperationId, eventType: MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_EVENT_TYPE,
        challengeId: challenge.id, challengeDigest: challenge.challengeDigest, targetLifecycleChallengeId: challenge.targetLifecycleChallengeId,
        targetLifecycleChallengeDigest: targetChallenge?.digest || challenge.targetLifecycleChallengeDigest,
        targetIntentEventId: targetIntent?.id || challenge.targetIntentEventId,
        targetIntentEventDigest: targetIntent?.digest || challenge.targetIntentEventDigest,
        dispositionEventId: dispositionEvent.id, dispositionEventDigest: dispositionEvent.digest,
        disposition: challenge.disposition, keyCutoffDetected: Boolean(dispositionEvent.keyCutoffDetected)
          || (challenge.currentKeyLifecycleBindingDigest || null) !== (currentKeyNow?.bindingDigest || null),
        finalizedKeyLifecycleBindingDigest: currentKeyNow?.bindingDigest || null,
        dispositionCheckpointAnchorDigest: checkpointAfterDisposition.anchorDigest || null,
        dispositionCheckpointAnchorSequence: checkpointAfterDisposition.anchorSequence ?? null,
        lifecycleDispositionCheckpointAnchorDigest: lifecycleDispositionCheckpointAfterDisposition.anchorDigest || null,
        lifecycleDispositionCheckpointAnchorSequence: lifecycleDispositionCheckpointAfterDisposition.anchorSequence ?? null,
        finalizedAt: isoNow(clock) };
      finalizationEvent = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true })).event;
    } else {
      const verification = await verifyAttestation(ownerId, finalizationEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false });
      if (finalizationEvent.dispositionEventId !== dispositionEvent.id || finalizationEvent.dispositionEventDigest !== dispositionEvent.digest
        || !verification?.historicallyValid || verification.status === "unhealthy")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_INVALID",
          "Disposition finalization receipt tidak valid", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, ids.finalizationOperationId);
      await advanceMarkerRecoveryJournalLifecycleDispositionCheckpointAfterAppend(ownerId, ids.finalizationOperationId);
    }
    const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
    const finalizedDispositionCheckpoint = await getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId);
    if (finalizedDispositionCheckpoint.enabled && finalizedDispositionCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_CHECKPOINT_PENDING",
        "Disposition finalization tersimpan tetapi dedicated external checkpoint belum current", 409,
        { status: finalizedDispositionCheckpoint.status || "unavailable", findings: finalizedDispositionCheckpoint.findings || [] });
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_PENDING",
        "Finalization receipt tersimpan tetapi checkpoint belum current", 409);
    const currentKeyNow = await getCurrentKeyBinding(ownerId);
    const completedUnsigned = { ...clean(challenge), status: "completed", dispositionEventId: dispositionEvent.id,
      dispositionEventDigest: dispositionEvent.digest, finalizationEventId: finalizationEvent.id,
      finalizationEventDigest: finalizationEvent.digest, finalizedCheckpointAnchorDigest: checkpoint.anchorDigest || null,
      finalizedCheckpointAnchorSequence: checkpoint.anchorSequence ?? null,
      finalizedDispositionCheckpointAnchorDigest: finalizedDispositionCheckpoint.anchorDigest || null,
      finalizedDispositionCheckpointAnchorSequence: finalizedDispositionCheckpoint.anchorSequence ?? null,
      finalizedKeyLifecycleBindingDigest: currentKeyNow?.bindingDigest || null,
      keyCutoffDetected: Boolean(dispositionEvent.keyCutoffDetected)
        || (challenge.currentKeyLifecycleBindingDigest || null) !== (currentKeyNow?.bindingDigest || null), completedAt: isoNow(clock) };
    delete completedUnsigned.digest;
    completedUnsigned.finalizationBindingDigest = sha256(canonical(markerJournalLifecycleDispositionFinalizationBinding(completedUnsigned)));
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    if (challenge.status !== "completed") {
      try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, challenge.id);
        if (!concurrent || concurrent.status !== "completed" || concurrent.finalizationEventDigest !== finalizationEvent.digest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZE_CONFLICT", "Disposition tersimpan tetapi challenge belum dapat difinalisasi secara CAS", 409);
      }
    } else {
      const expected = sha256(canonical(markerJournalLifecycleDispositionFinalizationBinding(challenge)));
      if (challenge.digest !== digestRecord(challengeUnsigned) || challenge.finalizationBindingDigest !== expected
        || challenge.finalizationEventDigest !== finalizationEvent.digest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_FINALIZATION_BINDING_INVALID", "Disposition challenge finalisasi tidak konsisten", 409);
    }
    return { status: "completed", disposition: dispositionEvent, finalizationReceipt: finalizationEvent,
      idempotent: challenge.status === "completed" || hadDurableDispositionEvent || hadDurableFinalizationEvent,
      keyCutoffDetected: Boolean(dispositionEvent.keyCutoffDetected)
        || (challenge.currentKeyLifecycleBindingDigest || null) !== (currentKeyNow?.bindingDigest || null),
      continuityAudit: await auditMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(ownerId),
      closure: await auditClosure(ownerId), readOnly: true, mutationAllowed: false };
  }

  async function reconcileMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDispositionChallenge(ownerId, challengeId) {
    assertOwner(ownerId);
    if (typeof challengeId !== "string" || !challengeId.trim() || challengeId.length > 240)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_INVALID",
        "Disposition challenge ID tidak valid", 400);
    const challenge = await store.getEvidence(ownerId, challengeId);
    const unsigned = clean(challenge || {}); delete unsigned.digest;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== MARKER_RECOVERY_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_KIND
      || challenge.digest !== digestRecord(unsigned) || !MARKER_JOURNAL_LIFECYCLE_DISPOSITIONS.has(challenge.disposition))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_INVALID",
        "Disposition challenge tidak valid", 409);
    const ids = markerJournalLifecycleDispositionOperationIds(challenge.targetLifecycleChallengeId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const durableEvent = ledger.events.find(event => event.operationId === ids.dispositionOperationId) || null;
    if (durableEvent) {
      const resumed = await applyMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(ownerId, challenge.id,
        { confirmation: challenge.confirmationPhrase });
      return { status: "resumed_after_persisted_commit", idempotent: true, result: resumed,
        expiryIgnoredBecauseCommitWasDurable: Date.parse(challenge.expiresAt) <= Date.parse(isoNow(clock)),
        readOnly: false, mutationAllowed: false };
    }
    if (challenge.status === "completed")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_RECEIPT_MISSING",
        "Challenge completed tidak memiliki disposition event persisten", 409);
    const expired = !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(isoNow(clock));
    if (!expired) return { status: "not_expired", challengeId: challenge.id, expiresAt: challenge.expiresAt,
      mutationPerformed: false, readOnly: true, mutationAllowed: false };
    if (challenge.status === "expired") return { status: "expired_without_commit", challengeId: challenge.id,
      idempotent: true, mutationPerformed: false, readOnly: true, mutationAllowed: false };
    if (challenge.status !== "prepared")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_CHALLENGE_STATE_INVALID",
        "Challenge tidak dapat direkonsiliasi dari status saat ini", 409, { status: challenge.status });
    const expiredUnsigned = { ...clean(challenge), status: "expired", expiredAt: isoNow(clock),
      expiryReconciliation: { outcome: "expired_without_commit", dispositionOperationId: ids.dispositionOperationId,
        observedLedgerHeadDigest: ledger.headDigest || null, observedLedgerCount: ledger.count } };
    delete expiredUnsigned.digest;
    const expiredRecord = { ...expiredUnsigned, digest: digestRecord(expiredUnsigned) };
    let expiredConcurrently = false;
    try { await store.putEvidence(ownerId, expiredRecord, { expectedVersion: challenge._storage?.version }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, challenge.id);
      if (!concurrent || concurrent.status !== "expired" || concurrent.expiryReconciliation?.outcome !== "expired_without_commit")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_DISPOSITION_EXPIRY_CAS_CONFLICT",
          "Challenge kedaluwarsa tidak dapat difinalisasi melalui CAS", 409);
      expiredConcurrently = true;
    }
    return { status: "expired_without_commit", challengeId: challenge.id, idempotent: expiredConcurrently,
      mutationPerformed: !expiredConcurrently, readOnly: false, mutationAllowed: false };
  }

  async function auditMarkerRecoveryJournalAttestationLifecycleRecoveryIntents(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const rows = (await store.listEvidence(ownerId)).filter(row => row?.ownerId === ownerId
      && row.kind === MARKER_RECOVERY_JOURNAL_LIFECYCLE_CHALLENGE_KIND);
    const continuityAudit = await auditMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(ownerId);
    const dispositionedChallengeIds = new Set(continuityAudit.dispositionedChallengeIds || []);
    const byId = new Map(rows.map(row => [row.id, row]));
    const intentEvents = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_INTENT_EVENT_TYPE);
    const finalizationEvents = ledger.events.filter(event => event.eventType === MARKER_RECOVERY_JOURNAL_LIFECYCLE_FINALIZATION_EVENT_TYPE);
    const findings = [...ledger.findings, ...continuityAudit.findings];
    let pendingCount = 0, staleCount = 0;
    const intents = [];
    const currentKey = await getCurrentKeyBinding(ownerId);
    const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
    for (const event of intentEvents) {
      const challenge = byId.get(event.challengeId);
      const verification = await verifyAttestation(ownerId, event, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false });
      const challengeUnsigned = clean(challenge || {}); delete challengeUnsigned.digest;
      if (!challenge || challenge.digest !== digestRecord(challengeUnsigned)
        || (challenge.challengeDigest || challenge.digest) !== event.challengeDigest
        || challenge.action !== event.action || challenge.targetAttestationEventId !== event.targetAttestationEventId
        || challenge.targetAttestationEventDigest !== event.targetAttestationEventDigest
        || event.targetSnapshotDigest !== challenge.targetSnapshotDigest
        || event.closureCheckpointSnapshotDigest !== challenge.closureCheckpointSnapshotDigest
        || event.journalSnapshotDigest !== challenge.journalSnapshotDigest
        || event.journalEventCount !== challenge.journalEventCount
        || event.preparedKeyLifecycleBindingDigest !== (challenge.keyLifecycleBindingDigest || null)
        || event.preparedRecoveryReceiptCheckpointAnchorDigest !== (challenge.recoveryReceiptCheckpointAnchorDigest || null)
        || event.preparedRecoveryReceiptCheckpointAnchorSequence !== (challenge.recoveryReceiptCheckpointAnchorSequence ?? null)
        || event.expectedPriorRecoveryReceiptLedgerHeadDigest !== (challenge.recoveryReceiptLedgerHeadDigest || null)
        || !verification?.historicallyValid || verification.status === "unhealthy") {
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_INVALID",
          eventId: event.id, challengeId: event.challengeId, reasonCode: verification?.reasonCode || null });
        continue;
      }
      const ids = markerJournalLifecycleOperationIds(challenge.id);
      const lifecycleEvent = ledger.events.find(item => item.operationId === ids.lifecycleOperationId);
      const finalizationEvent = ledger.events.find(item => item.operationId === ids.finalizationOperationId);
      const dispositioned = dispositionedChallengeIds.has(challenge.id);
      if ((!lifecycleEvent || !finalizationEvent || challenge.status !== "completed") && !dispositioned) {
        pendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_RECOVERY_PENDING",
          intentEventId: event.id, challengeId: challenge.id, lifecycleEventId: lifecycleEvent?.id || null,
          finalizationEventId: finalizationEvent?.id || null, challengeStatus: challenge.status });
      } else if (dispositioned) {
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_DISPOSITIONED",
          intentEventId: event.id, challengeId: challenge.id,
          disposition: continuityAudit.chains.find(item => item.challengeId === challenge.id)?.status || "dispositioned" });
      }
      if (lifecycleEvent) {
        const lifecycleKind = challenge.action === "renew" ? MARKER_RECOVERY_JOURNAL_ATTESTATION_KIND : CHECKPOINT_RECOVERY_EVENT_KIND;
        const lifecycleVerification = await verifyAttestation(ownerId, lifecycleEvent, { attestationKind: lifecycleKind,
          required: true, checkCurrent: false });
        if (!lifecycleVerification?.historicallyValid || lifecycleVerification.status === "unhealthy")
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_EVENT_ATTESTATION_INVALID",
            lifecycleEventId: lifecycleEvent.id, reasonCode: lifecycleVerification?.reasonCode || null });
        if ((lifecycleEvent.lifecycleRecoveryIntentEventId !== event.id
          || lifecycleEvent.lifecycleRecoveryIntentEventDigest !== event.digest) && !event.legacyIntentReconstructed)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_BINDING_INVALID",
            intentEventId: event.id, lifecycleEventId: lifecycleEvent.id });
      }
      if (finalizationEvent && (!lifecycleEvent || finalizationEvent.challengeId !== challenge.id
        || finalizationEvent.challengeDigest !== (challenge.challengeDigest || challenge.digest)
        || finalizationEvent.recoveryIntentEventId !== event.id || finalizationEvent.recoveryIntentEventDigest !== event.digest
        || finalizationEvent.lifecycleEventId !== lifecycleEvent.id || finalizationEvent.lifecycleEventDigest !== lifecycleEvent.digest))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_INVALID",
          finalizationEventId: finalizationEvent.id, intentEventId: event.id });
      if (challenge.status === "completed") {
        const unsigned = clean(challenge); delete unsigned.digest;
        const binding = sha256(canonical(markerJournalLifecycleFinalizationBinding(challenge)));
        if (challenge.digest !== digestRecord(unsigned) || challenge.lifecycleRecoveryIntentEventId !== event.id
          || challenge.lifecycleRecoveryIntentEventDigest !== event.digest
          || challenge.lifecycleEventId !== lifecycleEvent?.id || challenge.lifecycleEventDigest !== lifecycleEvent?.digest
          || challenge.lifecycleFinalizationEventId !== finalizationEvent?.id
          || challenge.lifecycleFinalizationEventDigest !== finalizationEvent?.digest
          || challenge.lifecycleFinalizationBindingDigest !== binding)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_BINDING_INVALID",
            challengeId: challenge.id });
      }
      const cutoff = Boolean(challenge.keyCutoffDetected)
        || (event.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)
        || (finalizationEvent && (finalizationEvent.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null));
      if (cutoff) {
        staleCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_KEY_CUTOFF",
          challengeId: challenge.id, intentKeyBindingDigest: event.keyLifecycleBindingDigest || null,
          currentKeyLifecycleBindingDigest: currentKey?.bindingDigest || null });
      }
      intents.push({ challengeId: challenge.id, action: challenge.action, status: challenge.status,
        intentEventId: event.id, intentEventDigest: event.digest, lifecycleEventId: lifecycleEvent?.id || null,
        finalizationEventId: finalizationEvent?.id || null,
        pending: (!lifecycleEvent || !finalizationEvent || challenge.status !== "completed") && !dispositioned,
        dispositioned, keyCutoffDetected: cutoff });
    }
    for (const challenge of rows.filter(item => item.status === "completed")) {
      if (!intentEvents.some(event => event.challengeId === challenge.id))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_MISSING", challengeId: challenge.id });
    }
    for (const event of finalizationEvents) {
      const verification = await verifyAttestation(ownerId, event, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false });
      if (!verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_ATTESTATION_INVALID",
          eventId: event.id, reasonCode: verification?.reasonCode || null });
      const intent = intentEvents.find(item => item.id === event.recoveryIntentEventId && item.digest === event.recoveryIntentEventDigest);
      const lifecycle = ledger.events.find(item => item.id === event.lifecycleEventId && item.digest === event.lifecycleEventDigest);
      const challenge = byId.get(event.challengeId);
      if (!intent || !lifecycle || !challenge || (challenge.challengeDigest || challenge.digest) !== event.challengeDigest
        || event.action !== challenge.action)
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_FINALIZATION_BINDING_INVALID",
          finalizationEventId: event.id, challengeId: event.challengeId,
          recoveryIntentEventId: event.recoveryIntentEventId || null, lifecycleEventId: event.lifecycleEventId || null });
    }
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true) {
      staleCount++;
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_CHECKPOINT_NOT_CURRENT",
        status: checkpoint.status || "unavailable", checkpointFindings: checkpoint.findings || [] });
    }
    const hard = continuityAudit.status === "unhealthy" || findings.some(item => /_INVALID|_MISSING|LEDGER_INVALID|CHAIN_INVALID/.test(item.code || ""));
    const status = hard ? "unhealthy" : staleCount || continuityAudit.status === "stale" ? "stale" : pendingCount || continuityAudit.pendingDispositionCount ? "recovery_required"
      : intentEvents.length ? "verified_current" : "not_initialized";
    return { status, ownerId, intentCount: intentEvents.length, finalizationCount: finalizationEvents.length,
      pendingCount, dispositionedCount: continuityAudit.dispositionedCount || 0, intents, continuityAudit,
      currentKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
      recoveryReceiptCheckpoint: checkpoint, lifecycleDispositionCheckpoint: continuityAudit.lifecycleDispositionCheckpoint || null,
      findings, usableForCurrentDecision: !hard && staleCount === 0 && pendingCount === 0
        && continuityAudit.usableForCurrentDecision === true
        && (!checkpoint.enabled || checkpoint.usableForCurrentDecision === true)
        && (!(continuityAudit.lifecycleDispositionCheckpoint?.enabled) || continuityAudit.lifecycleDispositionCheckpoint.usableForCurrentDecision === true),
      readOnly: true, mutationAllowed: false };
  }

  function lifecycleDispositionRollbackFingerprint(checkpoint = {}, inspection = {}, receiptCheckpoint = {}) {
    return sha256(canonical({ schemaVersion: 1,
      checkpoint: { status: checkpoint.status || null, anchorSequence: checkpoint.anchorSequence ?? null,
        anchorDigest: checkpoint.anchorDigest || null, sourceDigest: checkpoint.sourceDigest || null,
        sourceCount: checkpoint.sourceCount ?? null, anchoredSourceDigest: checkpoint.anchoredSourceDigest || null,
        anchoredSourceCount: checkpoint.anchoredSourceCount ?? null, policyDrift: Boolean(checkpoint.policyDrift),
        historyNotProven: Boolean(checkpoint.historyNotProven), findings: (checkpoint.findings || []).map(item => item.code).sort() },
      inspection: { status: inspection.status || null, anchorSequence: inspection.anchorSequence ?? null,
        anchorDigest: inspection.anchorDigest || null, markerSequence: inspection.markerSequence ?? null,
        markerDigest: inspection.markerDigest || null, expectedAnchorSequence: inspection.expectedAnchorSequence ?? null,
        previousAnchorDigest: inspection.previousAnchorDigest || null, findings: (inspection.findings || []).map(item => item.code).sort() },
      // Do not bind the challenge fingerprint to the recovery-receipt anchor head: the
      // challenge's own continuity receipts advance that independent anchor. Currentness
      // is enforced separately before receipt writes and during final revalidation.
      recoveryReceiptCheckpoint: { enabled: Boolean(receiptCheckpoint.enabled), required: Boolean(receiptCheckpoint.required) } }));
  }

  async function readLifecycleDispositionRollbackContinuityLedger(ownerId) {
    return readLedger(ownerId, { kind: LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_LEDGER_KIND,
      id: lifecycleDispositionRollbackContinuityLedgerId, eventKind: LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_EVENT_KIND });
  }

  async function appendLifecycleDispositionRollbackContinuityReceipt(ownerId, event) {
    const operationId = `${event.operationId}:external`;
    const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`,
      operationId, eventType: "lifecycle_disposition_checkpoint_rollback_continuity_phase",
      checkpointName: "lifecycle_disposition", continuityEventId: event.id, continuityEventDigest: event.digest,
      continuityOperationId: event.operationId, continuityPhase: event.phase, continuitySequence: event.sequence,
      continuityPreviousEventDigest: event.previousEventDigest || null, continuityHeadDigest: event.digest,
      continuityLedgerCount: event.sequence, challengeId: event.challengeId, challengeDigest: event.challengeDigest,
      rollbackOperationId: event.rollbackOperationId, rollbackEventId: event.rollbackEventId || null,
      rollbackEventDigest: event.rollbackEventDigest || null, finalizationReceiptId: event.finalizationReceiptId || null,
      finalizationReceiptDigest: event.finalizationReceiptDigest || null, checkpointFingerprint: event.checkpointFingerprint,
      occurredAt: event.occurredAt };
    return appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true });
  }

  async function appendLifecycleDispositionRollbackContinuityPhase(ownerId, challenge, phase, references = {}) {
    if (!LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES.includes(phase))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASE_INVALID",
        "Fase kontinuitas rollback tidak dikenal", 400);
    const preparedChallengeDigest = challenge.preparedChallengeDigest || challenge.digest;
    const eventId = `${lifecycleDispositionRollbackContinuityLedgerId(ownerId)}-${sha256(`${challenge.id}:${phase}`).slice(0, 24)}`;
    const operationId = `lifecycle-disposition-rollback-continuity:${challenge.id}:${phase}`;
    const eventBase = { id: eventId, operationId, eventType: "lifecycle_disposition_checkpoint_rollback_continuity_phase",
      phase, phaseOrder: LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES.indexOf(phase) + 1,
      challengeId: challenge.id, challengeDigest: preparedChallengeDigest,
      rollbackOperationId: sha256(canonical({ ownerId, challengeId: challenge.id, checkpointFingerprint: challenge.checkpointFingerprint,
        disposition: challenge.disposition, reason: challenge.reason })),
      disposition: challenge.disposition, reasonDigest: sha256(String(challenge.reason || "")),
      checkpointFingerprint: challenge.checkpointFingerprint,
      rollbackEventId: references.rollbackEventId || null, rollbackEventDigest: references.rollbackEventDigest || null,
      finalizationReceiptId: references.finalizationReceiptId || null,
      finalizationReceiptDigest: references.finalizationReceiptDigest || null,
      externalReceiptId: references.externalReceiptId || null, externalReceiptDigest: references.externalReceiptDigest || null,
      referenceDigest: sha256(canonical(references)), occurredAt: references.occurredAt || challenge.createdAt || isoNow(clock) };
    const appended = await appendSignedEvent(ownerId, { ledgerKind: LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_LEDGER_KIND,
      ledgerIdForOwner: lifecycleDispositionRollbackContinuityLedgerId,
      eventKind: LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_EVENT_KIND,
      attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND, eventBase, requireSignature: true });
    const anchored = await appendLifecycleDispositionRollbackContinuityReceipt(ownerId, appended.event);
    return { event: appended.event, externalReceipt: anchored.event, idempotent: appended.idempotent === true || anchored.idempotent === true };
  }

  async function auditLifecycleDispositionCheckpointRollbackContinuity(ownerId) {
    assertOwner(ownerId);
    const [ledger, receiptLedger, rows, currentKey] = await Promise.all([
      readLifecycleDispositionRollbackContinuityLedger(ownerId), readCheckpointRecoveryLedger(ownerId),
      store.listEvidence(ownerId), getCurrentKeyBinding(ownerId)
    ]);
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND);
    const findings = [...ledger.findings];
    const receipts = new Map(receiptLedger.events.filter(event => event.eventType === "lifecycle_disposition_checkpoint_rollback_continuity_phase")
      .map(event => [event.continuityEventId, event]));
    const phaseByChallenge = new Map();
    let pendingCount = 0;
    for (const event of ledger.events) {
      const verification = await verifyAttestation(ownerId, event, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
        required: true, checkCurrent: false }).catch(() => ({ status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }));
      if (event.digest !== digestRecord(event) || !verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_EVENT_INVALID",
          eventId: event.id, reasonCode: verification?.reasonCode || null });
      if (!LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES.includes(event.phase)
        || event.phaseOrder !== LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES.indexOf(event.phase) + 1)
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASE_INVALID", eventId: event.id });
      const prior = phaseByChallenge.get(event.challengeId) || new Map();
      if (prior.has(event.phase)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASE_DUPLICATE",
        challengeId: event.challengeId, phase: event.phase });
      prior.set(event.phase, event); phaseByChallenge.set(event.challengeId, prior);
      const receipt = receipts.get(event.id);
      if (!receipt || receipt.continuityEventDigest !== event.digest || receipt.continuityOperationId !== event.operationId
        || receipt.continuityPhase !== event.phase || receipt.continuityHeadDigest !== event.digest
        || receipt.continuityLedgerCount !== event.sequence) {
        pendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_EXTERNAL_RECEIPT_MISSING",
          eventId: event.id, phase: event.phase });
      }
    }
    const cases = [];
    for (const challenge of challenges) {
      const phases = phaseByChallenge.get(challenge.id) || new Map();
      const missing = LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES.filter(phase => !phases.has(phase));
      const ordered = [...phases.values()].sort((a, b) => a.sequence - b.sequence);
      for (let index = 1; index < ordered.length; index++) {
        if (ordered[index].phaseOrder <= ordered[index - 1].phaseOrder) {
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_ORDER_INVALID",
            challengeId: challenge.id, previousPhase: ordered[index - 1].phase, phase: ordered[index].phase });
          break;
        }
      }
      if (missing.length && (phases.size || challenge.status === "completed"))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES_INCOMPLETE",
          challengeId: challenge.id, missingPhases: missing });
      cases.push({ challengeId: challenge.id, phaseCount: phases.size, missingPhases: missing,
        status: missing.length ? phases.size ? "recovery_required" : "history_unproven" : "verified_current",
        usableForCurrentDecision: missing.length === 0 && ordered.every(event => receipts.has(event.id)) });
    }
    const hard = findings.some(item => /_INVALID|_DUPLICATE|_CONFLICT/.test(item.code || ""));
    const historyUnproven = cases.some(item => item.status === "history_unproven");
    const incomplete = cases.some(item => item.status === "recovery_required");
    const status = hard ? "unhealthy" : pendingCount || incomplete ? "recovery_required" : historyUnproven ? "history_unproven"
      : ledger.count ? "verified_current" : "not_initialized";
    const recoveryReceiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    return { status, ownerId, ledgerId: ledger.ledgerId, eventCount: ledger.count, headDigest: ledger.headDigest,
      snapshotDigest: ledger.snapshotDigest, pendingCount, cases, currentKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
      recoveryReceiptCheckpoint, findings,
      usableForCurrentDecision: !hard && pendingCount === 0 && !incomplete && !historyUnproven
        && (ledger.count === 0 || cases.every(item => item.usableForCurrentDecision))
        && (!receiptLedger.findings.length)
        && (!recoveryReceiptCheckpoint.enabled || recoveryReceiptCheckpoint.usableForCurrentDecision === true),
      readOnly: true, mutationAllowed: false };
  }

  async function revalidateLifecycleDispositionCheckpointRollbackRecovery(ownerId, challengeId = null, { generation = null } = {}) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND
      && (!challengeId || row.id === challengeId));
    if (challengeId && !challenges.length) throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_NOT_FOUND",
      "Rollback recovery challenge tidak ditemukan", 404);
    const results = [];
    for (const challenge of challenges) {
      const eventId = `${LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_KIND}-${sha256(canonical({ ownerId, challengeId: challenge.id,
        checkpointFingerprint: challenge.checkpointFingerprint, disposition: challenge.disposition, reason: challenge.reason })).slice(0, 32)}`;
      const event = await store.getEvidence(ownerId, eventId);
      const finalizationId = `${LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_KIND}-${sha256(canonical({ ownerId, challengeId: challenge.id,
        checkpointFingerprint: challenge.checkpointFingerprint, disposition: challenge.disposition, reason: challenge.reason })).slice(0, 32)}`;
      const finalization = await store.getEvidence(ownerId, finalizationId);
      if (!event || !finalization || event.digest !== digestRecord(event) || finalization.digest !== digestRecord(finalization)
        || finalization.rollbackEventDigest !== event.digest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_EVIDENCE_INCOMPLETE",
          "Revalidasi membutuhkan rollback event dan finalization receipt yang valid", 409, { challengeId: challenge.id });
      let receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
      if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true
        && !["rollback_suspected", "unhealthy", "policy_drift", "invalid"].includes(receiptCheckpoint.status)) {
        try { await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, `lifecycle-disposition-rollback-revalidation-preflight:${challenge.id}`); }
        catch { /* The subsequent idempotent receipt append may still reconcile an already-persisted revalidation. */ }
        receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
      }
      const continuity = await auditLifecycleDispositionCheckpointRollbackContinuity(ownerId);
      const phases = continuity.cases.find(item => item.challengeId === challenge.id);
      if (!phases || phases.missingPhases.length)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_INCOMPLETE",
          "Revalidasi diblokir sampai semua fase kontinuitas dan external receipt tersedia", 409,
          { challengeId: challenge.id, missingPhases: phases?.missingPhases || LIFECYCLE_DISPOSITION_ROLLBACK_CONTINUITY_PHASES });
      const [current, keyBinding] = await Promise.all([inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId),
        getCurrentKeyBinding(ownerId)]);
      const revalidationCheckpointFingerprint = lifecycleDispositionRollbackFingerprint(current.checkpoint, current.inspection, {});
      const keyCutoffDetected = Boolean(challenge.keyCutoffDetected || finalization.keyCutoffDetected
        || (finalization.keyLifecycleBindingDigest || null) !== (keyBinding?.bindingDigest || null));
      const usable = current.status === "current" && current.checkpoint.usableForCurrentDecision === true
        && current.checkpoint.historyNotProven !== true && current.checkpoint.policyDrift !== true
        && !keyCutoffDetected && continuity.usableForCurrentDecision === true
        && receiptCheckpoint.usableForCurrentDecision === true;
      const status = usable ? "revalidated_current" : current.status === "rollback_suspected" ? "rollback_unresolved"
        : keyCutoffDetected ? "key_cutoff_stale" : "revalidation_not_current";
      const generationKey = typeof generation === "string" && generation.trim() ? generation.trim().slice(0, 200) : null;
      const unsigned = { id: `${LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KIND}-${sha256(canonical({ ownerId, challengeId: challenge.id,
        continuityDigest: continuity.snapshotDigest, checkpointFingerprint: revalidationCheckpointFingerprint,
        keyLifecycleBindingDigest: keyBinding?.bindingDigest || null, generation: generationKey })).slice(0, 32)}`,
        ownerId, kind: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KIND, schemaVersion: 1,
        generation: generationKey,
        operationId: `lifecycle-disposition-rollback-revalidation:${challenge.id}:${continuity.snapshotDigest}:${revalidationCheckpointFingerprint}${generationKey ? `:${sha256(generationKey).slice(0, 16)}` : ""}`,
        challengeId: challenge.id, challengeDigest: challenge.preparedChallengeDigest || challenge.digest,
        rollbackEventId: event.id, rollbackEventDigest: event.digest, finalizationReceiptId: finalization.id,
        finalizationReceiptDigest: finalization.digest, checkpointFingerprint: revalidationCheckpointFingerprint,
        observedCompositeCheckpointFingerprint: current.checkpointFingerprint, observedCheckpointStatus: current.status, observedAnchorDigest: current.checkpoint.anchorDigest || null,
        observedAnchorSequence: current.checkpoint.anchorSequence ?? null, observedSourceDigest: current.checkpoint.sourceDigest || null,
        observedSourceCount: current.checkpoint.sourceCount ?? null, continuityLedgerDigest: continuity.snapshotDigest,
        continuityLedgerHeadDigest: continuity.headDigest || null, continuityLedgerCount: continuity.eventCount,
        recoveryReceiptCheckpointRequired: Boolean(receiptCheckpoint.enabled || receiptCheckpoint.required),
        observedRecoveryReceiptCheckpointStatus: receiptCheckpoint.status || "unavailable",
        keyLifecycleBindingDigest: keyBinding?.bindingDigest || null, keyCutoffDetected, status,
        usableForCurrentDecision: usable, findings: [...current.findings, ...(continuity.findings || []),
          ...(keyCutoffDetected ? [{ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KEY_CUTOFF" }] : [])],
        createdAt: isoNow(clock), externalAnchorMutationPerformed: false };
      const existing = await store.getEvidence(ownerId, unsigned.id);
      if (!existing && receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_CHECKPOINT_NOT_CURRENT",
          "Revalidation baru diblokir karena external recovery-receipt checkpoint belum current", 409,
          { status: receiptCheckpoint.status || "unavailable" });
      let attestationRecord = existing;
      if (existing) {
        if (existing.digest !== digestRecord(existing) || existing.operationId !== unsigned.operationId
          || existing.continuityLedgerDigest !== continuity.snapshotDigest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_CONFLICT",
            "Revalidation attestation tersimpan memiliki binding berbeda", 409);
      } else {
        const attestation = await createAttestation(ownerId, unsigned, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
          keyLifecycleBinding: keyBinding, required: true, attestationIdSuffix: unsigned.operationId });
        const signed = { ...unsigned, attestation: attestation || null };
        attestationRecord = { ...signed, digest: digestRecord(signed) };
        try { await store.putEvidence(ownerId, attestationRecord, { overwrite: false }); }
        catch {
          const concurrent = await store.getEvidence(ownerId, unsigned.id);
          if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.operationId !== unsigned.operationId)
            throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_WRITE_FAILED",
              "Revalidation attestation gagal disimpan secara konsisten", 409);
          attestationRecord = concurrent;
        }
      }
      const verified = await verifyAttestation(ownerId, attestationRecord, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
        required: true, checkCurrent: false });
      if (!verified?.historicallyValid || verified.status === "unhealthy")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_ATTESTATION_INVALID",
          "Signature revalidation attestation tidak valid", 409);
      const receiptOperationId = `lifecycle-disposition-rollback-revalidation-anchored:${attestationRecord.id}:${attestationRecord.digest}`;
      const receiptBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(receiptOperationId).slice(0, 24)}`,
        operationId: receiptOperationId, eventType: "lifecycle_disposition_checkpoint_rollback_revalidation_attested",
        checkpointName: "lifecycle_disposition", challengeId: challenge.id, challengeDigest: attestationRecord.challengeDigest,
        revalidationAttestationId: attestationRecord.id, revalidationAttestationDigest: attestationRecord.digest,
        rollbackEventId: event.id, rollbackEventDigest: event.digest, finalizationReceiptId: finalization.id,
        finalizationReceiptDigest: finalization.digest, checkpointFingerprint: attestationRecord.checkpointFingerprint,
        continuityLedgerDigest: attestationRecord.continuityLedgerDigest, continuityLedgerHeadDigest: attestationRecord.continuityLedgerHeadDigest,
        continuityLedgerCount: attestationRecord.continuityLedgerCount, status: attestationRecord.status,
        keyLifecycleBindingDigest: attestationRecord.keyLifecycleBindingDigest, keyCutoffDetected: attestationRecord.keyCutoffDetected,
        usableForCurrentDecision: attestationRecord.usableForCurrentDecision, occurredAt: attestationRecord.createdAt };
      const anchored = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase: receiptBase, requireSignature: true });
      const receiptAfter = await getRecoveryReceiptCheckpointState(ownerId);
      if (receiptAfter.enabled && receiptAfter.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_ANCHOR_PENDING",
          "Revalidation tersimpan tetapi external recovery-receipt anchor belum current", 409,
          { status: receiptAfter.status || "unavailable", attestationId: attestationRecord.id });
      results.push({ challengeId: challenge.id, status: attestationRecord.status, attestation: attestationRecord,
        externalReceipt: anchored.event, externalReceiptId: anchored.event.id, checkpoint: receiptAfter,
        keyCutoffDetected, usableForCurrentDecision: attestationRecord.usableForCurrentDecision === true });
    }
    return { status: results.every(item => item.usableForCurrentDecision) ? "revalidated_current"
      : results.length ? "revalidation_not_current" : "not_initialized", ownerId, results,
      usableForCurrentDecision: results.length > 0 && results.every(item => item.usableForCurrentDecision),
      readOnly: false, mutationAllowed: false, externalAnchorMutationPerformed: false };
  }

  function rollbackRevalidationLifecycleOperationIds(challengeId) {
    return {
      intent: `lifecycle-disposition-rollback-revalidation-lifecycle-intent:${challengeId}`,
      applied: `lifecycle-disposition-rollback-revalidation-lifecycle-applied:${challengeId}`,
      finalized: `lifecycle-disposition-rollback-revalidation-lifecycle-finalized:${challengeId}`
    };
  }

  async function getRollbackRevalidationLifecycleSnapshot(ownerId) {
    assertOwner(ownerId);
    const ledger = await readCheckpointRecoveryLedger(ownerId);
    const events = ledger.events.filter(event => LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_EVENT_TYPES.has(event.eventType));
    const snapshot = { schemaVersion: 1, domain: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN,
      events: clean(events) };
    return { status: ledger.status === "unhealthy" ? "unhealthy" : events.length ? "healthy" : "not_initialized",
      ownerId, snapshot, digest: sha256(canonical(snapshot)), count: events.length, findings: ledger.findings,
      historyNotProven: false, readOnly: true, mutationAllowed: false };
  }

  async function prepareLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId, { action, attestationId, reason } = {}) {
    assertOwner(ownerId);
    if (!new Set(["renew", "revoke"]).has(action) || typeof attestationId !== "string" || !attestationId.trim()
      || typeof reason !== "string" || reason.trim() !== reason || reason.length < 12 || reason.length > 240
      || /[\u0000-\u001f\u007f]/.test(reason))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_INPUT_INVALID",
        "Action renew/revoke, attestationId, dan alasan 12–240 karakter wajib diberikan", 400);
    const rows = await store.listEvidence(ownerId);
    const target = rows.find(row => row?.ownerId === ownerId && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KIND && row.id === attestationId);
    if (!target || target.digest !== digestRecord(target))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_TARGET_INVALID",
        "Revalidation attestation target tidak ditemukan atau digest-nya tidak valid", 409);
    const receiptLedger = await readCheckpointRecoveryLedger(ownerId);
    const targetReceipt = receiptLedger.events.find(item => item.eventType === "lifecycle_disposition_checkpoint_rollback_revalidation_attested"
      && item.revalidationAttestationId === target.id && item.revalidationAttestationDigest === target.digest);
    const targetVerification = await verifyAttestation(ownerId, target, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
      required: true, checkCurrent: false }).catch(() => ({ historicallyValid: false, status: "unhealthy" }));
    if (!targetReceipt || !targetVerification?.historicallyValid || targetVerification.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_TARGET_UNANCHORED",
        "Target revalidation attestation harus valid secara historis dan sudah di-anchor", 409);
    const pendingLifecycle = (await store.listEvidence(ownerId)).find(row => row?.ownerId === ownerId
      && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHALLENGE_KIND
      && row.targetAttestationId === target.id && row.status === "prepared" && Date.parse(row.expiresAt) > Date.parse(String(clock())));
    if (pendingLifecycle) throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHALLENGE_PENDING",
      "Target sudah memiliki lifecycle challenge yang belum diselesaikan", 409, { challengeId: pendingLifecycle.id });
    const priorLifecycle = receiptLedger.events.filter(item => item.eventType === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_FINALIZATION_EVENT_TYPE
      && item.targetAttestationId === target.id).sort((a, b) => a.sequence - b.sequence).at(-1);
    if (priorLifecycle?.action === "revoke")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ALREADY_REVOKED",
        "Attestation yang sudah dicabut tidak dapat diperpanjang atau dicabut kembali", 409);
    if (priorLifecycle?.action === "renew")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ALREADY_SUPERSEDED",
        "Attestation telah digantikan oleh renewal; targetkan attestation pengganti", 409,
        { replacementAttestationId: priorLifecycle.replacementAttestationId || null });
    const currentAudit = await auditLifecycleDispositionCheckpointRollbackRecovery(ownerId);
    const latest = currentAudit.latestRevalidations?.find(item => item.challengeId === target.challengeId);
    if (!latest || latest.attestationId !== target.id || latest.current !== true || latest.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_TARGET_NOT_CURRENT",
        "Lifecycle renewal/revocation hanya dapat menargetkan revalidation attestation terkini", 409,
        { auditStatus: currentAudit.status, latestAttestationId: latest?.attestationId || null });
    const current = await inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId);
    const continuity = await auditLifecycleDispositionCheckpointRollbackContinuity(ownerId);
    const lifecycleCheckpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    if (lifecycleCheckpoint.enabled && lifecycleCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_NOT_CURRENT",
        "Renewal/revocation memerlukan independent revalidation lifecycle checkpoint yang current", 409,
        { status: lifecycleCheckpoint.status || "unavailable", findings: lifecycleCheckpoint.findings || [] });
    if (current.status !== "current" || continuity.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_SOURCE_NOT_CURRENT",
        "Lifecycle revalidation memerlukan external anchor dan continuity ledger yang current", 409,
        { checkpointStatus: current.status, continuityStatus: continuity.status });
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const now = isoNow(clock);
    const id = `${LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHALLENGE_KIND}-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHALLENGE_KIND,
      schemaVersion: 1, status: "prepared", action, reason, targetAttestationId: target.id,
      targetAttestationDigest: target.digest, rollbackChallengeId: target.challengeId,
      checkpointFingerprint: current.checkpointFingerprint, continuityLedgerDigest: continuity.snapshotDigest,
      keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      recoveryReceiptCheckpointAnchorDigest: current.recoveryReceiptCheckpoint.anchorDigest || null,
      recoveryReceiptCheckpointAnchorSequence: current.recoveryReceiptCheckpoint.anchorSequence ?? null,
      targetReceiptSequence: targetReceipt.sequence, createdAt: now,
      expiresAt: new Date(Date.parse(now) + 10 * 60_000).toISOString(),
      confirmationPhrase: `${action.toUpperCase()} ROLLBACK REVALIDATION ATTESTATION ${sha256(canonical({ ownerId, id, target: target.id })).slice(0, 12)}` };
    const challengeDigest = digestRecord(unsigned);
    const challenge = { ...unsigned, challengeDigest, digest: digestRecord({ ...unsigned, challengeDigest }) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { status: "prepared", challengeId: id, action, targetAttestationId: target.id,
      targetAttestationDigest: target.digest, expiresAt: challenge.expiresAt, confirmation: challenge.confirmationPhrase,
      checkpointFingerprint: challenge.checkpointFingerprint, continuityLedgerDigest: challenge.continuityLedgerDigest,
      readOnly: false, mutationAllowed: false };
  }

  async function applyLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId, challengeId, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHALLENGE_KIND
      || challenge.digest !== digestRecord(challenge) || !["renew", "revoke"].includes(challenge.action)
      || confirmation !== challenge.confirmationPhrase || !["prepared", "completed"].includes(challenge.status))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHALLENGE_INVALID",
        "Lifecycle challenge tidak valid atau konfirmasinya tidak cocok", 409);
    const { intent: intentOperationId, applied: appliedOperationId, finalized: finalizationOperationId } = rollbackRevalidationLifecycleOperationIds(challenge.id);
    let ledger = await readCheckpointRecoveryLedger(ownerId);
    let intent = ledger.events.find(item => item.operationId === intentOperationId);
    let applied = ledger.events.find(item => item.operationId === appliedOperationId);
    let finalized = ledger.events.find(item => item.operationId === finalizationOperationId);
    if (!intent) {
      if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt))
        || Date.parse(challenge.expiresAt) <= Date.parse(String(clock())))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHALLENGE_EXPIRED",
          "Challenge kedaluwarsa sebelum intent lifecycle tersimpan", 409);
      const [current, continuity, keyBinding, rows] = await Promise.all([inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId),
        auditLifecycleDispositionCheckpointRollbackContinuity(ownerId), getCurrentKeyBinding(ownerId), store.listEvidence(ownerId)]);
      const target = rows.find(row => row?.id === challenge.targetAttestationId && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KIND);
      if (!target || target.digest !== challenge.targetAttestationDigest || current.checkpointFingerprint !== challenge.checkpointFingerprint
        || continuity.snapshotDigest !== challenge.continuityLedgerDigest
        || (keyBinding?.bindingDigest || null) !== (challenge.keyLifecycleBindingDigest || null))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_SNAPSHOT_CHANGED",
          "Checkpoint, continuity ledger, target attestation, atau signing-key lifecycle berubah sejak challenge dibuat", 409);
      const operationBase = sha256(canonical({ ownerId, challengeId: challenge.id, action: challenge.action,
        targetAttestationId: challenge.targetAttestationId, targetAttestationDigest: challenge.targetAttestationDigest }));
      const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(intentOperationId).slice(0, 24)}`,
        operationId: intentOperationId, eventType: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_INTENT_EVENT_TYPE,
        lifecycleOperationId: operationBase, challengeId: challenge.id, challengeDigest: challenge.challengeDigest || challenge.digest,
        action: challenge.action, targetAttestationId: challenge.targetAttestationId,
        targetAttestationDigest: challenge.targetAttestationDigest, rollbackChallengeId: challenge.rollbackChallengeId,
        checkpointFingerprint: challenge.checkpointFingerprint, continuityLedgerDigest: challenge.continuityLedgerDigest,
        preparedKeyLifecycleBindingDigest: challenge.keyLifecycleBindingDigest,
        reasonDigest: sha256(challenge.reason), createdAt: challenge.createdAt };
      intent = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true })).event;
    } else {
      if (intent.challengeId !== challenge.id || intent.challengeDigest !== (challenge.challengeDigest || challenge.digest)
        || intent.action !== challenge.action || intent.targetAttestationId !== challenge.targetAttestationId
        || intent.targetAttestationDigest !== challenge.targetAttestationDigest
        || intent.checkpointFingerprint !== challenge.checkpointFingerprint
        || intent.continuityLedgerDigest !== challenge.continuityLedgerDigest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_INTENT_CONFLICT",
          "Lifecycle recovery intent tersimpan dengan binding berbeda", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, intentOperationId);
      await advanceRollbackRevalidationLifecycleCheckpointAfterAppend(ownerId, intentOperationId);
    }
    // Renewal creates a fresh, independently signed replacement attestation. The generation key makes retries idempotent.
    let replacement = null;
    if (challenge.action === "renew") {
      const renewal = await revalidateLifecycleDispositionCheckpointRollbackRecovery(ownerId, challenge.rollbackChallengeId,
        { generation: challenge.id });
      replacement = renewal.results[0]?.attestation || null;
      if (!replacement)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RENEWAL_NOT_RECORDED",
          "Renewal tidak menghasilkan revalidation receipt yang dapat diverifikasi", 409,
          { status: renewal.status, resultCount: renewal.results.length });
    }
    ledger = await readCheckpointRecoveryLedger(ownerId);
    applied = ledger.events.find(item => item.operationId === appliedOperationId);
    const current = await inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId);
    const continuity = await auditLifecycleDispositionCheckpointRollbackContinuity(ownerId);
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const keyCutoffDetected = (challenge.keyLifecycleBindingDigest || null) !== (keyBinding?.bindingDigest || null);
    const appliedBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(appliedOperationId).slice(0, 24)}`,
      operationId: appliedOperationId, eventType: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_APPLIED_EVENT_TYPE,
      lifecycleOperationId: intent.lifecycleOperationId, challengeId: challenge.id, challengeDigest: challenge.challengeDigest || challenge.digest,
      action: challenge.action, targetAttestationId: challenge.targetAttestationId,
      targetAttestationDigest: challenge.targetAttestationDigest, replacementAttestationId: replacement?.id || null,
      replacementAttestationDigest: replacement?.digest || null, checkpointFingerprint: current.checkpointFingerprint,
      continuityLedgerDigest: continuity.snapshotDigest, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      keyCutoffDetected, appliedAt: isoNow(clock) };
    if (!applied) applied = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase: appliedBase, requireSignature: true })).event;
    else {
      if (applied.challengeId !== challenge.id || applied.challengeDigest !== (challenge.challengeDigest || challenge.digest)
        || applied.action !== challenge.action || applied.targetAttestationId !== challenge.targetAttestationId
        || applied.targetAttestationDigest !== challenge.targetAttestationDigest
        || (challenge.action === "renew" && (!replacement || applied.replacementAttestationId !== replacement.id
          || applied.replacementAttestationDigest !== replacement.digest)))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_APPLIED_CONFLICT",
          "Lifecycle applied receipt tersimpan dengan binding berbeda", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, appliedOperationId);
      await advanceRollbackRevalidationLifecycleCheckpointAfterAppend(ownerId, appliedOperationId);
    }
    ledger = await readCheckpointRecoveryLedger(ownerId);
    finalized = ledger.events.find(item => item.operationId === finalizationOperationId);
    const finalizedBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(finalizationOperationId).slice(0, 24)}`,
      operationId: finalizationOperationId, eventType: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_FINALIZATION_EVENT_TYPE,
      lifecycleOperationId: intent.lifecycleOperationId, challengeId: challenge.id, challengeDigest: challenge.challengeDigest || challenge.digest,
      action: challenge.action, targetAttestationId: challenge.targetAttestationId,
      targetAttestationDigest: challenge.targetAttestationDigest, appliedEventId: applied.id, appliedEventDigest: applied.digest,
      replacementAttestationId: applied.replacementAttestationId || null,
      replacementAttestationDigest: applied.replacementAttestationDigest || null,
      checkpointFingerprint: applied.checkpointFingerprint, continuityLedgerDigest: applied.continuityLedgerDigest,
      keyLifecycleBindingDigest: applied.keyLifecycleBindingDigest || null, keyCutoffDetected: Boolean(applied.keyCutoffDetected),
      finalizedAt: isoNow(clock) };
    if (!finalized) finalized = (await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase: finalizedBase, requireSignature: true })).event;
    else {
      if (finalized.challengeId !== challenge.id || finalized.challengeDigest !== (challenge.challengeDigest || challenge.digest)
        || finalized.action !== challenge.action || finalized.targetAttestationId !== challenge.targetAttestationId
        || finalized.targetAttestationDigest !== challenge.targetAttestationDigest
        || finalized.appliedEventDigest !== applied.digest || finalized.replacementAttestationDigest !== (applied.replacementAttestationDigest || null))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FINALIZATION_CONFLICT",
          "Lifecycle finalization receipt tersimpan dengan binding berbeda", 409);
      await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, finalizationOperationId);
      await advanceRollbackRevalidationLifecycleCheckpointAfterAppend(ownerId, finalizationOperationId);
    }
    const checkpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_PENDING",
        "Lifecycle event tersimpan tetapi recovery-receipt checkpoint belum current", 409,
        { challengeId: challenge.id, status: checkpoint.status || "unavailable" });
    const revalidationLifecycleCheckpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    if (revalidationLifecycleCheckpoint.enabled && revalidationLifecycleCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_PENDING",
        "Lifecycle event tersimpan tetapi independent revalidation lifecycle checkpoint belum current", 409,
        { challengeId: challenge.id, status: revalidationLifecycleCheckpoint.status || "unavailable" });
    const currentKey = await getCurrentKeyBinding(ownerId);
    const completedUnsigned = { ...clean(challenge), status: "completed", intentEventId: intent.id, intentEventDigest: intent.digest,
      appliedEventId: applied.id, appliedEventDigest: applied.digest, finalizationEventId: finalized.id,
      finalizationEventDigest: finalized.digest, replacementAttestationId: applied.replacementAttestationId || null,
      replacementAttestationDigest: applied.replacementAttestationDigest || null,
      keyCutoffDetected: Boolean(applied.keyCutoffDetected || (challenge.keyLifecycleBindingDigest || null) !== (currentKey?.bindingDigest || null)),
      finalizedKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
      finalizedRecoveryReceiptCheckpointAnchorDigest: checkpoint.anchorDigest || null,
      finalizedRecoveryReceiptCheckpointAnchorSequence: checkpoint.anchorSequence ?? null,
      finalizedRevalidationLifecycleCheckpointAnchorDigest: revalidationLifecycleCheckpoint.anchorDigest || null,
      finalizedRevalidationLifecycleCheckpointAnchorSequence: revalidationLifecycleCheckpoint.anchorSequence ?? null,
      completedAt: isoNow(clock) };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    if (challenge.status !== "completed") {
      try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, challenge.id);
        if (!concurrent || concurrent.status !== "completed" || concurrent.finalizationEventDigest !== finalized.digest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FINALIZE_CONFLICT",
            "Lifecycle receipt tersimpan tetapi challenge gagal difinalisasi melalui CAS", 409);
      }
    }
    const lifecycleAudit = await auditLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId);
    return { status: "completed", action: challenge.action, challengeId: challenge.id, targetAttestationId: challenge.targetAttestationId,
      replacementAttestation: replacement, intentEvent: intent, lifecycleEvent: applied, finalizationReceipt: finalized,
      keyCutoffDetected: completed.keyCutoffDetected, checkpoint, revalidationLifecycleCheckpoint, lifecycleAudit,
      usableForCurrentDecision: challenge.action === "renew" && !completed.keyCutoffDetected && Boolean(replacement?.usableForCurrentDecision)
        && (!revalidationLifecycleCheckpoint.enabled || revalidationLifecycleCheckpoint.usableForCurrentDecision === true),
      readOnly: false, mutationAllowed: false };
  }

  async function auditLifecycleDispositionRollbackRevalidationAttestationLifecycleBase(ownerId) {
    assertOwner(ownerId);
    const [rows, ledger, currentKey, current, continuity, lifecycleCheckpoint] = await Promise.all([store.listEvidence(ownerId),
      readCheckpointRecoveryLedger(ownerId), getCurrentKeyBinding(ownerId), inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId),
      auditLifecycleDispositionCheckpointRollbackContinuity(ownerId), getRevalidationLifecycleCheckpointState(ownerId)]);
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHALLENGE_KIND);
    const lifecycleEvents = ledger.events.filter(event => [LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_INTENT_EVENT_TYPE,
      LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_APPLIED_EVENT_TYPE,
      LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_FINALIZATION_EVENT_TYPE].includes(event.eventType));
    const findings = [...ledger.findings, ...(continuity.findings || []), ...(lifecycleCheckpoint.findings || [])];
    if (lifecycleCheckpoint.enabled && lifecycleCheckpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_EXTERNAL_CHECKPOINT_NOT_CURRENT",
        status: lifecycleCheckpoint.status || "unavailable", anchorSequence: lifecycleCheckpoint.anchorSequence ?? null });
    const byChallenge = new Map();
    for (const event of lifecycleEvents) {
      const verification = await verifyAttestation(ownerId, event, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false }).catch(() => ({ historicallyValid: false, status: "unhealthy", reasonCode: "VERIFIER_FAILED" }));
      if (!verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_EVENT_INVALID", eventId: event.id,
          reasonCode: verification?.reasonCode || null });
      const phases = byChallenge.get(event.challengeId) || {};
      const key = event.eventType === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_INTENT_EVENT_TYPE ? "intent"
        : event.eventType === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_APPLIED_EVENT_TYPE ? "applied" : "finalized";
      if (phases[key]) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_PHASE_DUPLICATE",
        challengeId: event.challengeId, phase: key });
      phases[key] = event;
      byChallenge.set(event.challengeId, phases);
    }
    let pendingCount = 0, revokedCount = 0, supersededCount = 0, keyCutoffCount = 0;
    const cases = [];
    for (const challenge of challenges) {
      const unsigned = clean(challenge); delete unsigned.digest;
      if (challenge.digest !== digestRecord(unsigned)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHALLENGE_INVALID", challengeId: challenge.id });
      const phases = byChallenge.get(challenge.id) || {};
      const ordered = [phases.intent, phases.applied, phases.finalized].filter(Boolean);
      if (ordered.some((event, index) => index > 0 && ordered[index - 1].sequence >= event.sequence))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_ORDER_INVALID", challengeId: challenge.id });
      for (const event of ordered) {
        if (event.targetAttestationId !== challenge.targetAttestationId || event.targetAttestationDigest !== challenge.targetAttestationDigest
          || event.action !== challenge.action || event.challengeDigest !== (challenge.challengeDigest || challenge.digest))
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_BINDING_INVALID", challengeId: challenge.id, eventId: event.id });
      }
      if (ordered.length && (ordered.length !== 3 || challenge.status !== "completed"
        || challenge.intentEventDigest !== phases.intent?.digest || challenge.appliedEventDigest !== phases.applied?.digest
        || challenge.finalizationEventDigest !== phases.finalized?.digest
        || phases.finalized?.appliedEventDigest !== phases.applied?.digest)) {
        pendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FINALIZATION_PENDING", challengeId: challenge.id,
          presentPhases: Object.keys(phases) });
      }
      if (challenge.status === "completed" && ordered.length !== 3)
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_COMPLETED_WITHOUT_RECEIPTS", challengeId: challenge.id });
      const final = phases.finalized;
      if (final?.action === "renew") {
        const replacement = rows.find(row => row?.id === final.replacementAttestationId && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KIND);
        const replacementReceipt = ledger.events.find(item => item.eventType === "lifecycle_disposition_checkpoint_rollback_revalidation_attested"
          && item.revalidationAttestationId === final.replacementAttestationId && item.revalidationAttestationDigest === final.replacementAttestationDigest);
        if (!replacement || replacement.digest !== final.replacementAttestationDigest || !replacementReceipt
          || replacement.challengeId !== challenge.rollbackChallengeId || replacement.generation !== challenge.id)
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_REPLACEMENT_BINDING_INVALID",
            challengeId: challenge.id, replacementAttestationId: final.replacementAttestationId || null });
      }
      if (final?.action === "revoke" && (final.replacementAttestationId || final.replacementAttestationDigest))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_REVOCATION_REPLACEMENT_INVALID", challengeId: challenge.id });
      if (final?.action === "revoke") revokedCount++;
      if (final?.action === "renew") supersededCount++;
      if (final?.keyCutoffDetected || challenge.keyCutoffDetected) {
        keyCutoffCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_KEY_CUTOFF", challengeId: challenge.id });
      }
      cases.push({ challengeId: challenge.id, action: challenge.action, status: ordered.length === 3 && challenge.status === "completed"
        ? final.action === "revoke" ? "revoked" : "renewed" : ordered.length ? "recovery_required" : challenge.status,
        targetAttestationId: challenge.targetAttestationId, replacementAttestationId: final?.replacementAttestationId || null,
        eventCount: ordered.length, keyCutoffDetected: Boolean(final?.keyCutoffDetected || challenge.keyCutoffDetected),
        usableForCurrentDecision: final?.action === "renew" && !final.keyCutoffDetected && Boolean(final.replacementAttestationId) });
    }
    const latestByTarget = new Map();
    for (const event of lifecycleEvents.filter(item => item.eventType === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_FINALIZATION_EVENT_TYPE)) {
      const prior = latestByTarget.get(event.targetAttestationId);
      if (prior) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_TARGET_REPLAY_DUPLICATE",
        targetAttestationId: event.targetAttestationId, eventIds: [prior.id, event.id] });
      if (!prior || event.sequence > prior.sequence) latestByTarget.set(event.targetAttestationId, event);
    }
    const hard = findings.some(item => /_INVALID|_DUPLICATE|_CONFLICT|_ORDER_INVALID|WITHOUT_RECEIPTS/.test(item.code || ""));
    const status = hard ? "unhealthy" : pendingCount ? "recovery_required" : keyCutoffCount ? "stale"
      : lifecycleCheckpoint.enabled && lifecycleCheckpoint.usableForCurrentDecision !== true ? "checkpoint_not_current"
      : latestByTarget.size ? "verified_current" : "not_initialized";
    return { status, ownerId, challengeCount: challenges.length, eventCount: lifecycleEvents.length, pendingCount,
      revokedCount, supersededCount, keyCutoffCount, cases, lifecycleCheckpoint,
      independentLifecycleCheckpointCurrent: !lifecycleCheckpoint.enabled || lifecycleCheckpoint.usableForCurrentDecision === true, latestByTarget: [...latestByTarget.values()].map(event => ({
        targetAttestationId: event.targetAttestationId, targetAttestationDigest: event.targetAttestationDigest,
        action: event.action, replacementAttestationId: event.replacementAttestationId || null,
        replacementAttestationDigest: event.replacementAttestationDigest || null, sequence: event.sequence,
        checkpointFingerprint: event.checkpointFingerprint, continuityLedgerDigest: event.continuityLedgerDigest,
        keyLifecycleBindingDigest: event.keyLifecycleBindingDigest || null, keyCutoffDetected: Boolean(event.keyCutoffDetected),
        challengeId: event.challengeId })), findings,
      currentCheckpointFingerprint: current.checkpointFingerprint, currentContinuityLedgerDigest: continuity.snapshotDigest,
      currentKeyLifecycleBindingDigest: currentKey?.bindingDigest || null,
      usableForCurrentDecision: !hard && pendingCount === 0 && keyCutoffCount === 0
        && (!lifecycleCheckpoint.enabled || lifecycleCheckpoint.usableForCurrentDecision === true)
        && continuity.usableForCurrentDecision === true
        && (!current.checkpoint.enabled || current.checkpoint.usableForCurrentDecision === true)
        && (!current.recoveryReceiptCheckpoint.enabled || current.recoveryReceiptCheckpoint.usableForCurrentDecision === true),
      readOnly: true, mutationAllowed: false };
  }

  function revalidationLifecycleCheckpointFingerprint(state) {
    return sha256(canonical({ domain: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN,
      status: state?.status || "unavailable", snapshotDigest: state?.snapshotDigest || null,
      anchorDigest: state?.anchorDigest || null, anchorSequence: state?.anchorSequence ?? null,
      sourceDigest: state?.sourceDigest || null, sourceCount: state?.sourceCount ?? null,
      freshnessStatus: state?.freshnessStatus || null, historyNotProven: Boolean(state?.historyNotProven),
      policyDrift: Boolean(state?.policyDrift), findings: (state?.findings || []).map(item => item.code || "UNKNOWN").sort() }));
  }

  function revalidationLifecycleAuditDigest(audit) {
    return sha256(canonical({ status: audit?.status || "unavailable", challengeCount: audit?.challengeCount ?? null,
      eventCount: audit?.eventCount ?? null, pendingCount: audit?.pendingCount ?? null,
      revokedCount: audit?.revokedCount ?? null, supersededCount: audit?.supersededCount ?? null,
      keyCutoffCount: audit?.keyCutoffCount ?? null,
      findings: (audit?.findings || []).map(item => item.code || "UNKNOWN").sort(),
      latestByTarget: (audit?.latestByTarget || []).map(item => ({ targetAttestationId: item.targetAttestationId,
        targetAttestationDigest: item.targetAttestationDigest, action: item.action,
        replacementAttestationId: item.replacementAttestationId || null,
        replacementAttestationDigest: item.replacementAttestationDigest || null,
        keyCutoffDetected: Boolean(item.keyCutoffDetected), challengeId: item.challengeId })).sort((a, b) => String(a.targetAttestationId).localeCompare(String(b.targetAttestationId))) }));
  }

  function revalidationLifecycleDriftAuditDigest(audit) {
    return sha256(canonical({ status: audit?.status || "unavailable", pendingCount: audit?.pendingCount ?? null,
      unresolvedCount: audit?.unresolvedCount ?? null, invalidCount: audit?.invalidCount ?? null,
      anchoredCount: audit?.anchoredCount ?? null }));
  }

  function revalidationLifecycleFreshnessSupersessionAuditDigest(audit) {
    return sha256(canonical({ status: audit?.status || "unavailable", eventCount: audit?.eventCount ?? null,
      pendingCount: audit?.pendingCount ?? null, invalidCount: audit?.invalidCount ?? null,
      supersededAttestationIds: [...(audit?.supersededAttestationIds || [])].sort(),
      findings: (audit?.findings || []).map(item => item.code || "UNKNOWN").sort() }));
  }

  async function updateRevalidationLifecycleDriftEvidenceRecord(ownerId, record, patch) {
    const unsigned = { ...clean(record), ...clean(patch), updatedAt: isoNow(clock) };
    delete unsigned.digest;
    const updated = { ...unsigned, digest: digestRecord(unsigned) };
    try {
      await store.putEvidence(ownerId, updated, { expectedVersion: record?._storage?.version });
    } catch {
      const current = await store.getEvidence(ownerId, record.id);
      if (!current || current.evidenceDigest !== record.evidenceDigest)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_CAS_CONFLICT",
          "Drift evidence berubah secara bersamaan; rekonsiliasi ulang diperlukan", 409);
      return current;
    }
    return (await store.getEvidence(ownerId, updated.id)) || updated;
  }

  async function anchorRevalidationLifecycleDriftEvidenceRecord(ownerId, record) {
    const evidence = record.evidence;
    const operationId = `revalidation-lifecycle-drift:${evidence.evidenceFingerprint}`;
    const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`,
      operationId, eventType: REVALIDATION_LIFECYCLE_DRIFT_OBSERVED_EVENT_TYPE,
      driftEvidenceId: record.id, evidenceDigest: record.evidenceDigest,
      evidenceFingerprint: evidence.evidenceFingerprint, checkpointFingerprint: evidence.checkpointFingerprint,
      checkpointStatus: evidence.checkpointStatus, anchorDigest: evidence.anchorDigest || null,
      anchorSequence: evidence.anchorSequence ?? null, sourceDigest: evidence.sourceDigest || null,
      sourceCount: evidence.sourceCount ?? null, keyLifecycleBindingDigest: evidence.keyLifecycleBindingDigest || null,
      driftTypes: evidence.driftTypes, findings: evidence.findings, observedAt: evidence.firstObservedAt,
      occurredAt: evidence.firstObservedAt };
    const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true });
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_ANCHOR_PENDING",
        "Drift evidence tersimpan tetapi recovery-receipt checkpoint belum current", 409,
        { operationId, checkpointStatus: receiptCheckpoint.status || "unavailable" });
    return updateRevalidationLifecycleDriftEvidenceRecord(ownerId, record, { status: receiptCheckpoint.enabled ? "anchored" : "local_only",
      anchorEventId: appended.event.id, anchorEventDigest: appended.event.digest,
      anchoredAt: isoNow(clock), externalReceiptCheckpointAnchorDigest: receiptCheckpoint.anchorDigest || null,
      externalReceiptCheckpointAnchorSequence: receiptCheckpoint.anchorSequence ?? null,
      lastErrorCode: null });
  }

  async function captureRevalidationLifecycleDriftEvidence(ownerId, { checkpoint, rollbackStatus, activeRollback, externalAnchorDriftDetected = false, driftedAttestations = [], lifecycleAuditStatus = null } = {}) {
    assertOwner(ownerId);
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const checkpointFingerprint = revalidationLifecycleCheckpointFingerprint(checkpoint);
    const findings = [...(checkpoint?.findings || []), ...driftedAttestations].map(item => ({
      code: String(item?.code || "UNKNOWN").slice(0, 160), status: item?.status || null,
      checkpointStatus: item?.checkpointStatus || null, targetAttestationId: item?.targetAttestationId || null,
      reasonCode: item?.reasonCode || null })).sort((a, b) => canonical(a).localeCompare(canonical(b)));
    const driftTypes = [...new Set([...(checkpoint?.usableForCurrentDecision === true ? [] : ["revalidation_lifecycle_checkpoint"]),
      ...(activeRollback ? ["lifecycle_disposition_rollback"] : []),
      ...(externalAnchorDriftDetected ? ["external_anchor_drift"] : []),
      ...(driftedAttestations.length ? ["revalidation_evidence_drift"] : [])])].sort();
    const driftStateFingerprint = sha256(canonical({ domain: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN,
      checkpointFingerprint, rollbackStatus: rollbackStatus || null, activeRollback: Boolean(activeRollback),
      lifecycleAuditStatus: lifecycleAuditStatus || null, driftTypes, findings }));
    const [records, existingLedger] = await Promise.all([store.listEvidence(ownerId), readCheckpointRecoveryLedger(ownerId)]);
    const driftRecords = records.filter(row => row?.ownerId === ownerId && row.kind === REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_RECORD_KIND);
    let record = driftRecords.find(row => row.evidence?.driftStateFingerprint === driftStateFingerprint
      && !row.resolvedAt && !existingLedger.events.some(event => event.eventType === REVALIDATION_LIFECYCLE_DRIFT_RESOLVED_EVENT_TYPE
        && event.evidenceDigest === row.evidenceDigest)) || null;
    const incidentGeneration = driftRecords.filter(row => row.evidence?.driftStateFingerprint === driftStateFingerprint).length + 1;
    const evidenceFingerprint = record?.evidence?.evidenceFingerprint || sha256(canonical({ driftStateFingerprint, incidentGeneration }));
    if (!record) {
      const evidence = { schemaVersion: 1, domain: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN,
        evidenceFingerprint, driftStateFingerprint, incidentGeneration, checkpointFingerprint, checkpointStatus: checkpoint?.status || "unavailable",
        anchorDigest: checkpoint?.anchorDigest || null, anchorSequence: checkpoint?.anchorSequence ?? null,
        sourceDigest: checkpoint?.sourceDigest || null, sourceCount: checkpoint?.sourceCount ?? null,
        keyLifecycleBindingDigest: keyBinding?.bindingDigest || null, rollbackStatus: rollbackStatus || null,
        activeRollback: Boolean(activeRollback), lifecycleAuditStatus: lifecycleAuditStatus || null,
        driftTypes, findings, firstObservedAt: isoNow(clock) };
      const evidenceDigest = sha256(canonical(evidence));
      const unsigned = { id: `${REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_RECORD_KIND}-${sha256(`${ownerId}:${evidenceFingerprint}`).slice(0, 32)}`,
        ownerId, kind: REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_RECORD_KIND, schemaVersion: 1,
        evidence, evidenceDigest, status: "pending_anchor", anchorEventId: null, anchorEventDigest: null,
        resolvedAt: null, resolutionEventId: null, createdAt: evidence.firstObservedAt, updatedAt: evidence.firstObservedAt };
      const candidate = { ...unsigned, digest: digestRecord(unsigned) };
      try { await store.putEvidence(ownerId, candidate, { overwrite: false }); }
      catch {
        record = await store.getEvidence(ownerId, candidate.id);
        if (!record || record.evidenceDigest !== evidenceDigest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_CONFLICT",
            "Drift evidence fingerprint memiliki record yang berbeda", 409);
      }
      record ||= await store.getEvidence(ownerId, candidate.id);
    }
    if (record.digest !== digestRecord(record) || record.evidenceDigest !== sha256(canonical(record.evidence)))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_INVALID",
        "Digest drift evidence tidak valid", 409);
    try {
      if (record.status !== "anchored" || !(await getRecoveryReceiptCheckpointState(ownerId)).usableForCurrentDecision)
        record = await anchorRevalidationLifecycleDriftEvidenceRecord(ownerId, record);
    } catch (error) {
      const latest = await store.getEvidence(ownerId, record.id) || record;
      record = await updateRevalidationLifecycleDriftEvidenceRecord(ownerId, latest, { status: "pending_anchor",
        lastErrorCode: error?.code || error?.name || "DRIFT_EVIDENCE_ANCHOR_FAILED" });
    }
    return { record, audit: await auditRevalidationLifecycleDriftEvidence(ownerId), readOnly: false,
      mutationAllowed: false, externalAnchorMutationPerformed: false };
  }

  async function auditRevalidationLifecycleDriftEvidence(ownerId) {
    assertOwner(ownerId);
    const [rows, ledger, receiptCheckpoint] = await Promise.all([store.listEvidence(ownerId),
      readCheckpointRecoveryLedger(ownerId), getRecoveryReceiptCheckpointState(ownerId)]);
    const records = rows.filter(row => row?.ownerId === ownerId && row.kind === REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_RECORD_KIND);
    const findings = [...ledger.findings];
    let pendingCount = 0, unresolvedCount = 0, invalidCount = 0, anchoredCount = 0, resolvedCount = 0;
    for (const record of records) {
      if (record.digest !== digestRecord(record) || record.evidenceDigest !== sha256(canonical(record.evidence || {}))
        || record.evidence?.schemaVersion !== 1 || !record.evidence?.evidenceFingerprint) {
        invalidCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_INVALID", evidenceId: record.id });
        continue;
      }
      const observedOperationId = `revalidation-lifecycle-drift:${record.evidence.evidenceFingerprint}`;
      const observedEvents = ledger.events.filter(event => event.operationId === observedOperationId);
      if (observedEvents.length > 1) {
        invalidCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_REPLAY", evidenceId: record.id,
          eventIds: observedEvents.map(event => event.id) });
        continue;
      }
      const observedEvent = observedEvents[0] || null;
      if (!observedEvent) {
        pendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_NOT_ANCHORED", evidenceId: record.id,
          status: record.status });
      } else {
        const verification = await verifyAttestation(ownerId, observedEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
          required: true, checkCurrent: false }).catch(() => ({ historicallyValid: false, status: "unhealthy", reasonCode: "VERIFIER_FAILED" }));
        if (!verification?.historicallyValid || verification.status === "unhealthy"
          || observedEvent.evidenceDigest !== record.evidenceDigest || observedEvent.evidenceFingerprint !== record.evidence.evidenceFingerprint
          || record.anchorEventId && record.anchorEventId !== observedEvent.id
          || record.anchorEventDigest && record.anchorEventDigest !== observedEvent.digest) {
          invalidCount++;
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVENT_INVALID", evidenceId: record.id,
            eventId: observedEvent.id, reasonCode: verification?.reasonCode || null });
          continue;
        }
        anchoredCount++;
        if (record.status === "pending_anchor" || record.status === "local_only") {
          pendingCount++;
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RECORD_FINALIZATION_PENDING",
            evidenceId: record.id, status: record.status, eventId: observedEvent.id });
        }
      }
      const resolutions = ledger.events.filter(event => event.eventType === REVALIDATION_LIFECYCLE_DRIFT_RESOLVED_EVENT_TYPE
        && event.evidenceDigest === record.evidenceDigest);
      if (resolutions.length > 1) {
        invalidCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_REPLAY", evidenceId: record.id,
          eventIds: resolutions.map(event => event.id) });
        continue;
      }
      let resolved = false;
      if (resolutions.length === 1) {
        const resolution = resolutions[0];
        const verification = await verifyAttestation(ownerId, resolution, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
          required: true, checkCurrent: false }).catch(() => ({ historicallyValid: false, status: "unhealthy", reasonCode: "VERIFIER_FAILED" }));
        if (!verification?.historicallyValid || verification.status === "unhealthy"
          || resolution.priorEvidenceFingerprint !== record.evidence.evidenceFingerprint
          || resolution.evidenceDigest !== record.evidenceDigest) {
          invalidCount++;
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_INVALID", evidenceId: record.id,
            eventId: resolution.id, reasonCode: verification?.reasonCode || null });
          continue;
        }
        const continuityReceipts = ledger.events.filter(event => event.eventType === REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_EVENT_TYPE
          && event.resolutionEventId === resolution.id);
        if (continuityReceipts.length > 1) {
          invalidCount++;
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_REPLAY",
            evidenceId: record.id, eventIds: continuityReceipts.map(event => event.id) });
          continue;
        }
        const continuityReceipt = continuityReceipts[0] || null;
        if (!continuityReceipt) {
          pendingCount++;
          findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_PENDING",
            evidenceId: record.id, resolutionEventId: resolution.id });
        } else {
          const continuityVerification = await verifyAttestation(ownerId, continuityReceipt, {
            attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, required: true, checkCurrent: false
          }).catch(() => ({ historicallyValid: false, status: "unhealthy", reasonCode: "VERIFIER_FAILED" }));
          const receiptCoversContinuity = receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision === true
            && Number.isSafeInteger(continuityReceipt.recoveryReceiptCheckpointSourceCountAtIssue)
            && receiptCheckpoint.sourceCount >= continuityReceipt.recoveryReceiptCheckpointSourceCountAtIssue
            && Number.isSafeInteger(continuityReceipt.recoveryReceiptCheckpointPriorAnchorSequence)
            && receiptCheckpoint.anchorSequence >= continuityReceipt.recoveryReceiptCheckpointPriorAnchorSequence + 1;
          if (!continuityVerification?.historicallyValid || continuityVerification.status === "unhealthy"
            || continuityReceipt.resolutionEventDigest !== resolution.digest
            || continuityReceipt.evidenceDigest !== record.evidenceDigest
            || continuityReceipt.driftEvidenceId !== record.id
            || continuityReceipt.priorEvidenceFingerprint !== record.evidence.evidenceFingerprint
            || continuityReceipt.sequence <= resolution.sequence
            || continuityReceipt.resolutionSourceCount !== resolution.sequence
            || continuityReceipt.recoveryReceiptCheckpointSourceCountAtIssue !== continuityReceipt.sequence
            || continuityReceipt.recoveryReceiptCheckpointPriorAnchorDigest !== continuityReceipt.resolutionAnchorDigest
            || continuityReceipt.recoveryReceiptCheckpointPriorAnchorSequence !== continuityReceipt.resolutionAnchorSequence) {
            invalidCount++;
            findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_INVALID",
              evidenceId: record.id, eventId: continuityReceipt.id, reasonCode: continuityVerification?.reasonCode || null });
            continue;
          }
          if (!receiptCoversContinuity) {
            pendingCount++;
            findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_NOT_ANCHORED",
              evidenceId: record.id, eventId: continuityReceipt.id, checkpointStatus: receiptCheckpoint.status || "unavailable" });
          } else if ((record.resolvedAt && record.resolutionEventId && record.resolutionEventId !== resolution.id)
            || (record.resolutionContinuityEventId && record.resolutionContinuityEventId !== continuityReceipt.id)
            || (record.resolutionContinuityEventDigest && record.resolutionContinuityEventDigest !== continuityReceipt.digest)) {
            invalidCount++;
            findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_BINDING_INVALID", evidenceId: record.id });
            continue;
          } else {
            resolved = true;
            resolvedCount++;
          }
        }
      }
      if (!resolved) {
        unresolvedCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_UNRESOLVED", evidenceId: record.id,
          checkpointFingerprint: record.evidence.checkpointFingerprint });
      } else if (record.resolvedAt && record.resolutionEventId && record.resolutionEventId !== resolutions[0]?.id) {
        invalidCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_BINDING_INVALID", evidenceId: record.id });
      }
    }
    if (records.length && !receiptCheckpoint.enabled)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RECEIPT_CHECKPOINT_REQUIRED" });
    if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RECEIPT_CHECKPOINT_NOT_CURRENT",
        status: receiptCheckpoint.status || "unavailable" });
    if (ledger.status === "unhealthy") invalidCount++;
    const status = invalidCount ? "unhealthy" : pendingCount || unresolvedCount ? "recovery_required"
      : receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true ? "checkpoint_not_current"
        : records.length ? "verified_current" : "not_initialized";
    return { status, ownerId, recordCount: records.length, pendingCount, unresolvedCount, invalidCount,
      anchoredCount, resolvedCount, receiptCheckpoint, findings,
      usableForCurrentDecision: invalidCount === 0 && pendingCount === 0 && unresolvedCount === 0
        && (!records.length || receiptCheckpoint.enabled === true)
        && (!receiptCheckpoint.enabled || receiptCheckpoint.usableForCurrentDecision === true),
      readOnly: true, mutationAllowed: false };
  }

  async function resolveRevalidationLifecycleDriftEvidenceIfSafe(ownerId) {
    const [checkpoint, baseAudit, rollbackAudit, keyBinding, rows] = await Promise.all([
      getRevalidationLifecycleCheckpointState(ownerId), auditLifecycleDispositionRollbackRevalidationAttestationLifecycleBase(ownerId),
      auditLifecycleDispositionCheckpointRollbackRecovery(ownerId), getCurrentKeyBinding(ownerId), store.listEvidence(ownerId)]);
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true || baseAudit.usableForCurrentDecision !== true
      || rollbackAudit.activeRollback === true || rollbackAudit.externalAnchorDriftDetected === true) return { resolvedCount: 0, blocked: true };
    const currentFingerprint = revalidationLifecycleCheckpointFingerprint(checkpoint);
    const records = rows.filter(row => row?.ownerId === ownerId && row.kind === REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_RECORD_KIND
      && row.evidence && !row.resolvedAt);
    let resolvedCount = 0;
    for (let record of records) {
      const priorFingerprint = record.evidence.evidenceFingerprint;
      const checkpointDriftResolved = record.evidence.driftTypes.includes("revalidation_lifecycle_checkpoint")
        && record.evidence.checkpointFingerprint !== currentFingerprint;
      const rollbackDriftResolved = record.evidence.activeRollback && rollbackAudit.activeRollback !== true;
      const externalDriftResolved = record.evidence.driftTypes.includes("external_anchor_drift")
        && rollbackAudit.externalAnchorDriftDetected !== true && rollbackAudit.activeRollback !== true;
      if (!checkpointDriftResolved && !rollbackDriftResolved && !externalDriftResolved) continue;
      const operationId = `revalidation-lifecycle-drift-resolved:${priorFingerprint}:${currentFingerprint}`;
      const ledger = await readCheckpointRecoveryLedger(ownerId);
      const existing = ledger.events.find(event => event.operationId === operationId);
      const resolvedAt = existing?.resolvedAt || isoNow(clock);
      const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(operationId).slice(0, 24)}`,
        operationId, eventType: REVALIDATION_LIFECYCLE_DRIFT_RESOLVED_EVENT_TYPE,
        driftEvidenceId: record.id, evidenceDigest: record.evidenceDigest,
        priorEvidenceFingerprint: priorFingerprint, priorCheckpointFingerprint: record.evidence.checkpointFingerprint,
        currentCheckpointFingerprint: currentFingerprint, currentCheckpointSnapshotDigest: checkpoint.snapshotDigest || null,
        currentAnchorDigest: checkpoint.anchorDigest || null, currentAnchorSequence: checkpoint.anchorSequence ?? null,
        currentSourceDigest: checkpoint.sourceDigest || null, currentSourceCount: checkpoint.sourceCount ?? null,
        keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
        lifecycleAuditDigest: revalidationLifecycleAuditDigest(baseAudit), resolvedAt, occurredAt: resolvedAt };
      const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase, requireSignature: true });
      const resolutionCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
      if (resolutionCheckpoint.enabled && resolutionCheckpoint.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_ANCHOR_PENDING",
          "Drift resolution event tersimpan tetapi belum ter-anchor pada recovery-receipt checkpoint", 409,
          { resolutionEventId: appended.event.id, checkpointStatus: resolutionCheckpoint.status || "unavailable" });
      const continuityOperationId = `revalidation-lifecycle-drift-resolution-continuity:${appended.event.id}`;
      const ledgerAfterResolution = await readCheckpointRecoveryLedger(ownerId);
      const existingContinuity = ledgerAfterResolution.events.find(event => event.operationId === continuityOperationId) || null;
      const continuityAnchorDigest = existingContinuity?.resolutionAnchorDigest ?? resolutionCheckpoint.anchorDigest ?? null;
      const continuityAnchorSequence = existingContinuity?.resolutionAnchorSequence ?? resolutionCheckpoint.anchorSequence ?? null;
      const continuitySourceCount = existingContinuity?.resolutionSourceCount ?? resolutionCheckpoint.sourceCount ?? null;
      const continuityBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(continuityOperationId).slice(0, 24)}`,
        operationId: continuityOperationId, eventType: REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_EVENT_TYPE,
        driftEvidenceId: record.id, evidenceDigest: record.evidenceDigest,
        priorEvidenceFingerprint: priorFingerprint, resolutionEventId: appended.event.id,
        resolutionEventDigest: appended.event.digest, resolutionSequence: appended.event.sequence,
        resolutionAnchorDigest: continuityAnchorDigest,
        resolutionAnchorSequence: continuityAnchorSequence,
        resolutionSourceCount: continuitySourceCount,
        currentCheckpointFingerprint: currentFingerprint, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
        recordedAt: appended.event.resolvedAt || resolvedAt, occurredAt: appended.event.resolvedAt || resolvedAt };
      const continuity = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
        ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND, eventBase: continuityBase, requireSignature: true });
      const finalReceiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
      if (finalReceiptCheckpoint.enabled && finalReceiptCheckpoint.usableForCurrentDecision !== true)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_PENDING",
          "Drift resolution continuity receipt tersimpan tetapi checkpoint belum current", 409,
          { continuityEventId: continuity.event.id, checkpointStatus: finalReceiptCheckpoint.status || "unavailable" });
      record = await store.getEvidence(ownerId, record.id) || record;
      await updateRevalidationLifecycleDriftEvidenceRecord(ownerId, record, { resolvedAt: appended.event.resolvedAt || resolvedAt,
        resolutionEventId: appended.event.id, resolutionEventDigest: appended.event.digest,
        resolutionContinuityEventId: continuity.event.id, resolutionContinuityEventDigest: continuity.event.digest,
        resolutionCheckpointFingerprint: currentFingerprint, resolutionCheckpointAnchorDigest: resolutionCheckpoint.anchorDigest || null,
        resolutionCheckpointAnchorSequence: resolutionCheckpoint.anchorSequence ?? null, status: "resolved" });
      resolvedCount++;
    }
    return { resolvedCount, blocked: false, checkpointFingerprint: currentFingerprint };
  }

  async function reconcileRevalidationLifecycleCheckpointEvidence(ownerId) {
    assertOwner(ownerId);
    const failures = [];
    let anchoredCount = 0;
    let checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    const receiptBefore = await getRecoveryReceiptCheckpointState(ownerId);
    if (receiptBefore.enabled && receiptBefore.usableForCurrentDecision !== true) {
      const ledger = await readCheckpointRecoveryLedger(ownerId);
      const pendingCheckpointEvents = ledger.events.filter(event => [REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE,
        REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_EVENT_TYPE, REVALIDATION_LIFECYCLE_DRIFT_RESOLUTION_CONTINUITY_EVENT_TYPE]
        .includes(event.eventType) && event.recoveryReceiptCheckpointSourceCountAtIssue === ledger.count)
        .sort((a, b) => a.sequence - b.sequence);
      for (const event of pendingCheckpointEvents) {
        try { await advanceRecoveryReceiptCheckpointAfterAppend(ownerId, event.operationId); anchoredCount++; }
        catch (error) { failures.push({ operationId: event.operationId, code: error?.code || "FRESHNESS_CHECKPOINT_RECONCILIATION_FAILED" }); }
      }
    }
    const rows = (await store.listEvidence(ownerId)).filter(row => row?.ownerId === ownerId
      && row.kind === REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_RECORD_KIND && row.status !== "resolved");
    for (let record of rows) {
      try {
        record = await anchorRevalidationLifecycleDriftEvidenceRecord(ownerId, record);
        anchoredCount++;
      } catch (error) {
        failures.push({ evidenceId: record.id, code: error?.code || "DRIFT_EVIDENCE_RECONCILIATION_FAILED" });
      }
    }
    checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    let resolved = { resolvedCount: 0, blocked: false };
    try { resolved = await resolveRevalidationLifecycleDriftEvidenceIfSafe(ownerId); }
    catch (error) { failures.push({ code: error?.code || "DRIFT_EVIDENCE_RESOLUTION_FAILED" }); }
    const audit = await auditRevalidationLifecycleDriftEvidence(ownerId);
    return { status: failures.length || audit.pendingCount || audit.unresolvedCount ? "recovery_required" : "reconciled",
      ownerId, checkpoint, anchoredCount, resolvedCount: resolved.resolvedCount || 0, resolutionBlocked: resolved.blocked === true,
      failures, audit, usableForCurrentDecision: audit.usableForCurrentDecision === true,
      externalAnchorMutationPerformed: false, readOnly: false, mutationAllowed: false };
  }

  async function auditRevalidationLifecycleFreshnessSupersessionLedger(ownerId, suppliedLedger = null) {
    assertOwner(ownerId);
    const ledger = suppliedLedger || await readCheckpointRecoveryLedger(ownerId);
    const freshnessEvents = ledger.events.filter(event => event.eventType === REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE);
    const supersessions = ledger.events.filter(event => event.eventType === REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_EVENT_TYPE);
    const findings = [...(ledger.findings || [])];
    const supersededIds = new Set();
    const replacementOperations = new Set();
    let invalidCount = 0, pendingCount = 0;
    for (const event of supersessions) {
      const priorMatches = freshnessEvents.filter(item => item.id === event.priorAttestationId);
      const replacementMatches = freshnessEvents.filter(item => item.operationId === event.replacementOperationId);
      const prior = priorMatches[0] || null;
      const replacement = replacementMatches[0] || null;
      const verification = await verifyAttestation(ownerId, event, { attestationKind: REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_ATTESTATION_KIND,
        required: true, checkCurrent: false }).catch(() => ({ historicallyValid: false, status: "unhealthy", reasonCode: "VERIFIER_FAILED" }));
      const duplicatePrior = supersessions.filter(item => item.priorAttestationId === event.priorAttestationId).length > 1;
      const duplicateReplacement = replacementOperations.has(event.replacementOperationId);
      if (!event.operationId || !prior || priorMatches.length !== 1 || prior.sequence >= event.sequence
        || event.priorAttestationDigest !== prior.digest
        || event.priorGenerationId !== prior.generationId || event.replacementOperationId === prior.operationId
        || !event.replacementOperationId || !event.replacementGenerationId || !DIGEST.test(event.replacementSnapshotDigest || "")
        || duplicatePrior || duplicateReplacement || replacementMatches.length > 1 || (replacement && (replacement.sequence <= event.sequence
          || replacement.generationId !== event.replacementGenerationId
          || replacement.checkpointSnapshotDigest !== event.replacementSnapshotDigest
          || replacement.keyLifecycleBindingDigest !== event.replacementKeyLifecycleBindingDigest))) {
        invalidCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_INVALID",
          eventId: event.id, priorAttestationId: event.priorAttestationId || null,
          replacementOperationId: event.replacementOperationId || null });
        continue;
      }
      if (!verification?.historicallyValid || verification.status === "unhealthy") {
        invalidCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_SIGNATURE_INVALID",
          eventId: event.id, reasonCode: verification?.reasonCode || null });
        continue;
      }
      supersededIds.add(prior.id);
      replacementOperations.add(event.replacementOperationId);
      if (!replacement) {
        pendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_REPLACEMENT_PENDING",
          eventId: event.id, priorAttestationId: prior.id, replacementOperationId: event.replacementOperationId });
      }
    }
    const status = invalidCount ? "unhealthy" : pendingCount ? "recovery_required"
      : supersessions.length ? "verified_current" : "not_initialized";
    return { status, ownerId, eventCount: supersessions.length, supersededAttestationIds: [...supersededIds],
      pendingCount, invalidCount, findings, usableForCurrentDecision: invalidCount === 0 && pendingCount === 0,
      readOnly: true, mutationAllowed: false };
  }

  async function attestRevalidationLifecycleCheckpointFreshness(ownerId, { operationId = null } = {}) {
    assertOwner(ownerId);
    if (operationId !== null && (typeof operationId !== "string" || operationId.trim() !== operationId
      || operationId.length < 8 || operationId.length > 200 || /[\u0000-\u001f\u007f]/.test(operationId)))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_OPERATION_INVALID",
        "operationId harus berupa string valid sepanjang 8–200 karakter", 400);
    const recovered = await reconcileRevalidationLifecycleCheckpointEvidence(ownerId);
    if (recovered.failures.length || recovered.audit.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_NOT_CURRENT",
        "Drift evidence harus di-anchor dan diselesaikan sebelum freshness attestation diterbitkan", 409,
        { status: recovered.audit.status, failures: recovered.failures, findings: recovered.audit.findings });
    let checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    if (!checkpoint.enabled || checkpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_NOT_CURRENT",
        "Freshness attestation memerlukan independent lifecycle checkpoint yang current", 409,
        { status: checkpoint.status || "unavailable", findings: checkpoint.findings || [] });
    let baseAudit = await auditLifecycleDispositionRollbackRevalidationAttestationLifecycleBase(ownerId);
    if (baseAudit.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_AUDIT_NOT_CURRENT",
        "Lifecycle audit harus current sebelum freshness attestation diterbitkan", 409,
        { status: baseAudit.status, findings: baseAudit.findings || [] });
    let driftAudit = await auditRevalidationLifecycleDriftEvidence(ownerId);
    if (driftAudit.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_UNRESOLVED",
        "Drift evidence belum seluruhnya terselesaikan", 409, { findings: driftAudit.findings });
    let receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    if (!receiptCheckpoint.enabled || receiptCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_RECEIPT_CHECKPOINT_NOT_CURRENT",
        "Freshness attestation memerlukan recovery-receipt external checkpoint yang current", 409,
        { status: receiptCheckpoint.status || "not_configured", findings: receiptCheckpoint.findings || [] });
    const keyBinding = await getCurrentKeyBinding(ownerId);
    let ledgerBefore = await readCheckpointRecoveryLedger(ownerId);
    if (!operationId) {
      const currentFreshness = await auditRevalidationLifecycleCheckpointFreshnessAttestation(ownerId);
      if (currentFreshness.status === "verified_current") {
        const currentEvent = ledgerBefore.events.find(event => event.id === currentFreshness.eventId) || null;
        if (currentEvent) return { status: "verified_current", attestation: currentEvent, idempotent: true,
          audit: currentFreshness, checkpoint, readOnly: false, mutationAllowed: false };
      }
    }
    const checkpointFingerprint = revalidationLifecycleCheckpointFingerprint(checkpoint);
    const lifecycleAuditDigest = revalidationLifecycleAuditDigest(baseAudit);
    const driftEvidenceAuditDigest = revalidationLifecycleDriftAuditDigest(driftAudit);
    const checkpointSnapshotDigest = sha256(canonical({ domain: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN,
      checkpointSnapshotDigest: checkpoint.snapshotDigest || null, checkpointFingerprint,
      anchorDigest: checkpoint.anchorDigest || null, anchorSequence: checkpoint.anchorSequence ?? null,
      sourceDigest: checkpoint.sourceDigest || null, sourceCount: checkpoint.sourceCount ?? null,
      lifecycleAuditDigest, driftEvidenceAuditDigest, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null }));
    const now = isoNow(clock);
    const bucket = Math.floor(Date.parse(now) / 60000);
    const freshnessEventsBefore = ledgerBefore.events.filter(event => event.eventType === REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE);
    const supersessionEventsBefore = ledgerBefore.events.filter(event => event.eventType === REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_EVENT_TYPE);
    const pendingSupersession = supersessionEventsBefore.filter(event =>
      event.replacementSnapshotDigest === checkpointSnapshotDigest
      && event.replacementKeyLifecycleBindingDigest === (keyBinding?.bindingDigest || null)
      && !freshnessEventsBefore.some(item => item.operationId === event.replacementOperationId)).at(-1) || null;
    if (pendingSupersession && operationId && pendingSupersession.replacementOperationId !== operationId)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_RECOVERY_REQUIRED",
        "Supersession sebelumnya belum memiliki attestation pengganti; lanjutkan operationId yang sama", 409,
        { pendingOperationId: pendingSupersession.replacementOperationId });
    let selectedOperationId = operationId || pendingSupersession?.replacementOperationId || `revalidation-lifecycle-freshness:${sha256(canonical({ ownerId,
      checkpointSnapshotDigest, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      ledgerCount: ledgerBefore.count, minuteBucket: bucket })).slice(0, 32)}`;
    let expectedGenerationId = sha256(canonical({ ownerId, selectedOperationId, checkpointSnapshotDigest,
      keyLifecycleBindingDigest: keyBinding?.bindingDigest || null })).slice(0, 32);
    let existing = ledgerBefore.events.find(event => event.operationId === selectedOperationId);
    if (existing && (existing.eventType !== REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE
      || existing.checkpointSnapshotDigest !== checkpointSnapshotDigest
      || existing.keyLifecycleBindingDigest !== (keyBinding?.bindingDigest || null)))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_OPERATION_CONFLICT",
        "operationId freshness sudah terikat pada snapshot atau key lifecycle berbeda", 409);
    if (existing) {
      const supersessionAudit = await auditRevalidationLifecycleFreshnessSupersessionLedger(ownerId, ledgerBefore);
      if (supersessionAudit.supersededAttestationIds.includes(existing.id))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_OPERATION_SUPERSEDED",
          "Operation ID menunjuk freshness attestation yang sudah digantikan generation berikutnya", 409);
    } else {
      const supersededIds = new Set(supersessionEventsBefore.map(event => event.priorAttestationId));
      const priorAttestation = freshnessEventsBefore.filter(event => !supersededIds.has(event.id)).at(-1) || null;
      if (pendingSupersession) {
        const prior = freshnessEventsBefore.find(event => event.id === pendingSupersession.priorAttestationId) || null;
        if (!prior || prior.digest !== pendingSupersession.priorAttestationDigest
          || pendingSupersession.replacementGenerationId !== expectedGenerationId)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_INVALID",
            "Pending supersession tidak cocok dengan generation pengganti yang diminta", 409);
      }
      if (priorAttestation || pendingSupersession) {
        const prior = pendingSupersession
          ? freshnessEventsBefore.find(event => event.id === pendingSupersession.priorAttestationId)
          : priorAttestation;
        const supersessionOperationId = `revalidation-lifecycle-freshness-supersession:${prior.id}:${expectedGenerationId}`;
        const existingSupersession = supersessionEventsBefore.find(event => event.operationId === supersessionOperationId) || null;
        const supersededAt = existingSupersession?.supersededAt || now;
        const supersessionBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(supersessionOperationId).slice(0, 24)}`,
          operationId: supersessionOperationId, eventType: REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_EVENT_TYPE,
          priorAttestationId: prior.id, priorAttestationDigest: prior.digest, priorGenerationId: prior.generationId,
          replacementOperationId: selectedOperationId, replacementGenerationId: expectedGenerationId,
          replacementSnapshotDigest: checkpointSnapshotDigest,
          replacementKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
          supersededAt, occurredAt: supersededAt };
        const supersession = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
          ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
          attestationKind: REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_ATTESTATION_KIND,
          eventBase: supersessionBase, requireSignature: true });
        ledgerBefore = await readCheckpointRecoveryLedger(ownerId);
        receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
        if (receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision !== true)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_ANCHOR_PENDING",
            "Supersession tersimpan tetapi external recovery-receipt checkpoint belum current", 409,
            { eventId: supersession.event.id, status: receiptCheckpoint.status || "unavailable" });
        existing = ledgerBefore.events.find(event => event.operationId === selectedOperationId) || null;
      }
    }
    const issuedAt = existing?.issuedAt || now;
    const eventBase = { id: `${checkpointRecoveryLedgerId(ownerId)}-${sha256(selectedOperationId).slice(0, 24)}`,
      operationId: selectedOperationId, eventType: REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE,
      generationId: expectedGenerationId,
      checkpointDomain: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN,
      checkpointSnapshotDigest, checkpointFingerprint, lifecycleCheckpointSnapshotDigest: checkpoint.snapshotDigest || null,
      anchorDigest: checkpoint.anchorDigest || null, anchorSequence: checkpoint.anchorSequence ?? null,
      sourceDigest: checkpoint.sourceDigest || null, sourceCount: checkpoint.sourceCount ?? null,
      lifecycleAuditDigest, driftEvidenceAuditDigest, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      issuedAt, expiresAt: new Date(Date.parse(issuedAt) + maxRevalidationLifecycleFreshnessAgeMs).toISOString(),
      occurredAt: issuedAt };
    const appended = await appendSignedEvent(ownerId, { ledgerKind: CHECKPOINT_RECOVERY_LEDGER_KIND,
      ledgerIdForOwner: checkpointRecoveryLedgerId, eventKind: CHECKPOINT_RECOVERY_EVENT_KIND,
      attestationKind: REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_KIND, eventBase, requireSignature: true });
    const audit = await auditRevalidationLifecycleCheckpointFreshnessAttestation(ownerId, appended.event.id);
    if (audit.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_FINALIZATION_PENDING",
        "Freshness attestation tersimpan tetapi belum dapat diverifikasi sebagai current", 409,
        { eventId: appended.event.id, status: audit.status, findings: audit.findings || [] });
    return { status: "verified_current", attestation: appended.event, idempotent: appended.idempotent === true,
      audit, checkpoint, readOnly: false, mutationAllowed: false };
  }

  async function auditRevalidationLifecycleCheckpointFreshnessAttestation(ownerId, eventId = null) {
    assertOwner(ownerId);
    const [ledger, checkpoint, baseAudit, driftAudit, keyBinding, receiptCheckpoint] = await Promise.all([
      readCheckpointRecoveryLedger(ownerId), getRevalidationLifecycleCheckpointState(ownerId),
      auditLifecycleDispositionRollbackRevalidationAttestationLifecycleBase(ownerId),
      auditRevalidationLifecycleDriftEvidence(ownerId), getCurrentKeyBinding(ownerId), getRecoveryReceiptCheckpointState(ownerId)]);
    const events = ledger.events.filter(event => event.eventType === REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_EVENT_TYPE);
    const event = eventId ? events.find(item => item.id === eventId) : events.at(-1);
    const required = Boolean(requireRevalidationLifecycleFreshnessAttestation);
    const supersessionAudit = await auditRevalidationLifecycleFreshnessSupersessionLedger(ownerId, ledger);
    if (!event) {
      const pendingSupersession = supersessionAudit.pendingCount > 0;
      return { status: pendingSupersession ? "recovery_required" : "missing", required,
        usableForCurrentDecision: !required && supersessionAudit.usableForCurrentDecision,
        findings: [...(required ? [{ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_REQUIRED" }] : []),
          ...supersessionAudit.findings], supersessionAudit, checkpoint, driftEvidenceAudit: driftAudit,
        receiptCheckpoint, readOnly: true, mutationAllowed: false };
    }
    const findings = [...ledger.findings, ...supersessionAudit.findings];
    const superseded = supersessionAudit.supersededAttestationIds.includes(event.id);
    if (superseded) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_SUPERSEDED",
      eventId: event.id, generationId: event.generationId });
    if (!supersessionAudit.usableForCurrentDecision && !superseded)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_SUPERSESSION_LEDGER_NOT_CURRENT",
        status: supersessionAudit.status, pendingCount: supersessionAudit.pendingCount, invalidCount: supersessionAudit.invalidCount });
    const verification = await verifyAttestation(ownerId, event, { attestationKind: REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_KIND,
      required: true, checkCurrent: true }).catch(() => ({ historicallyValid: false, status: "unhealthy", reasonCode: "VERIFIER_FAILED" }));
    const nowMs = Date.parse(isoNow(clock)), issuedMs = Date.parse(event.issuedAt), expiryMs = Date.parse(event.expiresAt);
    const timeValid = Number.isFinite(issuedMs) && Number.isFinite(expiryMs) && issuedMs <= nowMs + 60000
      && expiryMs > nowMs && expiryMs - issuedMs <= maxRevalidationLifecycleFreshnessAgeMs
      && nowMs - issuedMs <= maxRevalidationLifecycleFreshnessAgeMs;
    const checkpointFingerprint = revalidationLifecycleCheckpointFingerprint(checkpoint);
    const checkpointSnapshotDigest = sha256(canonical({ domain: LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN,
      checkpointSnapshotDigest: checkpoint.snapshotDigest || null, checkpointFingerprint,
      anchorDigest: checkpoint.anchorDigest || null, anchorSequence: checkpoint.anchorSequence ?? null,
      sourceDigest: checkpoint.sourceDigest || null, sourceCount: checkpoint.sourceCount ?? null,
      lifecycleAuditDigest: revalidationLifecycleAuditDigest(baseAudit),
      driftEvidenceAuditDigest: revalidationLifecycleDriftAuditDigest(driftAudit),
      keyLifecycleBindingDigest: keyBinding?.bindingDigest || null }));
    const bindingMatches = event.checkpointDomain === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHECKPOINT_DOMAIN
      && event.checkpointSnapshotDigest === checkpointSnapshotDigest && event.checkpointFingerprint === checkpointFingerprint
      && event.lifecycleCheckpointSnapshotDigest === (checkpoint.snapshotDigest || null)
      && event.anchorDigest === (checkpoint.anchorDigest || null) && event.anchorSequence === (checkpoint.anchorSequence ?? null)
      && event.sourceDigest === (checkpoint.sourceDigest || null) && event.sourceCount === (checkpoint.sourceCount ?? null)
      && event.keyLifecycleBindingDigest === (keyBinding?.bindingDigest || null)
      && event.lifecycleAuditDigest === revalidationLifecycleAuditDigest(baseAudit)
      && event.driftEvidenceAuditDigest === revalidationLifecycleDriftAuditDigest(driftAudit);
    const generationDuplicates = events.filter(item => item.generationId === event.generationId).length > 1;
    const receiptCheckpointMatches = receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision === true
      && Number.isSafeInteger(event.recoveryReceiptCheckpointSourceCountAtIssue)
      && receiptCheckpoint.sourceCount === event.recoveryReceiptCheckpointSourceCountAtIssue
      && Number.isSafeInteger(event.recoveryReceiptCheckpointPriorAnchorSequence)
      && receiptCheckpoint.anchorSequence === event.recoveryReceiptCheckpointPriorAnchorSequence + 1;
    if (!verification?.historicallyValid || verification.status === "unhealthy") findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_INVALID",
      reasonCode: verification?.reasonCode || null });
    if (verification?.status !== "verified_current" || event.keyLifecycleBindingDigest !== (keyBinding?.bindingDigest || null))
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_KEY_CUTOFF",
        verificationStatus: verification?.status || "unverified" });
    if (!timeValid) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_EXPIRED" });
    if (!bindingMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_BINDING_CHANGED" });
    if (generationDuplicates) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_GENERATION_REPLAY",
      generationId: event.generationId });
    if (!checkpoint.enabled || checkpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHECKPOINT_NOT_CURRENT", status: checkpoint.status || "unavailable" });
    if (baseAudit.usableForCurrentDecision !== true) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_AUDIT_NOT_CURRENT",
      status: baseAudit.status, findings: baseAudit.findings || [] });
    if (driftAudit.usableForCurrentDecision !== true) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_NOT_CURRENT",
      status: driftAudit.status, findings: driftAudit.findings || [] });
    if (!receiptCheckpointMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_RECEIPT_CHECKPOINT_CHANGED",
      status: receiptCheckpoint.status || "unavailable", expectedSourceCount: event.recoveryReceiptCheckpointSourceCountAtIssue ?? null,
      currentSourceCount: receiptCheckpoint.sourceCount ?? null });
    const hard = findings.some(item => /_INVALID|_REPLAY|_CONFLICT|CHAIN_INVALID|LEDGER_INVALID/.test(item.code || ""));
    const status = hard ? "unhealthy" : superseded ? "superseded"
      : !supersessionAudit.usableForCurrentDecision ? "recovery_required"
        : !timeValid || !bindingMatches || verification?.status !== "verified_current"
          || !checkpoint.enabled || checkpoint.usableForCurrentDecision !== true || baseAudit.usableForCurrentDecision !== true
          || driftAudit.usableForCurrentDecision !== true || !receiptCheckpointMatches ? "stale" : "verified_current";
    return { status, required, eventId: event.id, generationId: event.generationId,
      checkpointSnapshotDigest: event.checkpointSnapshotDigest, currentCheckpointSnapshotDigest: checkpoint.snapshotDigest || null,
      createdAt: event.issuedAt, expiresAt: event.expiresAt, verification, checkpoint, baseAuditStatus: baseAudit.status,
      driftEvidenceAudit: driftAudit, receiptCheckpoint, supersessionAudit, findings,
      usableForCurrentDecision: status === "verified_current", readOnly: true, mutationAllowed: false };
  }

  async function readRevalidationLifecycleRecoveryGateProofLedger(ownerId) {
    const id = ledgerId(REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_LEDGER_KIND, ownerId);
    const record = await store.getEvidence(ownerId, id);
    const events = Array.isArray(record?.events) ? record.events : [];
    const findings = [];
    if (record && (record.ownerId !== ownerId || record.kind !== REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_LEDGER_KIND
      || record.schemaVersion !== 1 || record.digest !== digestRecord(record) || record.eventCount !== events.length
      || (record.headDigest || null) !== (events.at(-1)?.digest || null)))
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_LEDGER_INVALID" });
    let previous = null;
    const seenIds = new Set(), seenOperations = new Set();
    for (let index = 0; index < events.length; index++) {
      const event = events[index];
      if (!event || event.ownerId !== ownerId || event.kind !== REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_EVENT_TYPE
        || event.sequence !== index + 1 || (event.previousEventDigest || null) !== (previous?.digest || null)
        || !event.id || seenIds.has(event.id) || !event.operationId || seenOperations.has(event.operationId)
        || event.digest !== digestRecord(event) || !DIGEST.test(event.payloadBindingDigest || "")
        || event.payloadBindingDigest !== eventBaseDigest(event))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_CHAIN_INVALID",
          sequence: index + 1, eventId: event?.id || null });
      seenIds.add(event?.id);
      seenOperations.add(event?.operationId);
      previous = event;
    }
    return { id, record, events, count: events.length, headDigest: events.at(-1)?.digest || null,
      findings, status: findings.length ? "unhealthy" : events.length ? "healthy" : "not_initialized" };
  }

  async function getRevalidationLifecycleRecoveryGateProofSnapshot(ownerId) {
    assertOwner(ownerId);
    const ledger = await readRevalidationLifecycleRecoveryGateProofLedger(ownerId);
    const snapshot = { schemaVersion: 1, domain: "cross_domain_recovery_intent_closure_recovery_gate_proofs",
      ownerId, ledgerId: ledger.id,
      events: ledger.events.map(event => ({ id: event.id, digest: event.digest, sequence: event.sequence,
        operationId: event.operationId, proofSnapshotDigest: event.proofSnapshotDigest,
        decisionStatus: event.decisionStatus, createdAt: event.createdAt })) };
    return { status: ledger.status === "unhealthy" ? "unhealthy" : ledger.count ? "healthy" : "not_initialized",
      ownerId, count: ledger.count, digest: sha256(canonical(snapshot)), snapshot, findings: ledger.findings,
      readOnly: true, mutationAllowed: false };
  }

  async function appendRevalidationLifecycleRecoveryGateProof(ownerId, decision) {
    assertOwner(ownerId);
    const checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    const receiptCheckpoint = await getRecoveryReceiptCheckpointState(ownerId);
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const checkpointFingerprint = revalidationLifecycleCheckpointFingerprint(checkpoint);
    const stableSnapshot = { ownerId, checkpointFingerprint, checkpointSnapshotDigest: checkpoint.snapshotDigest || null,
      anchorDigest: checkpoint.anchorDigest || null, anchorSequence: checkpoint.anchorSequence ?? null,
      sourceDigest: checkpoint.sourceDigest || null, sourceCount: checkpoint.sourceCount ?? null,
      freshnessAttestationEventId: decision.freshnessAttestation?.eventId || null,
      freshnessAttestationGenerationId: decision.freshnessAttestation?.generationId || null,
      freshnessAttestationStatus: decision.freshnessAttestation?.status || "missing",
      freshnessSupersessionAuditDigest: revalidationLifecycleFreshnessSupersessionAuditDigest(decision.freshnessAttestation?.supersessionAudit),
      lifecycleAuditDigest: revalidationLifecycleAuditDigest(decision.lifecycleAudit),
      closureAuditDigest: sha256(canonical({ status: decision.closureAudit?.status || "unavailable",
        usableForCurrentDecision: decision.closureAudit?.usableForCurrentDecision === true,
        findings: decision.closureAudit?.findings || [] })),
      driftEvidenceAuditDigest: revalidationLifecycleDriftAuditDigest(decision.driftEvidenceAudit),
      receiptCheckpoint: { enabled: Boolean(receiptCheckpoint.enabled), status: receiptCheckpoint.status || "unavailable",
        anchorDigest: receiptCheckpoint.anchorDigest || null, anchorSequence: receiptCheckpoint.anchorSequence ?? null,
        sourceDigest: receiptCheckpoint.sourceDigest || null, sourceCount: receiptCheckpoint.sourceCount ?? null },
      keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      decisionStatus: decision.usableForCurrentDecision === true ? "verified_current" : "recovery_required",
      decisionUsableForCurrentDecision: decision.usableForCurrentDecision === true };
    const proofSnapshotDigest = sha256(canonical(stableSnapshot));
    const operationId = `revalidation-lifecycle-recovery-gate-proof:${proofSnapshotDigest}`;
    for (let attempt = 0; attempt < 4; attempt++) {
      const current = await readRevalidationLifecycleRecoveryGateProofLedger(ownerId);
      if (current.status === "unhealthy") throw new AgenticError(
        "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_LEDGER_UNHEALTHY",
        "Recovery-gate proof ledger tidak sehat; penulisan proof baru ditolak", 409, { findings: current.findings });
      const existing = current.events.find(event => event.operationId === operationId);
      if (existing) {
        if (existing.proofSnapshotDigest !== proofSnapshotDigest || existing.keyLifecycleBindingDigest !== (keyBinding?.bindingDigest || null))
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_CONFLICT",
            "Operation ID proof sudah terikat pada keputusan berbeda", 409);
        return { event: existing, idempotent: true };
      }
      const eventBase = { id: `${current.id}-${sha256(operationId).slice(0, 24)}`, ownerId,
        kind: REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_EVENT_TYPE, schemaVersion: 1,
        sequence: current.count + 1, previousEventDigest: current.headDigest || null, operationId,
        proofSnapshotDigest, ...stableSnapshot, createdAt: isoNow(clock) };
      const payloadBindingDigest = payloadDigest(eventBase);
      const signable = { ...eventBase, payloadBindingDigest };
      const attestation = await createAttestation(ownerId, signable, { attestationKind: REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_KIND,
        keyLifecycleBinding: keyBinding, required: true, attestationIdSuffix: operationId });
      const unsignedEvent = { ...signable, attestation: attestation || null };
      const event = { ...unsignedEvent, digest: digestRecord(unsignedEvent) };
      const events = [...current.events, event];
      const unsignedLedger = { id: current.id, ownerId, kind: REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_LEDGER_KIND,
        schemaVersion: 1, events, eventCount: events.length, headDigest: event.digest, updatedAt: isoNow(clock) };
      const candidate = { ...unsignedLedger, digest: digestRecord(unsignedLedger) };
      try {
        if (current.record) await store.putEvidence(ownerId, candidate, { expectedVersion: current.record._storage?.version });
        else await store.putEvidence(ownerId, candidate, { overwrite: false });
      } catch {
        const concurrent = await readRevalidationLifecycleRecoveryGateProofLedger(ownerId);
        const matched = concurrent.events.find(item => item.operationId === operationId);
        if (matched) {
          if (matched.proofSnapshotDigest !== proofSnapshotDigest)
            throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_CONFLICT",
              "Concurrent proof operation memiliki binding berbeda", 409);
          return { event: matched, idempotent: true };
        }
        if (attempt === 3) throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_CAS_EXHAUSTED",
          "CAS proof ledger gagal setelah retry terbatas", 409);
        continue;
      }
      const post = await readRevalidationLifecycleRecoveryGateProofLedger(ownerId);
      const saved = post.events.find(item => item.operationId === operationId);
      if (post.status === "unhealthy" || !saved) throw new AgenticError(
        "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_POSTCONDITION_FAILED",
        "Recovery-gate proof gagal diverifikasi setelah penyimpanan", 409, { findings: post.findings });
      return { event: saved, idempotent: false };
    }
    throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_CAS_EXHAUSTED",
      "CAS proof ledger gagal setelah retry terbatas", 409);
  }

  async function auditRevalidationLifecycleRecoveryGateProof(ownerId) {
    assertOwner(ownerId);
    const [ledger, checkpoint, receiptCheckpoint, keyBinding, currentFreshness, currentLifecycleAudit, currentClosureAudit] = await Promise.all([
      readRevalidationLifecycleRecoveryGateProofLedger(ownerId), getRevalidationLifecycleCheckpointState(ownerId),
      getRecoveryReceiptCheckpointState(ownerId), getCurrentKeyBinding(ownerId),
      auditRevalidationLifecycleCheckpointFreshnessAttestation(ownerId),
      auditLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId), auditClosure(ownerId)]);
    const findings = [...ledger.findings];
    const events = ledger.events;
    const latest = events.at(-1) || null;
    let invalidCount = 0;
    for (const event of events) {
      const verification = await verifyAttestation(ownerId, event, { attestationKind: REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_KIND,
        required: true, checkCurrent: false }).catch(() => ({ historicallyValid: false, status: "unhealthy", reasonCode: "VERIFIER_FAILED" }));
      if (!verification?.historicallyValid || verification.status === "unhealthy") {
        invalidCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_SIGNATURE_INVALID",
          eventId: event.id, reasonCode: verification?.reasonCode || null });
      }
    }
    if (!latest) return { status: "missing", ownerId, eventCount: 0, latestProof: null, findings,
      usableForCurrentDecision: false, readOnly: true, mutationAllowed: false };
    const currentFingerprint = revalidationLifecycleCheckpointFingerprint(checkpoint);
    const receiptMatches = receiptCheckpoint.enabled && receiptCheckpoint.usableForCurrentDecision === true
      && latest.receiptCheckpoint?.enabled === true && latest.receiptCheckpoint.anchorDigest === (receiptCheckpoint.anchorDigest || null)
      && latest.receiptCheckpoint.anchorSequence === (receiptCheckpoint.anchorSequence ?? null)
      && latest.receiptCheckpoint.sourceDigest === (receiptCheckpoint.sourceDigest || null)
      && latest.receiptCheckpoint.sourceCount === (receiptCheckpoint.sourceCount ?? null);
    const bindingMatches = latest.checkpointFingerprint === currentFingerprint
      && latest.checkpointSnapshotDigest === (checkpoint.snapshotDigest || null)
      && latest.keyLifecycleBindingDigest === (keyBinding?.bindingDigest || null);
    const currentClosureDigest = sha256(canonical({ status: currentClosureAudit?.status || "unavailable",
      usableForCurrentDecision: currentClosureAudit?.usableForCurrentDecision === true,
      findings: currentClosureAudit?.findings || [] }));
    const gateEvidenceMatches = latest.freshnessAttestationEventId === (currentFreshness.eventId || null)
      && latest.freshnessAttestationGenerationId === (currentFreshness.generationId || null)
      && latest.freshnessAttestationStatus === (currentFreshness.status || "missing")
      && latest.freshnessSupersessionAuditDigest === revalidationLifecycleFreshnessSupersessionAuditDigest(currentFreshness.supersessionAudit)
      && latest.lifecycleAuditDigest === revalidationLifecycleAuditDigest(currentLifecycleAudit)
      && latest.closureAuditDigest === currentClosureDigest
      && latest.driftEvidenceAuditDigest === revalidationLifecycleDriftAuditDigest(currentLifecycleAudit.driftEvidenceAudit || null);
    if (!receiptMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_RECEIPT_CHECKPOINT_STALE" });
    if (!bindingMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_BINDING_STALE" });
    if (!gateEvidenceMatches) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_DECISION_EVIDENCE_STALE" });
    if (invalidCount) findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_RECOVERY_GATE_PROOF_INVALID", invalidCount });
    const status = invalidCount || ledger.status === "unhealthy" ? "unhealthy"
      : !receiptMatches || !bindingMatches || !gateEvidenceMatches ? "stale"
        : latest.decisionUsableForCurrentDecision === true && currentFreshness.usableForCurrentDecision === true
          && currentLifecycleAudit.usableForCurrentDecision === true && currentClosureAudit.usableForCurrentDecision === true
          ? "verified_current" : "decision_blocked";
    return { status, ownerId, eventCount: ledger.count, headDigest: ledger.headDigest,
      latestProof: { id: latest.id, digest: latest.digest, operationId: latest.operationId,
        proofSnapshotDigest: latest.proofSnapshotDigest, decisionStatus: latest.decisionStatus,
        decisionUsableForCurrentDecision: latest.decisionUsableForCurrentDecision,
        createdAt: latest.createdAt, receiptCheckpoint: latest.receiptCheckpoint },
      checkpoint, receiptCheckpoint, currentFreshnessStatus: currentFreshness.status,
      currentLifecycleAuditStatus: currentLifecycleAudit.status, currentClosureAuditStatus: currentClosureAudit.status, findings,
      usableForCurrentDecision: status === "verified_current", readOnly: true, mutationAllowed: false };
  }

  async function revalidateRevalidationLifecycleRecoveryGate(ownerId) {
    assertOwner(ownerId);
    const monitor = await monitorLifecycleDispositionRollbackRevalidationExternalAnchorDrift(ownerId);
    let checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    const blockedStates = new Set(["unhealthy", "rollback_suspected", "policy_drift", "unavailable", "enrollment_required",
      "not_initialized", "anchor_missing", "continuity_unproven"]);
    let checkpointReconciliation = null;
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true && !blockedStates.has(checkpoint.status)) {
      try { checkpointReconciliation = await reconcileRevalidationLifecycleCheckpoint(ownerId); }
      catch (error) { checkpointReconciliation = { status: "recovery_required", code: error?.code || "CHECKPOINT_RECONCILIATION_FAILED" }; }
      checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    }
    const evidenceReconciliation = await reconcileRevalidationLifecycleCheckpointEvidence(ownerId);
    let lifecycleReconciliation = null;
    if (!blockedStates.has(checkpoint.status) && (!checkpoint.enabled || checkpoint.usableForCurrentDecision === true)) {
      lifecycleReconciliation = await reconcileLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId, null);
    }
    const freshnessAttestation = await auditRevalidationLifecycleCheckpointFreshnessAttestation(ownerId);
    const lifecycleAudit = await auditLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId);
    const closureAudit = await auditClosure(ownerId);
    const decisionUsableForCurrentDecision = closureAudit.usableForCurrentDecision === true
      && lifecycleAudit.usableForCurrentDecision === true && freshnessAttestation.usableForCurrentDecision === true;
    const decision = { usableForCurrentDecision: decisionUsableForCurrentDecision, freshnessAttestation, lifecycleAudit, closureAudit,
      driftEvidenceAudit: lifecycleAudit.driftEvidenceAudit || evidenceReconciliation.audit || null };
    const proofWrite = await appendRevalidationLifecycleRecoveryGateProof(ownerId, decision);
    const recoveryGateProofAudit = await auditRevalidationLifecycleRecoveryGateProof(ownerId);
    const usableForCurrentDecision = decisionUsableForCurrentDecision && recoveryGateProofAudit.usableForCurrentDecision === true;
    return { status: usableForCurrentDecision ? "verified_current" : "recovery_required", ownerId, monitor,
      checkpoint, checkpointReconciliation, evidenceReconciliation, lifecycleReconciliation, freshnessAttestation,
      lifecycleAudit, closureAudit, recoveryGateProof: proofWrite.event, recoveryGateProofIdempotent: proofWrite.idempotent,
      recoveryGateProofAudit, usableForCurrentDecision, readOnly: false, mutationAllowed: false,
      externalAnchorMutationPerformed: false };
  }

  async function auditLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId) {
    const base = await auditLifecycleDispositionRollbackRevalidationAttestationLifecycleBase(ownerId);
    const [freshnessAttestation, driftEvidenceAudit] = await Promise.all([
      auditRevalidationLifecycleCheckpointFreshnessAttestation(ownerId), auditRevalidationLifecycleDriftEvidence(ownerId)]);
    const findings = [...(base.findings || [])];
    if (requireRevalidationLifecycleFreshnessAttestation && freshnessAttestation.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_REQUIRED_OR_STALE",
        status: freshnessAttestation.status, findings: freshnessAttestation.findings || [] });
    else if (freshnessAttestation.status !== "missing" && freshnessAttestation.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_FRESHNESS_ATTESTATION_STALE",
        status: freshnessAttestation.status, findings: freshnessAttestation.findings || [] });
    if (driftEvidenceAudit.invalidCount > 0 || driftEvidenceAudit.pendingCount > 0 || driftEvidenceAudit.unresolvedCount > 0
      || driftEvidenceAudit.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_DRIFT_EVIDENCE_NOT_CURRENT",
        status: driftEvidenceAudit.status, pendingCount: driftEvidenceAudit.pendingCount,
        unresolvedCount: driftEvidenceAudit.unresolvedCount, invalidCount: driftEvidenceAudit.invalidCount });
    const hard = base.status === "unhealthy" || driftEvidenceAudit.status === "unhealthy";
    const status = hard ? "unhealthy" : base.pendingCount ? "recovery_required"
      : requireRevalidationLifecycleFreshnessAttestation && freshnessAttestation.usableForCurrentDecision !== true
        ? "freshness_attestation_required" : freshnessAttestation.status !== "missing" && freshnessAttestation.usableForCurrentDecision !== true
          ? "stale" : driftEvidenceAudit.pendingCount || driftEvidenceAudit.unresolvedCount ? "recovery_required" : base.status;
    return { ...base, status, findings, freshnessAttestation, driftEvidenceAudit,
      usableForCurrentDecision: base.usableForCurrentDecision === true
        && (!requireRevalidationLifecycleFreshnessAttestation || freshnessAttestation.usableForCurrentDecision === true)
        && (freshnessAttestation.status === "missing" || freshnessAttestation.usableForCurrentDecision === true)
        && driftEvidenceAudit.usableForCurrentDecision === true,
      readOnly: true, mutationAllowed: false };
  }

  async function reconcileLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId, challengeId = null) {
    assertOwner(ownerId);
    let checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
    if (checkpoint.enabled && ["unhealthy", "rollback_suspected", "policy_drift", "unavailable", "enrollment_required", "not_initialized", "anchor_missing", "continuity_unproven"]
      .includes(checkpoint.status))
      return { status: "recovery_blocked", ownerId, checkpoint, resumedCount: 0, failures: [],
        externalAnchorMutationPerformed: false, usableForCurrentDecision: false, readOnly: false, mutationAllowed: false };
    if (checkpoint.enabled && checkpoint.usableForCurrentDecision !== true) {
      try {
        await reconcileRevalidationLifecycleCheckpoint(ownerId);
      } catch (error) {
        checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
        return { status: "recovery_required", ownerId, checkpoint, resumedCount: 0,
          failures: [{ challengeId: challengeId || null, code: error?.code || "CHECKPOINT_RECONCILIATION_FAILED" }],
          externalAnchorMutationPerformed: false, usableForCurrentDecision: false, readOnly: false, mutationAllowed: false };
      }
      checkpoint = await getRevalidationLifecycleCheckpointState(ownerId);
      if (checkpoint.usableForCurrentDecision !== true)
        return { status: "recovery_required", ownerId, checkpoint, resumedCount: 0, failures: [],
          externalAnchorMutationPerformed: false, usableForCurrentDecision: false, readOnly: false, mutationAllowed: false };
    }
    const [rows, ledger] = await Promise.all([store.listEvidence(ownerId), readCheckpointRecoveryLedger(ownerId)]);
    const challenges = rows.filter(row => row?.ownerId === ownerId
      && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_CHALLENGE_KIND
      && (!challengeId || row.id === challengeId));
    if (challengeId && !challenges.length)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_CHALLENGE_INVALID",
        "Lifecycle challenge tidak ditemukan untuk reconciliation", 404);
    const failures = [];
    let resumedCount = 0;
    for (const challenge of challenges) {
      const ids = rollbackRevalidationLifecycleOperationIds(challenge.id);
      const hasIntent = ledger.events.some(event => event.operationId === ids.intent);
      const hasFinal = ledger.events.some(event => event.operationId === ids.finalized);
      if (!hasIntent || hasFinal && challenge.status === "completed") continue;
      try {
        await applyLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId, challenge.id,
          { confirmation: challenge.confirmationPhrase });
        resumedCount++;
      } catch (error) {
        failures.push({ challengeId: challenge.id, code: error?.code || "LIFECYCLE_RECONCILIATION_FAILED" });
      }
    }
    const audit = await auditLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId);
    return { status: failures.length || audit.pendingCount ? "recovery_required" : "reconciled", ownerId,
      checkpoint: audit.lifecycleCheckpoint || checkpoint, resumedCount, failures, audit,
      externalAnchorMutationPerformed: false, usableForCurrentDecision: audit.usableForCurrentDecision === true,
      readOnly: false, mutationAllowed: false };
  }

  async function monitorLifecycleDispositionRollbackRevalidationExternalAnchorDrift(ownerId) {
    assertOwner(ownerId);
    const [audit, lifecycleAudit, lifecycleCheckpoint] = await Promise.all([auditLifecycleDispositionCheckpointRollbackRecovery(ownerId),
      auditLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId), getRevalidationLifecycleCheckpointState(ownerId)]);
    const driftedAttestations = [...audit.findings, ...(lifecycleAudit.findings || [])].filter(item => item.code === "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EXTERNAL_ANCHOR_DRIFT_DETECTED"
      || item.code === "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_STALE"
      || item.code === "RECOVERY_INTENT_CLOSURE_REVALIDATION_LIFECYCLE_EXTERNAL_CHECKPOINT_NOT_CURRENT")
      .map(item => ({ ...item }));
    const lifecycleCheckpointDrift = lifecycleCheckpoint.enabled && lifecycleCheckpoint.usableForCurrentDecision !== true;
    const detected = audit.externalAnchorDriftDetected === true || audit.activeRollback === true || lifecycleCheckpointDrift;
    let driftEvidenceRetention = null;
    if (detected) {
      try {
        driftEvidenceRetention = await captureRevalidationLifecycleDriftEvidence(ownerId, { checkpoint: lifecycleCheckpoint,
          rollbackStatus: audit.checkpointStatus || audit.status, activeRollback: audit.activeRollback === true,
          externalAnchorDriftDetected: audit.externalAnchorDriftDetected === true,
          driftedAttestations, lifecycleAuditStatus: lifecycleAudit.status });
      } catch (error) {
        driftEvidenceRetention = { status: "retention_failed", errorCode: error?.code || error?.name || "DRIFT_EVIDENCE_RETENTION_FAILED",
          usableForCurrentDecision: false, readOnly: false, mutationAllowed: false };
      }
    }
    const driftEvidenceAudit = await auditRevalidationLifecycleDriftEvidence(ownerId);
    return { status: detected ? "drift_detected" : audit.usableForCurrentDecision ? "current" : audit.status,
      ownerId, externalAnchorDriftDetected: detected, checkpointFingerprint: audit.checkpointFingerprint,
      revalidationLifecycleCheckpoint: lifecycleCheckpoint, revalidationLifecycleAuditStatus: lifecycleAudit.status,
      driftedAttestationCount: driftedAttestations.length, driftedAttestations,
      driftEvidenceRetention, driftEvidenceAudit,
      rollbackStatus: audit.checkpointStatus, recoveryRequired: audit.pendingCount > 0 || audit.revalidationPendingCount > 0
        || audit.revalidationLifecyclePendingCount > 0 || audit.continuityPendingCount > 0
        || driftEvidenceAudit.pendingCount > 0 || driftEvidenceAudit.unresolvedCount > 0,
      usableForCurrentDecision: !detected && audit.usableForCurrentDecision === true && lifecycleAudit.usableForCurrentDecision !== false
        && driftEvidenceAudit.usableForCurrentDecision === true,
      readOnly: false, mutationAllowed: false, externalAnchorMutationPerformed: false };
  }

  async function reconcileLifecycleDispositionCheckpointRollbackRecovery(ownerId, challengeId) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND
      || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_INVALID",
        "Rollback recovery challenge tidak valid", 409);
    const operationId = sha256(canonical({ ownerId, challengeId: challenge.id, checkpointFingerprint: challenge.checkpointFingerprint,
      disposition: challenge.disposition, reason: challenge.reason }));
    const eventId = `${LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_KIND}-${operationId.slice(0, 32)}`;
    const event = await store.getEvidence(ownerId, eventId);
    if (!event && (challenge.status !== "prepared" || Date.parse(challenge.expiresAt) <= Date.parse(String(clock()))))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_EXPIRED",
        "Challenge kedaluwarsa sebelum rollback event tersimpan; siapkan challenge baru setelah inspeksi ulang", 409);
    const applied = await applyLifecycleDispositionCheckpointRollbackRecoveryIntent(ownerId, challengeId,
      { confirmation: challenge.confirmationPhrase });
    return { status: "reconciled", challengeId, result: applied,
      continuityAudit: await auditLifecycleDispositionCheckpointRollbackContinuity(ownerId),
      readOnly: false, mutationAllowed: false, externalAnchorMutationPerformed: false };
  }

  async function inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId) {
    assertOwner(ownerId);
    const [checkpoint, inspection, receiptCheckpoint, keyBinding, continuity] = await Promise.all([
      getMarkerRecoveryJournalLifecycleDispositionCheckpointState(ownerId),
      inspectMarkerRecoveryJournalLifecycleDispositionCheckpointRecovery(ownerId),
      getRecoveryReceiptCheckpointState(ownerId), getCurrentKeyBinding(ownerId),
      auditMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity(ownerId)
    ]);
    const rollback = checkpoint.status === "rollback_suspected"
      || ["continuity_unproven", "anchor_missing"].includes(inspection.status)
      || (checkpoint.status === "unhealthy" && (checkpoint.findings || []).some(item => /ROLLBACK|MARKER_CONFLICT|SOURCE_ROLLBACK|MISSING_AFTER_ENROLLMENT/.test(item.code || "")));
    const fingerprint = lifecycleDispositionRollbackFingerprint(checkpoint, inspection, receiptCheckpoint);
    return { status: rollback ? "rollback_suspected" : checkpoint.usableForCurrentDecision === true ? "current" : checkpoint.status || "unavailable",
      domain: "cross_domain_recovery_intent_closure_lifecycle_dispositions", checkpoint: clean(checkpoint), inspection: clean(inspection),
      recoveryReceiptCheckpoint: clean(receiptCheckpoint), continuityStatus: continuity.status,
      continuityDigest: sha256(canonical({ status: continuity.status, intentCount: continuity.intentCount,
        finalizationCount: continuity.finalizationCount, pendingCount: continuity.pendingCount,
        pendingDispositionCount: continuity.pendingDispositionCount, staleCount: continuity.staleCount,
        findings: (continuity.findings || []).map(item => item.code).sort() })),
      checkpointFingerprint: fingerprint, keyLifecycleBindingDigest: keyBinding?.bindingDigest || null,
      recoverable: false, automaticRepairAllowed: false,
      findings: [...(checkpoint.findings || []), ...(inspection.findings || []),
        ...(rollback ? [{ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REQUIRES_EXPLICIT_RECOVERY" }] : [])],
      usableForCurrentDecision: (!checkpoint.enabled && !checkpoint.required || checkpoint.usableForCurrentDecision === true)
        && receiptCheckpoint.usableForCurrentDecision !== false && !rollback && continuity.status !== "unhealthy",
      readOnly: true, mutationAllowed: false };
  }

  async function prepareLifecycleDispositionCheckpointRollbackRecoveryIntent(ownerId, { disposition, reason } = {}) {
    assertOwner(ownerId);
    if (!LIFECYCLE_DISPOSITION_ROLLBACK_ACTIONS.has(disposition))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_DISPOSITION_INVALID",
        "Disposition harus quarantine atau mark_unrecoverable", 400);
    if (typeof reason !== "string" || reason.trim() !== reason || reason.length < 12 || reason.length > 240
      || /[\u0000-\u001f\u007f]/.test(reason))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REASON_INVALID",
        "Alasan rollback recovery wajib 12–240 karakter", 400);
    const inspection = await inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId);
    if (inspection.status !== "rollback_suspected")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_NOT_DETECTED",
        "Recovery intent hanya dapat dibuat ketika rollback external anchor terdeteksi", 409,
        { status: inspection.status, findings: inspection.findings });
    if (inspection.recoveryReceiptCheckpoint.enabled && inspection.recoveryReceiptCheckpoint.usableForCurrentDecision !== true)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_ROLLBACK_RECOVERY_RECEIPT_CHECKPOINT_NOT_CURRENT",
        "Rollback recovery intent diblokir karena recovery-receipt checkpoint tidak current", 409,
        { status: inspection.recoveryReceiptCheckpoint.status || "unavailable" });
    const rows = await store.listEvidence(ownerId);
    const existing = rows.filter(row => row?.ownerId === ownerId && row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND
      && row.checkpointFingerprint === inspection.checkpointFingerprint && row.status === "prepared");
    if (existing.length) {
      const challenge = existing[0];
      if (challenge.digest !== digestRecord(challenge))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_INVALID",
          "Rollback recovery challenge tersimpan tidak valid", 409);
      await appendLifecycleDispositionRollbackContinuityPhase(ownerId, challenge, "challenge_prepared", {
        challengeCreatedAt: challenge.createdAt, preparedChallengeDigest: challenge.preparedChallengeDigest || challenge.digest });
      return { status: "prepared", challengeId: challenge.id, challengeDigest: challenge.digest,
        disposition: challenge.disposition, expiresAt: challenge.expiresAt,
        confirmation: challenge.confirmationPhrase, idempotent: true, inspection, readOnly: false, mutationAllowed: false };
    }
    const now = isoNow(clock), id = `${LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND}-${randomUUID()}`;
    const keyBinding = await getCurrentKeyBinding(ownerId);
    const confirmationPhrase = `RESOLVE LIFECYCLE DISPOSITION CHECKPOINT ROLLBACK ${sha256(canonical({ ownerId, id, fingerprint: inspection.checkpointFingerprint, disposition })).slice(0, 12)}`;
    const unsigned = { id, ownerId, kind: LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND, schemaVersion: 1,
      status: "prepared", disposition, reason, checkpointFingerprint: inspection.checkpointFingerprint,
      checkpointStatus: inspection.checkpoint.status || null, anchorDigest: inspection.checkpoint.anchorDigest || inspection.inspection.anchorDigest || null,
      anchorSequence: inspection.checkpoint.anchorSequence ?? inspection.inspection.anchorSequence ?? null,
      markerDigest: inspection.inspection.markerDigest || null, markerSequence: inspection.inspection.markerSequence ?? null,
      inspectionStatus: inspection.inspection.status || null, continuityDigest: inspection.continuityDigest,
      recoveryReceiptCheckpointDigest: inspection.recoveryReceiptCheckpoint.snapshotDigest || null,
      keyLifecycleBindingDigest: keyBinding?.bindingDigest || null, confirmationPhrase,
      createdAt: now, expiresAt: new Date(Date.parse(now) + 10 * 60_000).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    await appendLifecycleDispositionRollbackContinuityPhase(ownerId, challenge, "challenge_prepared", {
      challengeCreatedAt: challenge.createdAt, preparedChallengeDigest: challenge.digest });
    return { status: "prepared", challengeId: id, challengeDigest: challenge.digest, disposition,
      expiresAt: challenge.expiresAt, confirmation: confirmationPhrase, inspection,
      readOnly: false, mutationAllowed: false };
  }

  async function applyLifecycleDispositionCheckpointRollbackRecoveryIntent(ownerId, challengeId, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND
      || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_INVALID",
        "Rollback recovery challenge tidak valid", 409);
    const operationId = sha256(canonical({ ownerId, challengeId, checkpointFingerprint: challenge.checkpointFingerprint,
      disposition: challenge.disposition, reason: challenge.reason }));
    const eventId = `${LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_KIND}-${operationId.slice(0, 32)}`;
    const finalizationId = `${LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_KIND}-${operationId.slice(0, 32)}`;
    let event = await store.getEvidence(ownerId, eventId);
    let finalization = await store.getEvidence(ownerId, finalizationId);
    let current = await inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId);
    if (current.checkpointFingerprint !== challenge.checkpointFingerprint && !event)
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_SNAPSHOT_CHANGED",
        "Checkpoint atau closure evidence berubah sejak recovery intent dibuat", 409,
        { expectedFingerprint: challenge.checkpointFingerprint, actualFingerprint: current.checkpointFingerprint });
    if (!event) {
      if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt))
        || Date.parse(challenge.expiresAt) <= Date.parse(String(clock())) || confirmation !== challenge.confirmationPhrase)
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EXPIRED_OR_UNCONFIRMED",
          "Challenge rollback recovery kedaluwarsa atau konfirmasi tidak cocok", 409);
      if (current.status !== "rollback_suspected")
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_NOT_DETECTED",
          "Rollback tidak lagi terdeteksi; siapkan ulang berdasarkan checkpoint terkini", 409);
      const keyBinding = await getCurrentKeyBinding(ownerId);
      if ((keyBinding?.bindingDigest || null) !== (challenge.keyLifecycleBindingDigest || null))
        throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_KEY_CUTOFF",
          "Signing-key lifecycle berubah sebelum recovery event tersimpan", 409);
      const unsigned = { id: eventId, ownerId, kind: LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_KIND, schemaVersion: 1,
        operationId, challengeId: challenge.id, challengeDigest: challenge.preparedChallengeDigest || challenge.digest, disposition: challenge.disposition,
        reason: challenge.reason, checkpointFingerprint: challenge.checkpointFingerprint,
        checkpointStatus: challenge.checkpointStatus, anchorDigest: challenge.anchorDigest, anchorSequence: challenge.anchorSequence,
        markerDigest: challenge.markerDigest, markerSequence: challenge.markerSequence,
        continuityDigest: challenge.continuityDigest, recoveryReceiptCheckpointDigest: challenge.recoveryReceiptCheckpointDigest,
        preparedKeyLifecycleBindingDigest: challenge.keyLifecycleBindingDigest || null,
        createdAt: isoNow(clock), mutationOfExternalAnchor: false, automaticRepairPerformed: false };
      const attestation = await createAttestation(ownerId, unsigned, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
        keyLifecycleBinding: keyBinding, required: true, attestationIdSuffix: operationId });
      const signed = { ...unsigned, attestation: attestation || null };
      event = { ...signed, digest: digestRecord(signed) };
      try { await store.putEvidence(ownerId, event, { overwrite: false }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, eventId);
        if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.challengeDigest !== challenge.digest
          || concurrent.checkpointFingerprint !== challenge.checkpointFingerprint)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_CONFLICT",
            "Rollback recovery event memiliki konflik CAS atau binding", 409);
        event = concurrent;
      }
    } else if (event.digest !== digestRecord(event) || event.challengeDigest !== (challenge.preparedChallengeDigest || challenge.digest)
      || event.checkpointFingerprint !== challenge.checkpointFingerprint || event.operationId !== operationId) {
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_INVALID",
        "Rollback recovery event yang tersimpan tidak cocok dengan challenge", 409);
    }
    const eventVerification = await verifyAttestation(ownerId, event, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
      required: true, checkCurrent: false });
    if (!eventVerification?.historicallyValid || eventVerification.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_INVALID",
        "Attestation rollback recovery tidak valid", 409, { status: eventVerification?.status || "unavailable" });
    await appendLifecycleDispositionRollbackContinuityPhase(ownerId, challenge, "rollback_event_recorded", {
      rollbackEventId: event.id, rollbackEventDigest: event.digest, occurredAt: event.createdAt });
    const anchoredIntentReceipt = await appendLifecycleDispositionRollbackRecoveryReceipt(ownerId, event, "intent");
    await appendLifecycleDispositionRollbackContinuityPhase(ownerId, challenge, "external_intent_receipt_anchored", {
      rollbackEventId: event.id, rollbackEventDigest: event.digest,
      externalReceiptId: anchoredIntentReceipt.id, externalReceiptDigest: anchoredIntentReceipt.digest,
      occurredAt: anchoredIntentReceipt.occurredAt });
    current = await inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId);
    const keyBindingNow = await getCurrentKeyBinding(ownerId);
    const keyCutoffDetected = (event.preparedKeyLifecycleBindingDigest || null) !== (keyBindingNow?.bindingDigest || null);
    if (!finalization) {
      const unsigned = { id: finalizationId, ownerId, kind: LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_KIND, schemaVersion: 1,
        operationId: `${operationId}:finalize`, challengeId: challenge.id, challengeDigest: challenge.digest,
        rollbackEventId: event.id, rollbackEventDigest: event.digest, disposition: challenge.disposition,
        observedCheckpointFingerprint: current.checkpointFingerprint, observedCheckpointStatus: current.checkpoint.status || null,
        currentAnchorDigest: current.checkpoint.anchorDigest || null, currentAnchorSequence: current.checkpoint.anchorSequence ?? null,
        keyLifecycleBindingDigest: keyBindingNow?.bindingDigest || null, keyCutoffDetected,
        revalidatedAfterExternalRecovery: current.status === "current" && current.checkpoint.usableForCurrentDecision === true,
        finalizedAt: isoNow(clock), mutationOfExternalAnchor: false };
      const attestation = await createAttestation(ownerId, unsigned, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
        keyLifecycleBinding: keyBindingNow, required: true, attestationIdSuffix: `${operationId}:finalize` });
      const signed = { ...unsigned, attestation: attestation || null };
      finalization = { ...signed, digest: digestRecord(signed) };
      try { await store.putEvidence(ownerId, finalization, { overwrite: false }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, finalizationId);
        if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.rollbackEventDigest !== event.digest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_CONFLICT",
            "Rollback finalization receipt memiliki konflik CAS", 409);
        finalization = concurrent;
      }
    }
    const finalVerification = await verifyAttestation(ownerId, finalization, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
      required: true, checkCurrent: false });
    if (finalization.digest !== digestRecord(finalization) || finalization.rollbackEventId !== event.id
      || finalization.rollbackEventDigest !== event.digest || !finalVerification?.historicallyValid || finalVerification.status === "unhealthy")
      throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_INVALID",
        "Rollback finalization receipt tidak dapat diverifikasi", 409);
    await appendLifecycleDispositionRollbackContinuityPhase(ownerId, challenge, "finalization_receipt_recorded", {
      rollbackEventId: event.id, rollbackEventDigest: event.digest, finalizationReceiptId: finalization.id,
      finalizationReceiptDigest: finalization.digest, occurredAt: finalization.finalizedAt });
    const anchoredFinalizationReceipt = await appendLifecycleDispositionRollbackRecoveryReceipt(ownerId, finalization, "finalization");
    await appendLifecycleDispositionRollbackContinuityPhase(ownerId, challenge, "external_finalization_receipt_anchored", {
      rollbackEventId: event.id, rollbackEventDigest: event.digest, finalizationReceiptId: finalization.id,
      finalizationReceiptDigest: finalization.digest, externalReceiptId: anchoredFinalizationReceipt.id,
      externalReceiptDigest: anchoredFinalizationReceipt.digest, occurredAt: anchoredFinalizationReceipt.occurredAt });
    const latestChallenge = await store.getEvidence(ownerId, challenge.id);
    if (latestChallenge.status !== "completed") {
      const completedUnsigned = { ...clean(latestChallenge), status: "completed",
        preparedChallengeDigest: latestChallenge.preparedChallengeDigest || latestChallenge.digest,
        rollbackEventId: event.id, rollbackEventDigest: event.digest, finalizationReceiptId: finalization.id,
        finalizationReceiptDigest: finalization.digest, keyCutoffDetected, completedAt: isoNow(clock) };
      delete completedUnsigned.digest;
      const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
      try { await store.putEvidence(ownerId, completed, { expectedVersion: latestChallenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, challenge.id);
        if (!concurrent || concurrent.status !== "completed" || concurrent.finalizationReceiptDigest !== finalization.digest)
          throw new AgenticError("RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_CAS_CONFLICT",
            "Rollback recovery tersimpan tetapi challenge belum dapat difinalisasi", 409);
      }
    }
    const finalizedChallenge = await store.getEvidence(ownerId, challenge.id);
    await appendLifecycleDispositionRollbackContinuityPhase(ownerId, finalizedChallenge, "challenge_finalized", {
      rollbackEventId: event.id, rollbackEventDigest: event.digest, finalizationReceiptId: finalization.id,
      finalizationReceiptDigest: finalization.digest, occurredAt: finalizedChallenge.completedAt });
    const revalidation = await revalidateLifecycleDispositionCheckpointRollbackRecovery(ownerId, challenge.id);
    return { status: "recorded_without_anchor_mutation", disposition: challenge.disposition,
      rollbackEvent: event, finalizationReceipt: finalization, anchoredIntentReceipt,
      anchoredFinalizationReceipt, keyCutoffDetected, revalidation,
      continuityAudit: await auditLifecycleDispositionCheckpointRollbackContinuity(ownerId),
      checkpointAudit: await inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId),
      readOnly: false, mutationAllowed: false, externalAnchorChanged: false };
  }

  async function auditLifecycleDispositionCheckpointRollbackRecovery(ownerId) {
    assertOwner(ownerId);
    const rows = (await store.listEvidence(ownerId)).filter(row => row?.ownerId === ownerId);
    const challenges = rows.filter(row => row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_KIND);
    const events = rows.filter(row => row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_KIND);
    const finalizations = rows.filter(row => row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_KIND);
    const current = await inspectLifecycleDispositionCheckpointRollbackRecovery(ownerId);
    const receiptLedger = await readCheckpointRecoveryLedger(ownerId);
    const continuityAudit = await auditLifecycleDispositionCheckpointRollbackContinuity(ownerId);
    const revalidationLifecycleAudit = await auditLifecycleDispositionRollbackRevalidationAttestationLifecycle(ownerId);
    const revalidationRecords = rows.filter(row => row.kind === LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KIND);
    const currentKeyBinding = await getCurrentKeyBinding(ownerId);
    const currentRevalidationCheckpointFingerprint = lifecycleDispositionRollbackFingerprint(current.checkpoint, current.inspection, {});
    const findings = [...current.findings, ...receiptLedger.findings, ...continuityAudit.findings, ...revalidationLifecycleAudit.findings];
    const anchoredRollbackReceipts = receiptLedger.events.filter(item => ["lifecycle_disposition_checkpoint_rollback_recovery_intent",
      "lifecycle_disposition_checkpoint_rollback_finalized", "lifecycle_disposition_checkpoint_rollback_continuity_phase",
      "lifecycle_disposition_checkpoint_rollback_revalidation_attested",
      LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_INTENT_EVENT_TYPE,
      LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_APPLIED_EVENT_TYPE,
      LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_LIFECYCLE_FINALIZATION_EVENT_TYPE].includes(item.eventType));
    for (const receiptEvent of anchoredRollbackReceipts) {
      const verification = await verifyAttestation(ownerId, receiptEvent, { attestationKind: CHECKPOINT_RECOVERY_EVENT_KIND,
        required: true, checkCurrent: false });
      if (!verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EXTERNAL_RECEIPT_ATTESTATION_INVALID",
          eventId: receiptEvent.id, reasonCode: verification?.reasonCode || null });
    }
    const eventByChallenge = new Map();
    for (const event of events) {
      if (eventByChallenge.has(event.challengeId)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_DUPLICATE", challengeId: event.challengeId });
      eventByChallenge.set(event.challengeId, event);
      const verification = await verifyAttestation(ownerId, event, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
        required: true, checkCurrent: false });
      if (event.digest !== digestRecord(event) || !verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_INVALID", eventId: event.id,
          reasonCode: verification?.reasonCode || null });
    }
    const finalByChallenge = new Map();
    for (const receipt of finalizations) {
      if (finalByChallenge.has(receipt.challengeId)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_DUPLICATE", challengeId: receipt.challengeId });
      finalByChallenge.set(receipt.challengeId, receipt);
      const verification = await verifyAttestation(ownerId, receipt, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
        required: true, checkCurrent: false });
      const event = eventByChallenge.get(receipt.challengeId);
      if (receipt.digest !== digestRecord(receipt) || !event || receipt.rollbackEventId !== event.id
        || receipt.rollbackEventDigest !== event.digest || !verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_INVALID", receiptId: receipt.id,
          reasonCode: verification?.reasonCode || null });
    }
    const revalidationReceipts = new Map(receiptLedger.events
      .filter(item => item.eventType === "lifecycle_disposition_checkpoint_rollback_revalidation_attested")
      .map(item => [item.revalidationAttestationId, item]));
    const latestRevalidationByChallenge = new Map();
    const latestCandidateByChallenge = new Map();
    for (const record of revalidationRecords) {
      const receipt = revalidationReceipts.get(record.id);
      if (!receipt) continue;
      const prior = latestCandidateByChallenge.get(record.challengeId);
      if (!prior || receipt.sequence > prior.receipt.sequence) latestCandidateByChallenge.set(record.challengeId, { record, receipt });
    }
    const lifecycleByTarget = new Map(revalidationLifecycleAudit.latestByTarget.map(item => [item.targetAttestationId, item]));
    const cutoffReplacementIds = new Set(revalidationLifecycleAudit.latestByTarget
      .filter(item => item.action === "renew" && item.keyCutoffDetected && item.replacementAttestationId)
      .map(item => item.replacementAttestationId));
    let revalidationPendingCount = 0, staleRevalidationCount = 0;
    for (const revalidation of revalidationRecords) {
      const verification = await verifyAttestation(ownerId, revalidation, { attestationKind: LIFECYCLE_DISPOSITION_ROLLBACK_ATTESTATION_KIND,
        required: true, checkCurrent: false }).catch(() => ({ status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }));
      const anchored = revalidationReceipts.get(revalidation.id);
      if (revalidation.digest !== digestRecord(revalidation) || !verification?.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_ATTESTATION_INVALID",
          attestationId: revalidation.id, reasonCode: verification?.reasonCode || null });
      if (!anchored || anchored.revalidationAttestationDigest !== revalidation.digest
        || anchored.challengeId !== revalidation.challengeId || anchored.rollbackEventDigest !== revalidation.rollbackEventDigest
        || anchored.finalizationReceiptDigest !== revalidation.finalizationReceiptDigest
        || anchored.continuityLedgerDigest !== revalidation.continuityLedgerDigest) {
        revalidationPendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_EXTERNAL_RECEIPT_MISSING",
          attestationId: revalidation.id });
      }
      const lifecycleState = lifecycleByTarget.get(revalidation.id) || null;
      const anchorDrift = revalidation.checkpointFingerprint !== currentRevalidationCheckpointFingerprint;
      const continuityDrift = revalidation.continuityLedgerDigest !== continuityAudit.snapshotDigest;
      const latestCandidate = latestCandidateByChallenge.get(revalidation.challengeId)?.record?.id === revalidation.id;
      if (latestCandidate && (anchorDrift || continuityDrift)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EXTERNAL_ANCHOR_DRIFT_DETECTED",
        attestationId: revalidation.id, anchorDrift, continuityDrift,
        expectedCheckpointFingerprint: revalidation.checkpointFingerprint,
        observedCheckpointFingerprint: currentRevalidationCheckpointFingerprint });
      const supersededOrRevoked = Boolean(lifecycleState && ["renew", "revoke"].includes(lifecycleState.action));
      const ageMs = Date.parse(String(clock())) - Date.parse(String(revalidation.createdAt || ""));
      const ageCurrent = Number.isFinite(ageMs) && ageMs >= 0 && ageMs <= maxFreshnessAgeMs;
      const currentMatch = revalidation.checkpointFingerprint === currentRevalidationCheckpointFingerprint
        && revalidation.continuityLedgerDigest === continuityAudit.snapshotDigest
        && (revalidation.keyLifecycleBindingDigest || null) === (currentKeyBinding?.bindingDigest || null)
        && !revalidation.keyCutoffDetected && ageCurrent && !supersededOrRevoked && !cutoffReplacementIds.has(revalidation.id);
      if (latestCandidate && !ageCurrent) findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_EXPIRED",
        attestationId: revalidation.id, ageMs: Number.isFinite(ageMs) ? ageMs : null });
      if (lifecycleState?.action === "revoke") findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_REVOKED",
        attestationId: revalidation.id, lifecycleChallengeId: lifecycleState.challengeId });
      if (lifecycleState?.action === "renew") findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_SUPERSEDED",
        attestationId: revalidation.id, replacementAttestationId: lifecycleState.replacementAttestationId || null });
      if (cutoffReplacementIds.has(revalidation.id)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_KEY_CUTOFF",
        attestationId: revalidation.id, lifecycleChallengeId: revalidationLifecycleAudit.latestByTarget.find(item => item.replacementAttestationId === revalidation.id)?.challengeId || null });
      if (anchored) {
        const prior = latestRevalidationByChallenge.get(revalidation.challengeId);
        if (!prior || anchored.sequence > prior.receipt.sequence)
          latestRevalidationByChallenge.set(revalidation.challengeId, { attestation: revalidation, receipt: anchored,
            current: currentMatch && anchored.revalidationAttestationDigest === revalidation.digest });
      }
    }
    for (const [challengeId, latest] of latestRevalidationByChallenge) {
      if (!latest.current) {
        staleRevalidationCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_REVALIDATION_STALE",
          attestationId: latest.attestation.id, challengeId,
          checkpointMatch: latest.attestation.checkpointFingerprint === currentRevalidationCheckpointFingerprint,
          continuityMatch: latest.attestation.continuityLedgerDigest === continuityAudit.snapshotDigest,
          keyLifecycleMatch: (latest.attestation.keyLifecycleBindingDigest || null) === (currentKeyBinding?.bindingDigest || null) });
      }
    }
    const cases = [];
    let pendingCount = 0, staleReceiptCount = 0;
    for (const challenge of challenges) {
      const event = eventByChallenge.get(challenge.id), receipt = finalByChallenge.get(challenge.id);
      const intentReceiptOperationId = event ? `lifecycle-disposition-checkpoint-rollback:${event.operationId}:intent` : null;
      const finalReceiptOperationId = event ? `lifecycle-disposition-checkpoint-rollback:${event.operationId}:finalization` : null;
      const anchoredIntentReceipt = receiptLedger.events.find(item => item.operationId === intentReceiptOperationId);
      const anchoredFinalizationReceipt = receiptLedger.events.find(item => item.operationId === finalReceiptOperationId);
      const unsigned = clean(challenge); delete unsigned.digest;
      if (challenge.digest !== digestRecord(unsigned)) findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_CHALLENGE_INVALID", challengeId: challenge.id });
      const preparedChallengeDigest = challenge.preparedChallengeDigest || challenge.digest;
      if (event && (event.challengeId !== challenge.id || event.challengeDigest !== preparedChallengeDigest
        || event.disposition !== challenge.disposition || event.checkpointFingerprint !== challenge.checkpointFingerprint))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EVENT_BINDING_INVALID", challengeId: challenge.id, eventId: event.id });
      if (receipt && (receipt.challengeId !== challenge.id || receipt.challengeDigest !== preparedChallengeDigest
        || receipt.disposition !== challenge.disposition || receipt.rollbackEventId !== event?.id
        || receipt.rollbackEventDigest !== event?.digest))
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_FINALIZATION_BINDING_INVALID", challengeId: challenge.id, receiptId: receipt.id });
      if (!event || !receipt || challenge.status !== "completed" || challenge.rollbackEventDigest !== event?.digest
        || challenge.finalizationReceiptDigest !== receipt?.digest || !anchoredIntentReceipt || !anchoredFinalizationReceipt
        || anchoredIntentReceipt.rollbackOperationId !== event?.operationId
        || anchoredIntentReceipt.disposition !== challenge.disposition
        || anchoredIntentReceipt.rollbackEventDigest !== event?.digest
        || anchoredIntentReceipt.rollbackChallengeDigest !== preparedChallengeDigest
        || anchoredFinalizationReceipt.rollbackOperationId !== event?.operationId
        || anchoredFinalizationReceipt.disposition !== challenge.disposition
        || anchoredFinalizationReceipt.rollbackEventDigest !== event?.digest || anchoredFinalizationReceipt.rollbackEventId !== event.id
        || anchoredFinalizationReceipt.rollbackChallengeDigest !== preparedChallengeDigest) {
        pendingCount++;
        findings.push({ code: "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_RECOVERY_PENDING", challengeId: challenge.id,
          anchoredIntentReceiptId: anchoredIntentReceipt?.id || null, anchoredFinalizationReceiptId: anchoredFinalizationReceipt?.id || null });
      }
      const revalidated = Boolean(receipt && current.status === "current" && current.checkpoint.usableForCurrentDecision === true
        && current.checkpoint.anchorSequence > (challenge.anchorSequence ?? 0)
        && current.checkpoint.historyNotProven !== true && current.checkpoint.policyDrift !== true);
      const revalidation = latestRevalidationByChallenge.get(challenge.id) || null;
      const revalidationCurrent = Boolean(revalidation?.current && revalidation.attestation.checkpointFingerprint === currentRevalidationCheckpointFingerprint
        && revalidation.attestation.continuityLedgerDigest === continuityAudit.snapshotDigest
        && (revalidation.attestation.keyLifecycleBindingDigest || null) === (currentKeyBinding?.bindingDigest || null));
      if (receipt && !revalidated) staleReceiptCount++;
      cases.push({ challengeId: challenge.id, status: !event || !receipt ? "pending" : revalidated && revalidationCurrent ? "revalidated_after_external_recovery"
          : revalidated ? "revalidation_attestation_stale" : "recorded_rollback_unresolved",
        disposition: challenge.disposition, eventId: event?.id || null, finalizationReceiptId: receipt?.id || null,
        anchoredIntentReceiptId: anchoredIntentReceipt?.id || null, anchoredFinalizationReceiptId: anchoredFinalizationReceipt?.id || null,
        revalidationAttestationId: revalidation?.attestation.id || null, revalidationExternalReceiptId: revalidation?.receipt.id || null,
        revalidationStatus: revalidation?.attestation.status || "not_revalidated", revalidationCurrent,
        externalReceiptBindingValid: Boolean(anchoredIntentReceipt && anchoredFinalizationReceipt
          && anchoredIntentReceipt.rollbackOperationId === event?.operationId && anchoredIntentReceipt.disposition === challenge.disposition
          && anchoredIntentReceipt.rollbackEventDigest === event?.digest
          && anchoredIntentReceipt.rollbackChallengeDigest === preparedChallengeDigest
          && anchoredFinalizationReceipt.rollbackOperationId === event?.operationId && anchoredFinalizationReceipt.disposition === challenge.disposition
          && anchoredFinalizationReceipt.rollbackEventDigest === event?.digest && anchoredFinalizationReceipt.rollbackEventId === event?.id
          && anchoredFinalizationReceipt.rollbackChallengeDigest === preparedChallengeDigest),
        challengeBindingValid: Boolean(challenge.status === "completed" && challenge.rollbackEventDigest === event?.digest
          && challenge.finalizationReceiptDigest === receipt?.digest),
        keyCutoffDetected: Boolean(challenge.keyCutoffDetected || receipt?.keyCutoffDetected || revalidation?.attestation.keyCutoffDetected),
        revalidatedAfterExternalRecovery: revalidated, usableForCurrentDecision: revalidated && revalidationCurrent
          && revalidation.attestation.usableForCurrentDecision === true });
    }
    const hard = findings.some(item => /_INVALID|_DUPLICATE|_UNHEALTHY|_CONFLICT/.test(item.code || ""));
    const activeRollback = current.status === "rollback_suspected";
    const continuityRequired = challenges.some(challenge => eventByChallenge.has(challenge.id));
    const continuityCurrent = !continuityRequired || continuityAudit.usableForCurrentDecision === true;
    const revalidationCoverageComplete = challenges.every(challenge => !eventByChallenge.has(challenge.id)
      || Boolean(latestRevalidationByChallenge.get(challenge.id)));
    const lifecycleCheckpointNotCurrent = revalidationLifecycleAudit.lifecycleCheckpoint?.enabled === true
      && revalidationLifecycleAudit.lifecycleCheckpoint.usableForCurrentDecision !== true;
    const status = hard ? "unhealthy" : pendingCount || revalidationPendingCount || revalidationLifecycleAudit.pendingCount > 0
        || continuityAudit.status === "recovery_required" || lifecycleCheckpointNotCurrent
        ? "recovery_required" : activeRollback || staleReceiptCount || staleRevalidationCount || !continuityCurrent
          ? "rollback_unresolved" : current.status === "current" ? "revalidated" : current.status;
    return { status, ownerId, checkpointStatus: current.status, activeRollback, challengeCount: challenges.length,
      eventCount: events.length, finalizationCount: finalizations.length, pendingCount, staleReceiptCount, cases,
      continuityAudit, continuityPendingCount: continuityAudit.pendingCount || 0, revalidationLifecycleAudit,
      revalidationLifecyclePendingCount: revalidationLifecycleAudit.pendingCount || 0,
      revalidationAttestationCount: revalidationRecords.length, revalidationPendingCount, staleRevalidationCount,
      latestRevalidations: [...latestRevalidationByChallenge.values()].map(item => ({ attestationId: item.attestation.id,
        challengeId: item.attestation.challengeId, status: item.attestation.status, current: item.current,
        externalReceiptId: item.receipt.id, usableForCurrentDecision: item.attestation.usableForCurrentDecision === true && item.current })),
      checkpointFingerprint: current.checkpointFingerprint, checkpoint: current.checkpoint,
      externalAnchorDriftDetected: findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_LIFECYCLE_DISPOSITION_ROLLBACK_EXTERNAL_ANCHOR_DRIFT_DETECTED")
        || current.status === "rollback_suspected",
      recoveryReceiptCheckpoint: current.recoveryReceiptCheckpoint, findings,
      usableForCurrentDecision: !hard && pendingCount === 0 && revalidationPendingCount === 0
        && revalidationLifecycleAudit.pendingCount === 0 && revalidationLifecycleAudit.usableForCurrentDecision !== false
        && staleRevalidationCount === 0 && continuityCurrent && revalidationCoverageComplete && challenges.every(challenge => !eventByChallenge.has(challenge.id)
          || cases.find(item => item.challengeId === challenge.id)?.usableForCurrentDecision === true)
        && !activeRollback
        && (current.status === "current" && current.checkpoint.usableForCurrentDecision === true
          || current.status === "not_configured" && current.checkpoint.usableForCurrentDecision === true)
        && current.recoveryReceiptCheckpoint.usableForCurrentDecision !== false,
      readOnly: true, mutationAllowed: false, externalAnchorChanged: false };
  }

  async function auditClosure(ownerId) {
    assertOwner(ownerId);
    const [transitionAudit, dispositionLedger, intents, orphans, keyBinding, checkpoint,
      transitionCheckpoint, dispositionCheckpoint, recoveryReceiptAudit, freshnessAttestation, markerRecoveryAudit,
      lifecycleDispositionRollbackRecoveryAudit] = await Promise.all([
      auditStatusTransitions(ownerId), readDispositionLedger(ownerId), getIntentRows(ownerId), getOrphanCandidates(ownerId),
      getCurrentKeyBinding(ownerId), getStrictCheckpointState(ownerId),
      getTransitionCheckpointState(ownerId), getDispositionCheckpointState(ownerId),
      auditCheckpointRecoveryReceipts(ownerId), auditCheckpointFreshnessAttestation(ownerId),
      auditRecoveryReceiptCheckpointMarkerRecovery(ownerId), auditLifecycleDispositionCheckpointRollbackRecovery(ownerId)
    ]);
    const markerJournalAttestationAudit = recoveryReceiptAudit.markerRecoveryJournalAttestationAudit
      || await auditMarkerRecoveryJournalCheckpointAttestation(ownerId);
    const findings = [...transitionAudit.findings, ...dispositionLedger.findings, ...recoveryReceiptAudit.findings,
      ...(markerRecoveryAudit.findings || []), ...(lifecycleDispositionRollbackRecoveryAudit.findings || []),
      ...(requireMarkerRecoveryJournalAttestation ? (markerJournalAttestationAudit.findings || []) : [])];
    if (requireFreshnessAttestation && freshnessAttestation.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_NOT_CURRENT", status: freshnessAttestation.status });
    for (const [label, state] of [["transition", transitionCheckpoint], ["disposition", dispositionCheckpoint]]) {
      if (state.enabled && state.usableForCurrentDecision !== true)
        findings.push({ code: ["unhealthy", "rollback_suspected", "policy_drift", "invalid"].includes(state.status)
          ? `RECOVERY_INTENT_CLOSURE_${label.toUpperCase()}_CHECKPOINT_UNHEALTHY`
          : `RECOVERY_INTENT_CLOSURE_${label.toUpperCase()}_CHECKPOINT_NOT_CURRENT`,
        status: state.status || "unavailable", findings: state.findings || [] });
    }
    const rows = intents.filter(item => item?.ownerId === ownerId && item.kind === intentKind);
    const latestDispositionByIntent = new Map();
    for (const event of dispositionLedger.events) latestDispositionByIntent.set(event.intentId, event);
    const verifiedDispositionEvents = new Map();
    let staleDisposition = false;
    for (const event of dispositionLedger.events) {
      let verification = { status: "not_present", historicallyValid: false, usableForCurrentDecision: false };
      try { if (event.attestation) verification = await verifyAttestation(ownerId, event, { attestationKind: DISPOSITION_ATTESTATION_KIND,
        required: true, checkCurrent: latestDispositionByIntent.get(event.intentId)?.id === event.id }); }
      catch { verification = { status: "unhealthy", historicallyValid: false, reasonCode: "VERIFIER_FAILED" }; }
      verifiedDispositionEvents.set(event.id, verification);
      if (!event.attestation || !verification.historicallyValid || verification.status === "unhealthy")
        findings.push({ code: "RECOVERY_INTENT_ORPHAN_DISPOSITION_ATTESTATION_INVALID", eventId: event.id,
          reasonCode: verification.reasonCode || null });
      else if (latestDispositionByIntent.get(event.intentId)?.id === event.id && verification.status !== "verified_current") {
        staleDisposition = true;
        findings.push({ code: "RECOVERY_INTENT_ORPHAN_DISPOSITION_ATTESTATION_STALE", eventId: event.id,
          status: verification.status, staleReasons: verification.staleReasons || [] });
      }
    }
    const dispositionedIntents = [], unresolvedOrphans = [];
    for (const orphan of orphans) {
      const event = latestDispositionByIntent.get(orphan.intentId);
      const verification = event ? verifiedDispositionEvents.get(event.id) : null;
      const validDisposition = Boolean(event && event.intentDigest === orphan.intentDigest && event.orphanReason === orphan.reason
        && event.disposition && DISPOSITIONS.has(event.disposition) && verification?.historicallyValid && verification.status === "verified_current");
      if (validDisposition) dispositionedIntents.push({ intentId: orphan.intentId, intentDigest: orphan.intentDigest, status: orphan.status,
        disposition: event.disposition, dispositionEventId: event.id, dispositionEventDigest: event.digest, orphanReason: orphan.reason,
        usableForCurrentDecision: false });
      else unresolvedOrphans.push({ ...orphan, dispositionEventId: event?.id || null,
        dispositionStatus: event ? verification?.status || "unverified" : "not_dispositioned" });
    }
    for (const event of dispositionLedger.events) {
      const intent = rows.find(row => row.id === event.intentId);
      if (!intent || intent.digest !== event.intentDigest)
        findings.push({ code: "RECOVERY_INTENT_ORPHAN_DISPOSITION_TARGET_INVALID", eventId: event.id, intentId: event.intentId });
    }
    if (unresolvedOrphans.length) findings.push({ code: "RECOVERY_INTENT_CLOSURE_ORPHANS_UNRESOLVED", count: unresolvedOrphans.length,
      intentIds: unresolvedOrphans.map(item => item.intentId) });
    if (checkpoint.required && checkpoint.usableForCurrentDecision !== true)
      findings.push({ code: "RECOVERY_INTENT_CLOSURE_CHECKPOINT_NOT_CURRENT", status: checkpoint.status || "unavailable" });
    const dispositionedIds = new Set(dispositionedIntents.map(item => `${item.intentId}:${item.intentDigest}`));
    const pendingCount = rows.filter(item => ["prepared", "recovery_required"].includes(item.status)
      && !dispositionedIds.has(`${item.id}:${item.digest}`)).length;
    if (pendingCount) findings.push({ code: "RECOVERY_INTENT_CLOSURE_PENDING_INTENTS", pendingCount });
    const hard = findings.some(item => /INVALID|UNHEALTHY|CONFLICT|CHAIN|TARGET_INVALID/.test(item.code || ""));
    const historyUnproven = transitionAudit.status === "history_unproven" || transitionAudit.historyNotProven;
    const checkpointStale = [transitionCheckpoint, dispositionCheckpoint].some(state => state.enabled && state.usableForCurrentDecision !== true);
    const status = hard ? "unhealthy" : staleDisposition || transitionAudit.status === "stale" || checkpointStale
        || lifecycleDispositionRollbackRecoveryAudit.status === "rollback_unresolved"
        || lifecycleDispositionRollbackRecoveryAudit.status === "recovery_required"
        || (requireFreshnessAttestation && freshnessAttestation.usableForCurrentDecision !== true)
        || recoveryReceiptAudit.status === "stale" || ["stale", "checkpoint_not_current"].includes(markerRecoveryAudit.status) ? "stale"
      : unresolvedOrphans.length || pendingCount || recoveryReceiptAudit.pendingCount > 0
        || recoveryReceiptAudit.lifecycleRecoveryPendingCount > 0 || markerRecoveryAudit.pendingCount > 0 ? "recovery_required"
        : historyUnproven ? "history_unproven"
          : dispositionedIntents.length ? "closed_with_disposition"
            : transitionAudit.status === "healthy" && (!checkpoint.required || checkpoint.usableForCurrentDecision) ? "healthy"
              : rows.length ? "local_only" : "not_initialized";
    return { status, ownerId, transitionAudit, dispositionLedgerId: dispositionLedger.ledgerId,
      dispositionCount: dispositionLedger.count, dispositions: dispositionLedger.events.map(event => ({ ...event,
        verification: verifiedDispositionEvents.get(event.id) || null })), orphanCount: orphans.length,
      dispositionedIntents, unresolvedOrphans, pendingIntentCount: pendingCount, checkpoint, transitionCheckpoint, dispositionCheckpoint,
      currentKeyLifecycleBindingDigest: keyBinding?.bindingDigest || null, findings,
      recoveryReceiptAudit, recoveryReceiptCheckpoint: recoveryReceiptAudit.recoveryReceiptCheckpoint || null,
      recoveryReceiptContinuityAudit: recoveryReceiptAudit.continuityAudit || null, freshnessAttestation, markerRecoveryAudit,
      markerJournalAttestationAudit,
      closureComplete: unresolvedOrphans.length === 0 && pendingCount === 0 && recoveryReceiptAudit.pendingCount === 0
        && recoveryReceiptAudit.lifecycleRecoveryPendingCount === 0 && markerRecoveryAudit.pendingCount === 0 && ["healthy", "not_initialized"].includes(markerRecoveryAudit.status)
        && ["healthy", "not_initialized"].includes(recoveryReceiptAudit.status)
        && (!requireFreshnessAttestation || freshnessAttestation.usableForCurrentDecision === true)
        && (!requireMarkerRecoveryJournalAttestation || markerJournalAttestationAudit.usableForCurrentDecision === true)
        && !hard && !historyUnproven && !checkpointStale
        && lifecycleDispositionRollbackRecoveryAudit.usableForCurrentDecision !== false,
      usableForCurrentDecision: status === "healthy" && transitionAudit.usableForCurrentDecision === true
        && unresolvedOrphans.length === 0 && dispositionedIntents.length === 0 && pendingCount === 0 && recoveryReceiptAudit.pendingCount === 0
        && recoveryReceiptAudit.lifecycleRecoveryPendingCount === 0
        && (!requireFreshnessAttestation || freshnessAttestation.usableForCurrentDecision === true)
        && (!requireMarkerRecoveryJournalAttestation || markerJournalAttestationAudit.usableForCurrentDecision === true)
        && markerRecoveryAudit.usableForCurrentDecision === true
        && (!checkpoint.required || checkpoint.usableForCurrentDecision === true)
        && (!transitionCheckpoint.enabled || transitionCheckpoint.usableForCurrentDecision === true)
        && (!dispositionCheckpoint.enabled || dispositionCheckpoint.usableForCurrentDecision === true)
        && lifecycleDispositionRollbackRecoveryAudit.usableForCurrentDecision !== false,
      lifecycleDispositionRollbackRecoveryAudit,
      readOnly: true, mutationAllowed: false, deletionPerformed: false, compactionPerformed: false };
  }

  return Object.freeze({ recordStatusTransition, auditStatusTransitions, getStatusTransitionSnapshot, getOrphanDispositionSnapshot,
    prepareOrphanDisposition, applyOrphanDisposition, auditClosure, getCheckpointFreshnessSnapshot,
    prepareCheckpointRecoveryIntent, finalizeCheckpointRecoveryIntent, auditCheckpointRecoveryReceipts, auditCheckpointRecoveryReceiptContinuity, getCheckpointRecoverySnapshot,
    prepareRecoveryReceiptCheckpointMarkerRecoveryIntent, finalizeRecoveryReceiptCheckpointMarkerRecoveryIntent,
    getCheckpointMarkerRecoverySnapshot, auditRecoveryReceiptCheckpointMarkerRecovery,
    attestCheckpointFreshness, auditCheckpointFreshnessAttestation, prepareCheckpointFreshnessAttestationLifecycle,
    applyCheckpointFreshnessAttestationLifecycle, getMarkerRecoveryJournalAttestationSnapshot,
    attestMarkerRecoveryJournalCheckpoint, auditMarkerRecoveryJournalCheckpointAttestation,
    prepareMarkerRecoveryJournalAttestationLifecycle, applyMarkerRecoveryJournalAttestationLifecycle,
    prepareMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition,
    applyMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition,
    reconcileMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDispositionChallenge,
    getMarkerRecoveryJournalLifecycleDispositionSnapshot, auditMarkerRecoveryJournalLifecycleDispositionLedger,
    auditMarkerRecoveryJournalAttestationLifecycleFinalizationContinuity,
    auditMarkerRecoveryJournalAttestationLifecycleRecoveryIntents,
    inspectLifecycleDispositionCheckpointRollbackRecovery,
    prepareLifecycleDispositionCheckpointRollbackRecoveryIntent,
    applyLifecycleDispositionCheckpointRollbackRecoveryIntent,
    auditLifecycleDispositionCheckpointRollbackContinuity,
    reconcileLifecycleDispositionCheckpointRollbackRecovery,
    revalidateLifecycleDispositionCheckpointRollbackRecovery,
    getRollbackRevalidationLifecycleSnapshot,
    prepareLifecycleDispositionRollbackRevalidationAttestationLifecycle,
    applyLifecycleDispositionRollbackRevalidationAttestationLifecycle,
    auditLifecycleDispositionRollbackRevalidationAttestationLifecycle,
    reconcileLifecycleDispositionRollbackRevalidationAttestationLifecycle,
    monitorLifecycleDispositionRollbackRevalidationExternalAnchorDrift,
    attestRevalidationLifecycleCheckpointFreshness,
    auditRevalidationLifecycleCheckpointFreshnessAttestation,
    auditRevalidationLifecycleDriftEvidence,
    reconcileRevalidationLifecycleCheckpointEvidence,
    auditRevalidationLifecycleFreshnessSupersessionLedger,
    getRevalidationLifecycleRecoveryGateProofSnapshot,
    auditRevalidationLifecycleRecoveryGateProof,
    revalidateRevalidationLifecycleRecoveryGate,
    auditLifecycleDispositionCheckpointRollbackRecovery });
}
