import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const MAX_ID = 200;
const MAX_ALERTS = 500;
const MAX_EVENTS = 5000;
const MAX_SAMPLES = 200;
const MAX_ARCHIVE_BATCH = 500;
const MAX_ARCHIVES = 1000;
const MAX_EVALUATIONS = 2000;
const MAX_POLICY_EVENTS = 100;
const MAX_EVALUATION_ARCHIVES = 1000;
const MAX_EVALUATION_ARCHIVE_BATCH = 500;
const MAX_EXPORT_BYTES = 25 * 1024 * 1024;
const DEFAULT_POLICY = Object.freeze({
  windowMs: 60 * 60 * 1000,
  minSamples: 3,
  availabilityTarget: 0.99,
  maxPendingAgeMs: 5 * 60 * 1000,
  maxLatencyMs: 1000,
  highObservations: 3,
  highAfterMs: 5 * 60 * 1000,
  criticalObservations: 10,
  criticalAfterMs: 15 * 60 * 1000,
  evaluationRetentionMs: 30 * 24 * 60 * 60 * 1000
});
const bounded = (value, max = MAX_ID) => String(value ?? "").slice(0, max);
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function isDigest(value) { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}
function boundedRatio(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, number));
}
function severityRank(value) { return ({ info: 0, warning: 1, high: 2, critical: 3 })[value] ?? -1; }
function withoutStorage(record) {
  const { _storage: ignoredStorage, digest: ignoredDigest, ...unsigned } = record || {};
  return unsigned;
}
function recordDigest(record) { return sha256(canonical(withoutStorage(record))); }
function boundedText(value, min, max) { return typeof value === "string" && value.trim().length >= min && value.trim().length <= max; }

export function verifyRecoverySloEvidenceExportBundle(bundle, options = {}) {
  // Reuse the same canonical digest rules as the producing service without needing its storage.
  const invalid = code => ({ status: "invalid", valid: false, findings: [{ code }], authenticity: "not_established", readOnly: true, mutationAllowed: false });
  try {
    if (!bundle || typeof bundle !== "object" || Array.isArray(bundle) || bundle.schemaVersion !== 1
      || bundle.kind !== "recovery-slo-evidence-export-bundle" || typeof bundle.ownerId !== "string" || !bundle.ownerId
      || !Number.isFinite(Date.parse(bundle.exportedAt)) || !bundle.sections || typeof bundle.sections !== "object"
      || Array.isArray(bundle.sections) || !bundle.manifest || !Array.isArray(bundle.manifest.sections) || !/^[a-f0-9]{64}$/.test(bundle.manifest.bundleDigest || "")) return invalid("RECOVERY_SLO_EXPORT_BUNDLE_SHAPE_INVALID");
    const expectedNames = ["alertArchives", "alertLedger", "evaluationEvidence", "evaluationEvidenceArchiveIndex", "evaluationEvidenceArchives", "policyLedger"].sort();
    if (canonical(Object.keys(bundle.sections).sort()) !== canonical(expectedNames)) return invalid("RECOVERY_SLO_EXPORT_SECTION_SET_INVALID");
    const countOf = value => value == null ? 0 : Array.isArray(value) ? value.length : 1;
    const expectedManifest = expectedNames.map(name => ({ name, count: countOf(bundle.sections[name]), digest: sha256(canonical(bundle.sections[name])) }));
    if (canonical(expectedManifest) !== canonical(bundle.manifest.sections)) return invalid("RECOVERY_SLO_EXPORT_SECTION_DIGEST_MISMATCH");
    const digestPayload = { domain: "agentic-v4-recovery-slo-evidence-export", schemaVersion: 1, ownerId: bundle.ownerId,
      exportedAt: bundle.exportedAt, sections: bundle.sections, manifestSections: expectedManifest };
    const bundleDigest = sha256(canonical(digestPayload));
    if (bundleDigest !== bundle.manifest.bundleDigest) return invalid("RECOVERY_SLO_EXPORT_BUNDLE_DIGEST_MISMATCH");
    const attestation = bundle.attestation;
    const expectedPayload = { domain: "agentic-v4-recovery-slo-export-attestation", schemaVersion: 1, ownerId: bundle.ownerId,
      exportedAt: bundle.exportedAt, bundleDigest, keyId: attestation?.keyId ?? null };
    if (!attestation || canonical(attestation.payload) !== canonical(expectedPayload)) return invalid("RECOVERY_SLO_EXPORT_ATTESTATION_BINDING_MISMATCH");
    if (attestation.status === "integrity_only" && attestation.algorithm === "SHA-256" && attestation.signature === null && attestation.keyId === null)
      return { status: "valid_integrity_only", valid: true, bundleDigest, authenticity: "not_established", findings: [], readOnly: true, mutationAllowed: false };
    if (attestation.status !== "signed" || attestation.algorithm !== "Ed25519" || typeof attestation.keyId !== "string"
      || !attestation.keyId || typeof attestation.signature !== "string" || !/^[A-Za-z0-9_-]{80,100}$/.test(attestation.signature)) return invalid("RECOVERY_SLO_EXPORT_ATTESTATION_FORMAT_INVALID");
    if (!options.publicKey) return { status: "valid_integrity_signature_unverified", valid: true, bundleDigest, keyId: attestation.keyId,
      authenticity: "signature_present_but_public_key_not_supplied", findings: [], readOnly: true, mutationAllowed: false };
    const signatureValid = verifySignature(null, Buffer.from(canonical(expectedPayload), "utf8"), (options.publicKey?.type === "public" ? options.publicKey : createPublicKey(options.publicKey)), Buffer.from(attestation.signature, "base64url"));
    if (!signatureValid) return invalid("RECOVERY_SLO_EXPORT_SIGNATURE_INVALID");
    return { status: "valid_signed", valid: true, bundleDigest, keyId: attestation.keyId, authenticity: "signature_verified", findings: [], readOnly: true, mutationAllowed: false };
  } catch (error) { return invalid(String(error?.code || "RECOVERY_SLO_EXPORT_VERIFICATION_FAILED").slice(0, 100)); }
}

export function createRecoverySloAlertingService({
  store,
  clock = () => new Date().toISOString(),
  getAnchorHealth,
  listAnchorHealthTelemetry,
  auditCrossStoreJournal,
  signExportBundle = null,
  exportAttestationKeyId = null,
  exportAttestationPublicKey = null,
  hasPendingRestorePromotion = async () => []
} = {}) {
  if (!store?.getEvidence || !store?.listEvidence || !store?.mutateEvidence || !store?.putEvidence
    || typeof getAnchorHealth !== "function" || typeof listAnchorHealthTelemetry !== "function"
    || typeof auditCrossStoreJournal !== "function") {
    throw new TypeError("Recovery SLO alerting membutuhkan evidence store dan API health/audit yang valid");
  }
  const signingConfigured = !!signExportBundle || !!exportAttestationKeyId || !!exportAttestationPublicKey;
  if (signingConfigured && (typeof signExportBundle !== "function" || typeof exportAttestationKeyId !== "string"
    || !exportAttestationKeyId.trim() || exportAttestationKeyId.length > 100 || !exportAttestationPublicKey)) {
    throw new TypeError("Export attestation membutuhkan signer eksternal, key ID, dan public key verifikasi secara bersamaan");
  }

  function assertOwner(ownerId) {
    if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > MAX_ID) {
      throw new AgenticError("RECOVERY_SLO_OWNER_REQUIRED", "Owner wajib ditentukan untuk evaluasi SLO", 400);
    }
  }

  async function pendingRestorePromotion(ownerId) {
    try {
      const pending = await hasPendingRestorePromotion(ownerId);
      return Array.isArray(pending) ? pending : [{ code: "PROMOTION_STATUS_INVALID" }];
    } catch {
      return [{ code: "PROMOTION_STATUS_UNAVAILABLE" }];
    }
  }
  async function assertRestorePromotionFinalized(ownerId) {
    const pending = await pendingRestorePromotion(ownerId);
    if (pending.length) throw new AgenticError("RECOVERY_SLO_RESTORE_PROMOTION_FINALIZATION_REQUIRED",
      "Operasi SLO diblokir sampai seluruh evidence promotion selesai dan finalization receipt terverifikasi", 409,
      { pendingPromotions: pending.slice(0, 20) });
  }
  async function promotionAuditHold(ownerId) {
    const pending = await pendingRestorePromotion(ownerId);
    if (!pending.length) return null;
    return { status: "recovery_required", ownerId, findings: [{ code: "RECOVERY_SLO_RESTORE_PROMOTION_FINALIZATION_REQUIRED",
      promotionJournalIds: pending.slice(0, 20).map(item => item.journalId || null) }],
      readOnly: true, mutationAllowed: false };
  }

  function ledgerId(ownerId) {
    return `recovery-slo-alert-ledger-${sha256(canonical({ domain: "agentic-v4-recovery-slo-alert-ledger", ownerId })).slice(0, 32)}`;
  }
  function policyLedgerId(ownerId) {
    return `recovery-slo-policy-ledger-${sha256(canonical({ domain: "agentic-v4-recovery-slo-policy-ledger", ownerId })).slice(0, 32)}`;
  }
  function evaluationEvidenceId(ownerId, evaluationDigest) {
    return `recovery-slo-evaluation-${sha256(canonical({ domain: "agentic-v4-recovery-slo-evaluation", ownerId, evaluationDigest })).slice(0, 40)}`;
  }
  function archiveId(ownerId, startSequence, endSequence, endHash) {
    return `recovery-slo-alert-archive-${sha256(canonical({ domain: "agentic-v4-recovery-slo-alert-archive", ownerId, startSequence, endSequence, endHash })).slice(0, 40)}`;
  }
  function evaluationArchiveIndexId(ownerId) {
    return `recovery-slo-evaluation-archive-index-${sha256(canonical({ domain: "agentic-v4-recovery-slo-evaluation-archive-index", ownerId })).slice(0, 32)}`;
  }
  function evaluationArchiveGenesis(ownerId, id) {
    return sha256(canonical({ domain: "agentic-v4-recovery-slo-evaluation-archive-genesis", ownerId, id }));
  }
  function evaluationArchiveId(ownerId, sequence, previousArchiveDigest, entries) {
    return `recovery-slo-evaluation-archive-${sha256(canonical({ domain: "agentic-v4-recovery-slo-evaluation-archive", ownerId, sequence, previousArchiveDigest, entryDigests: entries.map(item => ({ id: item.id, digest: item.digest })) })).slice(0, 40)}`;
  }
  function retentionMs(value) { return Number.isSafeInteger(value) && value >= 24 * 60 * 60 * 1000 && value <= 365 * 24 * 60 * 60 * 1000; }
  function validPolicy(policy) {
    return !!policy && Number.isSafeInteger(policy.windowMs) && policy.windowMs >= 60_000 && policy.windowMs <= 24 * 60 * 60 * 1000
      && Number.isSafeInteger(policy.minSamples) && policy.minSamples >= 1 && policy.minSamples <= 20
      && Number.isFinite(policy.availabilityTarget) && policy.availabilityTarget >= 0.9 && policy.availabilityTarget <= 1
      && Number.isSafeInteger(policy.maxPendingAgeMs) && policy.maxPendingAgeMs >= 30_000 && policy.maxPendingAgeMs <= 60 * 60 * 1000
      && Number.isSafeInteger(policy.maxLatencyMs) && policy.maxLatencyMs >= 100 && policy.maxLatencyMs <= 10_000
      && Number.isSafeInteger(policy.highObservations) && policy.highObservations >= 2 && policy.highObservations <= 100
      && Number.isSafeInteger(policy.highAfterMs) && policy.highAfterMs >= 30_000 && policy.highAfterMs <= 60 * 60 * 1000
      && Number.isSafeInteger(policy.criticalObservations) && policy.criticalObservations >= 3 && policy.criticalObservations <= 1000
      && Number.isSafeInteger(policy.criticalAfterMs) && policy.criticalAfterMs >= 60_000 && policy.criticalAfterMs <= 24 * 60 * 60 * 1000
      && policy.highObservations < policy.criticalObservations && policy.highAfterMs < policy.criticalAfterMs
      && retentionMs(policy.evaluationRetentionMs);
  }
  function policyDigest(policy) { return sha256(canonical(policy)); }
  function policyGenesis(ownerId, id) { return sha256(canonical({ domain: "agentic-v4-recovery-slo-policy-genesis", ownerId, id })); }
  function policyEventHash(event) { const { eventHash: ignored, ...unsigned } = event || {}; return sha256(canonical(unsigned)); }
  function validatePolicyLedger(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_SLO_POLICY_LEDGER_INTEGRITY_FAILED", "Ledger kebijakan SLO tidak valid", 409); };
    const snapshot = record?.snapshot;
    if (!record || record.kind !== "recovery-slo-policy-ledger" || record.ownerId !== ownerId || record.id !== policyLedgerId(ownerId)
      || !snapshot || snapshot.schemaVersion !== 1 || snapshot.ownerId !== ownerId || !Number.isSafeInteger(snapshot.revision)
      || snapshot.revision < 1 || !validPolicy(snapshot.currentPolicy) || !Array.isArray(snapshot.events) || !snapshot.events.length
      || snapshot.events.length > MAX_POLICY_EVENTS || snapshot.revision !== snapshot.events.length || record.digest !== sha256(canonical(snapshot))) fail();
    let previous = policyGenesis(ownerId, record.id);
    for (let index = 0; index < snapshot.events.length; index += 1) {
      const event = snapshot.events[index];
      if (!event || event.sequence !== index + 1 || event.revision !== index + 1 || event.previousHash !== previous
        || !isDigest(event.eventHash) || event.eventHash !== policyEventHash(event) || !["policy_created", "policy_updated"].includes(event.type)
        || !validPolicy(event.policy) || event.policyDigest !== policyDigest(event.policy) || !Number.isFinite(Date.parse(event.occurredAt))
        || (event.type === "policy_updated" && !boundedText(event.reason, 12, 240))) fail();
      previous = event.eventHash;
    }
    const last = snapshot.events.at(-1);
    if (last.revision !== snapshot.revision || last.policyDigest !== policyDigest(snapshot.currentPolicy)
      || canonical(last.policy) !== canonical(snapshot.currentPolicy)) fail();
    return snapshot;
  }
  async function ensurePolicy(ownerId) {
    const id = policyLedgerId(ownerId);
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock kebijakan SLO tidak valid", 500);
    const result = await store.mutateEvidence(ownerId, id, current => {
      if (current) return { write: false, result: structuredClone(validatePolicyLedger(current, ownerId)) };
      const policy = { ...DEFAULT_POLICY };
      const unsignedEvent = { sequence: 1, revision: 1, type: "policy_created", occurredAt: now,
        previousHash: policyGenesis(ownerId, id), policy, policyDigest: policyDigest(policy), reason: "Initial default policy" };
      const event = { ...unsignedEvent, eventHash: policyEventHash(unsignedEvent) };
      const snapshot = { schemaVersion: 1, ownerId, revision: 1, currentPolicy: policy, events: [event] };
      return { value: { id, ownerId, kind: "recovery-slo-policy-ledger", createdAt: now, snapshot, digest: sha256(canonical(snapshot)),
        provenance: { source: "recovery-slo-policy-versioning", schemaVersion: 1, ownerScoped: true, hashLinked: true } }, result: snapshot };
    });
    return structuredClone(result);
  }

  function genesis(ownerId, id) {
    return sha256(canonical({ domain: "agentic-v4-recovery-slo-alert-ledger-genesis", ownerId, id }));
  }

  function eventHash(event) {
    const { eventHash: ignored, ...unsigned } = event || {};
    return sha256(canonical(unsigned));
  }

  function validateLedger(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_SLO_ALERT_LEDGER_INTEGRITY_FAILED", "Ledger alert SLO tidak valid; mutasi ledger dihentikan", 409); };
    const snapshot = record?.snapshot;
    if (!record || record.kind !== "recovery-slo-alert-ledger" || record.ownerId !== ownerId
      || record.id !== ledgerId(ownerId) || !snapshot || snapshot.schemaVersion !== 1 || snapshot.ownerId !== ownerId
      || !Number.isSafeInteger(snapshot.baseSequence) || snapshot.baseSequence < 0 || !isDigest(snapshot.baseHash)
      || !Number.isSafeInteger(snapshot.sequence) || snapshot.sequence < snapshot.baseSequence
      || !Array.isArray(snapshot.events) || snapshot.events.length > MAX_EVENTS
      || !Array.isArray(snapshot.alerts) || snapshot.alerts.length > MAX_ALERTS
      || snapshot.sequence !== snapshot.baseSequence + snapshot.events.length
      || record.digest !== sha256(canonical(snapshot))
      || (snapshot.baseSequence === 0 && snapshot.baseHash !== genesis(ownerId, record.id))) fail();
    let previous = snapshot.baseHash;
    let sequence = snapshot.baseSequence;
    const eventIds = new Set();
    const alertIds = new Set(snapshot.alerts.map(alert => alert?.id));
    for (const event of snapshot.events) {
      sequence += 1;
      if (!event || event.sequence !== sequence || event.previousHash !== previous || !isDigest(event.eventHash)
        || event.eventHash !== eventHash(event) || typeof event.id !== "string" || eventIds.has(event.id)
        || !["alert_opened", "alert_observed", "alert_escalated", "alert_acknowledged", "alert_resolved", "alert_reopened"].includes(event.type)
        || !Number.isFinite(Date.parse(event.occurredAt)) || !isDigest(event.evaluationDigest)
        || typeof event.alertId !== "string" || !alertIds.has(event.alertId) || typeof event.alertKey !== "string"
        || !["active", "acknowledged", "resolved"].includes(event.status)
        || !["warning", "high", "critical"].includes(event.severity) || event.actorOwnerId !== ownerId
        || (event.policyRevision != null && (!Number.isSafeInteger(event.policyRevision) || event.policyRevision < 1))
        || (event.policyDigest != null && !isDigest(event.policyDigest))
        || (event.evaluationEvidenceId != null && typeof event.evaluationEvidenceId !== "string")
        || (event.type === "alert_acknowledged" && (typeof event.reason !== "string" || event.reason.trim().length < 12))) fail();
      eventIds.add(event.id);
      previous = event.eventHash;
    }
    const checkedAlertIds = new Set();
    const activeKeys = new Set();
    for (const alert of snapshot.alerts) {
      if (!alert || typeof alert.id !== "string" || checkedAlertIds.has(alert.id) || typeof alert.alertKey !== "string"
        || !["active", "acknowledged", "resolved"].includes(alert.status)
        || !["warning", "high", "critical"].includes(alert.severity)
        || !Number.isSafeInteger(alert.observationCount) || alert.observationCount < 1
        || !Number.isFinite(Date.parse(alert.openedAt)) || !Number.isFinite(Date.parse(alert.lastObservedAt))
        || !isDigest(alert.lastEvaluationDigest) || (alert.policyRevision != null && (!Number.isSafeInteger(alert.policyRevision) || alert.policyRevision < 1))
        || (alert.policyDigest != null && !isDigest(alert.policyDigest))
        || (alert.acknowledgedAt != null && !Number.isFinite(Date.parse(alert.acknowledgedAt)))
        || (alert.resolvedAt != null && !Number.isFinite(Date.parse(alert.resolvedAt)))) fail();
      if ((alert.status === "active" || alert.status === "acknowledged") && activeKeys.has(alert.alertKey)) fail();
      if (alert.status === "active" || alert.status === "acknowledged") activeKeys.add(alert.alertKey);
      checkedAlertIds.add(alert.id);
    }
    return snapshot;
  }

  function validateArchiveRecord(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED", "Arsip ledger alert SLO tidak valid", 409); };
    if (!record || record.kind !== "recovery-slo-alert-archive" || record.ownerId !== ownerId
      || record.id !== archiveId(ownerId, record.startSequence, record.endSequence, record.endHash)
      || !Number.isFinite(Date.parse(record.createdAt)) || !["prepared", "committed"].includes(record.state) || !Number.isSafeInteger(record.startSequence) || record.startSequence < 1
      || !Number.isSafeInteger(record.endSequence) || record.endSequence < record.startSequence
      || record.endSequence - record.startSequence + 1 !== record.events?.length || !Array.isArray(record.events)
      || record.events.length < 1 || record.events.length > MAX_ARCHIVE_BATCH || !isDigest(record.previousHash)
      || !isDigest(record.endHash) || !isDigest(record.payloadDigest) || !Array.isArray(record.archivedAlerts)
      || !Array.isArray(record.alertIds) || record.digest !== recordDigest(record)) fail();
    const payload = { startSequence: record.startSequence, endSequence: record.endSequence, previousHash: record.previousHash,
      endHash: record.endHash, events: record.events, archivedAlerts: record.archivedAlerts, alertIds: record.alertIds };
    if (record.payloadDigest !== sha256(canonical(payload))) fail();
    let previous = record.previousHash;
    const seenEventIds = new Set();
    for (let index = 0; index < record.events.length; index += 1) {
      const event = record.events[index];
      if (!event || event.sequence !== record.startSequence + index || event.previousHash !== previous || !isDigest(event.eventHash)
        || event.eventHash !== eventHash(event) || seenEventIds.has(event.id) || !record.alertIds.includes(event.alertId)) fail();
      seenEventIds.add(event.id);
      previous = event.eventHash;
    }
    const expectedAlertIds = [...new Set(record.events.map(event => event.alertId))].sort();
    if (previous !== record.endHash || new Set(record.alertIds).size !== record.alertIds.length
      || record.alertIds.some(id => typeof id !== "string" || !id)
      || canonical(expectedAlertIds) !== canonical(record.alertIds)) fail();
    const archivedIds = new Set();
    for (const alert of record.archivedAlerts) {
      if (!alert || typeof alert.id !== "string" || archivedIds.has(alert.id) || !record.alertIds.includes(alert.id)
        || alert.status !== "resolved" || !Number.isFinite(Date.parse(alert.resolvedAt))) fail();
      archivedIds.add(alert.id);
    }
    return record;
  }

  async function listArchiveRecords(ownerId) {
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-slo-alert-archive");
    if (records.length > MAX_ARCHIVES) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_CAPACITY_REACHED", "Kapasitas arsip alert SLO tercapai", 409);
    return records.map(item => validateArchiveRecord(item, ownerId)).sort((a, b) => a.startSequence - b.startSequence);
  }

  function auditArchiveChain(ownerId, snapshot, archives) {
    const fail = code => ({ status: "unhealthy", findings: [{ code }], pendingArchive: null, archives });
    const genesisHash = genesis(ownerId, ledgerId(ownerId));
    let expectedSequence = 1;
    let previousHash = genesisHash;
    const seenAlertIds = new Set();
    const seenEventIds = new Set();
    const knownAlertIds = new Set((snapshot?.alerts || []).map(item => item.id));
    let pending = null;
    for (const archive of archives) {
      if (archive.startSequence !== expectedSequence || archive.previousHash !== previousHash) return fail("RECOVERY_SLO_ALERT_ARCHIVE_CHAIN_GAP");
      if (archive.state === "prepared") {
        if (pending) return fail("RECOVERY_SLO_ALERT_ARCHIVE_MULTIPLE_PREPARED");
        pending = archive;
      }
      for (const event of archive.events) {
        if (seenEventIds.has(event.id)) return fail("RECOVERY_SLO_ALERT_ARCHIVE_DUPLICATE_EVENT");
        seenEventIds.add(event.id);
      }
      for (const alert of archive.archivedAlerts) {
        if (seenAlertIds.has(alert.id)) return fail("RECOVERY_SLO_ALERT_ARCHIVE_DUPLICATE_ALERT");
        seenAlertIds.add(alert.id);
        knownAlertIds.add(alert.id);
      }
      expectedSequence = archive.endSequence + 1;
      previousHash = archive.endHash;
    }
    if (archives.some(archive => archive.alertIds.some(alertId => !knownAlertIds.has(alertId)))) return fail("RECOVERY_SLO_ALERT_ARCHIVE_ORPHAN_EVENT");
    const committed = archives.filter(item => item.state === "committed");
    const committedThrough = committed.at(-1)?.endSequence || 0;
    const committedHash = committed.at(-1)?.endHash || genesisHash;
    if (!pending) {
      if (committedThrough !== (snapshot?.baseSequence || 0) || committedHash !== (snapshot?.baseHash || genesisHash)) return fail("RECOVERY_SLO_ALERT_ARCHIVE_CHECKPOINT_MISMATCH");
      return { status: "healthy", findings: [], pendingArchive: null, archives };
    }
    if (committedThrough !== pending.startSequence - 1 || committedHash !== pending.previousHash) return fail("RECOVERY_SLO_ALERT_ARCHIVE_PENDING_CHAIN_MISMATCH");
    if (snapshot.baseSequence === pending.startSequence - 1) {
      const count = pending.events.length;
      const prefix = snapshot.events.slice(0, count);
      if (prefix.length !== count || canonical(prefix) !== canonical(pending.events)
        || pending.archivedAlerts.some(archived => canonical(snapshot.alerts.find(item => item.id === archived.id) || null) !== canonical(archived))) {
        return fail("RECOVERY_SLO_ALERT_ARCHIVE_PREPARED_PAYLOAD_MISMATCH");
      }
      return { status: "recovery_required", findings: [{ code: "RECOVERY_SLO_ALERT_ARCHIVE_PREPARED" }], pendingArchive: pending, archives };
    }
    if (snapshot.baseSequence === pending.endSequence && snapshot.baseHash === pending.endHash
      && pending.archivedAlerts.every(archived => !snapshot.alerts.some(item => item.id === archived.id))) {
      return { status: "recovery_required", findings: [{ code: "RECOVERY_SLO_ALERT_ARCHIVE_FINALIZATION_PENDING" }], pendingArchive: pending, archives };
    }
    return fail("RECOVERY_SLO_ALERT_ARCHIVE_CHECKPOINT_MISMATCH");
  }

  async function auditAlertEvidenceBindings(ownerId, snapshot, archives) {
    const findings = [];
    const events = [...archives.flatMap(archive => archive.events), ...(snapshot?.events || [])];
    const policyRecord = await store.getEvidence(ownerId, policyLedgerId(ownerId));
    let policies = new Map();
    if (policyRecord) {
      try { policies = new Map(validatePolicyLedger(policyRecord, ownerId).events.map(event => [event.revision, event.policyDigest])); }
      catch (error) { findings.push({ code: "RECOVERY_SLO_POLICY_LEDGER_INTEGRITY_FAILED", errorCode: bounded(error?.code || "POLICY_INVALID", 100) }); }
    }
    let archivedEvidence = new Map();
    const evaluationArchiveAudit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (["unhealthy", "recovery_required"].includes(evaluationArchiveAudit.status)) findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_AUDIT_FAILED" });
    else {
      try { archivedEvidence = new Map((await listEvaluationArchiveRecords(ownerId)).flatMap(item => item.entries).map(item => [item.id, item])); }
      catch (error) { findings.push({ code: bounded(error?.code || "RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED", 100) }); }
    }
    const seen = new Set();
    for (const event of events) {
      if (seen.has(event.sequence)) continue;
      seen.add(event.sequence);
      if (event.policyRevision != null || event.policyDigest != null) {
        if (!Number.isSafeInteger(event.policyRevision) || !isDigest(event.policyDigest) || policies.get(event.policyRevision) !== event.policyDigest) {
          findings.push({ code: "RECOVERY_SLO_ALERT_POLICY_BINDING_MISMATCH", sequence: event.sequence });
        }
      }
      if (event.evaluationEvidenceId != null) {
        const evidence = await store.getEvidence(ownerId, event.evaluationEvidenceId) || archivedEvidence.get(event.evaluationEvidenceId) || null;
        try {
          validateEvaluationEvidence(evidence, ownerId);
          if (evidence.evaluationDigest !== event.evaluationDigest || evidence.policyRevision !== event.policyRevision
            || evidence.policyDigest !== event.policyDigest) throw new AgenticError("RECOVERY_SLO_ALERT_EVALUATION_EVIDENCE_BINDING_MISMATCH", "Event alert tidak cocok dengan evidence evaluasi", 409);
        } catch (error) {
          findings.push({ code: bounded(error?.code || "RECOVERY_SLO_ALERT_EVALUATION_EVIDENCE_MISSING", 100), sequence: event.sequence });
        }
      }
      if (findings.length >= 100) break;
    }
    return { status: findings.length ? "unhealthy" : "healthy", findings };
  }

  async function assertArchiveWritable(ownerId, snapshot) {
    const archives = await listArchiveRecords(ownerId);
    const audit = auditArchiveChain(ownerId, snapshot, archives);
    if (audit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED", "Riwayat arsip alert SLO tidak valid; penulisan dihentikan", 409, { findings: audit.findings });
    if (audit.status === "recovery_required") throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_RECOVERY_REQUIRED", "Pemulihan arsip alert SLO harus diselesaikan sebelum penulisan berikutnya", 409, { findings: audit.findings });
    const bindings = await auditAlertEvidenceBindings(ownerId, snapshot, archives);
    if (bindings.status !== "healthy") throw new AgenticError("RECOVERY_SLO_ALERT_EVIDENCE_BINDING_FAILED", "Binding policy/evidence pada riwayat alert tidak valid", 409, { findings: bindings.findings });
    return audit;
  }

  function summaryEvaluation(evaluation) {
    return {
      evaluatedAt: evaluation.evaluatedAt, status: evaluation.status, evaluationDigest: evaluation.evaluationDigest, windowMs: evaluation.windowMs,
      sampleCount: evaluation.sampleCount, policyRevision: evaluation.policyRevision ?? null, policyDigest: evaluation.policyDigest ?? null,
      evaluationEvidenceId: evaluation.evaluationEvidenceId ?? null,
      objectives: evaluation.objectives.map(item => ({ code: item.code, status: item.status, measured: item.measured, target: item.target, severity: item.severity || null }))
    };
  }

  async function getRecoverySloEscalationPolicy(ownerId) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const existed = !!(await store.getEvidence(ownerId, policyLedgerId(ownerId)));
    const snapshot = await ensurePolicy(ownerId);
    return { ownerId, revision: snapshot.revision, policy: structuredClone(snapshot.currentPolicy), policyDigest: policyDigest(snapshot.currentPolicy),
      eventCount: snapshot.events.length, lastEventHash: snapshot.events.at(-1)?.eventHash || null, initialized: !existed, readOnly: existed };
  }

  async function updateRecoverySloEscalationPolicy(ownerId, input = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    await ensurePolicy(ownerId);
    if (!Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 1) {
      throw new AgenticError("RECOVERY_SLO_POLICY_EXPECTED_REVISION_REQUIRED", "expectedRevision wajib berupa revision positif", 400);
    }
    if (!boundedText(input.reason, 12, 240)) throw new AgenticError("RECOVERY_SLO_POLICY_CHANGE_REASON_INVALID", "Alasan perubahan kebijakan harus 12–240 karakter", 400);
    const changes = input.changes;
    const allowed = new Set(Object.keys(DEFAULT_POLICY));
    if (!changes || typeof changes !== "object" || Array.isArray(changes) || !Object.keys(changes).length
      || Object.keys(changes).some(key => !allowed.has(key))) {
      throw new AgenticError("RECOVERY_SLO_POLICY_CHANGES_INVALID", "Perubahan kebijakan berisi field yang tidak dikenal atau kosong", 400);
    }
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock kebijakan SLO tidak valid", 500);
    const id = policyLedgerId(ownerId);
    return store.mutateEvidence(ownerId, id, current => {
      if (!current) throw new AgenticError("RECOVERY_SLO_POLICY_NOT_INITIALIZED", "Kebijakan SLO belum diinisialisasi", 409);
      const snapshot = validatePolicyLedger(current, ownerId);
      if (snapshot.revision !== input.expectedRevision) throw new AgenticError("RECOVERY_SLO_POLICY_REVISION_CONFLICT", "Revision kebijakan berubah; baca ulang sebelum memperbarui", 409,
        { expectedRevision: input.expectedRevision, currentRevision: snapshot.revision });
      if (snapshot.events.length >= MAX_POLICY_EVENTS) throw new AgenticError("RECOVERY_SLO_POLICY_HISTORY_CAPACITY_REACHED", "Kapasitas riwayat kebijakan SLO tercapai", 409);
      const nextPolicy = { ...snapshot.currentPolicy, ...changes };
      if (!validPolicy(nextPolicy)) throw new AgenticError("RECOVERY_SLO_POLICY_VALUES_INVALID", "Nilai kebijakan SLO berada di luar batas yang diizinkan", 400);
      if (canonical(nextPolicy) === canonical(snapshot.currentPolicy)) return { write: false, result: { status: "unchanged", ownerId,
        revision: snapshot.revision, policy: structuredClone(snapshot.currentPolicy), policyDigest: policyDigest(snapshot.currentPolicy), readOnly: true } };
      const revision = snapshot.revision + 1;
      const unsignedEvent = { sequence: revision, revision, type: "policy_updated", occurredAt: now,
        previousHash: snapshot.events.at(-1).eventHash, policy: nextPolicy, policyDigest: policyDigest(nextPolicy), reason: input.reason.trim() };
      const event = { ...unsignedEvent, eventHash: policyEventHash(unsignedEvent) };
      const updated = { ...snapshot, revision, currentPolicy: nextPolicy, events: [...snapshot.events, event] };
      const value = { ...current, snapshot: updated, digest: sha256(canonical(updated)), provenance: current.provenance };
      return { value, result: { status: "updated", ownerId, revision, policy: structuredClone(nextPolicy), policyDigest: policyDigest(nextPolicy),
        eventHash: event.eventHash, readOnly: false } };
    });
  }

  async function listRecoverySloPolicyEvents(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const limit = boundedInteger(options.limit, 100, 1, MAX_POLICY_EVENTS);
    const record = await store.getEvidence(ownerId, policyLedgerId(ownerId));
    if (!record) return { status: "empty", ownerId, total: 0, items: [], truncated: false, readOnly: true };
    const snapshot = validatePolicyLedger(record, ownerId);
    const items = snapshot.events.slice(-limit).reverse().map(item => structuredClone(item));
    return { status: "healthy", ownerId, total: snapshot.events.length, items, truncated: snapshot.events.length > items.length, readOnly: true };
  }

  async function persistEvaluationEvidence(ownerId, evaluation, policy) {
    const id = evaluationEvidenceId(ownerId, evaluation.evaluationDigest);
    const now = evaluation.evaluatedAt;
    const record = { id, ownerId, kind: "recovery-slo-evaluation-evidence", state: "active", createdAt: now,
      evaluatedAt: evaluation.evaluatedAt, retentionUntil: new Date(Date.parse(now) + policy.evaluationRetentionMs).toISOString(),
      policyRevision: evaluation.policyRevision, policyDigest: evaluation.policyDigest, evaluationDigest: evaluation.evaluationDigest,
      contentDigest: sha256(canonical(evaluation)), summary: summaryEvaluation(evaluation), evaluation: structuredClone(evaluation) };
    record.digest = recordDigest(record);
    const policyId = policyLedgerId(ownerId);
    const result = await store.mutateEvidence(ownerId, policyId, async policyRecord => {
      if (!policyRecord) throw new AgenticError("RECOVERY_SLO_POLICY_NOT_INITIALIZED", "Kebijakan SLO belum diinisialisasi", 409);
      validatePolicyLedger(policyRecord, ownerId);
      const current = await store.getEvidence(ownerId, id);
      if (current) {
        validateEvaluationEvidence(current, ownerId);
        if (current.contentDigest !== record.contentDigest) throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_CONFLICT", "ID evidence evaluasi sudah digunakan untuk payload berbeda", 409);
        if (current.state !== "active") throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_EXPIRED", "Evidence evaluasi yang sudah melewati retensi tidak dapat dihidupkan kembali", 409);
        return { write: false, result: { id, recordDigest: current.digest, contentDigest: current.contentDigest } };
      }
      const existingRecords = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-slo-evaluation-evidence");
      if (existingRecords.length >= MAX_EVALUATIONS) throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_CAPACITY_REACHED", "Kapasitas evidence evaluasi SLO tercapai; evaluasi baru ditolak sampai evidence lama diekspor atau dihapus sesuai kebijakan", 409);
      const stored = await store.mutateEvidence(ownerId, id, latest => {
        if (latest) {
          validateEvaluationEvidence(latest, ownerId);
          if (latest.contentDigest !== record.contentDigest || latest.state !== "active") throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_CONFLICT", "Evidence evaluasi berubah selama penyimpanan", 409);
          return { write: false, result: latest };
        }
        return { value: record, result: record };
      });
      return { write: false, result: { id, recordDigest: stored.digest, contentDigest: stored.contentDigest } };
    });
    return result;
  }

  function validateEvaluationEvidence(record, ownerId) {
    if (!record || record.kind !== "recovery-slo-evaluation-evidence" || record.ownerId !== ownerId
      || record.id !== evaluationEvidenceId(ownerId, record.evaluationDigest) || !isDigest(record.evaluationDigest)
      || !isDigest(record.contentDigest) || !isDigest(record.digest) || record.digest !== recordDigest(record)
      || !Number.isFinite(Date.parse(record.evaluatedAt)) || !Number.isFinite(Date.parse(record.retentionUntil))
      || !Number.isSafeInteger(record.policyRevision) || record.policyRevision < 1 || !isDigest(record.policyDigest)
      || !["active", "expired"].includes(record.state)) {
      throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_INTEGRITY_FAILED", "Evidence evaluasi SLO tidak valid", 409);
    }
    if (record.state === "active") {
      if (!record.evaluation || record.evaluation.evaluationDigest !== record.evaluationDigest
        || sha256(canonical(record.evaluation)) !== record.contentDigest || !record.summary
        || record.summary.evaluationDigest !== record.evaluationDigest) {
        throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_INTEGRITY_FAILED", "Payload evidence evaluasi SLO tidak cocok dengan digest", 409);
      }
    } else if (record.evaluation != null || !Number.isFinite(Date.parse(record.expiredAt))
      || Date.parse(record.expiredAt) < Date.parse(record.retentionUntil)
      || record.retentionTombstone?.reason !== "RETENTION_POLICY_ELAPSED"
      || record.retentionTombstone?.originalContentDigest !== record.contentDigest
      || record.retentionTombstone?.policyRevision !== record.policyRevision
      || record.retentionTombstone?.policyDigest !== record.policyDigest
      || record.retentionTombstone?.expiredAt !== record.expiredAt
      || record.summary?.evaluationDigest !== record.evaluationDigest) {
      throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_INTEGRITY_FAILED", "Tombstone retensi evidence evaluasi SLO tidak valid", 409);
    }
    return record;
  }

  function validateEvaluationArchive(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED", "Arsip evidence evaluasi SLO tidak valid", 409); };
    if (!record || record.kind !== "recovery-slo-evaluation-evidence-archive" || record.ownerId !== ownerId
      || !Number.isSafeInteger(record.sequence) || record.sequence < 1 || !isDigest(record.previousArchiveDigest)
      || !Number.isFinite(Date.parse(record.createdAt)) || !Array.isArray(record.entries) || !record.entries.length
      || record.entries.length > MAX_EVALUATION_ARCHIVE_BATCH || record.entryCount !== record.entries.length || !isDigest(record.payloadDigest)
      || record.digest !== recordDigest(record)) fail();
    const expectedId = evaluationArchiveId(ownerId, record.sequence, record.previousArchiveDigest, record.entries);
    const payload = { sequence: record.sequence, previousArchiveDigest: record.previousArchiveDigest, createdAt: record.createdAt, entries: record.entries };
    if (record.id !== expectedId || record.payloadDigest !== sha256(canonical(payload))) fail();
    const seen = new Set();
    let previousId = "";
    for (const entry of record.entries) {
      validateEvaluationEvidence(entry, ownerId);
      if (entry.state !== "expired" || entry.evaluation != null || seen.has(entry.id) || (previousId && entry.id.localeCompare(previousId) < 0)) fail();
      seen.add(entry.id);
      previousId = entry.id;
    }
    return record;
  }

  function validateEvaluationArchiveIndex(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_INTEGRITY_FAILED", "Index arsip evidence evaluasi SLO tidak valid", 409); };
    const id = evaluationArchiveIndexId(ownerId);
    const snapshot = record?.snapshot;
    if (!record || record.kind !== "recovery-slo-evaluation-archive-index" || record.ownerId !== ownerId || record.id !== id
      || !snapshot || snapshot.schemaVersion !== 1 || snapshot.ownerId !== ownerId || !Number.isSafeInteger(snapshot.sequence)
      || snapshot.sequence < 0 || !Array.isArray(snapshot.archives) || snapshot.archives.length !== snapshot.sequence
      || !isDigest(snapshot.lastArchiveDigest) || record.digest !== sha256(canonical(snapshot))) fail();
    let previous = evaluationArchiveGenesis(ownerId, id);
    for (let index = 0; index < snapshot.archives.length; index += 1) {
      const item = snapshot.archives[index];
      if (!item || item.sequence !== index + 1 || item.previousArchiveDigest !== previous || typeof item.id !== "string"
        || !isDigest(item.digest) || !Number.isSafeInteger(item.entryCount) || item.entryCount < 1 || item.entryCount > MAX_EVALUATION_ARCHIVE_BATCH) fail();
      previous = item.digest;
    }
    if (snapshot.lastArchiveDigest !== previous) fail();
    return snapshot;
  }

  async function listEvaluationArchiveRecords(ownerId) {
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-slo-evaluation-evidence-archive");
    if (records.length > MAX_EVALUATION_ARCHIVES) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_CAPACITY_REACHED", "Kapasitas arsip evidence evaluasi SLO tercapai", 409);
    return records.map(item => validateEvaluationArchive(item, ownerId)).sort((a, b) => a.sequence - b.sequence);
  }

  async function auditRecoverySloEvaluationEvidenceArchives(ownerId) {
    assertOwner(ownerId);
    const promotionHold = await promotionAuditHold(ownerId);
    if (promotionHold) return promotionHold;
    let archives;
    try { archives = await listEvaluationArchiveRecords(ownerId); }
    catch (error) { return { status: "unhealthy", ownerId, findings: [{ code: bounded(error?.code || "RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED", 100) }], readOnly: true, mutationAllowed: false }; }
    const findings = [];
    const indexRecord = await store.getEvidence(ownerId, evaluationArchiveIndexId(ownerId));
    const genesisHash = evaluationArchiveGenesis(ownerId, evaluationArchiveIndexId(ownerId));
    let previous = genesisHash;
    const archivedById = new Map();
    for (let index = 0; index < archives.length; index += 1) {
      const archive = archives[index];
      if (archive.sequence !== index + 1 || archive.previousArchiveDigest !== previous) {
        findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_CHAIN_GAP", sequence: archive.sequence });
        break;
      }
      for (const entry of archive.entries) {
        if (archivedById.has(entry.id)) findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_DUPLICATE_ENTRY", evidenceId: bounded(entry.id, MAX_ID) });
        archivedById.set(entry.id, entry);
      }
      previous = archive.digest;
    }
    let indexSnapshot = null;
    if (indexRecord) {
      try {
        indexSnapshot = validateEvaluationArchiveIndex(indexRecord, ownerId);
        if (indexSnapshot.sequence > archives.length) findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_AHEAD" });
        for (const reference of indexSnapshot.archives) {
          const archive = archives[reference.sequence - 1];
          if (!archive || archive.id !== reference.id || archive.digest !== reference.digest || archive.entryCount !== reference.entryCount
            || archive.previousArchiveDigest !== reference.previousArchiveDigest) {
            findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_MISMATCH", sequence: reference.sequence });
            break;
          }
        }
      } catch (error) { findings.push({ code: bounded(error?.code || "RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_INTEGRITY_FAILED", 100) }); }
    } else if (archives.length) findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_MISSING" });
    if (indexSnapshot && indexSnapshot.sequence < archives.length) findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_BEHIND" });
    const liveRecords = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-slo-evaluation-evidence");
    for (const live of liveRecords) {
      const archived = archivedById.get(live.id);
      if (archived) {
        if (archived.digest !== live.digest || live.state !== "expired") findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_SOURCE_CONFLICT", evidenceId: bounded(live.id, MAX_ID) });
        else findings.push({ code: "RECOVERY_SLO_EVALUATION_ARCHIVE_SOURCE_CLEANUP_PENDING", evidenceId: bounded(live.id, MAX_ID) });
      }
    }
    const status = findings.some(item => /INTEGRITY|CHAIN_GAP|DUPLICATE_ENTRY|INDEX_AHEAD|INDEX_MISMATCH|SOURCE_CONFLICT/.test(item.code))
      ? "unhealthy" : findings.length ? "recovery_required" : archives.length ? "healthy" : "empty";
    return { status, ownerId, archiveCount: archives.length, archivedEvidenceCount: archives.reduce((sum, item) => sum + item.entries.length, 0),
      indexSequence: indexSnapshot?.sequence ?? 0, lastArchiveDigest: archives.at(-1)?.digest || genesisHash,
      findings: findings.slice(0, 100), readOnly: true, mutationAllowed: false };
  }

  async function recoverRecoverySloEvaluationEvidenceArchives(ownerId) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const before = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (before.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED", "Arsip evidence tidak dapat dipulihkan karena integritas gagal", 409, { findings: before.findings });
    const archives = await listEvaluationArchiveRecords(ownerId);
    const id = evaluationArchiveIndexId(ownerId);
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock recovery arsip tidak valid", 500);
    const indexResult = await store.mutateEvidence(ownerId, id, current => {
      let existing = null;
      if (current) existing = validateEvaluationArchiveIndex(current, ownerId);
      if (existing && existing.sequence > archives.length) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_AHEAD", "Index arsip mendahului arsip yang tersedia", 409);
      if (existing) for (const reference of existing.archives) {
        const archive = archives[reference.sequence - 1];
        if (!archive || archive.id !== reference.id || archive.digest !== reference.digest) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_INDEX_MISMATCH", "Index arsip tidak cocok dengan riwayat arsip", 409);
      }
      const refs = archives.map(archive => ({ sequence: archive.sequence, id: archive.id, digest: archive.digest,
        entryCount: archive.entries.length, previousArchiveDigest: archive.previousArchiveDigest }));
      const lastArchiveDigest = archives.at(-1)?.digest || evaluationArchiveGenesis(ownerId, id);
      const snapshot = { schemaVersion: 1, ownerId, sequence: archives.length, lastArchiveDigest, archives: refs };
      if (existing && existing.sequence === snapshot.sequence && existing.lastArchiveDigest === snapshot.lastArchiveDigest) return { write: false, result: { changed: false, snapshot: existing } };
      const value = { id, ownerId, kind: "recovery-slo-evaluation-archive-index", createdAt: current?.createdAt || now,
        updatedAt: now, snapshot, digest: sha256(canonical(snapshot)), provenance: { source: "recovery-slo-evidence-archive-index", schemaVersion: 1, ownerScoped: true, hashLinked: true } };
      return { value, result: { changed: true, snapshot } };
    });
    let removedSources = 0;
    for (const archive of archives) for (const entry of archive.entries) {
      const result = await store.mutateEvidence(ownerId, entry.id, current => {
        if (!current) return { write: false, result: false };
        validateEvaluationEvidence(current, ownerId);
        if (current.state !== "expired" || current.digest !== entry.digest) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_SOURCE_CONFLICT", "Evidence sumber berbeda dari tombstone arsip; penghapusan ditolak", 409);
        return { delete: true, result: true };
      });
      if (result) removedSources += 1;
    }
    const after = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (after.status === "unhealthy" || after.status === "recovery_required") throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_RECOVERY_INCOMPLETE", "Pemulihan arsip evidence belum lengkap", 409, { findings: after.findings });
    return { ownerId, status: "healthy", recovered: before.status !== "healthy" && before.status !== "empty" || indexResult.changed || removedSources > 0,
      archiveCount: archives.length, archivedEvidenceCount: after.archivedEvidenceCount, removedSourceCount: removedSources,
      indexRebuilt: indexResult.changed, readOnly: false, mutationAllowed: false };
  }

  async function archiveExpiredRecoverySloEvaluationEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const limit = boundedInteger(options.limit, 100, 1, MAX_EVALUATION_ARCHIVE_BATCH);
    const audit = await auditRecoverySloEvaluationEvidence(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_INTEGRITY_FAILED", "Evidence tidak dapat diarsipkan sebelum audit bersih", 409, { findings: audit.findings });
    const archiveAudit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (archiveAudit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED", "Arsip evidence tidak valid", 409, { findings: archiveAudit.findings });
    if (archiveAudit.status === "recovery_required") await recoverRecoverySloEvaluationEvidenceArchives(ownerId);
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock pengarsipan evidence tidak valid", 500);
    const indexId = evaluationArchiveIndexId(ownerId);
    return store.mutateEvidence(ownerId, indexId, async current => {
      let indexSnapshot;
      if (current) indexSnapshot = validateEvaluationArchiveIndex(current, ownerId);
      else indexSnapshot = { schemaVersion: 1, ownerId, sequence: 0, lastArchiveDigest: evaluationArchiveGenesis(ownerId, indexId), archives: [] };
      const all = await store.listEvidence(ownerId);
      const archivedIds = new Set(all.filter(item => item.kind === "recovery-slo-evaluation-evidence-archive").flatMap(item => item.entries || []).map(item => item.id));
      const candidates = all.filter(item => item.kind === "recovery-slo-evaluation-evidence" && item.state === "expired" && !archivedIds.has(item.id))
        .map(item => validateEvaluationEvidence(item, ownerId)).sort((a, b) => a.id.localeCompare(b.id)).slice(0, limit)
        .map(item => { const { _storage: ignoredStorage, ...copy } = item; return copy; });
      if (!candidates.length) return { write: false, result: { status: "nothing_to_archive", ownerId, archivedCount: 0,
        archiveCount: indexSnapshot.sequence, readOnly: false, mutationAllowed: false } };
      if (indexSnapshot.sequence >= MAX_EVALUATION_ARCHIVES) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_CAPACITY_REACHED", "Kapasitas arsip evidence evaluasi SLO tercapai", 409);
      const sequence = indexSnapshot.sequence + 1;
      const previousArchiveDigest = indexSnapshot.lastArchiveDigest;
      const entries = candidates.sort((a, b) => a.id.localeCompare(b.id));
      const payload = { sequence, previousArchiveDigest, createdAt: now, entries };
      const candidate = { id: evaluationArchiveId(ownerId, sequence, previousArchiveDigest, entries), ownerId,
        kind: "recovery-slo-evaluation-evidence-archive", sequence, previousArchiveDigest, createdAt: now,
        entries, entryCount: entries.length, payloadDigest: sha256(canonical(payload)) };
      candidate.digest = recordDigest(candidate);
      validateEvaluationArchive(candidate, ownerId);
      await store.putEvidence(ownerId, candidate, { overwrite: false });
      let removed = 0;
      for (const entry of entries) {
        const result = await store.mutateEvidence(ownerId, entry.id, latest => {
          if (!latest) return { write: false, result: false };
          validateEvaluationEvidence(latest, ownerId);
          if (latest.state !== "expired" || latest.digest !== entry.digest) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_SOURCE_CONFLICT", "Evidence berubah setelah snapshot arsip dibuat", 409);
          return { delete: true, result: true };
        });
        if (result) removed += 1;
      }
      const reference = { sequence, id: candidate.id, digest: candidate.digest, entryCount: entries.length, previousArchiveDigest };
      const snapshot = { ...indexSnapshot, sequence, lastArchiveDigest: candidate.digest, archives: [...indexSnapshot.archives, reference] };
      const value = { id: indexId, ownerId, kind: "recovery-slo-evaluation-archive-index", createdAt: current?.createdAt || now,
        updatedAt: now, snapshot, digest: sha256(canonical(snapshot)), provenance: { source: "recovery-slo-evidence-archive-index", schemaVersion: 1, ownerScoped: true, hashLinked: true } };
      return { value, result: { status: "archived", ownerId, archiveId: candidate.id, archiveSequence: sequence,
        archivedCount: entries.length, removedSourceCount: removed, archiveDigest: candidate.digest, readOnly: false, mutationAllowed: false } };
    });
  }

  function stripStorageDeep(value) {
    if (Array.isArray(value)) return value.map(stripStorageDeep);
    if (!value || typeof value !== "object") return value;
    const out = {};
    for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = stripStorageDeep(item);
    return out;
  }

  async function exportRecoverySloEvidenceBundle(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const maxBytes = boundedInteger(options.maxBytes, MAX_EXPORT_BYTES, 1, MAX_EXPORT_BYTES);
    const alertAudit = await auditRecoverySloAlertLedger(ownerId);
    const policyAudit = await auditRecoverySloEscalationPolicy(ownerId);
    const evidenceAudit = await auditRecoverySloEvaluationEvidence(ownerId);
    const archiveAudit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if ([alertAudit, policyAudit, evidenceAudit, archiveAudit].some(item => ["unhealthy", "recovery_required"].includes(item.status))) {
      throw new AgenticError("RECOVERY_SLO_EXPORT_SOURCE_AUDIT_FAILED", "Ekspor ditolak karena satu atau lebih audit sumber belum sehat", 409,
        { alert: alertAudit.status, policy: policyAudit.status, evidence: evidenceAudit.status, evidenceArchives: archiveAudit.status });
    }
    const all = await store.listEvidence(ownerId);
    const policy = all.find(item => item.kind === "recovery-slo-policy-ledger") || null;
    const activeLedger = all.find(item => item.kind === "recovery-slo-alert-ledger") || null;
    const evidence = all.filter(item => item.kind === "recovery-slo-evaluation-evidence");
    for (const item of evidence) validateEvaluationEvidence(item, ownerId);
    if (policy) validatePolicyLedger(policy, ownerId);
    if (activeLedger) validateLedger(activeLedger, ownerId);
    const alertArchives = await listArchiveRecords(ownerId);
    const evaluationArchives = await listEvaluationArchiveRecords(ownerId);
    const index = await store.getEvidence(ownerId, evaluationArchiveIndexId(ownerId));
    if (index) validateEvaluationArchiveIndex(index, ownerId);
    const sections = {
      policyLedger: stripStorageDeep(policy),
      alertLedger: stripStorageDeep(activeLedger),
      alertArchives: stripStorageDeep(alertArchives),
      evaluationEvidence: stripStorageDeep(evidence),
      evaluationEvidenceArchives: stripStorageDeep(evaluationArchives),
      evaluationEvidenceArchiveIndex: stripStorageDeep(index)
    };
    const countOf = value => value == null ? 0 : Array.isArray(value) ? value.length : 1;
    const manifestSections = Object.keys(sections).sort().map(name => ({ name, count: countOf(sections[name]), digest: sha256(canonical(sections[name])) }));
    const exportedAt = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(exportedAt))) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock ekspor evidence tidak valid", 500);
    const digestPayload = { domain: "agentic-v4-recovery-slo-evidence-export", schemaVersion: 1, ownerId, exportedAt, sections, manifestSections };
    const bundleDigest = sha256(canonical(digestPayload));
    const attestationPayload = { domain: "agentic-v4-recovery-slo-export-attestation", schemaVersion: 1, ownerId, exportedAt, bundleDigest, keyId: exportAttestationKeyId || null };
    let attestation = { status: "integrity_only", algorithm: "SHA-256", keyId: null, payload: attestationPayload, signature: null,
      authenticity: "not_asserted" };
    if (signExportBundle) {
      let signature;
      try { signature = await signExportBundle(structuredClone(attestationPayload)); }
      catch (error) { throw new AgenticError("RECOVERY_SLO_EXPORT_ATTESTATION_FAILED", "Signer eksternal gagal menandatangani ekspor", 503); }
      if (typeof signature !== "string" || !/^[A-Za-z0-9_-]{80,100}$/.test(signature)) throw new AgenticError("RECOVERY_SLO_EXPORT_SIGNATURE_INVALID", "Signer mengembalikan tanda tangan Ed25519 base64url yang tidak valid", 502);
      let signatureValid = false;
      try { signatureValid = verifySignature(null, Buffer.from(canonical(attestationPayload), "utf8"),
        (exportAttestationPublicKey?.type === "public" ? exportAttestationPublicKey : createPublicKey(exportAttestationPublicKey)), Buffer.from(signature, "base64url")); }
      catch { signatureValid = false; }
      if (!signatureValid) throw new AgenticError("RECOVERY_SLO_EXPORT_SIGNATURE_INVALID", "Tanda tangan signer tidak cocok dengan public key konfigurasi", 502);
      attestation = { status: "signed", algorithm: "Ed25519", keyId: exportAttestationKeyId, payload: attestationPayload, signature,
        authenticity: "signed_by_configured_external_signer" };
    }
    const bundle = { schemaVersion: 1, kind: "recovery-slo-evidence-export-bundle", ownerId, exportedAt,
      sections, manifest: { sections: manifestSections, bundleDigest }, attestation };
    const byteLength = Buffer.byteLength(canonical(bundle), "utf8");
    if (byteLength > maxBytes) throw new AgenticError("RECOVERY_SLO_EXPORT_SIZE_LIMIT_EXCEEDED", "Ekspor melebihi batas ukuran yang diizinkan", 413,
      { byteLength, maxBytes });
    return { ...bundle, byteLength, readOnly: true, mutationAllowed: false };
  }



  async function getRecoverySloEvaluationEvidence(ownerId, evidenceId) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    if (typeof evidenceId !== "string" || !evidenceId.trim() || evidenceId.length > MAX_ID || evidenceId.trim() !== evidenceId) {
      throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_ID_INVALID", "ID evidence evaluasi SLO tidak valid", 400);
    }
    const record = await store.getEvidence(ownerId, evidenceId);
    if (record?.kind === "recovery-slo-evaluation-evidence") { validateEvaluationEvidence(record, ownerId); return structuredClone(record); }
    const archiveAudit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (["unhealthy", "recovery_required"].includes(archiveAudit.status)) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_AUDIT_FAILED", "Arsip evidence memerlukan audit atau pemulihan sebelum pembacaan", 409, { findings: archiveAudit.findings });
    for (const archive of await listEvaluationArchiveRecords(ownerId)) {
      const entry = archive.entries.find(item => item.id === evidenceId);
      if (entry) return structuredClone(entry);
    }
    throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_NOT_FOUND", "Evidence evaluasi SLO tidak ditemukan", 404);
  }

  async function listRecoverySloEvaluationEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const limit = boundedInteger(options.limit, 100, 1, 500);
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-slo-evaluation-evidence");
    const archiveAudit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (["unhealthy", "recovery_required"].includes(archiveAudit.status)) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_AUDIT_FAILED", "Arsip evidence memerlukan audit atau pemulihan sebelum listing", 409, { findings: archiveAudit.findings });
    const archived = (await listEvaluationArchiveRecords(ownerId)).flatMap(item => item.entries);
    const invalid = [];
    for (const record of [...records, ...archived]) { try { validateEvaluationEvidence(record, ownerId); } catch (error) { invalid.push({ id: record.id, code: bounded(error?.code || "EVIDENCE_INVALID", 100) }); } }
    if (invalid.length) throw new AgenticError("RECOVERY_SLO_EVALUATION_EVIDENCE_INTEGRITY_FAILED", "Ditemukan evidence evaluasi SLO yang tidak valid", 409, { findings: invalid.slice(0, 50) });
    const allRecords = [...records, ...archived];
    const items = allRecords.sort((a, b) => String(b.evaluatedAt).localeCompare(String(a.evaluatedAt))).slice(0, limit).map(record => ({
      id: record.id, state: record.state, evaluatedAt: record.evaluatedAt, retentionUntil: record.retentionUntil,
      policyRevision: record.policyRevision, policyDigest: record.policyDigest, evaluationDigest: record.evaluationDigest,
      contentDigest: record.contentDigest, summary: structuredClone(record.summary), expiredAt: record.expiredAt || null,
      archived: archived.some(item => item.id === record.id)
    }));
    return { status: "healthy", ownerId, total: allRecords.length, storedRecordCount: records.length, archivedCount: archived.length,
      activeCount: allRecords.filter(item => item.state === "active").length, expiredCount: allRecords.filter(item => item.state === "expired").length,
      items, limit, truncated: allRecords.length > items.length, readOnly: true };
  }

  async function auditRecoverySloEscalationPolicy(ownerId) {
    assertOwner(ownerId);
    const promotionHold = await promotionAuditHold(ownerId);
    if (promotionHold) return promotionHold;
    const record = await store.getEvidence(ownerId, policyLedgerId(ownerId));
    if (!record) return { status: "empty", ownerId, findings: [], readOnly: true, mutationAllowed: false };
    try {
      const snapshot = validatePolicyLedger(record, ownerId);
      return { status: "healthy", ownerId, revision: snapshot.revision, policyDigest: policyDigest(snapshot.currentPolicy),
        eventCount: snapshot.events.length, lastEventHash: snapshot.events.at(-1).eventHash, findings: [], readOnly: true, mutationAllowed: false };
    } catch (error) {
      return { status: "unhealthy", ownerId, findings: [{ code: bounded(error?.code || "RECOVERY_SLO_POLICY_LEDGER_INTEGRITY_FAILED", 100) }],
        readOnly: true, mutationAllowed: false };
    }
  }

  async function auditRecoverySloEvaluationEvidence(ownerId) {
    assertOwner(ownerId);
    const promotionHold = await promotionAuditHold(ownerId);
    if (promotionHold) return promotionHold;
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-slo-evaluation-evidence");
    const findings = [];
    const archiveAudit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (archiveAudit.status === "unhealthy") findings.push(...archiveAudit.findings.slice(0, 20));
    else if (archiveAudit.status === "recovery_required") findings.push(...archiveAudit.findings.slice(0, 20));
    let archived = [];
    try { archived = (await listEvaluationArchiveRecords(ownerId)).flatMap(item => item.entries); }
    catch (error) { findings.push({ code: bounded(error?.code || "RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED", 100) }); }
    let knownPolicies = new Map();
    const policyRecord = await store.getEvidence(ownerId, policyLedgerId(ownerId));
    if (policyRecord) {
      try { knownPolicies = new Map(validatePolicyLedger(policyRecord, ownerId).events.map(event => [event.revision, event.policyDigest])); }
      catch (error) { findings.push({ code: "RECOVERY_SLO_POLICY_LEDGER_INTEGRITY_FAILED", errorCode: bounded(error?.code || "POLICY_INVALID", 100) }); }
    } else if (records.length || archived.length) findings.push({ code: "RECOVERY_SLO_POLICY_LEDGER_MISSING" });
    const seenIds = new Set();
    for (const record of [...records, ...archived]) {
      try {
        validateEvaluationEvidence(record, ownerId);
        if (seenIds.has(record.id)) throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_DUPLICATE_ENTRY", "Evidence evaluasi terduplikasi antara storage dan arsip", 409);
        seenIds.add(record.id);
        if (knownPolicies.size && knownPolicies.get(record.policyRevision) !== record.policyDigest) throw new AgenticError("RECOVERY_SLO_EVALUATION_POLICY_BINDING_MISMATCH", "Evidence tidak terikat pada versi kebijakan yang tercatat", 409);
        if (policyRecord && !knownPolicies.size) throw new AgenticError("RECOVERY_SLO_POLICY_LEDGER_INTEGRITY_FAILED", "Riwayat kebijakan tidak dapat diverifikasi", 409);
      } catch (error) { if (findings.length < 100) findings.push({ evidenceId: bounded(record?.id, MAX_ID), code: bounded(error?.code || "EVIDENCE_INVALID", 100) }); }
    }
    const status = findings.length ? (findings.some(item => /INTEGRITY|MISMATCH|DUPLICATE|CHAIN_GAP|INDEX_AHEAD|SOURCE_CONFLICT/.test(item.code)) ? "unhealthy" : "recovery_required")
      : (records.length || archived.length) ? "healthy" : "empty";
    return { status, ownerId, total: records.length + archived.length, storedRecordCount: records.length, archivedCount: archived.length,
      activeCount: [...records, ...archived].filter(item => item.state === "active").length,
      expiredCount: [...records, ...archived].filter(item => item.state === "expired").length,
      findings: findings.slice(0, 100), readOnly: true, mutationAllowed: false };
  }

  async function pruneRecoverySloEvaluationEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const now = bounded(clock(), 64);
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock retensi evidence SLO tidak valid", 500);
    const limit = boundedInteger(options.limit, 100, 1, 500);
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-slo-evaluation-evidence" && item.state === "active")
      .sort((a, b) => String(a.retentionUntil).localeCompare(String(b.retentionUntil)));
    let expired = 0;
    for (const record of records) {
      if (expired >= limit) break;
      validateEvaluationEvidence(record, ownerId);
      if (Date.parse(record.retentionUntil) > nowMs) continue;
      await store.mutateEvidence(ownerId, record.id, current => {
        if (!current) return { write: false, result: false };
        validateEvaluationEvidence(current, ownerId);
        if (current.state === "expired" || Date.parse(current.retentionUntil) > nowMs) return { write: false, result: false };
        const next = { ...current, state: "expired", expiredAt: now,
          retentionTombstone: { originalContentDigest: current.contentDigest, policyRevision: current.policyRevision,
            policyDigest: current.policyDigest, expiredAt: now, reason: "RETENTION_POLICY_ELAPSED" }, evaluation: null };
        next.digest = recordDigest(next);
        return { value: next, result: true };
      }).then(result => { if (result) expired += 1; });
    }
    return { ownerId, expired, scanned: records.length, at: now, readOnly: false, mutationAllowed: false };
  }

  function addEvent(snapshot, input) {
    if (snapshot.events.length >= MAX_EVENTS) {
      throw new AgenticError("RECOVERY_SLO_ALERT_LEDGER_CAPACITY_REACHED", "Kapasitas ledger alert SLO tercapai; event baru ditolak tanpa menghapus histori", 409);
    }
    const sequence = snapshot.sequence + 1;
    const unsigned = { ...input,
      policyRevision: input.policyRevision ?? input.evaluation?.policyRevision ?? null,
      policyDigest: input.policyDigest ?? input.evaluation?.policyDigest ?? null,
      evaluationEvidenceId: input.evaluationEvidenceId ?? input.evaluation?.evaluationEvidenceId ?? null,
      id: `slo-alert-event-${randomUUID()}`, sequence, previousHash: snapshot.events.at(-1)?.eventHash || snapshot.baseHash };
    const event = { ...unsigned, eventHash: eventHash(unsigned) };
    snapshot.events.push(event);
    snapshot.sequence = sequence;
    return event;
  }

  async function evaluateRecoverySLOs(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const policySnapshot = await ensurePolicy(ownerId);
    const policy = policySnapshot.currentPolicy;
    const activePolicyDigest = policyDigest(policy);
    const existingLedger = await store.getEvidence(ownerId, ledgerId(ownerId));
    if (existingLedger) {
      const existingSnapshot = validateLedger(existingLedger, ownerId);
      await assertArchiveWritable(ownerId, existingSnapshot);
    }
    const now = bounded(clock(), 64);
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock evaluasi SLO tidak valid", 500);
    const windowMs = boundedInteger(options.windowMs, policy.windowMs, 60_000, 24 * 60 * 60 * 1000);
    const minSamples = boundedInteger(options.minSamples, policy.minSamples, 1, 20);
    const availabilityTarget = boundedRatio(options.availabilityTarget, policy.availabilityTarget, 0.9, 1);
    const maxPendingAgeMs = boundedInteger(options.maxPendingAgeMs, policy.maxPendingAgeMs, 30_000, 60 * 60 * 1000);
    const maxLatencyMs = boundedInteger(options.maxLatencyMs, policy.maxLatencyMs, 100, 10_000);
    const health = await getAnchorHealth(ownerId, { auditLimit: 200 });
    const telemetry = await listAnchorHealthTelemetry(ownerId, { limit: MAX_SAMPLES });
    const journalAudit = await auditCrossStoreJournal(ownerId, { limit: 200, findingLimit: 100 });
    const samples = (telemetry.items || []).filter(item => {
      const sampled = Date.parse(item.sampledAt);
      return Number.isFinite(sampled) && sampled >= nowMs - windowMs && sampled <= nowMs + 30_000;
    });
    const configuredSamples = samples.filter(item => item.providerConfigured === true);
    const anchoredCount = configuredSamples.filter(item => item.anchorStatus === "anchored" && item.status === "healthy").length;
    const availability = configuredSamples.length ? anchoredCount / configuredSamples.length : null;
    const latencies = configuredSamples.map(item => item.latencyMs).filter(Number.isFinite).sort((a, b) => a - b);
    const p95 = latencies.length ? latencies[Math.min(latencies.length - 1, Math.ceil(latencies.length * 0.95) - 1)] : null;
    const pendingAgeMs = journalAudit.oldestPendingAt ? Math.max(0, nowMs - Date.parse(journalAudit.oldestPendingAt)) : 0;
    const objectives = [];
    const objective = (code, status, measured, target, severity = null, detail = null) => objectives.push({ code, status, measured, target, ...(severity ? { severity } : {}), ...(detail ? { detail } : {}) });

    if (health.configured !== true) objective("external_anchor_configured", "breached", false, true, "high", "External rollback protection is not configured.");
    else objective("external_anchor_configured", "met", true, true);

    if (health.configured !== true) objective("anchor_availability", "not_applicable", null, availabilityTarget);
    else if (health.anchorStatus !== "anchored" || health.status === "unavailable") objective("anchor_availability", "breached", availability, availabilityTarget, "high", `Current anchor status: ${bounded(health.anchorStatus, 80)}.`);
    else if (configuredSamples.length < minSamples) objective("anchor_availability", "insufficient_data", availability, availabilityTarget);
    else objective("anchor_availability", availability >= availabilityTarget ? "met" : "breached", availability, availabilityTarget,
      availability >= availabilityTarget ? null : "warning");

    if (journalAudit.status === "unhealthy" || journalAudit.truncated) objective("cross_store_recovery_integrity", "breached", journalAudit.status, "healthy and complete", "critical");
    else if (journalAudit.pendingCount > 0 && pendingAgeMs > maxPendingAgeMs) objective("cross_store_recovery_latency", "breached", pendingAgeMs, maxPendingAgeMs, "high");
    else objective("cross_store_recovery_latency", "met", pendingAgeMs, maxPendingAgeMs);

    if (telemetry.status === "unhealthy" || health.telemetryPersistenceStatus !== "stored") objective("telemetry_integrity", "breached", telemetry.status, "healthy", "critical");
    else objective("telemetry_integrity", "met", telemetry.status, "healthy");

    if (health.configured !== true) objective("anchor_response_latency", "not_applicable", null, maxLatencyMs);
    else if (health.status === "unavailable") objective("anchor_response_latency", "breached", health.latencyMs, maxLatencyMs, "warning");
    else if (latencies.length < minSamples) objective("anchor_response_latency", "insufficient_data", p95, maxLatencyMs);
    else objective("anchor_response_latency", p95 <= maxLatencyMs ? "met" : "breached", p95, maxLatencyMs, p95 <= maxLatencyMs ? null : "warning");

    const breached = objectives.filter(item => item.status === "breached");
    const status = breached.length ? "breached" : objectives.some(item => item.status === "insufficient_data") ? "insufficient_data" : "met";
    const evaluationBase = { schemaVersion: 1, ownerId, evaluatedAt: now, status, windowMs, minSamples,
      policyRevision: policySnapshot.revision, policyDigest: activePolicyDigest,
      effectivePolicy: { windowMs, minSamples, availabilityTarget, maxPendingAgeMs, maxLatencyMs,
        highObservations: policy.highObservations, highAfterMs: policy.highAfterMs,
        criticalObservations: policy.criticalObservations, criticalAfterMs: policy.criticalAfterMs,
        evaluationRetentionMs: policy.evaluationRetentionMs },
      thresholds: { availabilityTarget, maxPendingAgeMs, maxLatencyMs }, sampleCount: samples.length,
      configuredSampleCount: configuredSamples.length, oldestPendingAt: journalAudit.oldestPendingAt || null,
      pendingCount: journalAudit.pendingCount || 0, journalAuditStatus: journalAudit.status,
      telemetryStatus: telemetry.status, anchorStatus: health.anchorStatus, objectives };
    const evaluationDigest = sha256(canonical(evaluationBase));
    const evidenceId = evaluationEvidenceId(ownerId, evaluationDigest);
    const evaluation = { ...evaluationBase, evaluationDigest, evaluationEvidenceId: evidenceId, readOnly: false, automaticRemediationAllowed: false };
    const evaluationEvidence = await persistEvaluationEvidence(ownerId, evaluation, policy);
    const breachedByKey = new Map(breached.map(item => [item.code, item]));
    const id = ledgerId(ownerId);
    const transitionSummary = await store.mutateEvidence(ownerId, id, async current => {
      let snapshot;
      if (current) snapshot = validateLedger(current, ownerId);
      else snapshot = { schemaVersion: 1, ownerId, baseSequence: 0, baseHash: genesis(ownerId, id), sequence: 0, alerts: [], events: [] };
      await assertArchiveWritable(ownerId, snapshot);
      const counts = { opened: 0, deduplicated: 0, escalated: 0, resolved: 0 };
      const eventSummary = summaryEvaluation(evaluation);
      const activeByKey = new Map(snapshot.alerts.filter(item => item.status === "active" || item.status === "acknowledged").map(item => [item.alertKey, item]));
      for (const [alertKey, item] of breachedByKey) {
        let alert = activeByKey.get(alertKey);
        if (!alert) {
          if (snapshot.alerts.length >= MAX_ALERTS) throw new AgenticError("RECOVERY_SLO_ALERT_LEDGER_CAPACITY_REACHED", "Kapasitas daftar alert SLO tercapai; alert baru ditolak", 409);
          alert = { id: `recovery-slo-alert-${randomUUID()}`, alertKey, status: "active", severity: item.severity || "warning",
            openedAt: now, lastObservedAt: now, observationCount: 1, policyRevision: policySnapshot.revision, policyDigest: activePolicyDigest,
            lastEvaluationDigest: evaluationDigest, lastEvaluation: eventSummary, acknowledgedAt: null, acknowledgedBy: null,
            acknowledgementReason: null, resolvedAt: null };
          snapshot.alerts.push(alert);
          addEvent(snapshot, { type: "alert_opened", occurredAt: now, alertId: alert.id, alertKey, status: alert.status,
            severity: alert.severity, evaluationDigest, evaluation: eventSummary, reason: null, actorOwnerId: ownerId });
          counts.opened += 1;
          continue;
        }
        counts.deduplicated += 1;
        const priorSeverity = alert.severity;
        alert.observationCount += 1;
        alert.lastObservedAt = now;
        alert.lastEvaluationDigest = evaluationDigest;
        alert.lastEvaluation = eventSummary;
        alert.policyRevision = policySnapshot.revision;
        alert.policyDigest = activePolicyDigest;
        const ageMs = Math.max(0, nowMs - Date.parse(alert.openedAt));
        let escalatedSeverity = item.severity || alert.severity;
        if (alert.observationCount >= policy.criticalObservations || ageMs >= policy.criticalAfterMs) escalatedSeverity = "critical";
        else if (alert.observationCount >= policy.highObservations || ageMs >= policy.highAfterMs) escalatedSeverity = severityRank(escalatedSeverity) < severityRank("high") ? "high" : escalatedSeverity;
        if (severityRank(escalatedSeverity) > severityRank(priorSeverity)) {
          alert.severity = escalatedSeverity;
          addEvent(snapshot, { type: "alert_escalated", occurredAt: now, alertId: alert.id, alertKey, status: alert.status,
            severity: escalatedSeverity, previousSeverity: priorSeverity, evaluationDigest, evaluation: eventSummary,
            reason: ageMs >= 15 * 60 * 1000 ? "BREACH_DURATION_THRESHOLD" : "BREACH_OBSERVATION_THRESHOLD", actorOwnerId: ownerId });
          counts.escalated += 1;
        } else {
          addEvent(snapshot, { type: "alert_observed", occurredAt: now, alertId: alert.id, alertKey, status: alert.status,
            severity: alert.severity, evaluationDigest, evaluation: eventSummary, reason: null, actorOwnerId: ownerId });
        }
      }
      for (const alert of snapshot.alerts) {
        if ((alert.status === "active" || alert.status === "acknowledged") && !breachedByKey.has(alert.alertKey)) {
          alert.status = "resolved";
          alert.resolvedAt = now;
          alert.lastEvaluationDigest = evaluationDigest;
          alert.lastEvaluation = eventSummary;
          alert.policyRevision = policySnapshot.revision;
          alert.policyDigest = activePolicyDigest;
          addEvent(snapshot, { type: "alert_resolved", occurredAt: now, alertId: alert.id, alertKey: alert.alertKey,
            status: alert.status, severity: alert.severity, evaluationDigest, evaluation: eventSummary,
            reason: "SLO_BREACH_CLEARED", actorOwnerId: ownerId });
          counts.resolved += 1;
        }
      }
      const value = { id, ownerId, kind: "recovery-slo-alert-ledger", createdAt: current?.createdAt || now,
        digest: sha256(canonical(snapshot)), snapshot,
        provenance: { source: "recovery-slo-alerting", schemaVersion: 1, ownerScoped: true, hashLinked: true } };
      return { value, result: { ...counts, activeAlerts: snapshot.alerts.filter(item => item.status !== "resolved").length,
        totalAlerts: snapshot.alerts.length, eventSequence: snapshot.sequence, ledgerDigest: value.digest } };
    });
    return { ...evaluation, evaluationEvidenceRecordDigest: evaluationEvidence.recordDigest, alerts: transitionSummary, mutationAllowed: false };
  }

  async function archiveRecoverySloAlertLedgerEvents(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const limit = boundedInteger(options.limit, 250, 1, MAX_ARCHIVE_BATCH);
    const retainRecent = boundedInteger(options.retainRecent, 100, 0, MAX_EVENTS - 1);
    const id = ledgerId(ownerId);
    const result = await store.mutateEvidence(ownerId, id, async current => {
      if (!current) throw new AgenticError("RECOVERY_SLO_ALERT_LEDGER_NOT_FOUND", "Ledger alert SLO belum tersedia", 404);
      const snapshot = validateLedger(current, ownerId);
      const archives = await listArchiveRecords(ownerId);
      const chainAudit = auditArchiveChain(ownerId, snapshot, archives);
      if (chainAudit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED", "Riwayat arsip alert SLO tidak valid", 409, { findings: chainAudit.findings });
      if (chainAudit.status === "recovery_required") throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_RECOVERY_REQUIRED", "Selesaikan arsip tertunda sebelum membuat arsip baru", 409);
      if (archives.length >= MAX_ARCHIVES) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_CAPACITY_REACHED", "Kapasitas arsip alert SLO tercapai", 409);
      const count = Math.min(limit, Math.max(0, snapshot.events.length - retainRecent));
      if (!count) return { write: false, result: { status: "nothing_to_archive", ownerId, eventCount: snapshot.sequence,
        retainedEventCount: snapshot.events.length, archiveCount: archives.length, readOnly: true } };
      const events = snapshot.events.slice(0, count);
      const startSequence = events[0].sequence;
      const endSequence = events.at(-1).sequence;
      const endHash = events.at(-1).eventHash;
      const lastSequenceByAlert = new Map();
      for (const event of snapshot.events) lastSequenceByAlert.set(event.alertId, event.sequence);
      const archivedAlerts = snapshot.alerts.filter(alert => alert.status === "resolved"
        && Number.isSafeInteger(lastSequenceByAlert.get(alert.id)) && lastSequenceByAlert.get(alert.id) <= endSequence).map(alert => structuredClone(alert));
      const alertIds = [...new Set(events.map(event => event.alertId))].sort();
      const previousHash = events[0].previousHash;
      const payload = { startSequence, endSequence, previousHash, endHash, events, archivedAlerts, alertIds };
      const archiveCreatedAt = bounded(clock(), 64);
      if (!Number.isFinite(Date.parse(archiveCreatedAt))) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock arsip alert SLO tidak valid", 500);
      const candidate = { id: archiveId(ownerId, startSequence, endSequence, endHash), ownerId, kind: "recovery-slo-alert-archive",
        state: "prepared", createdAt: archiveCreatedAt, ...payload, payloadDigest: sha256(canonical(payload)) };
      candidate.digest = recordDigest(candidate);
      await store.mutateEvidence(ownerId, candidate.id, existing => {
        if (existing) {
          const valid = validateArchiveRecord(existing, ownerId);
          if (valid.payloadDigest !== candidate.payloadDigest) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_CONFLICT", "ID arsip sudah terikat pada payload berbeda", 409);
          return { write: false, result: valid };
        }
        return { value: candidate, result: candidate };
      });
      const updated = { ...snapshot, baseSequence: endSequence, baseHash: endHash,
        events: snapshot.events.slice(count), alerts: snapshot.alerts.filter(alert => !archivedAlerts.some(item => item.id === alert.id)) };
      const value = { ...current, snapshot: updated, digest: sha256(canonical(updated)), provenance: current.provenance };
      return { value, result: { status: "prepared", ownerId, archiveId: candidate.id, startSequence, endSequence, endHash,
        archivedEventCount: events.length, archivedAlertCount: archivedAlerts.length, retainedEventCount: updated.events.length,
        eventCount: updated.sequence, readOnly: false } };
    });
    if (result.status !== "prepared") return result;
    const committed = await store.mutateEvidence(ownerId, result.archiveId, current => {
      if (!current) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_MISSING", "Arsip yang disiapkan tidak ditemukan", 409);
      const archive = validateArchiveRecord(current, ownerId);
      if (archive.state === "committed") return { write: false, result: archive };
      const next = { ...archive, state: "committed" };
      next.digest = recordDigest(next);
      return { value: next, result: next };
    });
    return { ...result, status: "archived", archiveDigest: committed.digest, readOnly: false };
  }

  async function recoverRecoverySloAlertLedgerArchives(ownerId) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const id = ledgerId(ownerId);
    const current = await store.getEvidence(ownerId, id);
    if (!current) {
      const archives = await listArchiveRecords(ownerId);
      if (archives.length) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_LEDGER_MISSING", "Arsip ada tetapi ledger aktif tidak ditemukan", 409);
      return { status: "empty", ownerId, recovered: false, readOnly: true };
    }
    const snapshot = validateLedger(current, ownerId);
    const archives = await listArchiveRecords(ownerId);
    const audit = auditArchiveChain(ownerId, snapshot, archives);
    if (audit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED", "Arsip alert SLO rusak; recovery otomatis ditolak", 409, { findings: audit.findings });
    if (!audit.pendingArchive) return { status: "healthy", ownerId, recovered: false, archiveCount: archives.length, readOnly: true };
    const pending = audit.pendingArchive;
    await store.mutateEvidence(ownerId, id, async latest => {
      if (!latest) throw new AgenticError("RECOVERY_SLO_ALERT_LEDGER_NOT_FOUND", "Ledger alert SLO tidak ditemukan", 404);
      const latestSnapshot = validateLedger(latest, ownerId);
      if (latestSnapshot.baseSequence === pending.startSequence - 1) {
        const prefix = latestSnapshot.events.slice(0, pending.events.length);
        if (canonical(prefix) !== canonical(pending.events)
          || pending.archivedAlerts.some(alert => canonical(latestSnapshot.alerts.find(item => item.id === alert.id) || null) !== canonical(alert))) {
          throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_RECOVERY_BINDING_FAILED", "Payload arsip tidak cocok dengan ledger aktif", 409);
        }
        const updated = { ...latestSnapshot, baseSequence: pending.endSequence, baseHash: pending.endHash,
          events: latestSnapshot.events.slice(pending.events.length), alerts: latestSnapshot.alerts.filter(alert => !pending.archivedAlerts.some(item => item.id === alert.id)) };
        return { value: { ...latest, snapshot: updated, digest: sha256(canonical(updated)), provenance: latest.provenance },
          result: { status: "checkpoint_advanced" } };
      }
      if (latestSnapshot.baseSequence === pending.endSequence && latestSnapshot.baseHash === pending.endHash
        && pending.archivedAlerts.every(alert => !latestSnapshot.alerts.some(item => item.id === alert.id))) return { write: false, result: { status: "checkpoint_already_advanced" } };
      throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_RECOVERY_BINDING_FAILED", "Checkpoint ledger tidak cocok dengan arsip tertunda", 409);
    });
    const finalized = await store.mutateEvidence(ownerId, pending.id, latest => {
      if (!latest) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_MISSING", "Arsip tertunda tidak ditemukan", 409);
      const archive = validateArchiveRecord(latest, ownerId);
      if (archive.state === "committed") return { write: false, result: archive };
      const next = { ...archive, state: "committed" };
      next.digest = recordDigest(next);
      return { value: next, result: next };
    });
    return { status: "recovered", ownerId, recovered: true, archiveId: pending.id, endSequence: pending.endSequence,
      archiveDigest: finalized.digest, readOnly: false };
  }

  async function getRecoverySloAlertLedger(ownerId) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const record = await store.getEvidence(ownerId, ledgerId(ownerId));
    const archives = await listArchiveRecords(ownerId);
    if (!record) {
      if (archives.length) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_LEDGER_MISSING", "Arsip ada tetapi ledger aktif tidak ditemukan", 409);
      return { status: "empty", ownerId, alerts: [], totalAlerts: 0, eventCount: 0, archiveCount: 0, readOnly: true };
    }
    const snapshot = validateLedger(record, ownerId);
    const archiveAudit = auditArchiveChain(ownerId, snapshot, archives);
    if (archiveAudit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED", "Riwayat arsip alert SLO tidak valid", 409, { findings: archiveAudit.findings });
    const allAlerts = new Map();
    for (const archive of archives) for (const alert of archive.archivedAlerts) allAlerts.set(alert.id, structuredClone(alert));
    for (const alert of snapshot.alerts) allAlerts.set(alert.id, structuredClone(alert));
    return { status: archiveAudit.status, ownerId, alerts: [...allAlerts.values()].sort((a, b) => String(a.openedAt).localeCompare(String(b.openedAt))),
      totalAlerts: allAlerts.size, activeCount: snapshot.alerts.filter(item => item.status !== "resolved").length,
      archivedAlertCount: archives.reduce((sum, item) => sum + item.archivedAlerts.length, 0), archiveCount: archives.length,
      eventCount: snapshot.sequence, retainedEventCount: snapshot.events.length, archivedEventCount: snapshot.baseSequence,
      lastEventHash: snapshot.events.at(-1)?.eventHash || snapshot.baseHash, digest: record.digest, readOnly: true };
  }

  async function listRecoverySloAlertEvents(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const limit = boundedInteger(options.limit, 100, 1, 500);
    const record = await store.getEvidence(ownerId, ledgerId(ownerId));
    const archives = await listArchiveRecords(ownerId);
    if (!record) {
      if (archives.length) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_LEDGER_MISSING", "Arsip ada tetapi ledger aktif tidak ditemukan", 409);
      return { status: "empty", ownerId, total: 0, items: [], limit, truncated: false, readOnly: true };
    }
    const snapshot = validateLedger(record, ownerId);
    const archiveAudit = auditArchiveChain(ownerId, snapshot, archives);
    if (archiveAudit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED", "Riwayat arsip alert SLO tidak valid", 409, { findings: archiveAudit.findings });
    const bySequence = new Map();
    for (const archive of archives) for (const event of archive.events) {
      const previous = bySequence.get(event.sequence);
      if (previous && canonical(previous) !== canonical(event)) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_DUPLICATE_EVENT", "Event arsip bertentangan pada sequence yang sama", 409);
      bySequence.set(event.sequence, event);
    }
    for (const event of snapshot.events) {
      const previous = bySequence.get(event.sequence);
      if (previous && canonical(previous) !== canonical(event)) throw new AgenticError("RECOVERY_SLO_ALERT_ARCHIVE_DUPLICATE_EVENT", "Event aktif bertentangan dengan arsip", 409);
      bySequence.set(event.sequence, event);
    }
    const all = [...bySequence.values()].sort((a, b) => a.sequence - b.sequence);
    const items = all.slice(-limit).reverse().map(item => structuredClone(item));
    return { status: archiveAudit.status, ownerId, total: snapshot.sequence, items, limit, truncated: snapshot.sequence > items.length,
      archivedCount: snapshot.baseSequence, retainedCount: snapshot.events.length, archiveCount: archives.length, readOnly: true };
  }

  async function auditRecoverySloAlertLedger(ownerId) {
    assertOwner(ownerId);
    const promotionHold = await promotionAuditHold(ownerId);
    if (promotionHold) return promotionHold;
    const record = await store.getEvidence(ownerId, ledgerId(ownerId));
    let archives = [];
    try { archives = await listArchiveRecords(ownerId); }
    catch (error) { return { status: "unhealthy", ownerId, findings: [{ code: "RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED", errorCode: bounded(error?.code || "ARCHIVE_INVALID", 100) }], readOnly: true, mutationAllowed: false }; }
    if (!record) return archives.length
      ? { status: "unhealthy", ownerId, findings: [{ code: "RECOVERY_SLO_ALERT_ARCHIVE_LEDGER_MISSING" }], readOnly: true, mutationAllowed: false }
      : { status: "empty", ownerId, findings: [], archiveCount: 0, readOnly: true, mutationAllowed: false };
    try {
      const snapshot = validateLedger(record, ownerId);
      const archiveAudit = auditArchiveChain(ownerId, snapshot, archives);
      const bindingAudit = await auditAlertEvidenceBindings(ownerId, snapshot, archives);
      const findings = [...archiveAudit.findings, ...bindingAudit.findings].slice(0, 100);
      const status = archiveAudit.status === "unhealthy" || bindingAudit.status === "unhealthy" ? "unhealthy" : archiveAudit.status;
      return { status, ownerId, sequence: snapshot.sequence, activeCount: snapshot.alerts.filter(item => item.status !== "resolved").length,
        retainedEventCount: snapshot.events.length, archivedEventCount: snapshot.baseSequence, eventCount: snapshot.sequence,
        archivedAlertCount: archives.reduce((sum, item) => sum + item.archivedAlerts.length, 0), archiveCount: archives.length,
        digest: record.digest, findings, readOnly: true, mutationAllowed: false };
    } catch (error) {
      return { status: "unhealthy", ownerId, findings: [{ code: "RECOVERY_SLO_ALERT_LEDGER_INTEGRITY_FAILED", errorCode: bounded(error?.code || "LEDGER_INVALID", 100) }],
        readOnly: true, mutationAllowed: false };
    }
  }

  async function acknowledgeRecoverySloAlert(ownerId, alertId, reason) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    if (typeof alertId !== "string" || !alertId.trim() || alertId.length > MAX_ID || alertId.trim() !== alertId) {
      throw new AgenticError("RECOVERY_SLO_ALERT_ID_INVALID", "ID alert SLO tidak valid", 400);
    }
    if (typeof reason !== "string" || reason.trim().length < 12 || reason.trim().length > 240) {
      throw new AgenticError("RECOVERY_SLO_ALERT_ACKNOWLEDGEMENT_REASON_INVALID", "Alasan acknowledgement harus 12–240 karakter", 400);
    }
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_CLOCK_INVALID", "Clock acknowledgement tidak valid", 500);
    const id = ledgerId(ownerId);
    return store.mutateEvidence(ownerId, id, async current => {
      if (!current) throw new AgenticError("RECOVERY_SLO_ALERT_NOT_FOUND", "Alert SLO tidak ditemukan", 404);
      const snapshot = validateLedger(current, ownerId);
      await assertArchiveWritable(ownerId, snapshot);
      const alert = snapshot.alerts.find(item => item.id === alertId);
      if (!alert) throw new AgenticError("RECOVERY_SLO_ALERT_NOT_FOUND", "Alert SLO tidak ditemukan dalam owner scope", 404);
      if (alert.status === "resolved") throw new AgenticError("RECOVERY_SLO_ALERT_ALREADY_RESOLVED", "Alert yang sudah selesai tidak dapat di-acknowledge", 409);
      if (alert.status === "acknowledged") return { write: false, result: { status: "already_acknowledged", alert: structuredClone(alert), readOnly: true } };
      if (snapshot.events.length >= MAX_EVENTS) throw new AgenticError("RECOVERY_SLO_ALERT_LEDGER_CAPACITY_REACHED", "Kapasitas ledger alert SLO tercapai; acknowledgement ditolak", 409);
      alert.status = "acknowledged";
      alert.acknowledgedAt = now;
      alert.acknowledgedBy = ownerId;
      alert.acknowledgementReason = reason.trim();
      addEvent(snapshot, { type: "alert_acknowledged", occurredAt: now, alertId, alertKey: alert.alertKey,
        status: alert.status, severity: alert.severity, evaluationDigest: alert.lastEvaluationDigest,
        evaluation: alert.lastEvaluation, reason: reason.trim(), actorOwnerId: ownerId });
      const value = { id: current.id, ownerId, kind: current.kind, createdAt: current.createdAt,
        digest: sha256(canonical(snapshot)), snapshot, provenance: current.provenance };
      return { value, result: { status: "acknowledged", alert: structuredClone(alert), eventSequence: snapshot.sequence,
        evidenceDigest: value.digest, readOnly: false } };
    });
  }

  async function getRecoverySloEvaluationEvidenceArchiveStatus(ownerId) {
    const audit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    return { ...audit, readOnly: true, mutationAllowed: false };
  }

  async function listRecoverySloEvaluationEvidenceArchives(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRestorePromotionFinalized(ownerId);
    const limit = boundedInteger(options.limit, 100, 1, 500);
    const audit = await auditRecoverySloEvaluationEvidenceArchives(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED", "Arsip evidence tidak valid", 409, { findings: audit.findings });
    const archives = await listEvaluationArchiveRecords(ownerId);
    const items = archives.slice(-limit).reverse().map(item => ({ id: item.id, sequence: item.sequence, createdAt: item.createdAt,
      entryCount: item.entries.length, previousArchiveDigest: item.previousArchiveDigest, digest: item.digest,
      evidenceIds: item.entries.map(entry => entry.id) }));
    return { ...audit, items, limit, truncated: archives.length > items.length, readOnly: true, mutationAllowed: false };
  }

  return Object.freeze({ evaluateRecoverySLOs, getRecoverySloAlertLedger, listRecoverySloAlertEvents,
    auditRecoverySloAlertLedger, acknowledgeRecoverySloAlert, archiveRecoverySloAlertLedgerEvents,
    recoverRecoverySloAlertLedgerArchives, getRecoverySloEscalationPolicy, updateRecoverySloEscalationPolicy,
    listRecoverySloPolicyEvents, auditRecoverySloEscalationPolicy, listRecoverySloEvaluationEvidence, getRecoverySloEvaluationEvidence,
    auditRecoverySloEvaluationEvidence, pruneRecoverySloEvaluationEvidence, auditRecoverySloEvaluationEvidenceArchives,
    getRecoverySloEvaluationEvidenceArchiveStatus, listRecoverySloEvaluationEvidenceArchives, archiveExpiredRecoverySloEvaluationEvidence,
    recoverRecoverySloEvaluationEvidenceArchives, exportRecoverySloEvidenceBundle,
    verifyRecoverySloEvidenceExportBundle: (bundle, options = {}) => verifyRecoverySloEvidenceExportBundle(bundle, options) });
}
