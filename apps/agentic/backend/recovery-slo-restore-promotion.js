import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const MAX_OWNER_ID = 200;
const MAX_RECORDS = 10000;
const MAX_EVENTS = 20002;
const MAX_REASONS = 240;
const digestPattern = /^[a-f0-9]{64}$/;
const QUARANTINE_KIND = "recovery-slo-restore-quarantined-evidence";
const IMPORT_JOURNAL_KIND = "recovery-slo-evidence-restore-import-journal";
const REVIEW_KIND = "recovery-slo-evidence-restore-quarantine-review";
const APPROVAL_KIND = "recovery-slo-evidence-promotion-approval";
const PROMOTION_JOURNAL_KIND = "recovery-slo-evidence-promotion-journal";
const FINALIZATION_KIND = "recovery-slo-evidence-restore-finalization";
const MUTABLE_POST_PROMOTION_SECTIONS = new Set(["policyLedger", "alertLedger", "evaluationEvidence", "evaluationEvidenceArchiveIndex"]);

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const stripStorageDeep = value => {
  if (Array.isArray(value)) return value.map(stripStorageDeep);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = stripStorageDeep(item);
  return result;
};
const stripRootStorage = value => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const result = { ...value };
  delete result._storage;
  return result;
};
const recordDigest = record => {
  const copy = stripRootStorage(record);
  delete copy.digest;
  return sha256(canonical(copy));
};
const reasonValid = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= MAX_REASONS;

export function createRecoverySloRestorePromotionService({
  store,
  clock = () => new Date().toISOString(),
  restoreService,
  finalizationAttestationSigner = null,
  finalizationAttestationKeyId = null,
  finalizationAttestationPublicKeys = null,
  finalizationKeyPolicy = null,
  requireFinalizationAttestation = false,
  activeEvidenceAudit = null
} = {}) {
  if (!store?.getEvidence || !store?.listEvidence || !store?.putEvidence || !store?.mutateEvidence
    || typeof clock !== "function" || !restoreService?.getRecoverySloEvidenceRestoreImportJournal
    || !restoreService?.auditRecoverySloEvidenceRestoreImports
    || (activeEvidenceAudit != null && typeof activeEvidenceAudit !== "function")
    || (finalizationKeyPolicy != null && (typeof finalizationKeyPolicy.resolveRecoverySloFinalizationReceiptKey !== "function"
      || typeof finalizationKeyPolicy.getRecoverySloFinalizationSigningContext !== "function"))) {
    throw new TypeError("Restore promotion membutuhkan evidence store dan restore service yang valid");
  }

  const trustedFinalizationKeys = new Map();
  const keySource = finalizationAttestationPublicKeys instanceof Map
    ? [...finalizationAttestationPublicKeys.entries()]
    : finalizationAttestationPublicKeys && typeof finalizationAttestationPublicKeys === "object" && !Array.isArray(finalizationAttestationPublicKeys)
      ? Object.entries(finalizationAttestationPublicKeys) : [];
  for (const [keyId, value] of keySource.slice(0, 100)) {
    if (typeof keyId !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(keyId)) continue;
    try {
      const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
      if (key?.type === "public" && key.asymmetricKeyType === "ed25519") trustedFinalizationKeys.set(keyId, key);
    } catch { /* invalid key material is ignored; verification fails closed */ }
  }
  const signingConfigured = finalizationAttestationSigner != null || finalizationAttestationKeyId != null || requireFinalizationAttestation;
  if (signingConfigured && (typeof finalizationAttestationSigner !== "function"
    || typeof finalizationAttestationKeyId !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(finalizationAttestationKeyId)
    || !trustedFinalizationKeys.has(finalizationAttestationKeyId))) {
    throw new TypeError("Finalization attestation membutuhkan signer dan trusted public key Ed25519 yang cocok");
  }
  if (requireFinalizationAttestation && !signingConfigured) {
    throw new TypeError("Finalization attestation wajib tetapi signer tidak dikonfigurasi");
  }
  const LEGACY_FINALIZATION_ALLOWED = !requireFinalizationAttestation;
  function finalizationUnsignedPayload(record) {
    const copy = stripRootStorage(record);
    delete copy.digest;
    delete copy.attestation;
    delete copy.receiptDigest;
    return copy;
  }
  function finalizationAttestationPayload(record, keyId = record?.attestation?.keyId ?? null) {
    return { domain: "agentic-v4-recovery-slo-restore-finalization-attestation", schemaVersion: 1,
      ownerId: record.ownerId, promotionJournalId: record.promotionJournalId,
      promotionJournalDigest: record.promotionJournalDigest, finalizationId: record.id,
      receiptDigest: record.receiptDigest, activeSetDigest: record.activeSetDigest,
      activeRecordCount: record.activeRecordCount, finalizedAt: record.finalizedAt, keyId };
  }
  async function verifyFinalizationAttestation(record, ownerId = record?.ownerId) {
    if (!record || typeof record !== "object") return { valid: false, signatureValid: false, authorizedForCurrentUse: false, status: "invalid", code: "ATTESTATION_RECEIPT_MISSING" };
    if (record.attestation == null && record.receiptDigest == null) {
      return LEGACY_FINALIZATION_ALLOWED
        ? { valid: true, signatureValid: false, authorizedForCurrentUse: true, status: "legacy_integrity_only", code: null }
        : { valid: false, signatureValid: false, authorizedForCurrentUse: false, status: "invalid", code: "ATTESTATION_REQUIRED" };
    }
    if (record.receiptDigest !== sha256(canonical(finalizationUnsignedPayload(record)))) {
      return { valid: false, signatureValid: false, authorizedForCurrentUse: false, status: "invalid", code: "RECEIPT_DIGEST_MISMATCH" };
    }
    const attestation = record.attestation;
    if (!attestation || typeof attestation !== "object" || Array.isArray(attestation)
      || canonical(attestation.payload) !== canonical(finalizationAttestationPayload(record))) {
      return { valid: false, signatureValid: false, authorizedForCurrentUse: false, status: "invalid", code: "ATTESTATION_BINDING_MISMATCH" };
    }
    if (attestation.status === "integrity_only" && attestation.algorithm === "SHA-256"
      && attestation.keyId === null && attestation.signature === null) {
      return requireFinalizationAttestation
        ? { valid: false, signatureValid: false, authorizedForCurrentUse: false, status: "invalid", code: "ATTESTATION_REQUIRED" }
        : { valid: true, signatureValid: false, authorizedForCurrentUse: true, status: "valid_integrity_only", code: null };
    }
    if (attestation.status !== "signed" || attestation.algorithm !== "Ed25519"
      || typeof attestation.keyId !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(attestation.keyId)
      || typeof attestation.signature !== "string" || !/^[A-Za-z0-9_-]{80,100}$/.test(attestation.signature)) {
      return { valid: false, signatureValid: false, authorizedForCurrentUse: false, status: "invalid", code: "ATTESTATION_FORMAT_INVALID" };
    }
    let keyInfo;
    if (finalizationKeyPolicy) {
      try { keyInfo = await finalizationKeyPolicy.resolveRecoverySloFinalizationReceiptKey(ownerId, attestation.keyId, record.finalizedAt); }
      catch { keyInfo = { trusted: false, authorizedForCurrentUse: false, status: "policy_unhealthy", publicKey: null }; }
    } else {
      const key = trustedFinalizationKeys.get(attestation.keyId);
      keyInfo = key ? { trusted: true, authorizedForCurrentUse: true, status: "valid_signed", publicKey: key }
        : { trusted: false, authorizedForCurrentUse: false, status: "untrusted_key", publicKey: null };
    }
    if (!keyInfo?.publicKey) return { valid: false, signatureValid: false, authorizedForCurrentUse: false,
      status: keyInfo?.status || "untrusted_key", keyId: attestation.keyId,
      code: keyInfo?.status === "policy_unhealthy" ? "KEY_POLICY_UNHEALTHY" : "ATTESTATION_KEY_UNTRUSTED",
      policyRevision: keyInfo?.policyRevision ?? null };
    let signatureValid = false;
    try {
      const signature = Buffer.from(attestation.signature, "base64url");
      signatureValid = signature.length === 64 && verifySignature(null, Buffer.from(canonical(attestation.payload), "utf8"), keyInfo.publicKey, signature);
    } catch { signatureValid = false; }
    if (!signatureValid) return { valid: false, signatureValid: false, authorizedForCurrentUse: false,
      status: "invalid", keyId: attestation.keyId, code: "ATTESTATION_SIGNATURE_INVALID", policyRevision: keyInfo.policyRevision ?? null };
    if (!keyInfo.trusted || !keyInfo.authorizedForCurrentUse) return { valid: false, signatureValid: true, authorizedForCurrentUse: false,
      status: keyInfo.status || "historical_signature_not_authorized", keyId: attestation.keyId,
      code: keyInfo.status === "compromise_window" ? "ATTESTATION_KEY_COMPROMISE_WINDOW" : "ATTESTATION_KEY_NOT_AUTHORIZED_AT_SIGNING",
      policyRevision: keyInfo.policyRevision ?? null };
    return { valid: true, signatureValid: true, authorizedForCurrentUse: true, status: keyInfo.status || "valid_signed",
      keyId: attestation.keyId, code: null, signingKeyActive: Boolean(keyInfo.signingKeyActive),
      policyRevision: keyInfo.policyRevision ?? null };
  }
  function assertOwner(ownerId) {
    if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > MAX_OWNER_ID) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_PROMOTION_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
    }
  }
  function assertId(value, code, label) {
    if (typeof value !== "string" || !value.trim() || value.trim() !== value || value.length > 240) {
      throw new AgenticError(code, `${label} tidak valid`, 400);
    }
  }
  const reviewIdFor = (ownerId, journalId, reviewDigest) => `recovery-slo-restore-review-${sha256(canonical({ ownerId, journalId, reviewDigest })).slice(0, 48)}`;
  const approvalIdFor = reviewDigest => `recovery-slo-evidence-promotion-approval-${sha256(reviewDigest).slice(0, 48)}`;
  const promotionJournalIdFor = approvalId => `recovery-slo-evidence-promotion-${sha256(approvalId).slice(0, 48)}`;
  const finalizationIdFor = journalId => `recovery-slo-restore-finalization-${sha256(journalId).slice(0, 48)}`;
  const journalGenesis = (ownerId, id) => sha256(`agentic-v4-recovery-slo-promotion-journal:${ownerId}:${id}`);
  const eventHash = event => sha256(canonical({ sequence: event.sequence, type: event.type, at: event.at,
    previousHash: event.previousHash, details: event.details }));

  function reviewPayload(record) {
    const copy = stripRootStorage(record);
    delete copy.id;
    delete copy.reviewDigest;
    delete copy.digest;
    return copy;
  }
  function verifyReview(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.kind !== REVIEW_KIND || record.schemaVersion !== 1
      || !["ready", "blocked"].includes(record.status) || !Array.isArray(record.items) || record.items.length < 1 || record.items.length > MAX_RECORDS
      || !Array.isArray(record.findings) || typeof record.importJournalId !== "string" || !record.importJournalId
      || !digestPattern.test(record.importJournalDigest || "") || !digestPattern.test(record.sourceBundleDigest || "")
      || typeof record.reviewedBy !== "string" || !record.reviewedBy || !Number.isFinite(Date.parse(record.reviewedAt)) || !reasonValid(record.reason)
      || record.items.some((item, index) => !item || item.order !== index + 1 || typeof item.sourceRecordId !== "string"
        || !item.sourceRecordId || typeof item.quarantineRecordId !== "string" || !item.quarantineRecordId
        || !digestPattern.test(item.quarantineRecordDigest || "") || !digestPattern.test(item.payloadDigest || "")
        || !["promote", "already_present", "conflict"].includes(item.action))
      || (record.status === "ready" && record.items.some(item => item.action === "conflict"))
      || (record.status === "blocked" && !record.items.some(item => item.action === "conflict"))
      || record.reviewDigest !== sha256(canonical(reviewPayload(record))) || record.id !== reviewIdFor(ownerId, record.importJournalId, record.reviewDigest)
      || record.digest !== recordDigest(record)) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_INVALID", "Quarantine review tidak valid atau integritasnya gagal", 409);
    }
    return record;
  }
  function verifyApproval(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.kind !== APPROVAL_KIND || record.schemaVersion !== 1
      || record.status !== "approved" || !digestPattern.test(record.reviewDigest || "")
      || !digestPattern.test(record.importJournalDigest || "") || !digestPattern.test(record.sourceBundleDigest || "")
      || !Array.isArray(record.items) || record.items.length < 1 || record.items.length > MAX_RECORDS
      || typeof record.reviewId !== "string" || !record.reviewId || typeof record.importJournalId !== "string" || !record.importJournalId
      || record.items.some(item => !item || !["promote", "already_present"].includes(item.action)
        || !digestPattern.test(item.payloadDigest || "") || typeof item.sourceRecordId !== "string" || !item.sourceRecordId)
      || !reasonValid(record.reason) || typeof record.approvedBy !== "string" || !record.approvedBy
      || !Number.isFinite(Date.parse(record.approvedAt)) || record.id !== approvalIdFor(record.reviewDigest)
      || record.itemsDigest !== sha256(canonical(record.items)) || record.digest !== recordDigest(record)) {
      throw new AgenticError("RECOVERY_SLO_EVIDENCE_PROMOTION_APPROVAL_INVALID", "Promotion approval tidak valid atau integritasnya gagal", 409);
    }
    return record;
  }
  async function verifyFinalization(record, ownerId, journal = null) {
    const bindingMismatch = Boolean(journal && (
      record?.promotionJournalId !== journal.id
      || record?.promotionJournalDigest !== journal.digest
      || record?.reviewDigest !== journal.reviewDigest
      || record?.approvalDigest !== journal.approvalDigest
      || record?.approvalId !== journal.approvalId || record?.reviewId !== journal.reviewId
      || record?.importJournalId !== journal.importJournalId || record?.importJournalDigest !== journal.importJournalDigest
      || record?.sourceBundleDigest !== journal.sourceBundleDigest
      || canonical(record?.activeEntries || []) !== canonical(journal.items.map(item => ({ id: item.sourceRecordId, digest: item.sourceRecordDigest })))
    ));
    if (!record || record.ownerId !== ownerId || record.kind !== FINALIZATION_KIND || record.schemaVersion !== 1
      || record.status !== "finalized" || !digestPattern.test(record.promotionJournalDigest || "")
      || !digestPattern.test(record.reviewDigest || "") || !digestPattern.test(record.approvalDigest || "")
      || !digestPattern.test(record.importJournalDigest || "") || !digestPattern.test(record.sourceBundleDigest || "")
      || typeof record.approvalId !== "string" || !record.approvalId || typeof record.reviewId !== "string" || !record.reviewId
      || typeof record.importJournalId !== "string" || !record.importJournalId || typeof record.finalizedBy !== "string" || !record.finalizedBy
      || !digestPattern.test(record.activeSetDigest || "") || !Array.isArray(record.activeEntries)
      || record.activeRecordCount !== record.activeEntries.length || record.activeSetDigest !== sha256(canonical(record.activeEntries))
      || record.activeEntries.some(item => !item || typeof item.id !== "string" || !digestPattern.test(item.digest || ""))
      || !Number.isFinite(Date.parse(record.finalizedAt)) || record.id !== finalizationIdFor(record.promotionJournalId)
      || record.digest !== recordDigest(record) || bindingMismatch || !(await verifyFinalizationAttestation(record, ownerId)).valid) return false;
    return true;
  }
  function verifyPromotionJournal(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.kind !== PROMOTION_JOURNAL_KIND || record.schemaVersion !== 1
      || typeof record.approvalId !== "string" || !record.approvalId || record.id !== promotionJournalIdFor(record.approvalId)
      || !digestPattern.test(record.reviewDigest || "") || !digestPattern.test(record.approvalDigest || "")
      || typeof record.reviewId !== "string" || !record.reviewId || typeof record.importJournalId !== "string" || !record.importJournalId
      || !digestPattern.test(record.importJournalDigest || "")
      || !digestPattern.test(record.sourceBundleDigest || "") || !Array.isArray(record.items) || record.items.length > MAX_RECORDS
      || !Array.isArray(record.events) || record.events.length < 1 || record.events.length > MAX_EVENTS) {
      return { valid: false, code: "RECOVERY_SLO_PROMOTION_JOURNAL_SHAPE_INVALID" };
    }
    let previousHash = journalGenesis(ownerId, record.id);
    let status = "prepared";
    let items = null;
    for (let index = 0; index < record.events.length; index += 1) {
      const event = record.events[index];
      if (!event || event.sequence !== index + 1 || event.previousHash !== previousHash || !Number.isFinite(Date.parse(event.at))
        || typeof event.type !== "string" || !event.details || typeof event.details !== "object" || event.eventHash !== eventHash(event)) {
        return { valid: false, code: "RECOVERY_SLO_PROMOTION_JOURNAL_EVENT_INVALID" };
      }
      if (index === 0) {
        if (event.type !== "promotion_journal_created" || event.details.initialStatus !== "prepared"
          || event.details.approvalId !== record.approvalId || event.details.reviewDigest !== record.reviewDigest
          || !Array.isArray(event.details.initialItems)) return { valid: false, code: "RECOVERY_SLO_PROMOTION_JOURNAL_GENESIS_INVALID" };
        items = structuredClone(event.details.initialItems);
        if (items.length !== record.items.length) return { valid: false, code: "RECOVERY_SLO_PROMOTION_JOURNAL_INITIAL_ITEMS_INVALID" };
        for (let itemIndex = 0; itemIndex < items.length; itemIndex += 1) {
          const item = items[itemIndex];
          if (!item || item.order !== itemIndex + 1 || typeof item.sourceRecordId !== "string" || !item.sourceRecordId
            || typeof item.quarantineRecordId !== "string" || !digestPattern.test(item.sourceRecordDigest || "")
            || !["promote", "already_present"].includes(item.action)
            || item.state !== (item.action === "already_present" ? "already_present" : "pending")) {
            return { valid: false, code: "RECOVERY_SLO_PROMOTION_JOURNAL_INITIAL_ITEM_INVALID" };
          }
        }
      } else if (event.type === "status_changed") {
        if (event.details.fromStatus !== status) return { valid: false, code: "RECOVERY_SLO_PROMOTION_STATUS_CHAIN_INVALID" };
        const allowed = status === "prepared" ? ["applying", "blocked"] : status === "applying" ? ["completed", "blocked"] : [];
        if (!allowed.includes(event.details.toStatus)) return { valid: false, code: "RECOVERY_SLO_PROMOTION_STATUS_TRANSITION_INVALID" };
        status = event.details.toStatus;
      } else if (event.type === "item_state_changed") {
        const item = items?.find(candidate => candidate.order === event.details.order);
        if (!item || item.sourceRecordId !== event.details.sourceRecordId || item.state !== event.details.fromState
          || item.state !== "pending" || !["promoted", "already_present", "conflict"].includes(event.details.toState)) {
          return { valid: false, code: "RECOVERY_SLO_PROMOTION_ITEM_CHAIN_INVALID" };
        }
        item.state = event.details.toState;
      } else if (event.type !== "recovery_resumed") {
        return { valid: false, code: "RECOVERY_SLO_PROMOTION_EVENT_TYPE_INVALID" };
      }
      previousHash = event.eventHash;
    }
    if (!items || canonical(items) !== canonical(record.items) || record.status !== status || record.digest !== previousHash
      || record.createdAt !== record.events[0].at || record.updatedAt !== record.events.at(-1).at) {
      return { valid: false, code: "RECOVERY_SLO_PROMOTION_JOURNAL_SNAPSHOT_MISMATCH" };
    }
    if (status === "completed" && items.some(item => !["promoted", "already_present"].includes(item.state))) {
      return { valid: false, code: "RECOVERY_SLO_PROMOTION_COMPLETION_INCOMPLETE" };
    }
    if (status === "blocked" && !items.some(item => item.state === "conflict")) {
      return { valid: false, code: "RECOVERY_SLO_PROMOTION_BLOCK_REASON_MISSING" };
    }
    return { valid: true, status, items };
  }

  function promotionItemsMatchApproval(journal, approval) {
    if (!Array.isArray(journal?.items) || !Array.isArray(approval?.items) || journal.items.length !== approval.items.length) return false;
    return journal.items.every((item, index) => {
      const expected = approval.items[index];
      if (!item || !expected || item.order !== index + 1 || item.section !== expected.section
        || item.sourceRecordId !== expected.sourceRecordId || item.quarantineRecordId !== expected.quarantineRecordId
        || item.sourceRecordDigest !== expected.payloadDigest || item.action !== expected.action) return false;
      if (item.action === "already_present") return item.state === "already_present";
      return item.action === "promote" && ["pending", "promoted", "already_present", "conflict"].includes(item.state);
    });
  }

  function appendEvent(record, type, details) {
    if (record.events.length >= MAX_EVENTS) throw new AgenticError("RECOVERY_SLO_PROMOTION_EVENT_LIMIT", "Kapasitas promotion journal tercapai", 409);
    const at = String(clock());
    if (!Number.isFinite(Date.parse(at))) throw new AgenticError("RECOVERY_SLO_RESTORE_PROMOTION_CLOCK_INVALID", "Clock promotion tidak valid", 500);
    const event = { sequence: record.events.length + 1, type, at, previousHash: record.events.at(-1)?.eventHash || journalGenesis(record.ownerId, record.id), details };
    event.eventHash = eventHash(event);
    record.events.push(event);
    record.updatedAt = at;
    record.digest = event.eventHash;
    return record;
  }
  async function mutatePromotionJournal(ownerId, journalId, transition) {
    return store.mutateEvidence(ownerId, journalId, current => {
      if (!current) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND", "Promotion journal tidak ditemukan", 404);
      const check = verifyPromotionJournal(current, ownerId);
      if (!check.valid) throw new AgenticError(check.code, "Integritas promotion journal gagal", 409);
      const decision = transition(structuredClone(stripRootStorage(current)));
      if (!decision || decision.write === false) return { write: false, result: decision?.result ?? current };
      appendEvent(decision.record, decision.eventType, decision.details || {});
      const nextCheck = verifyPromotionJournal(decision.record, ownerId);
      if (!nextCheck.valid) throw new AgenticError(nextCheck.code, "Transisi promotion journal tidak konsisten", 500);
      return { value: decision.record, result: decision.record };
    });
  }
  async function setPromotionStatus(ownerId, journalId, toStatus, reasonCode = null) {
    return mutatePromotionJournal(ownerId, journalId, current => {
      if (current.status === toStatus) return { write: false, result: current };
      if (["completed", "blocked"].includes(current.status)) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_TERMINAL", "Promotion journal sudah terminal", 409);
      if (toStatus === "completed" && current.items.some(item => !["promoted", "already_present"].includes(item.state))) {
        throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_READY", "Masih ada evidence yang belum dipromosikan", 409);
      }
      if (toStatus === "blocked" && !current.items.some(item => item.state === "conflict")) {
        throw new AgenticError("RECOVERY_SLO_PROMOTION_BLOCK_REASON_REQUIRED", "Promotion hanya dapat diblokir setelah konflik tercatat", 409);
      }
      const fromStatus = current.status;
      if (!(fromStatus === "prepared" && ["applying", "blocked"].includes(toStatus))
        && !(fromStatus === "applying" && ["completed", "blocked"].includes(toStatus))) {
        throw new AgenticError("RECOVERY_SLO_PROMOTION_STATUS_TRANSITION_INVALID", "Transisi status promotion tidak diizinkan", 409);
      }
      current.status = toStatus;
      return { record: current, eventType: "status_changed", details: { fromStatus, toStatus, reasonCode } };
    });
  }
  async function setPromotionItem(ownerId, journalId, order, toState) {
    return mutatePromotionJournal(ownerId, journalId, current => {
      const item = current.items.find(candidate => candidate.order === order);
      if (!item) throw new AgenticError("RECOVERY_SLO_PROMOTION_ITEM_NOT_FOUND", "Item promotion tidak ditemukan", 409);
      if (item.state === toState) return { write: false, result: current };
      if (["promoted", "already_present"].includes(item.state) && ["promoted", "already_present"].includes(toState)) {
        return { write: false, result: current };
      }
      if (current.status !== "applying" || item.state !== "pending" || !["promoted", "already_present", "conflict"].includes(toState)) {
        throw new AgenticError("RECOVERY_SLO_PROMOTION_ITEM_TRANSITION_INVALID", "Transisi item promotion tidak diizinkan", 409);
      }
      const fromState = item.state;
      item.state = toState;
      return { record: current, eventType: "item_state_changed", details: { order, sourceRecordId: item.sourceRecordId, fromState, toState } };
    });
  }

  async function getImportJournal(ownerId, journalId) {
    const journal = await restoreService.getRecoverySloEvidenceRestoreImportJournal(ownerId, journalId);
    if (!journal.integrityValid || journal.status !== "completed") {
      throw new AgenticError("RECOVERY_SLO_RESTORE_IMPORT_NOT_COMPLETE", "Import journal harus lengkap dan lolos audit sebelum review atau promotion", 409);
    }
    return journal;
  }
  async function assertImportAuditHealthy(ownerId) {
    const audit = await restoreService.auditRecoverySloEvidenceRestoreImports(ownerId, { limit: 500 });
    if (audit.status !== "healthy" || audit.truncated) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_IMPORT_AUDIT_FAILED", "Audit import/quarantine harus lengkap dan sehat sebelum promotion", 409,
        { status: audit.status, truncated: audit.truncated, findings: audit.findings?.slice(0, 20) || [] });
    }
    return audit;
  }
  async function getQuarantine(ownerId, importJournal, item) {
    const record = await store.getEvidence(ownerId, item.quarantineRecordId);
    if (!record || record.ownerId !== ownerId || record.kind !== QUARANTINE_KIND || record.status !== "quarantined"
      || record.journalId !== importJournal.journalId || record.approvalId !== importJournal.approvalId
      || record.planDigest !== importJournal.planDigest || record.sourceBundleDigest !== importJournal.sourceBundleDigest
      || record.sourceRecordId !== item.sourceRecordId || record.sourceSection !== item.section || record.sourceKind !== item.sourceKind
      || record.sourceRecordDigest !== item.sourceDigest || record.payloadDigest !== item.sourceDigest
      || record.payloadDigest !== sha256(canonical(stripStorageDeep(record.payload))) || record.digest !== recordDigest(record)) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_QUARANTINE_INTEGRITY_FAILED", "Quarantined evidence tidak cocok dengan import journal", 409,
        { recordId: item.quarantineRecordId });
    }
    return record;
  }
  async function verifyReviewTargets(ownerId, review, importJournal, promotionJournal = null) {
    for (const item of review.items) {
      const importItem = importJournal.items.find(candidate => candidate.sourceRecordId === item.sourceRecordId
        && candidate.section === item.section && candidate.quarantineRecordId === item.quarantineRecordId);
      if (!importItem || importItem.state !== "quarantined") throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_BINDING_INVALID", "Review tidak terikat pada item quarantine yang aktif", 409);
      const quarantine = await getQuarantine(ownerId, importJournal, importItem);
      if (quarantine.payloadDigest !== item.payloadDigest || quarantine.digest !== item.quarantineRecordDigest) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_STALE", "Quarantine berubah setelah review dibuat", 409);
      }
      const active = await store.getEvidence(ownerId, item.sourceRecordId);
      const activeDigest = active ? sha256(canonical(stripStorageDeep(active))) : null;
      const promotionItem = promotionJournal?.items?.find(candidate => candidate.sourceRecordId === item.sourceRecordId
        && candidate.section === item.section);
      const activeMatchesQuarantine = Boolean(active && activeDigest === item.payloadDigest
        && canonical(stripStorageDeep(active)) === canonical(stripStorageDeep(quarantine.payload)));
      if (item.action === "promote" && active && !(promotionJournal && promotionItem
        && ["pending", "promoted"].includes(promotionItem.state) && activeMatchesQuarantine)) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_STALE", "Target berubah setelah review; buat review baru", 409);
      }
      if (item.action === "already_present" && (!active || activeDigest !== item.payloadDigest || !activeMatchesQuarantine)) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_STALE", "Record target tidak lagi cocok dengan review", 409);
      }
      if (item.action === "conflict") throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_BLOCKED", "Review memiliki konflik yang belum terselesaikan", 409);
    }
  }
  function summarizePromotionJournal(journal) {
    return { journalId: journal.id, ownerId: journal.ownerId, status: journal.status, approvalId: journal.approvalId,
      reviewId: journal.reviewId, reviewDigest: journal.reviewDigest, importJournalId: journal.importJournalId,
      sourceBundleDigest: journal.sourceBundleDigest, createdAt: journal.createdAt, updatedAt: journal.updatedAt,
      digest: journal.digest, counts: { total: journal.items.length, pending: journal.items.filter(item => item.state === "pending").length,
        promoted: journal.items.filter(item => item.state === "promoted").length,
        alreadyPresent: journal.items.filter(item => item.state === "already_present").length,
        conflicts: journal.items.filter(item => item.state === "conflict").length },
      activated: false, finalized: false, mutationAllowed: false };
  }
  async function createPromotionJournal(ownerId, approval, review, importJournal) {
    const id = promotionJournalIdFor(approval.id);
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      const check = verifyPromotionJournal(existing, ownerId);
      if (!check.valid || existing.approvalId !== approval.id || existing.reviewDigest !== review.reviewDigest) {
        throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_CONFLICT", "Promotion journal yang ada tidak cocok dengan approval", 409);
      }
      return existing;
    }
    const current = (await store.listEvidence(ownerId)).filter(record => record?.kind === PROMOTION_JOURNAL_KIND);
    if (current.length >= 1000) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_LIMIT", "Batas promotion journal tercapai", 409);
    const now = String(clock());
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_RESTORE_PROMOTION_CLOCK_INVALID", "Clock promotion tidak valid", 500);
    const items = approval.items.map((item, index) => ({ order: index + 1, section: item.section, sourceRecordId: item.sourceRecordId,
      quarantineRecordId: item.quarantineRecordId, sourceRecordDigest: item.payloadDigest, action: item.action,
      state: item.action === "already_present" ? "already_present" : "pending" }));
    const first = { sequence: 1, type: "promotion_journal_created", at: now, previousHash: journalGenesis(ownerId, id),
      details: { initialStatus: "prepared", initialItems: structuredClone(items), approvalId: approval.id, reviewDigest: review.reviewDigest } };
    first.eventHash = eventHash(first);
    const record = { id, ownerId, kind: PROMOTION_JOURNAL_KIND, schemaVersion: 1, status: "prepared", approvalId: approval.id,
      approvalDigest: approval.digest, reviewId: review.id, reviewDigest: review.reviewDigest, importJournalId: importJournal.journalId,
      importJournalDigest: importJournal.digest, sourceBundleDigest: importJournal.sourceBundleDigest, createdAt: now, updatedAt: now,
      items, events: [first], digest: first.eventHash };
    const check = verifyPromotionJournal(record, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Promotion journal awal tidak valid", 500);
    try { await store.putEvidence(ownerId, record, { overwrite: false }); return record; }
    catch (error) {
      const raced = await store.getEvidence(ownerId, id);
      const racedCheck = verifyPromotionJournal(raced, ownerId);
      if (racedCheck.valid && raced.approvalId === approval.id && raced.reviewDigest === review.reviewDigest) return raced;
      throw error;
    }
  }

  async function reviewRecoverySloEvidenceRestoreQuarantine(ownerId, importJournalId, options = {}) {
    assertOwner(ownerId);
    assertId(importJournalId, "RECOVERY_SLO_RESTORE_IMPORT_JOURNAL_ID_INVALID", "Import journal ID");
    if (!reasonValid(options.reason)) throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_REASON_REQUIRED", "Alasan review harus 12–240 karakter", 400);
    await assertImportAuditHealthy(ownerId);
    const journal = await getImportJournal(ownerId, importJournalId);
    const candidates = journal.items.filter(item => item.state === "quarantined");
    if (!candidates.length) throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_EMPTY", "Import journal tidak memiliki evidence quarantine untuk direview", 409);
    const items = [];
    const findings = [];
    for (const item of candidates) {
      const quarantine = await getQuarantine(ownerId, journal, item);
      const active = await store.getEvidence(ownerId, item.sourceRecordId);
      const activeDigest = active ? sha256(canonical(stripStorageDeep(active))) : null;
      let action = "promote";
      if (active && activeDigest === quarantine.payloadDigest && canonical(stripStorageDeep(active)) === canonical(stripStorageDeep(quarantine.payload))) action = "already_present";
      else if (active) {
        action = "conflict";
        findings.push({ code: "RECOVERY_SLO_RESTORE_PROMOTION_TARGET_CONFLICT", sourceRecordId: item.sourceRecordId });
      }
      items.push({ order: items.length + 1, section: item.section, sourceRecordId: item.sourceRecordId,
        quarantineRecordId: quarantine.id, quarantineRecordDigest: quarantine.digest, payloadDigest: quarantine.payloadDigest,
        sourceKind: item.sourceKind, action, activeTargetDigest: activeDigest });
    }
    const reviewedAt = String(clock());
    if (!Number.isFinite(Date.parse(reviewedAt))) throw new AgenticError("RECOVERY_SLO_RESTORE_PROMOTION_CLOCK_INVALID", "Clock review tidak valid", 500);
    const payload = { schemaVersion: 1, kind: REVIEW_KIND, ownerId, importJournalId, importJournalDigest: journal.digest,
      sourceBundleDigest: journal.sourceBundleDigest, reviewedAt, reviewedBy: ownerId, reason: options.reason.trim(),
      status: findings.length ? "blocked" : "ready", items, findings };
    const reviewDigest = sha256(canonical(payload));
    const record = { ...payload, id: reviewIdFor(ownerId, importJournalId, reviewDigest), reviewDigest, digest: "" };
    record.digest = recordDigest(record);
    const existing = await store.getEvidence(ownerId, record.id);
    if (existing) {
      const valid = verifyReview(existing, ownerId);
      return summarizeReview(valid, true);
    }
    const count = (await store.listEvidence(ownerId)).filter(item => item?.kind === REVIEW_KIND).length;
    if (count >= 1000) throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_LIMIT", "Batas quarantine review tercapai", 409);
    await store.putEvidence(ownerId, record, { overwrite: false });
    return summarizeReview(record, false);
  }
  function summarizeReview(review, idempotent = false) {
    return { reviewId: review.id, ownerId: review.ownerId, importJournalId: review.importJournalId,
      importJournalDigest: review.importJournalDigest, sourceBundleDigest: review.sourceBundleDigest,
      status: review.status, reviewedAt: review.reviewedAt, reviewedBy: review.reviewedBy,
      reviewDigest: review.reviewDigest, counts: { total: review.items.length, promote: review.items.filter(item => item.action === "promote").length,
        alreadyPresent: review.items.filter(item => item.action === "already_present").length, conflicts: review.items.filter(item => item.action === "conflict").length },
      findings: structuredClone(review.findings), readOnly: true, mutationAllowed: false, idempotent };
  }
  async function getRecoverySloEvidenceRestoreQuarantineReview(ownerId, reviewId) {
    assertOwner(ownerId); assertId(reviewId, "RECOVERY_SLO_RESTORE_REVIEW_ID_INVALID", "Review ID");
    const record = await store.getEvidence(ownerId, reviewId);
    if (!record) throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_NOT_FOUND", "Quarantine review tidak ditemukan", 404);
    const review = verifyReview(record, ownerId);
    return { ...summarizeReview(review), items: structuredClone(review.items), reason: review.reason, digest: review.digest };
  }
  async function listRecoverySloEvidenceRestoreQuarantineReviews(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = Number.isSafeInteger(options.limit) ? Math.max(1, Math.min(100, options.limit)) : 25;
    const all = (await store.listEvidence(ownerId)).filter(item => item?.kind === REVIEW_KIND)
      .sort((a, b) => String(b.reviewedAt).localeCompare(String(a.reviewedAt)));
    const items = all.slice(0, limit).map(record => {
      try { return summarizeReview(verifyReview(record, ownerId)); }
      catch (error) { return { reviewId: record?.id || null, status: "unhealthy", finding: error?.code || "REVIEW_INVALID", mutationAllowed: false }; }
    });
    return { ownerId, items, total: all.length, limit, truncated: all.length > items.length, readOnly: true, mutationAllowed: false };
  }

  async function approveRecoverySloEvidencePromotion(ownerId, reviewId, options = {}) {
    assertOwner(ownerId); assertId(reviewId, "RECOVERY_SLO_RESTORE_REVIEW_ID_INVALID", "Review ID");
    if (!reasonValid(options.reason)) throw new AgenticError("RECOVERY_SLO_EVIDENCE_PROMOTION_REASON_REQUIRED", "Alasan promotion approval harus 12–240 karakter", 400);
    const review = verifyReview(await store.getEvidence(ownerId, reviewId), ownerId);
    if (review.status !== "ready") throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_BLOCKED", "Review tidak siap untuk promotion", 409);
    if (options.confirmation !== `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_EVIDENCE_PROMOTION_CONFIRMATION_REQUIRED", "Konfirmasi promotion tidak cocok dengan digest review", 400);
    }
    await assertImportAuditHealthy(ownerId);
    const importJournal = await getImportJournal(ownerId, review.importJournalId);
    if (importJournal.digest !== review.importJournalDigest || importJournal.sourceBundleDigest !== review.sourceBundleDigest) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_REVIEW_STALE", "Import journal berubah setelah review", 409);
    }
    await verifyReviewTargets(ownerId, review, importJournal);
    const id = approvalIdFor(review.reviewDigest);
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      const approval = verifyApproval(existing, ownerId);
      if (approval.reviewDigest !== review.reviewDigest || approval.itemsDigest !== sha256(canonical(review.items))) {
        throw new AgenticError("RECOVERY_SLO_EVIDENCE_PROMOTION_APPROVAL_CONFLICT", "Promotion approval yang ada tidak cocok", 409);
      }
      return summarizeApproval(approval, true);
    }
    const now = String(clock());
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_RESTORE_PROMOTION_CLOCK_INVALID", "Clock approval tidak valid", 500);
    const payload = { id, ownerId, kind: APPROVAL_KIND, schemaVersion: 1, status: "approved", reviewId: review.id,
      reviewDigest: review.reviewDigest, importJournalId: importJournal.journalId, importJournalDigest: importJournal.digest,
      sourceBundleDigest: importJournal.sourceBundleDigest, items: structuredClone(review.items), itemsDigest: sha256(canonical(review.items)),
      approvedAt: now, approvedBy: ownerId, reason: options.reason.trim() };
    const approval = { ...payload, digest: recordDigest(payload) };
    const count = (await store.listEvidence(ownerId)).filter(item => item?.kind === APPROVAL_KIND).length;
    if (count >= 1000) throw new AgenticError("RECOVERY_SLO_EVIDENCE_PROMOTION_APPROVAL_LIMIT", "Batas promotion approval tercapai", 409);
    try { await store.putEvidence(ownerId, approval, { overwrite: false }); }
    catch (error) {
      const raced = await store.getEvidence(ownerId, id);
      if (!raced || raced.digest !== approval.digest) throw error;
    }
    return summarizeApproval(approval, false);
  }
  function summarizeApproval(approval, idempotent = false) {
    return { approvalId: approval.id, ownerId: approval.ownerId, status: approval.status, reviewId: approval.reviewId,
      reviewDigest: approval.reviewDigest, importJournalId: approval.importJournalId, sourceBundleDigest: approval.sourceBundleDigest,
      approvedAt: approval.approvedAt, approvedBy: approval.approvedBy, itemsDigest: approval.itemsDigest,
      digest: approval.digest, readOnly: true, mutationAllowed: false, idempotent };
  }

  async function processPromotion(ownerId, journalId, { recovery = false } = {}) {
    let journal = await store.getEvidence(ownerId, journalId);
    let check = verifyPromotionJournal(journal, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Integritas promotion journal gagal", 409);
    if (["completed", "blocked"].includes(journal.status)) return summarizePromotionJournal(journal);
    const approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
    const review = verifyReview(await store.getEvidence(ownerId, journal.reviewId), ownerId);
    if (approval.digest !== journal.approvalDigest || review.reviewDigest !== journal.reviewDigest
      || approval.reviewDigest !== review.reviewDigest || approval.importJournalDigest !== journal.importJournalDigest
      || approval.itemsDigest !== sha256(canonical(review.items)) || canonical(approval.items) !== canonical(review.items)
      || !promotionItemsMatchApproval(journal, approval)) {
      throw new AgenticError("RECOVERY_SLO_PROMOTION_BINDING_INVALID", "Approval, review, dan journal tidak cocok", 409);
    }
    await assertImportAuditHealthy(ownerId);
    const importJournal = await getImportJournal(ownerId, journal.importJournalId);
    if (importJournal.digest !== journal.importJournalDigest) throw new AgenticError("RECOVERY_SLO_PROMOTION_IMPORT_BINDING_INVALID", "Import journal berubah setelah promotion disetujui", 409);
    await verifyReviewTargets(ownerId, review, importJournal, journal);
    if (journal.status === "prepared") journal = await setPromotionStatus(ownerId, journalId, "applying", recovery ? "RECOVERY_RESUMED" : null);
    for (const item of journal.items) {
      if (item.state !== "pending") continue;
      const reviewItem = review.items.find(candidate => candidate.sourceRecordId === item.sourceRecordId && candidate.section === item.section);
      const importItem = importJournal.items.find(candidate => candidate.sourceRecordId === item.sourceRecordId && candidate.section === item.section);
      if (!reviewItem || !importItem) throw new AgenticError("RECOVERY_SLO_PROMOTION_ITEM_BINDING_INVALID", "Item promotion tidak cocok dengan review/import", 409);
      const quarantine = await getQuarantine(ownerId, importJournal, importItem);
      if (quarantine.id !== item.quarantineRecordId || quarantine.payloadDigest !== item.sourceRecordDigest) {
        throw new AgenticError("RECOVERY_SLO_PROMOTION_QUARANTINE_BINDING_INVALID", "Quarantine berubah selama promotion", 409);
      }
      const active = await store.getEvidence(ownerId, item.sourceRecordId);
      if (active) {
        if (canonical(stripStorageDeep(active)) === canonical(stripStorageDeep(quarantine.payload))) {
          journal = await setPromotionItem(ownerId, journalId, item.order, "already_present");
          continue;
        }
        journal = await setPromotionItem(ownerId, journalId, item.order, "conflict");
        journal = await setPromotionStatus(ownerId, journalId, "blocked", "TARGET_RECORD_CONFLICT");
        return summarizePromotionJournal(journal);
      }
      try { await store.putEvidence(ownerId, stripStorageDeep(structuredClone(quarantine.payload)), { overwrite: false }); }
      catch (error) {
        const raced = await store.getEvidence(ownerId, item.sourceRecordId);
        if (!raced) throw error;
        if (canonical(stripStorageDeep(raced)) === canonical(stripStorageDeep(quarantine.payload))) {
          journal = await setPromotionItem(ownerId, journalId, item.order, "promoted");
          continue;
        }
        journal = await setPromotionItem(ownerId, journalId, item.order, "conflict");
        journal = await setPromotionStatus(ownerId, journalId, "blocked", "TARGET_RECORD_CONFLICT_AFTER_WRITE_RACE");
        return summarizePromotionJournal(journal);
      }
      const saved = await store.getEvidence(ownerId, item.sourceRecordId);
      if (!saved || canonical(stripStorageDeep(saved)) !== canonical(stripStorageDeep(quarantine.payload))) {
        throw new AgenticError("RECOVERY_SLO_PROMOTION_WRITE_UNVERIFIED", "Record aktif setelah write tidak cocok; journal tetap pending untuk recovery", 409);
      }
      journal = await setPromotionItem(ownerId, journalId, item.order, "promoted");
    }
    journal = await store.getEvidence(ownerId, journalId);
    check = verifyPromotionJournal(journal, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Promotion journal tidak valid setelah penerapan", 409);
    if (journal.status === "applying" && journal.items.every(item => ["promoted", "already_present"].includes(item.state))) {
      journal = await setPromotionStatus(ownerId, journalId, "completed");
    }
    return summarizePromotionJournal(journal);
  }

  async function promoteRecoverySloQuarantinedEvidence(ownerId, approvalId) {
    assertOwner(ownerId); assertId(approvalId, "RECOVERY_SLO_EVIDENCE_PROMOTION_APPROVAL_ID_INVALID", "Promotion approval ID");
    const approval = verifyApproval(await store.getEvidence(ownerId, approvalId), ownerId);
    const review = verifyReview(await store.getEvidence(ownerId, approval.reviewId), ownerId);
    if (review.reviewDigest !== approval.reviewDigest || review.status !== "ready"
      || approval.itemsDigest !== sha256(canonical(review.items)) || canonical(approval.items) !== canonical(review.items)) {
      throw new AgenticError("RECOVERY_SLO_PROMOTION_REVIEW_BINDING_INVALID", "Review tidak cocok atau tidak siap", 409);
    }
    await assertImportAuditHealthy(ownerId);
    const importJournal = await getImportJournal(ownerId, approval.importJournalId);
    if (importJournal.digest !== approval.importJournalDigest) throw new AgenticError("RECOVERY_SLO_PROMOTION_IMPORT_BINDING_INVALID", "Import journal berubah setelah approval", 409);
    await verifyReviewTargets(ownerId, review, importJournal);
    const journal = await createPromotionJournal(ownerId, approval, review, importJournal);
    return processPromotion(ownerId, journal.id);
  }

  async function recoverRecoverySloEvidencePromotion(ownerId, journalId) {
    assertOwner(ownerId); assertId(journalId, "RECOVERY_SLO_PROMOTION_JOURNAL_ID_INVALID", "Promotion journal ID");
    const journal = await store.getEvidence(ownerId, journalId);
    if (!journal) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND", "Promotion journal tidak ditemukan", 404);
    const check = verifyPromotionJournal(journal, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Integritas promotion journal gagal", 409);
    if (["completed", "blocked"].includes(journal.status)) return summarizePromotionJournal(journal);
    return processPromotion(ownerId, journalId, { recovery: true });
  }

  async function getRecoverySloEvidencePromotionJournal(ownerId, journalId) {
    assertOwner(ownerId); assertId(journalId, "RECOVERY_SLO_PROMOTION_JOURNAL_ID_INVALID", "Promotion journal ID");
    const journal = await store.getEvidence(ownerId, journalId);
    if (!journal) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND", "Promotion journal tidak ditemukan", 404);
    const check = verifyPromotionJournal(journal, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Integritas promotion journal gagal", 409);
    return { ...summarizePromotionJournal(journal), items: structuredClone(journal.items), events: structuredClone(journal.events),
      integrityValid: true, readOnly: true };
  }
  async function listRecoverySloEvidencePromotionJournals(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = Number.isSafeInteger(options.limit) ? Math.max(1, Math.min(100, options.limit)) : 25;
    const all = (await store.listEvidence(ownerId)).filter(item => item?.kind === PROMOTION_JOURNAL_KIND)
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    const items = all.slice(0, limit).map(record => {
      const check = verifyPromotionJournal(record, ownerId);
      return check.valid ? summarizePromotionJournal(record) : { journalId: record?.id || null, status: "unhealthy", finding: check.code, mutationAllowed: false };
    });
    return { ownerId, items, total: all.length, limit, truncated: all.length > items.length, readOnly: true, mutationAllowed: false };
  }

  async function finalizeRecoverySloEvidenceRestore(ownerId, promotionJournalId) {
    assertOwner(ownerId); assertId(promotionJournalId, "RECOVERY_SLO_PROMOTION_JOURNAL_ID_INVALID", "Promotion journal ID");
    const journal = await store.getEvidence(ownerId, promotionJournalId);
    if (!journal) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND", "Promotion journal tidak ditemukan", 404);
    const journalCheck = verifyPromotionJournal(journal, ownerId);
    if (!journalCheck.valid) throw new AgenticError(journalCheck.code, "Promotion journal tidak valid untuk finalisasi", 409);
    if (journal.status !== "completed") throw new AgenticError("RECOVERY_SLO_RESTORE_FINALIZATION_NOT_READY", "Promotion harus completed sebelum finalisasi", 409);
    const approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
    const review = verifyReview(await store.getEvidence(ownerId, journal.reviewId), ownerId);
    const importJournal = await getImportJournal(ownerId, journal.importJournalId);
    if (approval.digest !== journal.approvalDigest || review.reviewDigest !== journal.reviewDigest
      || approval.reviewDigest !== review.reviewDigest || approval.itemsDigest !== sha256(canonical(review.items))
      || canonical(approval.items) !== canonical(review.items) || !promotionItemsMatchApproval(journal, approval)
      || importJournal.digest !== journal.importJournalDigest || approval.importJournalDigest !== importJournal.digest) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_FINALIZATION_BINDING_INVALID", "Approval, review, atau import journal berubah sebelum finalisasi", 409);
    }
    await assertImportAuditHealthy(ownerId);
    const existing = await store.getEvidence(ownerId, finalizationIdFor(journal.id));
    if (existing) {
      if (!(await verifyFinalization(existing, ownerId, journal))) throw new AgenticError("RECOVERY_SLO_RESTORE_FINALIZATION_CONFLICT", "Finalization receipt yang ada tidak cocok", 409);
      return summarizeFinalization(existing, true);
    }
    const activeEntries = [];
    for (const item of journal.items) {
      if (!["promoted", "already_present"].includes(item.state)) throw new AgenticError("RECOVERY_SLO_RESTORE_FINALIZATION_INCOMPLETE", "Masih ada item promotion yang belum selesai", 409);
      const importItem = importJournal.items.find(candidate => candidate.sourceRecordId === item.sourceRecordId && candidate.section === item.section);
      if (!importItem) throw new AgenticError("RECOVERY_SLO_RESTORE_FINALIZATION_ITEM_MISSING", "Item tidak ditemukan dalam import journal", 409);
      const quarantine = await getQuarantine(ownerId, importJournal, importItem);
      const active = await store.getEvidence(ownerId, item.sourceRecordId);
      if (!active || canonical(stripStorageDeep(active)) !== canonical(stripStorageDeep(quarantine.payload))
        || sha256(canonical(stripStorageDeep(active))) !== item.sourceRecordDigest) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_FINALIZATION_ACTIVE_RECORD_MISMATCH", "Record aktif tidak cocok dengan evidence yang direview", 409,
          { sourceRecordId: item.sourceRecordId });
      }
      activeEntries.push({ id: item.sourceRecordId, digest: sha256(canonical(stripStorageDeep(active))) });
    }
    const finalizedAt = String(clock());
    if (!Number.isFinite(Date.parse(finalizedAt))) throw new AgenticError("RECOVERY_SLO_RESTORE_PROMOTION_CLOCK_INVALID", "Clock finalisasi tidak valid", 500);
    const payload = { id: finalizationIdFor(journal.id), ownerId, kind: FINALIZATION_KIND, schemaVersion: 1, status: "finalized",
      promotionJournalId: journal.id, promotionJournalDigest: journal.digest, approvalId: approval.id, approvalDigest: approval.digest,
      reviewId: review.id, reviewDigest: review.reviewDigest, importJournalId: importJournal.journalId,
      importJournalDigest: importJournal.digest, sourceBundleDigest: journal.sourceBundleDigest, finalizedAt, finalizedBy: ownerId,
      activeRecordCount: activeEntries.length, activeSetDigest: sha256(canonical(activeEntries)), activeEntries };
    if (requireFinalizationAttestation && !finalizationAttestationSigner) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_ATTESTATION_REQUIRED", "Finalization membutuhkan external Ed25519 attestation", 503);
    }
    const receiptDigest = sha256(canonical(payload));
    let signingContext = null;
    if (finalizationAttestationSigner && finalizationKeyPolicy) {
      try { signingContext = await finalizationKeyPolicy.getRecoverySloFinalizationSigningContext(ownerId); }
      catch (error) { throw new AgenticError(error?.code || "RECOVERY_SLO_FINALIZATION_SIGNING_KEY_UNAVAILABLE", "Finalization signing key policy tidak tersedia atau tidak sehat", 503); }
    }
    const attestationKeyId = finalizationAttestationSigner ? (signingContext?.keyId || finalizationAttestationKeyId) : null;
    const attestationPayload = finalizationAttestationPayload({ ...payload, receiptDigest }, attestationKeyId);
    let attestation;
    if (finalizationAttestationSigner) {
      let signature;
      try { signature = await finalizationAttestationSigner(structuredClone(attestationPayload)); }
      catch { throw new AgenticError("RECOVERY_SLO_FINALIZATION_ATTESTATION_SIGNING_FAILED", "External signer gagal membuat finalization attestation", 503); }
      if (typeof signature !== "string" || !/^[A-Za-z0-9_-]{80,100}$/.test(signature)) {
        throw new AgenticError("RECOVERY_SLO_FINALIZATION_ATTESTATION_SIGNATURE_INVALID", "External signer mengembalikan signature yang tidak valid", 502);
      }
      const key = signingContext?.publicKey || trustedFinalizationKeys.get(attestationKeyId);
      let signatureValid = false;
      try { signatureValid = verifySignature(null, Buffer.from(canonical(attestationPayload), "utf8"), key, Buffer.from(signature, "base64url")); } catch { /* fail closed */ }
      if (!signatureValid) throw new AgenticError("RECOVERY_SLO_FINALIZATION_ATTESTATION_SIGNATURE_INVALID", "Signature external signer tidak cocok dengan trusted public key", 502);
      attestation = { status: "signed", algorithm: "Ed25519", keyId: attestationKeyId, payload: attestationPayload, signature };
    } else {
      attestation = { status: "integrity_only", algorithm: "SHA-256", keyId: null, payload: attestationPayload, signature: null };
    }
    const receiptWithoutDigest = { ...payload, receiptDigest, attestation };
    const receipt = { ...receiptWithoutDigest, digest: recordDigest(receiptWithoutDigest) };
    try { await store.putEvidence(ownerId, receipt, { overwrite: false }); }
    catch (error) {
      const raced = await store.getEvidence(ownerId, receipt.id);
      if (!raced || !(await verifyFinalization(raced, ownerId, journal))) throw error;
      return summarizeFinalization(raced, true);
    }
    const saved = await store.getEvidence(ownerId, receipt.id);
    if (!(await verifyFinalization(saved, ownerId, journal))) throw new AgenticError("RECOVERY_SLO_RESTORE_FINALIZATION_WRITE_UNVERIFIED", "Finalization receipt tidak lolos verifikasi setelah disimpan", 500);
    return summarizeFinalization(saved, false);
  }
  function summarizeFinalization(record, idempotent = false) {
    return { finalizationId: record.id, ownerId: record.ownerId, status: record.status, promotionJournalId: record.promotionJournalId,
      promotionJournalDigest: record.promotionJournalDigest, activeRecordCount: record.activeRecordCount, activeSetDigest: record.activeSetDigest,
      finalizedAt: record.finalizedAt, finalizedBy: record.finalizedBy, digest: record.digest, receiptDigest: record.receiptDigest ?? null,
      attestationStatus: record.attestation?.status === "signed" ? "signed" : "valid_integrity_only", attestationKeyId: record.attestation?.keyId ?? null, idempotent,
      readOnly: true, mutationAllowed: false };
  }

  async function auditRecoverySloEvidenceRestorePromotions(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = Number.isSafeInteger(options.limit) ? Math.max(1, Math.min(500, options.limit)) : 100;
    const all = await store.listEvidence(ownerId);
    const journals = all.filter(item => item?.kind === PROMOTION_JOURNAL_KIND).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
    const finalizations = all.filter(item => item?.kind === FINALIZATION_KIND);
    const reviews = all.filter(item => item?.kind === REVIEW_KIND).sort((a, b) => String(a.reviewedAt).localeCompare(String(b.reviewedAt)));
    const approvals = all.filter(item => item?.kind === APPROVAL_KIND).sort((a, b) => String(a.approvedAt).localeCompare(String(b.approvedAt)));
    const findings = [];
    let checked = 0;
    for (const journal of journals.slice(0, limit)) {
      checked += 1;
      const check = verifyPromotionJournal(journal, ownerId);
      if (!check.valid) { findings.push({ code: check.code, journalId: journal.id, severity: "error" }); continue; }
      let approval, review, importJournal;
      try {
        approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
        review = verifyReview(await store.getEvidence(ownerId, journal.reviewId), ownerId);
        importJournal = await restoreService.getRecoverySloEvidenceRestoreImportJournal(ownerId, journal.importJournalId);
        if (approval.digest !== journal.approvalDigest || approval.reviewDigest !== journal.reviewDigest
          || approval.itemsDigest !== sha256(canonical(review.items)) || canonical(approval.items) !== canonical(review.items)
          || !promotionItemsMatchApproval(journal, approval) || review.reviewDigest !== journal.reviewDigest
          || review.status !== "ready" || importJournal.digest !== journal.importJournalDigest
          || importJournal.status !== "completed" || approval.importJournalDigest !== importJournal.digest) throw new Error("BINDING");
      } catch {
        findings.push({ code: "RECOVERY_SLO_PROMOTION_BINDING_INVALID", journalId: journal.id, severity: "error" });
        continue;
      }
      if (["prepared", "applying"].includes(journal.status)) findings.push({ code: "RECOVERY_SLO_PROMOTION_PENDING", journalId: journal.id, severity: "warning" });
      if (journal.status === "blocked") findings.push({ code: "RECOVERY_SLO_PROMOTION_BLOCKED", journalId: journal.id, severity: "error" });
      const receipt = await store.getEvidence(ownerId, finalizationIdFor(journal.id));
      const receiptValid = receipt ? await verifyFinalization(receipt, ownerId, journal) : false;
      for (const item of journal.items) {
        const importItem = importJournal.items.find(candidate => candidate.sourceRecordId === item.sourceRecordId && candidate.section === item.section);
        try {
          if (!importItem) throw new Error("IMPORT_ITEM_MISSING");
          const quarantine = await getQuarantine(ownerId, importJournal, importItem);
          if (quarantine.id !== item.quarantineRecordId || quarantine.payloadDigest !== item.sourceRecordDigest) throw new Error("QUARANTINE_BINDING");
          const active = await store.getEvidence(ownerId, item.sourceRecordId);
          if (["promoted", "already_present"].includes(item.state)) {
            if (!active) throw new Error("ACTIVE_MISMATCH");
            if (!(receiptValid && MUTABLE_POST_PROMOTION_SECTIONS.has(item.section))) {
              if (canonical(stripStorageDeep(active)) !== canonical(stripStorageDeep(quarantine.payload))) throw new Error("ACTIVE_MISMATCH");
              if (receiptValid) {
                const receiptEntry = receipt.activeEntries.find(entry => entry.id === item.sourceRecordId);
                const activeDigest = sha256(canonical(stripStorageDeep(active)));
                if (!receiptEntry || receiptEntry.digest !== activeDigest || activeDigest !== item.sourceRecordDigest) throw new Error("ACTIVE_RECEIPT_MISMATCH");
              }
            }
          } else if (item.state === "pending" && active && canonical(stripStorageDeep(active)) !== canonical(stripStorageDeep(quarantine.payload))) {
            throw new Error("ACTIVE_CONFLICT");
          }
        } catch (error) {
          findings.push({ code: error?.message === "ACTIVE_RECEIPT_MISMATCH" || error?.message === "ACTIVE_MISMATCH"
            ? "RECOVERY_SLO_POST_PROMOTION_ACTIVE_EVIDENCE_MISMATCH" : "RECOVERY_SLO_PROMOTION_EVIDENCE_BINDING_INVALID",
            journalId: journal.id, sourceRecordId: item.sourceRecordId, severity: "error" });
        }
      }
      if (journal.status === "completed" && !receipt) findings.push({ code: "RECOVERY_SLO_RESTORE_FINALIZATION_REQUIRED", journalId: journal.id, severity: "warning" });
      if (receipt && !receiptValid) findings.push({ code: "RECOVERY_SLO_RESTORE_FINALIZATION_INVALID", journalId: journal.id, severity: "error" });
      if (journal.status !== "completed" && receipt) findings.push({ code: "RECOVERY_SLO_RESTORE_FINALIZATION_PREMATURE", journalId: journal.id, severity: "error" });
    }
    const validReviewDigests = new Set();
    for (const reviewRecord of reviews.slice(-1000)) {
      try {
        const review = verifyReview(reviewRecord, ownerId);
        validReviewDigests.add(review.reviewDigest);
        const importJournal = await restoreService.getRecoverySloEvidenceRestoreImportJournal(ownerId, review.importJournalId);
        if (importJournal.status !== "completed" || importJournal.digest !== review.importJournalDigest
          || importJournal.sourceBundleDigest !== review.sourceBundleDigest) throw new Error("REVIEW_IMPORT_BINDING");
        if (review.status === "blocked") findings.push({ code: "RECOVERY_SLO_RESTORE_REVIEW_BLOCKED", reviewId: review.id, severity: "warning" });
        else if (!approvals.some(item => item?.reviewDigest === review.reviewDigest)) {
          findings.push({ code: "RECOVERY_SLO_RESTORE_REVIEW_AWAITING_APPROVAL", reviewId: review.id, severity: "warning" });
        }
      } catch {
        findings.push({ code: "RECOVERY_SLO_RESTORE_REVIEW_INVALID", reviewId: reviewRecord?.id || null, severity: "error" });
      }
    }
    if (reviews.length > 1000) findings.push({ code: "RECOVERY_SLO_RESTORE_REVIEW_AUDIT_TRUNCATED", severity: "warning" });
    const promotionApprovalIds = new Set(journals.map(item => item.approvalId));
    for (const approvalRecord of approvals.slice(-1000)) {
      try {
        const approval = verifyApproval(approvalRecord, ownerId);
        const review = verifyReview(await store.getEvidence(ownerId, approval.reviewId), ownerId);
        if (!validReviewDigests.has(review.reviewDigest) || review.reviewDigest !== approval.reviewDigest
          || review.status !== "ready" || approval.itemsDigest !== sha256(canonical(review.items))
          || canonical(approval.items) !== canonical(review.items)) throw new Error("APPROVAL_REVIEW_BINDING");
        if (!promotionApprovalIds.has(approval.id)) findings.push({ code: "RECOVERY_SLO_PROMOTION_NOT_STARTED", approvalId: approval.id, severity: "warning" });
      } catch {
        findings.push({ code: "RECOVERY_SLO_EVIDENCE_PROMOTION_APPROVAL_INVALID", approvalId: approvalRecord?.id || null, severity: "error" });
      }
    }
    if (approvals.length > 1000) findings.push({ code: "RECOVERY_SLO_PROMOTION_APPROVAL_AUDIT_TRUNCATED", severity: "warning" });
    for (const receipt of finalizations) {
      const journal = journals.find(item => item.id === receipt.promotionJournalId);
      if (!journal || !(await verifyFinalization(receipt, ownerId, journal))) findings.push({ code: "RECOVERY_SLO_RESTORE_FINALIZATION_ORPHANED", finalizationId: receipt.id, severity: "error" });
    }
    const truncated = journals.length > checked;
    if (truncated) findings.push({ code: "RECOVERY_SLO_PROMOTION_AUDIT_TRUNCATED", severity: "warning" });
    if (activeEvidenceAudit && journals.some(journal => journal.status === "completed" && finalizations.some(receipt => receipt.promotionJournalId === journal.id))) {
      const activeAudit = await collectActiveEvidenceAudit(ownerId);
      for (const result of activeAudit.results) {
        if (!["healthy", "empty"].includes(result.status)) {
          findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_DOMAIN_AUDIT_FAILED", domain: result.domain, status: result.status, severity: "error" });
        }
      }
    }
    const status = findings.some(item => item.severity === "error") ? "unhealthy"
      : findings.some(item => item.code === "RECOVERY_SLO_PROMOTION_PENDING" || item.code === "RECOVERY_SLO_RESTORE_FINALIZATION_REQUIRED"
        || item.code === "RECOVERY_SLO_PROMOTION_NOT_STARTED") ? "recovery_required"
        : findings.length ? "degraded" : journals.length ? "healthy" : reviews.length || approvals.length ? "degraded" : "empty";
    return { ownerId, status, checkedJournals: checked, totalJournals: journals.length, checkedFinalizations: finalizations.length,
      totalReviews: reviews.length, totalApprovals: approvals.length,
      findings: findings.slice(0, 200), totalFindings: findings.length, truncated: truncated || findings.length > 200,
      readOnly: true, mutationAllowed: false, automaticRepairAllowed: false };
  }

  async function finalizedPromotionIsIntact(ownerId, journal) {
    const journalCheck = verifyPromotionJournal(journal, ownerId);
    if (!journalCheck.valid || journal.status !== "completed") return false;
    const receipt = await store.getEvidence(ownerId, finalizationIdFor(journal.id));
    if (!(await verifyFinalization(receipt, ownerId, journal))) return false;
    try {
      const approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
      const review = verifyReview(await store.getEvidence(ownerId, journal.reviewId), ownerId);
      const importJournal = await getImportJournal(ownerId, journal.importJournalId);
      if (approval.digest !== journal.approvalDigest || approval.reviewDigest !== journal.reviewDigest
        || approval.itemsDigest !== sha256(canonical(review.items)) || canonical(approval.items) !== canonical(review.items)
        || !promotionItemsMatchApproval(journal, approval) || review.reviewDigest !== journal.reviewDigest
        || importJournal.digest !== journal.importJournalDigest) return false;
      const receipt = await store.getEvidence(ownerId, finalizationIdFor(journal.id));
      const receiptEntries = new Map((receipt?.activeEntries || []).map(entry => [entry.id, entry.digest]));
      if (receiptEntries.size !== journal.items.length) return false;
      for (const item of journal.items) {
        const importItem = importJournal.items.find(candidate => candidate.sourceRecordId === item.sourceRecordId && candidate.section === item.section);
        if (!importItem || !["promoted", "already_present"].includes(item.state)) return false;
        const quarantine = await getQuarantine(ownerId, importJournal, importItem);
        if (quarantine.id !== item.quarantineRecordId || quarantine.payloadDigest !== item.sourceRecordDigest) return false;
        const active = await store.getEvidence(ownerId, item.sourceRecordId);
        if (!active) return false;
        if (MUTABLE_POST_PROMOTION_SECTIONS.has(item.section)) continue;
        if (canonical(stripStorageDeep(active)) !== canonical(stripStorageDeep(quarantine.payload))) return false;
        const activeDigest = sha256(canonical(stripStorageDeep(active)));
        if (activeDigest !== item.sourceRecordDigest || receiptEntries.get(item.sourceRecordId) !== activeDigest) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  async function collectActiveEvidenceAudit(ownerId) {
    if (!activeEvidenceAudit) return { status: "not_configured", results: [] };
    try {
      const result = await activeEvidenceAudit(ownerId);
      const results = Array.isArray(result) ? result : Array.isArray(result?.results) ? result.results : [];
      return { status: results.every(item => ["healthy", "empty"].includes(item?.status)) ? "healthy" : "unhealthy", results };
    } catch (error) {
      return { status: "unhealthy", results: [{ domain: "active_evidence", status: "unhealthy", findings: [{ code: error?.code || "ACTIVE_EVIDENCE_AUDIT_FAILED" }] }] };
    }
  }

  async function verifyRecoverySloEvidenceRestoreFinalizationAttestation(ownerId, promotionJournalId) {
    assertOwner(ownerId); assertId(promotionJournalId, "RECOVERY_SLO_PROMOTION_JOURNAL_ID_INVALID", "Promotion journal ID");
    const journal = await store.getEvidence(ownerId, promotionJournalId);
    if (!journal || journal.kind !== PROMOTION_JOURNAL_KIND) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND", "Promotion journal tidak ditemukan", 404);
    const journalCheck = verifyPromotionJournal(journal, ownerId);
    if (!journalCheck.valid) throw new AgenticError(journalCheck.code, "Promotion journal tidak valid", 409);
    const receipt = await store.getEvidence(ownerId, finalizationIdFor(journal.id));
    if (!receipt) return { ownerId, promotionJournalId, status: "missing", valid: false, findings: ["FINALIZATION_RECEIPT_MISSING"], readOnly: true, mutationAllowed: false };
    const attestation = await verifyFinalizationAttestation(receipt, ownerId);
    const receiptValid = await verifyFinalization(receipt, ownerId, journal);
    return { ownerId, promotionJournalId, finalizationId: receipt.id, status: receiptValid ? attestation.status : "invalid",
      attestationStatus: attestation.status, valid: receiptValid, signatureValid: Boolean(attestation.signatureValid), authorizedForCurrentUse: Boolean(attestation.authorizedForCurrentUse),
      signingKeyActive: Boolean(attestation.signingKeyActive), policyRevision: attestation.policyRevision ?? null,
      keyId: receipt.attestation?.keyId ?? null, receiptDigest: receipt.receiptDigest ?? null,
      finalizationDigest: receipt.digest, findings: receiptValid ? [] : [attestation.code || "FINALIZATION_RECEIPT_INVALID"],
      readOnly: true, mutationAllowed: false };
  }

  async function reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(ownerId, promotionJournalId) {
    assertOwner(ownerId); assertId(promotionJournalId, "RECOVERY_SLO_PROMOTION_JOURNAL_ID_INVALID", "Promotion journal ID");
    const journal = await store.getEvidence(ownerId, promotionJournalId);
    if (!journal || journal.kind !== PROMOTION_JOURNAL_KIND) throw new AgenticError("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND", "Promotion journal tidak ditemukan", 404);
    const findings = [];
    const journalCheck = verifyPromotionJournal(journal, ownerId);
    if (!journalCheck.valid) return { ownerId, promotionJournalId, status: "unhealthy", findings: [{ code: journalCheck.code, severity: "error" }], readOnly: true, mutationAllowed: false, automaticRepairAllowed: false };
    if (journal.status !== "completed") findings.push({ code: "RECOVERY_SLO_PROMOTION_NOT_COMPLETED", severity: "error" });
    const receipt = await store.getEvidence(ownerId, finalizationIdFor(journal.id));
    if (!receipt) findings.push({ code: "RECOVERY_SLO_RESTORE_FINALIZATION_REQUIRED", severity: "error" });
    const attestationCheck = await verifyFinalizationAttestation(receipt, ownerId);
    if (receipt && !attestationCheck.valid) findings.push({ code: attestationCheck.code || "RECOVERY_SLO_FINALIZATION_ATTESTATION_INVALID", severity: "error" });
    if (receipt && !(await verifyFinalization(receipt, ownerId, journal))) findings.push({ code: "RECOVERY_SLO_FINALIZATION_RECEIPT_INVALID", severity: "error" });
    try {
      const approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
      const review = verifyReview(await store.getEvidence(ownerId, journal.reviewId), ownerId);
      const importJournal = await getImportJournal(ownerId, journal.importJournalId);
      if (approval.digest !== journal.approvalDigest || review.reviewDigest !== journal.reviewDigest
        || approval.reviewDigest !== review.reviewDigest || approval.itemsDigest !== sha256(canonical(review.items))
        || canonical(approval.items) !== canonical(review.items) || !promotionItemsMatchApproval(journal, approval)
        || importJournal.digest !== journal.importJournalDigest || importJournal.status !== "completed") {
        findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_BINDING_MISMATCH", severity: "error" });
      }
      const expectedEntries = [];
      for (const item of journal.items) {
        const importItem = importJournal.items.find(candidate => candidate.sourceRecordId === item.sourceRecordId && candidate.section === item.section);
        if (!importItem) { findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_IMPORT_ITEM_MISSING", sourceRecordId: item.sourceRecordId, severity: "error" }); continue; }
        const quarantine = await getQuarantine(ownerId, importJournal, importItem);
        if (quarantine.id !== item.quarantineRecordId || quarantine.payloadDigest !== item.sourceRecordDigest) {
          findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_QUARANTINE_MISMATCH", sourceRecordId: item.sourceRecordId, severity: "error" });
        }
        const active = await store.getEvidence(ownerId, item.sourceRecordId);
        if (!active) {
          findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_ACTIVE_EVIDENCE_MISSING", sourceRecordId: item.sourceRecordId, severity: "error" });
          continue;
        }
        const activeDigest = sha256(canonical(stripStorageDeep(active)));
        if (MUTABLE_POST_PROMOTION_SECTIONS.has(item.section)) {
          // These ledgers legitimately evolve after restore; their own domain audits verify current integrity.
          continue;
        }
        if (canonical(stripStorageDeep(active)) !== canonical(stripStorageDeep(quarantine.payload))) {
          findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_ACTIVE_EVIDENCE_MISMATCH", sourceRecordId: item.sourceRecordId, severity: "error" });
          continue;
        }
        if (activeDigest !== item.sourceRecordDigest) findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_ACTIVE_DIGEST_MISMATCH", sourceRecordId: item.sourceRecordId, severity: "error" });
        expectedEntries.push({ id: item.sourceRecordId, digest: activeDigest });
      }
      if (receipt) {
        const immutableEntries = receipt.activeEntries.filter(entry => !MUTABLE_POST_PROMOTION_SECTIONS.has(
          journal.items.find(item => item.sourceRecordId === entry.id)?.section));
        if (canonical(expectedEntries) !== canonical(immutableEntries)) {
          findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_ACTIVE_SET_MISMATCH", severity: "error" });
        }
      }
      if (activeEvidenceAudit) {
        const activeAudit = await collectActiveEvidenceAudit(ownerId);
        for (const result of activeAudit.results) {
          if (!["healthy", "empty"].includes(result.status)) findings.push({ code: "RECOVERY_SLO_POST_PROMOTION_DOMAIN_AUDIT_FAILED",
            domain: result.domain, status: result.status, severity: "error" });
        }
      }
    } catch (error) {
      findings.push({ code: error?.code || "RECOVERY_SLO_POST_PROMOTION_RECONCILIATION_FAILED", severity: "error" });
    }
    const status = findings.some(item => item.severity === "error") ? "unhealthy"
      : findings.some(item => item.severity === "warning") ? "degraded" : "healthy";
    return { ownerId, promotionJournalId, finalizationId: receipt?.id || null, status,
      attestationStatus: attestationCheck.status, findings: findings.slice(0, 200), totalFindings: findings.length,
      activeRecordCount: receipt?.activeRecordCount ?? null, reconciledRecordCount: receipt?.activeEntries?.length ?? 0,
      readOnly: true, mutationAllowed: false, automaticRepairAllowed: false };
  }

  async function hasPendingPromotion(ownerId) {
    assertOwner(ownerId);
    const all = await store.listEvidence(ownerId);
    const journals = all.filter(item => item?.kind === PROMOTION_JOURNAL_KIND);
    const pending = [];
    for (const journal of journals) {
      const check = verifyPromotionJournal(journal, ownerId);
      if (!check.valid) { pending.push({ journalId: journal.id, status: "unhealthy", code: check.code }); continue; }
      if (!await finalizedPromotionIsIntact(ownerId, journal)) {
        pending.push({ journalId: journal.id, status: journal.status,
          code: journal.status === "completed" ? "FINALIZATION_OR_ACTIVE_EVIDENCE_INVALID" : "PROMOTION_PENDING" });
      }
    }
    return pending;
  }
  async function listFinalizedQuarantineRecordIds(ownerId) {
    assertOwner(ownerId);
    const all = await store.listEvidence(ownerId);
    const result = new Set();
    for (const journal of all.filter(item => item?.kind === PROMOTION_JOURNAL_KIND)) {
      if (!await finalizedPromotionIsIntact(ownerId, journal)) continue;
      for (const item of journal.items) result.add(item.quarantineRecordId);
    }
    return [...result];
  }

  return Object.freeze({
    reviewRecoverySloEvidenceRestoreQuarantine,
    getRecoverySloEvidenceRestoreQuarantineReview,
    listRecoverySloEvidenceRestoreQuarantineReviews,
    approveRecoverySloEvidencePromotion,
    promoteRecoverySloQuarantinedEvidence,
    recoverRecoverySloEvidencePromotion,
    getRecoverySloEvidencePromotionJournal,
    listRecoverySloEvidencePromotionJournals,
    finalizeRecoverySloEvidenceRestore,
    verifyRecoverySloEvidenceRestoreFinalizationAttestation,
    reconcileRecoverySloEvidenceRestoreFinalizationIntegrity,
    auditRecoverySloEvidenceRestorePromotions,
    hasPendingPromotion,
    listFinalizedQuarantineRecordIds
  });
}
