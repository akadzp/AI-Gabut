import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";
import { verifyRecoverySloEvidenceExportBundle } from "./recovery-slo-alerting.js";

const MAX_OWNER_ID = 200;
const MAX_RECORDS = 10000;
const MAX_PLAN_ACTIONS = 5000;
const MAX_IMPORT_JOURNALS = 1000;
const MAX_QUARANTINE_RECORDS = 10000;
const MAX_IMPORT_JOURNAL_EVENTS = 10002;
const SECTION_ORDER = [
  "policyLedger",
  "evaluationEvidenceArchives",
  "evaluationEvidence",
  "alertArchives",
  "alertLedger",
  "evaluationEvidenceArchiveIndex"
];
const SECTION_SPEC = Object.freeze({
  policyLedger: { shape: "single", kind: "recovery-slo-policy-ledger" },
  alertLedger: { shape: "single", kind: "recovery-slo-alert-ledger" },
  alertArchives: { shape: "array", kind: "recovery-slo-alert-archive" },
  evaluationEvidence: { shape: "array", kind: "recovery-slo-evaluation-evidence" },
  evaluationEvidenceArchives: { shape: "array", kind: "recovery-slo-evaluation-evidence-archive" },
  evaluationEvidenceArchiveIndex: { shape: "single", kind: "recovery-slo-evaluation-archive-index" }
});

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestPattern = /^[a-f0-9]{64}$/;
const stripStorageDeep = value => {
  if (Array.isArray(value)) return value.map(stripStorageDeep);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = stripStorageDeep(item);
  return result;
};

function inspectObjectTree(value) {
  const stack = [{ value, depth: 0 }];
  let visited = 0;
  while (stack.length) {
    const current = stack.pop();
    if (!current.value || typeof current.value !== "object") continue;
    visited += 1;
    if (visited > 200000 || current.depth > 128) return { storageMetadata: false, boundsExceeded: true };
    if (Object.hasOwn(current.value, "_storage")) return { storageMetadata: true, boundsExceeded: false };
    for (const item of Object.values(current.value)) stack.push({ value: item, depth: current.depth + 1 });
  }
  return { storageMetadata: false, boundsExceeded: false };
}

function sectionRecords(sections) {
  const records = [];
  for (const section of SECTION_ORDER) {
    const spec = SECTION_SPEC[section];
    const value = sections[section];
    const items = spec.shape === "array" ? value : value == null ? [] : [value];
    for (const record of items) records.push({ section, record });
  }
  return records;
}

/**
 * Performs storage-independent bundle verification plus schema and owner-binding checks.
 * This function never writes to application storage and never authorizes a restore.
 */
export function inspectRecoverySloEvidenceExportBundle(bundle, options = {}) {
  const findings = [];
  let verification;
  try {
    verification = verifyRecoverySloEvidenceExportBundle(bundle, { publicKey: options.publicKey || null });
  } catch {
    verification = { status: "invalid", valid: false, findings: [{ code: "RECOVERY_SLO_EXPORT_VERIFICATION_FAILED" }], authenticity: "not_established" };
  }
  if (!verification.valid) findings.push(...(verification.findings || [{ code: "RECOVERY_SLO_EXPORT_BUNDLE_INVALID" }]));

  if (bundle && typeof bundle === "object" && !Array.isArray(bundle)) {
    if (options.expectedOwnerId !== undefined && bundle.ownerId !== options.expectedOwnerId) {
      findings.push({ code: "RECOVERY_SLO_EXPORT_OWNER_SCOPE_MISMATCH" });
    }
    const envelopeInspection = inspectObjectTree(bundle);
    if (envelopeInspection.storageMetadata) findings.push({ code: "RECOVERY_SLO_EXPORT_STORAGE_METADATA_FORBIDDEN" });
    if (envelopeInspection.boundsExceeded) findings.push({ code: "RECOVERY_SLO_EXPORT_OBJECT_BOUNDS_EXCEEDED" });
    const { byteLength, readOnly, mutationAllowed, ...canonicalBundle } = bundle;
    let calculatedBytes = Number.POSITIVE_INFINITY;
    if (!envelopeInspection.boundsExceeded) {
      try { calculatedBytes = Buffer.byteLength(canonical(canonicalBundle), "utf8"); }
      catch { findings.push({ code: "RECOVERY_SLO_EXPORT_CANONICALIZATION_FAILED" }); }
    }
    if (!Number.isSafeInteger(byteLength) || byteLength !== calculatedBytes) {
      findings.push({ code: "RECOVERY_SLO_EXPORT_BYTE_LENGTH_MISMATCH" });
    }
    if (readOnly !== true || mutationAllowed !== false) findings.push({ code: "RECOVERY_SLO_EXPORT_MUTATION_METADATA_INVALID" });
    if (calculatedBytes > 25 * 1024 * 1024) findings.push({ code: "RECOVERY_SLO_EXPORT_SIZE_LIMIT_EXCEEDED" });
    const sections = bundle.sections;
    if (!sections || typeof sections !== "object" || Array.isArray(sections)) {
      findings.push({ code: "RECOVERY_SLO_EXPORT_SECTIONS_INVALID" });
    } else {
      let totalRecords = 0;
      const ids = new Map();
      for (const [section, spec] of Object.entries(SECTION_SPEC)) {
        const value = sections[section];
        if (spec.shape === "array" && !Array.isArray(value)) {
          findings.push({ code: "RECOVERY_SLO_EXPORT_SECTION_SHAPE_INVALID", section });
          continue;
        }
        if (spec.shape === "single" && value !== null && (typeof value !== "object" || Array.isArray(value))) {
          findings.push({ code: "RECOVERY_SLO_EXPORT_SECTION_SHAPE_INVALID", section });
          continue;
        }
        const items = spec.shape === "array" ? value : value == null ? [] : [value];
        totalRecords += items.length;
        for (const record of items) {
          if (!record || typeof record !== "object" || Array.isArray(record)) {
            findings.push({ code: "RECOVERY_SLO_EXPORT_RECORD_SHAPE_INVALID", section });
            continue;
          }
          const treeInspection = inspectObjectTree(record);
          if (treeInspection.storageMetadata) findings.push({ code: "RECOVERY_SLO_EXPORT_STORAGE_METADATA_FORBIDDEN", section });
          if (treeInspection.boundsExceeded) findings.push({ code: "RECOVERY_SLO_EXPORT_OBJECT_BOUNDS_EXCEEDED", section });
          if (record.ownerId !== bundle.ownerId) findings.push({ code: "RECOVERY_SLO_EXPORT_RECORD_OWNER_MISMATCH", section });
          if (record.kind !== spec.kind) findings.push({ code: "RECOVERY_SLO_EXPORT_RECORD_KIND_MISMATCH", section });
          if (typeof record.id !== "string" || !record.id.trim() || record.id.length > 200 || record.id.trim() !== record.id) {
            findings.push({ code: "RECOVERY_SLO_EXPORT_RECORD_ID_INVALID", section });
          } else if (ids.has(record.id)) {
            findings.push({ code: "RECOVERY_SLO_EXPORT_DUPLICATE_RECORD_ID", section, conflictingSection: ids.get(record.id) });
          } else ids.set(record.id, section);
          if (typeof record.digest !== "string" || !digestPattern.test(record.digest)) {
            findings.push({ code: "RECOVERY_SLO_EXPORT_RECORD_DIGEST_INVALID", section });
          }
        }
      }
      if (totalRecords > MAX_RECORDS) findings.push({ code: "RECOVERY_SLO_EXPORT_RECORD_LIMIT_EXCEEDED", totalRecords, maxRecords: MAX_RECORDS });

      const archiveIndex = sections.evaluationEvidenceArchiveIndex;
      if (archiveIndex && archiveIndex.snapshot && Array.isArray(archiveIndex.snapshot.archives)) {
        const archiveIds = new Set((sections.evaluationEvidenceArchives || []).filter(Boolean).map(item => item.id));
        for (const reference of archiveIndex.snapshot.archives) {
          if (!reference || typeof reference.id !== "string" || !digestPattern.test(reference.digest || "")) {
            findings.push({ code: "RECOVERY_SLO_EXPORT_ARCHIVE_INDEX_REFERENCE_INVALID" });
          } else if (!archiveIds.has(reference.id)) {
            findings.push({ code: "RECOVERY_SLO_EXPORT_ARCHIVE_INDEX_DEPENDENCY_MISSING", archiveId: reference.id });
          }
        }
      } else if (archiveIndex && archiveIndex.snapshot && !Array.isArray(archiveIndex.snapshot.archives)) {
        findings.push({ code: "RECOVERY_SLO_EXPORT_ARCHIVE_INDEX_SHAPE_INVALID" });
      }
    }
  }

  const uniqueFindings = [];
  const seen = new Set();
  for (const finding of findings) {
    const key = canonical(finding);
    if (!seen.has(key)) { seen.add(key); uniqueFindings.push(finding); }
  }
  const valid = verification.valid === true && uniqueFindings.length === 0;
  const requireSignature = options.requireSignature === true;
  const signatureSatisfied = verification.status === "valid_signed";
  if (requireSignature && !signatureSatisfied) uniqueFindings.push({ code: "RECOVERY_SLO_EXPORT_TRUSTED_SIGNATURE_REQUIRED" });
  const finalValid = valid && (!requireSignature || signatureSatisfied);
  return {
    status: finalValid ? verification.status : "invalid",
    valid: finalValid,
    integrityValid: valid,
    bundleDigest: verification.bundleDigest || bundle?.manifest?.bundleDigest || null,
    ownerId: typeof bundle?.ownerId === "string" ? bundle.ownerId : null,
    authenticity: verification.authenticity || "not_established",
    keyId: verification.keyId || bundle?.attestation?.keyId || null,
    findings: uniqueFindings,
    readOnly: true,
    mutationAllowed: false
  };
}

export function createRecoverySloExportRestorePlanner({ store, clock = () => new Date().toISOString(), exportAttestationKeyId = null,
  exportAttestationPublicKey = null } = {}) {
  if (!store?.listEvidence || typeof clock !== "function") throw new TypeError("Restore planner membutuhkan evidence store dan clock");

  function assertOwner(ownerId) {
    if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > MAX_OWNER_ID) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_OWNER_REQUIRED", "Owner wajib ditentukan untuk restore planning", 400);
    }
  }

  async function planRecoverySloEvidenceRestore(ownerId, bundle, options = {}) {
    assertOwner(ownerId);
    const maxActions = Number.isSafeInteger(options.maxActions) ? Math.max(1, Math.min(MAX_PLAN_ACTIONS, options.maxActions)) : MAX_PLAN_ACTIONS;
    const requireTrustedSignature = options.requireTrustedSignature === true;
    const keyMatches = !!exportAttestationPublicKey && !!exportAttestationKeyId
      && bundle?.attestation?.keyId === exportAttestationKeyId;
    const inspection = inspectRecoverySloEvidenceExportBundle(bundle, {
      expectedOwnerId: ownerId,
      publicKey: keyMatches ? exportAttestationPublicKey : null
    });
    const findings = [...inspection.findings];
    if (requireTrustedSignature && (!keyMatches || inspection.status !== "valid_signed")) {
      findings.push({ code: "RECOVERY_SLO_RESTORE_TRUSTED_SIGNATURE_REQUIRED" });
    }
    const records = inspection.integrityValid ? sectionRecords(bundle.sections) : [];
    if (records.length > maxActions) findings.push({ code: "RECOVERY_SLO_RESTORE_ACTION_LIMIT_EXCEEDED", totalActions: records.length, maxActions });

    const current = inspection.integrityValid ? await store.listEvidence(ownerId) : [];
    const currentById = new Map(current.filter(item => item && typeof item.id === "string").map(item => [item.id, item]));
    const actions = [];
    for (const { section, record } of records.slice(0, maxActions)) {
      const existing = currentById.get(record.id);
      let action = "import";
      let reason = "MISSING_FROM_TARGET";
      if (existing) {
        const existingComparable = stripStorageDeep(existing);
        const incomingComparable = stripStorageDeep(record);
        if (canonical(existingComparable) === canonical(incomingComparable)) {
          action = "already_present";
          reason = "IDENTICAL_RECORD_PRESENT";
        } else {
          action = "conflict";
          reason = "TARGET_RECORD_DIFFERS";
          findings.push({ code: "RECOVERY_SLO_RESTORE_RECORD_CONFLICT", recordId: record.id, section });
        }
      }
      actions.push({ order: actions.length + 1, section, recordId: record.id, kind: record.kind, action, reason,
        digest: record.digest, sourceRecordDigest: sha256(canonical(stripStorageDeep(record))) });
    }

    const invalid = !inspection.integrityValid || findings.some(item => item.code === "RECOVERY_SLO_RESTORE_TRUSTED_SIGNATURE_REQUIRED"
      || item.code === "RECOVERY_SLO_RESTORE_ACTION_LIMIT_EXCEEDED"
      || item.code === "RECOVERY_SLO_RESTORE_RECORD_CONFLICT"
      || item.code === "RECOVERY_SLO_EXPORT_OWNER_SCOPE_MISMATCH"
      || item.code === "RECOVERY_SLO_EXPORT_RECORD_OWNER_MISMATCH"
      || item.code === "RECOVERY_SLO_EXPORT_RECORD_KIND_MISMATCH"
      || item.code === "RECOVERY_SLO_EXPORT_ARCHIVE_INDEX_DEPENDENCY_MISSING");
    const plannedAt = String(clock());
    const counts = {
      total: actions.length,
      import: actions.filter(item => item.action === "import").length,
      alreadyPresent: actions.filter(item => item.action === "already_present").length,
      conflicts: actions.filter(item => item.action === "conflict").length
    };
    const planPayload = {
      schemaVersion: 1, kind: "recovery-slo-evidence-restore-plan", ownerId, plannedAt,
      sourceBundleDigest: inspection.bundleDigest, sourceVerificationStatus: inspection.status,
      sourceAuthenticity: inspection.authenticity, status: invalid ? "blocked" : "ready",
      dryRun: true, restoreExecuted: false, mutationAllowed: false,
      requireTrustedSignature, actions, findings, counts, readOnly: true
    };
    const planDigest = sha256(canonical(planPayload));
    return { ...planPayload, planDigest };
  }

  const restoreApprovalKind = "recovery-slo-evidence-restore-approval";
  const restoreJournalKind = "recovery-slo-evidence-restore-import-journal";
  const quarantineKind = "recovery-slo-restore-quarantined-evidence";
  const stripRootStorage = value => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return value;
    const result = { ...value };
    delete result._storage;
    return result;
  };
  const planPayload = plan => {
    const copy = stripRootStorage(plan);
    delete copy.planDigest;
    return copy;
  };
  const planDigestOf = plan => sha256(canonical(planPayload(plan)));
  const recordDigest = record => {
    const copy = stripRootStorage(record);
    delete copy.digest;
    return sha256(canonical(copy));
  };
  const journalGenesis = (ownerId, id) => sha256(`agentic-v4-recovery-slo-restore-import-journal:${ownerId}:${id}`);
  const eventHash = event => sha256(canonical({ sequence: event.sequence, type: event.type, at: event.at,
    previousHash: event.previousHash, details: event.details }));
  const journalIdForApproval = approvalId => `recovery-slo-restore-import-${sha256(approvalId).slice(0, 48)}`;
  const quarantineIdFor = (ownerId, bundleDigest, sourceRecordId) =>
    `recovery-slo-quarantine-${sha256(canonical({ ownerId, bundleDigest, sourceRecordId })).slice(0, 48)}`;
  const actionDigest = actions => sha256(canonical(actions));

  function verifyApproval(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.kind !== restoreApprovalKind
      || record.schemaVersion !== 1 || record.status !== "approved"
      || typeof record.planDigest !== "string" || !digestPattern.test(record.planDigest)
      || typeof record.sourceBundleDigest !== "string" || !digestPattern.test(record.sourceBundleDigest)
      || !Array.isArray(record.actions) || record.actions.length > MAX_PLAN_ACTIONS
      || record.actionsDigest !== actionDigest(record.actions) || record.digest !== recordDigest(record)) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_INVALID", "Restore approval tidak valid atau integritasnya gagal", 409);
    }
    return record;
  }

  function verifyJournal(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.kind !== restoreJournalKind || record.schemaVersion !== 1
      || record.id !== journalIdForApproval(record.approvalId) || !digestPattern.test(record.planDigest || "")
      || !digestPattern.test(record.sourceBundleDigest || "") || typeof record.approvalId !== "string"
      || !Array.isArray(record.events) || record.events.length < 1 || record.events.length > MAX_IMPORT_JOURNAL_EVENTS
      || !Array.isArray(record.items) || record.items.length > MAX_PLAN_ACTIONS) {
      return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_SHAPE_INVALID" };
    }
    let previousHash = journalGenesis(ownerId, record.id);
    let replayStatus = "prepared";
    let replayItems = null;
    for (let index = 0; index < record.events.length; index += 1) {
      const event = record.events[index];
      if (!event || event.sequence !== index + 1 || event.previousHash !== previousHash
        || typeof event.at !== "string" || !Number.isFinite(Date.parse(event.at))
        || typeof event.type !== "string" || !event.details || typeof event.details !== "object"
        || event.eventHash !== eventHash(event)) {
        return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_EVENT_INVALID" };
      }
      if (index === 0) {
        if (event.type !== "journal_created" || event.details.initialStatus !== "prepared"
          || !Array.isArray(event.details.initialItems) || event.details.approvalId !== record.approvalId
          || event.details.planDigest !== record.planDigest || event.details.sourceBundleDigest !== record.sourceBundleDigest) {
          return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_GENESIS_INVALID" };
        }
        replayItems = structuredClone(event.details.initialItems);
        const seenSourceIds = new Set();
        for (let itemIndex = 0; itemIndex < replayItems.length; itemIndex += 1) {
          const item = replayItems[itemIndex];
          const spec = SECTION_SPEC[item?.section];
          const sourceKey = `${item?.section}\n${item?.sourceRecordId}`;
          if (!item || item.order !== itemIndex + 1 || !spec || typeof item.sourceRecordId !== "string"
            || !item.sourceRecordId.trim() || item.sourceRecordId.length > 200 || item.sourceKind !== spec.kind
            || typeof item.sourceDigest !== "string" || !digestPattern.test(item.sourceDigest)
            || typeof item.plannedDigest !== "string" || !digestPattern.test(item.plannedDigest)
            || !["import", "already_present"].includes(item.action)
            || item.state !== (item.action === "already_present" ? "already_present" : "pending")
            || item.quarantineRecordId !== null || seenSourceIds.has(sourceKey)) {
            return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_INITIAL_ITEM_INVALID" };
          }
          seenSourceIds.add(sourceKey);
        }
      } else if (event.type === "status_changed") {
        if (event.details.fromStatus !== replayStatus) return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_STATUS_CHAIN_INVALID" };
        const allowed = replayStatus === "prepared" ? new Set(["applying", "blocked"])
          : replayStatus === "applying" ? new Set(["completed", "blocked"]) : new Set();
        if (!allowed.has(event.details.toStatus)) return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_STATUS_TRANSITION_INVALID" };
        replayStatus = event.details.toStatus;
      } else if (event.type === "item_state_changed") {
        const item = replayItems?.find(candidate => candidate.order === event.details.order);
        if (!item || item.sourceRecordId !== event.details.sourceRecordId || item.state !== event.details.fromState) {
          return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_ITEM_CHAIN_INVALID" };
        }
        const allowed = item.state === "pending" ? new Set(["quarantined", "already_present", "conflict"]) : new Set();
        if (!allowed.has(event.details.toState)) return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_ITEM_TRANSITION_INVALID" };
        item.state = event.details.toState;
        item.quarantineRecordId = event.details.quarantineRecordId || null;
      } else if (event.type !== "recovery_resumed") {
        return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_EVENT_TYPE_INVALID" };
      }
      previousHash = event.eventHash;
    }
    if (!replayItems || record.status !== replayStatus || canonical(record.items) !== canonical(replayItems)
      || record.digest !== previousHash || record.createdAt !== record.events[0].at
      || record.updatedAt !== record.events.at(-1).at) {
      return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_SNAPSHOT_MISMATCH" };
    }
    if (record.status === "completed" && replayItems.some(item => !["quarantined", "already_present"].includes(item.state))) {
      return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_COMPLETION_INCOMPLETE" };
    }
    if (record.status === "blocked" && !replayItems.some(item => item.state === "conflict")) {
      return { valid: false, code: "RECOVERY_SLO_RESTORE_JOURNAL_BLOCK_REASON_MISSING" };
    }
    return { valid: true, status: replayStatus, items: replayItems };
  }

  function appendJournalEvent(record, type, details, at) {
    if (record.events.length >= MAX_IMPORT_JOURNAL_EVENTS) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_EVENT_LIMIT", "Batas event import journal tercapai", 409);
    }
    const event = { sequence: record.events.length + 1, type, at,
      previousHash: record.events.at(-1)?.eventHash || journalGenesis(record.ownerId, record.id), details };
    event.eventHash = eventHash(event);
    record.events.push(event);
    record.updatedAt = at;
    record.digest = event.eventHash;
    return record;
  }

  async function mutateJournal(ownerId, journalId, transition) {
    return store.mutateEvidence(ownerId, journalId, current => {
      if (!current) throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_NOT_FOUND", "Import journal tidak ditemukan", 404);
      const check = verifyJournal(current, ownerId);
      if (!check.valid) throw new AgenticError(check.code, "Integritas import journal gagal; perubahan ditolak", 409);
      const decision = transition(structuredClone(stripRootStorage(current)));
      if (!decision || decision.write === false) return { write: false, result: decision?.result ?? current };
      const next = decision.record;
      appendJournalEvent(next, decision.eventType, decision.details || {}, String(clock()));
      const after = verifyJournal(next, ownerId);
      if (!after.valid) throw new AgenticError(after.code, "Transisi import journal tidak konsisten", 500);
      return { value: next, result: next };
    });
  }

  async function changeJournalStatus(ownerId, journalId, toStatus, reasonCode = null) {
    return mutateJournal(ownerId, journalId, current => {
      if (current.status === toStatus) return { write: false, result: current };
      if (current.status === "completed" || current.status === "blocked") {
        throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_TERMINAL", "Import journal sudah terminal", 409);
      }
      if (toStatus === "completed" && current.items.some(item => !["quarantined", "already_present"].includes(item.state))) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_NOT_READY", "Masih ada evidence yang belum diselesaikan", 409);
      }
      if (toStatus === "blocked" && !current.items.some(item => item.state === "conflict")) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_BLOCK_REASON_REQUIRED", "Journal hanya dapat diblokir setelah konflik tercatat", 409);
      }
      const fromStatus = current.status;
      if (!(fromStatus === "prepared" && ["applying", "blocked"].includes(toStatus))
        && !(fromStatus === "applying" && ["completed", "blocked"].includes(toStatus))) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_STATUS_TRANSITION_INVALID", "Transisi status journal tidak diizinkan", 409);
      }
      current.status = toStatus;
      return { record: current, eventType: "status_changed", details: { fromStatus, toStatus, reasonCode } };
    });
  }

  async function changeJournalItem(ownerId, journalId, order, toState, quarantineRecordId = null) {
    return mutateJournal(ownerId, journalId, current => {
      const item = current.items.find(candidate => candidate.order === order);
      if (!item) throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_ITEM_NOT_FOUND", "Item journal tidak ditemukan", 409);
      if (item.state === toState && item.quarantineRecordId === (quarantineRecordId || null)) return { write: false, result: current };
      if (current.status !== "applying" || item.state !== "pending"
        || !["quarantined", "already_present", "conflict"].includes(toState)) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_ITEM_TRANSITION_INVALID", "Transisi item journal tidak diizinkan", 409);
      }
      const fromState = item.state;
      item.state = toState;
      item.quarantineRecordId = quarantineRecordId || null;
      return { record: current, eventType: "item_state_changed", details: { order, sourceRecordId: item.sourceRecordId,
        fromState, toState, quarantineRecordId: item.quarantineRecordId } };
    });
  }

  function buildQuarantineRecord(ownerId, approval, journal, item, sourceRecord) {
    const payload = stripStorageDeep(structuredClone(sourceRecord));
    const payloadDigest = sha256(canonical(payload));
    const base = { id: quarantineIdFor(ownerId, journal.sourceBundleDigest, item.sourceRecordId), ownerId,
      kind: quarantineKind, schemaVersion: 1, status: "quarantined", sourceRecordId: item.sourceRecordId,
      sourceSection: item.section, sourceKind: item.sourceKind, sourceRecordDigest: item.sourceDigest,
      payloadDigest, sourceBundleDigest: journal.sourceBundleDigest, approvalId: approval.id,
      planDigest: journal.planDigest, journalId: journal.id, quarantinedAt: String(clock()), payload };
    return { ...base, digest: recordDigest(base) };
  }

  function verifyQuarantineRecord(record, ownerId, journal, item) {
    if (!record || record.ownerId !== ownerId || record.kind !== quarantineKind || record.status !== "quarantined"
      || record.journalId !== journal.id || record.approvalId !== journal.approvalId
      || record.planDigest !== journal.planDigest || record.sourceBundleDigest !== journal.sourceBundleDigest
      || record.sourceRecordId !== item.sourceRecordId || record.sourceSection !== item.section
      || record.sourceKind !== item.sourceKind || record.sourceRecordDigest !== item.sourceDigest
      || record.payloadDigest !== record.sourceRecordDigest
      || record.payloadDigest !== sha256(canonical(stripStorageDeep(record.payload)))
      || record.digest !== recordDigest(record)) return false;
    return true;
  }

  async function saveQuarantineRecord(ownerId, candidate, journal, item) {
    const existing = await store.getEvidence(ownerId, candidate.id);
    if (existing) return verifyQuarantineRecord(existing, ownerId, journal, item) ? existing : null;
    const currentQuarantineCount = (await store.listEvidence(ownerId)).filter(record => record?.kind === quarantineKind).length;
    if (currentQuarantineCount >= MAX_QUARANTINE_RECORDS) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_QUARANTINE_LIMIT", "Batas evidence quarantine tercapai selama import", 409);
    }
    try {
      await store.putEvidence(ownerId, candidate, { overwrite: false });
      const saved = await store.getEvidence(ownerId, candidate.id);
      return verifyQuarantineRecord(saved, ownerId, journal, item) ? saved : null;
    } catch (error) {
      const raced = await store.getEvidence(ownerId, candidate.id);
      if (raced) return verifyQuarantineRecord(raced, ownerId, journal, item) ? raced : null;
      throw error;
    }
  }

  async function verifySourceForApproval(ownerId, plan, bundle) {
    if (!plan || typeof plan !== "object" || plan.schemaVersion !== 1 || plan.kind !== "recovery-slo-evidence-restore-plan"
      || plan.ownerId !== ownerId || plan.status !== "ready" || typeof plan.plannedAt !== "string" || !Number.isFinite(Date.parse(plan.plannedAt))
      || plan.dryRun !== true || plan.restoreExecuted !== false || plan.mutationAllowed !== false
      || plan.planDigest !== planDigestOf(plan) || plan.readOnly !== true || !Array.isArray(plan.actions)
      || plan.actions.length > MAX_PLAN_ACTIONS) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_PLAN_INVALID", "Restore plan tidak valid, berubah, atau belum siap", 409);
    }
    const fresh = await planRecoverySloEvidenceRestore(ownerId, bundle, { requireTrustedSignature: plan.requireTrustedSignature === true,
      maxActions: Math.max(1, plan.actions.length) });
    if (fresh.status !== "ready" || fresh.sourceBundleDigest !== plan.sourceBundleDigest
      || fresh.sourceVerificationStatus !== plan.sourceVerificationStatus || fresh.sourceAuthenticity !== plan.sourceAuthenticity
      || canonical(fresh.actions) !== canonical(plan.actions) || canonical(fresh.counts) !== canonical(plan.counts)) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_PLAN_STALE", "Target atau source berubah sejak restore plan dibuat; buat plan baru", 409);
    }
    return fresh;
  }

  async function approveRecoverySloEvidenceRestorePlan(ownerId, plan, bundle, options = {}) {
    assertOwner(ownerId);
    const reason = typeof options.reason === "string" ? options.reason.trim() : "";
    if (reason.length < 12 || reason.length > 240) throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_REASON_REQUIRED", "Alasan approval harus 12–240 karakter", 400);
    if (options.confirmation !== `APPROVE RESTORE ${String(plan?.planDigest || "").slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_CONFIRMATION_REQUIRED", "Konfirmasi eksplisit tidak cocok dengan digest restore plan", 400);
    }
    const fresh = await verifySourceForApproval(ownerId, plan, bundle);
    const all = await store.listEvidence(ownerId);
    const approvals = all.filter(item => item?.kind === restoreApprovalKind);
    const sameSourceApproval = approvals.find(item => item.sourceBundleDigest === fresh.sourceBundleDigest);
    if (sameSourceApproval) {
      const existing = verifyApproval(sameSourceApproval, ownerId);
      if (existing.planDigest === plan.planDigest && existing.actionsDigest === actionDigest(plan.actions)) {
        return { approvalId: existing.id, status: "approved", ownerId, planDigest: existing.planDigest,
          sourceBundleDigest: existing.sourceBundleDigest, actionsDigest: existing.actionsDigest, approvedAt: existing.approvedAt,
          approvedBy: existing.approvedBy, counts: existing.counts, readOnly: true, mutationAllowed: false, idempotent: true };
      }
      throw new AgenticError("RECOVERY_SLO_RESTORE_SOURCE_ALREADY_APPROVED", "Bundle ini sudah memiliki approval; gunakan approval yang tersimpan atau buat ekspor baru", 409);
    }
    const priorJournals = all.filter(item => item?.kind === restoreJournalKind && item.sourceBundleDigest === fresh.sourceBundleDigest);
    if (priorJournals.length) throw new AgenticError("RECOVERY_SLO_RESTORE_SOURCE_ALREADY_STAGED", "Bundle ini sudah memiliki import journal", 409);
    const existingQuarantine = all.filter(item => item?.kind === quarantineKind);
    const duplicateQuarantine = plan.actions.find(action => action.action === "import" && existingQuarantine.some(record =>
      record.sourceRecordId === action.recordId && record.sourceRecordDigest === action.sourceRecordDigest));
    if (duplicateQuarantine) throw new AgenticError("RECOVERY_SLO_RESTORE_EVIDENCE_ALREADY_QUARANTINED", "Evidence yang sama sudah berada dalam quarantine", 409);
    if (approvals.length >= MAX_IMPORT_JOURNALS) throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_LIMIT", "Batas restore approval tercapai", 409);
    const id = `recovery-slo-restore-approval-${sha256(canonical({ ownerId, planDigest: plan.planDigest,
      sourceBundleDigest: fresh.sourceBundleDigest })).slice(0, 48)}`;
    const record = { id, ownerId, kind: restoreApprovalKind, schemaVersion: 1, status: "approved", approvedBy: ownerId,
      approvedAt: String(clock()), reason, planDigest: plan.planDigest, sourceBundleDigest: fresh.sourceBundleDigest,
      sourceVerificationStatus: plan.sourceVerificationStatus, requireTrustedSignature: plan.requireTrustedSignature === true,
      actions: structuredClone(plan.actions), actionsDigest: actionDigest(plan.actions), counts: structuredClone(plan.counts),
      digest: "" };
    record.digest = recordDigest(record);
    try { await store.putEvidence(ownerId, record, { overwrite: false }); }
    catch (error) {
      const existing = await store.getEvidence(ownerId, id);
      if (!existing || existing.digest !== record.digest) throw error;
    }
    return { approvalId: id, status: "approved", ownerId, planDigest: record.planDigest,
      sourceBundleDigest: record.sourceBundleDigest, actionsDigest: record.actionsDigest, approvedAt: record.approvedAt,
      approvedBy: record.approvedBy, counts: record.counts, readOnly: true, mutationAllowed: false };
  }

  async function createImportJournal(ownerId, approval) {
    const id = journalIdForApproval(approval.id);
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      const check = verifyJournal(existing, ownerId);
      if (!check.valid || existing.approvalId !== approval.id || existing.planDigest !== approval.planDigest
        || existing.sourceBundleDigest !== approval.sourceBundleDigest) {
        throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_CONFLICT", "Journal import yang ada tidak cocok dengan approval", 409);
      }
      return existing;
    }
    const journals = (await store.listEvidence(ownerId)).filter(item => item?.kind === restoreJournalKind);
    if (journals.length >= MAX_IMPORT_JOURNALS) throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_LIMIT", "Batas import journal tercapai", 409);
    const all = (await store.listEvidence(ownerId)).filter(item => item?.kind === quarantineKind);
    if (all.length + approval.counts.import > MAX_QUARANTINE_RECORDS) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_QUARANTINE_LIMIT", "Batas evidence quarantine akan terlampaui", 409);
    }
    const now = String(clock());
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_SLO_RESTORE_CLOCK_INVALID", "Clock import journal tidak valid", 500);
    const items = approval.actions.map((action, index) => ({ order: index + 1, section: action.section,
      sourceRecordId: action.recordId, sourceKind: action.kind, sourceDigest: action.sourceRecordDigest || null,
      plannedDigest: action.digest, action: action.action, state: action.action === "already_present" ? "already_present" : "pending",
      quarantineRecordId: null }));
    const event = { sequence: 1, type: "journal_created", at: now, previousHash: journalGenesis(ownerId, id),
      details: { initialStatus: "prepared", initialItems: structuredClone(items), approvalId: approval.id,
        planDigest: approval.planDigest, sourceBundleDigest: approval.sourceBundleDigest } };
    event.eventHash = eventHash(event);
    const record = { id, ownerId, kind: restoreJournalKind, schemaVersion: 1, approvalId: approval.id,
      planDigest: approval.planDigest, sourceBundleDigest: approval.sourceBundleDigest, status: "prepared",
      createdAt: now, updatedAt: now, items, events: [event], digest: event.eventHash };
    const check = verifyJournal(record, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Journal import awal tidak valid", 500);
    try { await store.putEvidence(ownerId, record, { overwrite: false }); return record; }
    catch (error) {
      const raced = await store.getEvidence(ownerId, id);
      const racedCheck = verifyJournal(raced, ownerId);
      if (racedCheck.valid && raced.approvalId === approval.id && raced.sourceBundleDigest === approval.sourceBundleDigest) return raced;
      throw error;
    }
  }

  async function prepareBundleForImport(ownerId, bundle, expectedDigest, requireTrustedSignature) {
    const keyMatches = Boolean(exportAttestationKeyId && exportAttestationPublicKey
      && bundle?.attestation?.keyId === exportAttestationKeyId);
    if (requireTrustedSignature && !keyMatches) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_TRUSTED_SIGNATURE_REQUIRED", "Bundle harus ditandatangani oleh export key tepercaya yang dikonfigurasi", 409);
    }
    const inspection = inspectRecoverySloEvidenceExportBundle(bundle, { expectedOwnerId: ownerId,
      publicKey: keyMatches ? exportAttestationPublicKey : null, requireSignature: requireTrustedSignature === true });
    if (!inspection.valid || inspection.bundleDigest !== expectedDigest) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_SOURCE_INVALID", "Bundle sumber tidak valid atau berbeda dari approval", 409);
    }
    return sectionRecords(bundle.sections).map(({ section, record }) => ({ section, record: stripStorageDeep(structuredClone(record)) }));
  }

  async function processImportJournal(ownerId, journalId, bundle, { recovery = false } = {}) {
    let journal = await store.getEvidence(ownerId, journalId);
    let journalCheck = verifyJournal(journal, ownerId);
    if (!journalCheck.valid) throw new AgenticError(journalCheck.code, "Integritas import journal gagal", 409);
    if (journal.status === "completed" || journal.status === "blocked") return summarizeJournal(journal);
    const approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
    if (approval.planDigest !== journal.planDigest || approval.sourceBundleDigest !== journal.sourceBundleDigest) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_BINDING_INVALID", "Journal tidak terikat pada approval yang benar", 409);
    }
    const source = await prepareBundleForImport(ownerId, bundle, journal.sourceBundleDigest, approval.requireTrustedSignature);
    const sourceByKey = new Map(source.map(item => [`${item.section}\n${item.record.id}`, item.record]));
    if (source.length !== journal.items.length || journal.items.some(item => {
      const record = sourceByKey.get(`${item.section}\n${item.sourceRecordId}`);
      return !record || record.kind !== item.sourceKind || sha256(canonical(record)) !== item.sourceDigest;
    })) throw new AgenticError("RECOVERY_SLO_RESTORE_SOURCE_BINDING_INVALID", "Isi bundle tidak cocok dengan import journal", 409);

    if (journal.status === "prepared") journal = await changeJournalStatus(ownerId, journalId, "applying");
    else if (recovery) {
      journal = await mutateJournal(ownerId, journalId, current => ({ record: current, eventType: "recovery_resumed",
        details: { resumedAt: String(clock()) } }));
    } else {
      throw new AgenticError("RECOVERY_SLO_RESTORE_RECOVERY_REQUIRED", "Import sudah berjalan; gunakan endpoint recovery", 409);
    }

    for (const initialItem of journal.items) {
      journal = await store.getEvidence(ownerId, journalId);
      const check = verifyJournal(journal, ownerId);
      if (!check.valid) throw new AgenticError(check.code, "Integritas import journal gagal selama proses", 409);
      if (journal.status !== "applying") break;
      const item = journal.items.find(candidate => candidate.order === initialItem.order);
      if (!item || item.state !== "pending") continue;
      const sourceRecord = sourceByKey.get(`${item.section}\n${item.sourceRecordId}`);
      const existingTarget = await store.getEvidence(ownerId, item.sourceRecordId);
      if (existingTarget) {
        if (canonical(stripStorageDeep(existingTarget)) === canonical(sourceRecord)) {
          journal = await changeJournalItem(ownerId, journalId, item.order, "already_present");
          continue;
        }
        journal = await changeJournalItem(ownerId, journalId, item.order, "conflict");
        journal = await changeJournalStatus(ownerId, journalId, "blocked", "TARGET_RECORD_CONFLICT");
        return summarizeJournal(journal);
      }
      const candidate = buildQuarantineRecord(ownerId, approval, journal, item, sourceRecord);
      const saved = await saveQuarantineRecord(ownerId, candidate, journal, item);
      if (!saved) {
        journal = await changeJournalItem(ownerId, journalId, item.order, "conflict");
        journal = await changeJournalStatus(ownerId, journalId, "blocked", "QUARANTINE_RECORD_CONFLICT");
        return summarizeJournal(journal);
      }
      const targetAfterWrite = await store.getEvidence(ownerId, item.sourceRecordId);
      if (targetAfterWrite && canonical(stripStorageDeep(targetAfterWrite)) !== canonical(sourceRecord)) {
        journal = await changeJournalItem(ownerId, journalId, item.order, "conflict");
        journal = await changeJournalStatus(ownerId, journalId, "blocked", "TARGET_RECORD_CONFLICT_AFTER_STAGE");
        return summarizeJournal(journal);
      }
      journal = await changeJournalItem(ownerId, journalId, item.order, "quarantined", candidate.id);
    }
    journal = await store.getEvidence(ownerId, journalId);
    const finalCheck = verifyJournal(journal, ownerId);
    if (!finalCheck.valid) throw new AgenticError(finalCheck.code, "Integritas import journal gagal saat finalisasi", 409);
    if (journal.status === "applying" && journal.items.every(item => ["quarantined", "already_present"].includes(item.state))) {
      journal = await changeJournalStatus(ownerId, journalId, "completed");
    }
    return summarizeJournal(journal);
  }

  function summarizeJournal(journal) {
    return { journalId: journal.id, approvalId: journal.approvalId, ownerId: journal.ownerId, status: journal.status,
      planDigest: journal.planDigest, sourceBundleDigest: journal.sourceBundleDigest, createdAt: journal.createdAt,
      updatedAt: journal.updatedAt, digest: journal.digest, counts: {
        total: journal.items.length, pending: journal.items.filter(item => item.state === "pending").length,
        quarantined: journal.items.filter(item => item.state === "quarantined").length,
        alreadyPresent: journal.items.filter(item => item.state === "already_present").length,
        conflicts: journal.items.filter(item => item.state === "conflict").length
      }, quarantinedOnly: true, activated: false, mutationAllowed: false };
  }

  async function applyRecoverySloEvidenceRestorePlan(ownerId, approvalId, bundle) {
    assertOwner(ownerId);
    if (typeof approvalId !== "string" || !approvalId.trim() || approvalId.length > 240) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_ID_REQUIRED", "Approval ID wajib diisi", 400);
    }
    const approvalRecord = await store.getEvidence(ownerId, approvalId);
    if (!approvalRecord) throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_NOT_FOUND", "Restore approval tidak ditemukan", 404);
    const approval = verifyApproval(approvalRecord, ownerId);
    const journalId = journalIdForApproval(approval.id);
    const source = await prepareBundleForImport(ownerId, bundle, approval.sourceBundleDigest, approval.requireTrustedSignature);
    const existingJournal = await store.getEvidence(ownerId, journalId);
    if (existingJournal) {
      const check = verifyJournal(existingJournal, ownerId);
      if (!check.valid) throw new AgenticError(check.code, "Integritas import journal gagal", 409);
      if (existingJournal.status === "completed" || existingJournal.status === "blocked") return summarizeJournal(existingJournal);
      throw new AgenticError("RECOVERY_SLO_RESTORE_RECOVERY_REQUIRED", "Import journal sudah ada; gunakan endpoint recovery", 409);
    }
    const fresh = await planRecoverySloEvidenceRestore(ownerId, bundle, { requireTrustedSignature: approval.requireTrustedSignature,
      maxActions: Math.max(1, approval.actions.length) });
    if (fresh.status !== "ready" || fresh.sourceBundleDigest !== approval.sourceBundleDigest
      || fresh.sourceVerificationStatus !== approval.sourceVerificationStatus || actionDigest(fresh.actions) !== approval.actionsDigest
      || canonical(fresh.counts) !== canonical(approval.counts)) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_PLAN_STALE", "Target berubah setelah approval; import ditolak dan plan baru diperlukan", 409);
    }
    if (source.length !== approval.actions.length || source.some((entry, index) => {
      const action = approval.actions[index];
      return !action || action.section !== entry.section || action.recordId !== entry.record.id
        || action.kind !== entry.record.kind || action.digest !== entry.record.digest;
    })) throw new AgenticError("RECOVERY_SLO_RESTORE_APPROVAL_SOURCE_MISMATCH", "Approval tidak cocok dengan urutan bundle", 409);
    const journal = await createImportJournal(ownerId, approval);
    return processImportJournal(ownerId, journal.id, bundle);
  }

  async function recoverRecoverySloEvidenceRestoreImport(ownerId, journalId, bundle) {
    assertOwner(ownerId);
    if (typeof journalId !== "string" || !journalId.trim() || journalId.length > 240) {
      throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_ID_REQUIRED", "Journal ID wajib diisi", 400);
    }
    const journal = await store.getEvidence(ownerId, journalId);
    if (!journal) throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_NOT_FOUND", "Import journal tidak ditemukan", 404);
    const check = verifyJournal(journal, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Integritas import journal gagal", 409);
    const approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
    const source = await prepareBundleForImport(ownerId, bundle, journal.sourceBundleDigest, approval.requireTrustedSignature);
    const sourceByKey = new Map(source.map(item => [`${item.section}\n${item.record.id}`, item.record]));
    if (source.length !== journal.items.length || journal.items.some(item => {
      const record = sourceByKey.get(`${item.section}\n${item.sourceRecordId}`);
      return !record || record.kind !== item.sourceKind || sha256(canonical(record)) !== item.sourceDigest;
    })) throw new AgenticError("RECOVERY_SLO_RESTORE_SOURCE_BINDING_INVALID", "Isi bundle tidak cocok dengan import journal", 409);
    if (journal.status === "completed" || journal.status === "blocked") return summarizeJournal(journal);
    return processImportJournal(ownerId, journalId, bundle, { recovery: true });
  }

  async function getRecoverySloEvidenceRestoreImportJournal(ownerId, journalId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, journalId);
    if (!record) throw new AgenticError("RECOVERY_SLO_RESTORE_JOURNAL_NOT_FOUND", "Import journal tidak ditemukan", 404);
    const check = verifyJournal(record, ownerId);
    if (!check.valid) throw new AgenticError(check.code, "Integritas import journal gagal", 409);
    return { ...summarizeJournal(record), items: structuredClone(record.items), events: structuredClone(record.events), integrityValid: true, readOnly: true };
  }

  async function listRecoverySloEvidenceRestoreImportJournals(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = Number.isSafeInteger(options.limit) ? Math.max(1, Math.min(100, options.limit)) : 25;
    const all = (await store.listEvidence(ownerId)).filter(item => item?.kind === restoreJournalKind)
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    const items = [];
    for (const record of all.slice(0, limit)) {
      const check = verifyJournal(record, ownerId);
      items.push(check.valid ? summarizeJournal(record) : { journalId: record.id, status: "unhealthy", integrityValid: false,
        finding: check.code, mutationAllowed: false });
    }
    return { ownerId, items, total: all.length, limit, truncated: all.length > items.length, readOnly: true };
  }

  async function listRecoverySloEvidenceRestoreQuarantine(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = Number.isSafeInteger(options.limit) ? Math.max(1, Math.min(100, options.limit)) : 25;
    const journalId = typeof options.journalId === "string" && options.journalId ? options.journalId : null;
    const all = (await store.listEvidence(ownerId)).filter(item => item?.kind === quarantineKind
      && (!journalId || item.journalId === journalId)).sort((a, b) => String(a.quarantinedAt).localeCompare(String(b.quarantinedAt)));
    return { ownerId, items: all.slice(0, limit).map(record => ({ ...stripRootStorage(record), integrityValid: record.digest === recordDigest(record)
      && record.payloadDigest === sha256(canonical(stripStorageDeep(record.payload))), readOnly: true, activated: false })),
      total: all.length, limit, truncated: all.length > limit, readOnly: true, mutationAllowed: false };
  }

  async function auditRecoverySloEvidenceRestoreImports(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = Number.isSafeInteger(options.limit) ? Math.max(1, Math.min(500, options.limit)) : 100;
    const all = (await store.listEvidence(ownerId)).filter(item => item?.kind === restoreJournalKind)
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
    const findings = [];
    let checkedJournals = 0, checkedQuarantineRecords = 0;
    for (const journal of all.slice(0, limit)) {
      checkedJournals += 1;
      const check = verifyJournal(journal, ownerId);
      if (!check.valid) { findings.push({ code: check.code, journalId: journal.id, severity: "error" }); continue; }
      try {
        const approval = verifyApproval(await store.getEvidence(ownerId, journal.approvalId), ownerId);
        if (approval.planDigest !== journal.planDigest || approval.sourceBundleDigest !== journal.sourceBundleDigest
          || approval.actionsDigest !== actionDigest(approval.actions)) {
          findings.push({ code: "RECOVERY_SLO_RESTORE_APPROVAL_BINDING_INVALID", journalId: journal.id, severity: "error" });
        }
      } catch {
        findings.push({ code: "RECOVERY_SLO_RESTORE_APPROVAL_MISSING_OR_INVALID", journalId: journal.id, severity: "error" });
      }
      if (["prepared", "applying"].includes(journal.status)) findings.push({ code: "RECOVERY_SLO_RESTORE_IMPORT_PENDING",
        journalId: journal.id, severity: "warning" });
      if (journal.status === "blocked") findings.push({ code: "RECOVERY_SLO_RESTORE_IMPORT_BLOCKED",
        journalId: journal.id, severity: "warning" });
      for (const item of journal.items.filter(candidate => candidate.state === "quarantined")) {
        const record = await store.getEvidence(ownerId, item.quarantineRecordId);
        if (!verifyQuarantineRecord(record, ownerId, journal, item)) findings.push({ code: "RECOVERY_SLO_RESTORE_QUARANTINE_BINDING_INVALID",
          journalId: journal.id, recordId: item.quarantineRecordId, severity: "error" });
      }
    }
    const journalById = new Map(all.map(item => [item.id, item]));
    const quarantineRecords = (await store.listEvidence(ownerId)).filter(item => item?.kind === quarantineKind);
    checkedQuarantineRecords = quarantineRecords.length;
    for (const record of quarantineRecords) {
      const journal = journalById.get(record.journalId);
      const item = journal?.items?.find(candidate => candidate.sourceRecordId === record.sourceRecordId
        && candidate.section === record.sourceSection);
      if (!journal || !item || !["pending", "quarantined"].includes(item.state)
        || record.id !== quarantineIdFor(ownerId, journal.sourceBundleDigest, item.sourceRecordId)
        || !verifyQuarantineRecord(record, ownerId, journal, item)
        || (item.state === "quarantined" && item.quarantineRecordId !== record.id)) {
        findings.push({ code: "RECOVERY_SLO_RESTORE_ORPHANED_QUARANTINE_RECORD", recordId: record.id, severity: "error" });
      } else if (item.state === "pending") {
        findings.push({ code: "RECOVERY_SLO_RESTORE_QUARANTINE_WRITE_AWAITING_JOURNAL", journalId: journal.id,
          recordId: record.id, severity: "warning" });
      }
    }
    const truncated = all.length > checkedJournals;
    if (truncated) findings.push({ code: "RECOVERY_SLO_RESTORE_AUDIT_TRUNCATED", severity: "warning" });
    const status = findings.some(item => item.severity === "error") ? "unhealthy"
      : findings.some(item => item.code === "RECOVERY_SLO_RESTORE_IMPORT_PENDING") ? "recovery_required"
        : findings.length ? "degraded" : "healthy";
    return { ownerId, status, checkedJournals, totalJournals: all.length, checkedQuarantineRecords,
      findings: findings.slice(0, 200), totalFindings: findings.length, truncated: truncated || findings.length > 200,
      readOnly: true, mutationAllowed: false, automaticRepairAllowed: false };
  }

  return Object.freeze({ planRecoverySloEvidenceRestore, approveRecoverySloEvidenceRestorePlan,
    applyRecoverySloEvidenceRestorePlan, recoverRecoverySloEvidenceRestoreImport,
    getRecoverySloEvidenceRestoreImportJournal, listRecoverySloEvidenceRestoreImportJournals,
    listRecoverySloEvidenceRestoreQuarantine, auditRecoverySloEvidenceRestoreImports });
}
