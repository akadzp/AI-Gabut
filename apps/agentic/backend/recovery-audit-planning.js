import { createHash, randomUUID, createPublicKey, verify as verifySignature } from "node:crypto";
import { performance } from "node:perf_hooks";
import { AgenticError } from "./errors.js";

const MAX_ID = 200;
const MAX_MESSAGE = 240;
const MAX_ACTIONS = 100;
const MAX_EVIDENCE_ISSUES = 500;
const MAX_AUDIT_LIMIT = 500;
const MAX_MUTATION_INTENT_BYTES = 8192;
const MAX_CONSUMED_ACTIONS = 100;
const MAX_MUTATION_RESOLUTIONS = 100;
const MAX_MUTATION_OUTCOME_LEDGER_ENTRIES = 2000;
const MAX_MUTATION_OUTCOME_LEDGER_FINDINGS = 500;
const MAX_MUTATION_OUTCOME_LEDGER_POLICY_HISTORY = 500;
const MAX_MUTATION_OUTCOME_LEDGER_POLICY_CODES = 50;
const MAX_INTEGRITY_ATTESTATION_TTL_MS = 5 * 60 * 1000;
const MAX_ATTESTATION_TRUST_HISTORY = 500;
const MAX_ATTESTATION_TRUST_KEYS = 100;
const MAX_ATTESTATION_TRUST_AUTHORIZERS = 100;
const MAX_ATTESTATION_TRUST_CHALLENGES = 2000;
const MAX_PENDING_ATTESTATION_TRUST_CHALLENGES = 100;
const MAX_ATTESTATION_TRUST_ANCHOR_CHALLENGES = 1000;
const MAX_PENDING_ATTESTATION_TRUST_ANCHOR_CHALLENGES = 100;
const MAX_ATTESTATION_TRUST_AUDIT_RECORDS = 2000;
const MAX_TRUST_TRANSITION_JOURNALS = 1000;
const MAX_TRUST_TRANSITION_RECOVERY_LIMIT = 100;
const MAX_CROSS_STORE_AUDIT_LIMIT = 200;
const MAX_TRUST_ANCHOR_HEALTH_SAMPLES = 200;
const DEFAULT_TRUST_TRANSITION_STALE_MS = 30_000;
const MAX_INTEGRITY_ATTESTATION_SIGNATURE_BYTES = 256;
const MAX_MUTATION_EVIDENCE_REF = 300;
const MAX_MUTATION_EVIDENCE_SUMMARY = 240;
const MUTATION_EVIDENCE_METHODS = new Set(["provider_status", "idempotency_lookup", "transaction_log", "database_inspection", "manual_inspection", "operator_attestation"]);
const OUTCOME_EVIDENCE_METHODS = new Set(["provider_status", "idempotency_lookup", "transaction_log", "database_inspection", "manual_inspection"]);
const QUIESCENCE_EVIDENCE_METHODS = new Set(["process_exit", "provider_terminal_status", "execution_lease_fenced", "idempotency_terminal_record"]);
const RECORD_GETTERS = Object.freeze({ work: "getWork", task: "getTask", execution: "getExecution" });
const bounded = (value, max = MAX_ID) => String(value ?? "").slice(0, max);
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function safeIssue(issue) {
  const severities = new Set(["error", "warning", "info"]);
  return {
    code: bounded(issue?.code, 80),
    severity: severities.has(issue?.severity) ? issue.severity : "warning",
    entityType: bounded(issue?.entityType, 40),
    entityId: bounded(issue?.entityId),
    relatedId: issue?.relatedId == null ? null : bounded(issue.relatedId),
    message: bounded(issue?.message, MAX_MESSAGE)
  };
}

function operationFor(issue) {
  const code = issue.code;
  if (code === "AUDIT_RESULT_TRUNCATED") {
    return {
      operation: "rerun_audit",
      priority: "high",
      rationale: "The source audit inspected only a bounded subset; do not reconcile from partial evidence.",
      steps: ["Rerun the owner-scoped audit with an adequate record limit.", "Capture fresh evidence before reviewing any proposed repair."]
    };
  }
  if (code.includes("FENCE") || code.includes("FENCING")) {
    return {
      operation: "verify_fencing_history",
      priority: issue.severity === "error" ? "high" : "medium",
      rationale: "Fencing metadata may indicate a stale runner or regressed ownership history.",
      steps: ["Inspect the current lease and stored fencing values.", "Compare execution history before approving any correction; never lower a fence automatically."]
    };
  }
  if (code.includes("LEASE")) {
    return {
      operation: "inspect_durable_lease",
      priority: issue.severity === "error" ? "high" : "medium",
      rationale: "Lease ownership or lifecycle may disagree with the Work record.",
      steps: ["Inspect the current lease owner, expiry, and fence.", "Re-run the audit after confirming that no valid runner is active."]
    };
  }
  if (code.includes("STATUS_MISMATCH") || code === "ACTIVE_EXECUTION_FOR_PAUSED_WORK") {
    return {
      operation: "compare_lifecycle_records",
      priority: issue.severity === "error" ? "high" : "medium",
      rationale: "Work, task, execution, or recovery lifecycle states disagree.",
      steps: ["Read the current Work, task, and execution records.", "Determine the authoritative lifecycle transition and approve a bounded reconciliation separately."]
    };
  }
  if (code.includes("RECOVERY")) {
    return {
      operation: "validate_recovery_metadata",
      priority: issue.severity === "error" ? "high" : "medium",
      rationale: "Recovery metadata or its execution reference may be incomplete or inconsistent.",
      steps: ["Verify the referenced execution and checkpoint provenance.", "Confirm recovery fence and status before authorizing a repair."]
    };
  }
  if (code.includes("MISSING") || code.includes("MISMATCH")) {
    return {
      operation: "verify_record_references",
      priority: issue.severity === "error" ? "high" : "medium",
      rationale: "Related records or references may be missing, crossed, or inconsistent.",
      steps: ["Verify every referenced record within the same owner scope.", "Choose explicitly whether to restore a reference or retire an orphan; do not infer destructive intent."]
    };
  }
  return {
    operation: "manual_review",
    priority: issue.severity === "error" ? "high" : issue.severity === "warning" ? "medium" : "low",
    rationale: "The finding requires a human to review the current source records.",
    steps: ["Re-read the relevant records and their versions.", "Approve any state-changing operation separately."]
  };
}

function issueReference(issue) {
  return sha256(canonical({
    code: issue.code, entityType: issue.entityType, entityId: issue.entityId, relatedId: issue.relatedId
  })).slice(0, 24);
}

function relatedEntityType(issue) {
  const code = String(issue?.code || "");
  if (issue?.entityType === "execution") {
    if (code.includes("TASK")) return "task";
    if (code === "EXECUTION_LEASE_OWNER_MISMATCH") return "execution";
    if (code.includes("WORK") || code.includes("RECOVERY") || code.includes("LEASE")) return "work";
  }
  if (issue?.entityType === "task") return "work";
  if (issue?.entityType === "work") {
    if (code.includes("TASK")) return "task";
    if (code.includes("EXECUTION") || code.includes("RECOVERY") || code.includes("LEASE")) return "execution";
  }
  return null;
}

function recordProjection(type, record) {
  if (!record) return null;
  if (type === "work") return {
    state: record.state == null ? null : bounded(record.state, 40),
    taskIds: Array.isArray(record.taskIds) ? record.taskIds.slice(0, 100).map(value => bounded(value)).sort() : [],
    executionIds: Array.isArray(record.executionIds) ? record.executionIds.slice(0, 100).map(value => bounded(value)).sort() : [],
    executionLeaseId: record.executionLeaseId == null ? null : bounded(record.executionLeaseId),
    executionLeaseFence: record.executionLeaseFence ?? null,
    recovery: record.result?.recovery ? {
      status: record.result.recovery.status == null ? null : bounded(record.result.recovery.status, 40),
      executionId: record.result.recovery.executionId == null ? null : bounded(record.result.recovery.executionId),
      leaseFence: record.result.recovery.leaseFence ?? null
    } : null
  };
  if (type === "execution") return {
    status: record.status == null ? null : bounded(record.status, 40),
    workId: record.workId == null ? null : bounded(record.workId),
    taskId: record.taskId == null ? null : bounded(record.taskId),
    recoverable: record.recoverable === true,
    recovery: record.recovery ? {
      status: record.recovery.status == null ? null : bounded(record.recovery.status, 40),
      executionId: record.recovery.executionId == null ? null : bounded(record.recovery.executionId),
      leaseFence: record.recovery.leaseFence ?? null
    } : null
  };
  if (type === "task") return {
    status: record.status == null ? null : bounded(record.status, 40),
    workId: record.workId == null ? null : bounded(record.workId)
  };
  return null;
}

function safeRecordState(type, id, record) {
  const version = Number.isSafeInteger(record?._storage?.version) && record._storage.version >= 0
    ? record._storage.version : null;
  const projection = recordProjection(type, record);
  const state = { entityType: type, id: bounded(id), exists: Boolean(record), version, projection };
  return { ...state, fingerprint: sha256(canonical(state)) };
}

function safeLeaseState(workId, lease) {
  const state = {
    workId: bounded(workId),
    exists: lease?.exists === true,
    active: lease?.active === true,
    expired: lease?.expired === true,
    released: lease?.released === true,
    executionId: lease?.executionId == null ? null : bounded(lease.executionId),
    fence: boundedInteger(lease?.fence, 0, 0, Number.MAX_SAFE_INTEGER),
    expiresAtMs: boundedInteger(lease?.expiresAtMs, 0, 0, Number.MAX_SAFE_INTEGER),
    releasedAt: lease?.releasedAt == null ? null : bounded(lease.releasedAt, 64)
  };
  return { ...state, fingerprint: sha256(canonical(state)) };
}

function planAction(issue, index, precondition = null) {
  const recommendation = operationFor(issue);
  const issueRef = issueReference(issue);
  return {
    id: `reconcile-${String(index + 1).padStart(3, "0")}`,
    issueRef,
    preconditionDigest: precondition?.digest || null,
    preconditionRecordCount: Array.isArray(precondition?.records) ? precondition.records.length : 0,
    preconditionLeaseCount: Array.isArray(precondition?.leases) ? precondition.leases.length : 0,
    issueCode: issue.code,
    severity: issue.severity,
    priority: recommendation.priority,
    target: { entityType: issue.entityType, entityId: issue.entityId, relatedId: issue.relatedId },
    operation: recommendation.operation,
    rationale: bounded(recommendation.rationale, MAX_MESSAGE),
    steps: recommendation.steps.map(step => bounded(step, MAX_MESSAGE)),
    preconditions: [
      "Re-read current records and verify their owner scope and versions.",
      "Run a fresh integrity audit immediately before any separately approved repair."
    ],
    requiresHumanApproval: true,
    automaticExecutionAllowed: false,
    mutation: "none-until-separately-approved"
  };
}

export function createRecoveryAuditPlanningService({ store, auditService, workExecutionLeaseService = null, clock = () => new Date().toISOString(), integrityAttestationPublicKeys = null, attestationTrustAnchor = null } = {}) {
  if (!store?.putEvidence || !store?.getEvidence || !store?.listEvidence || !store?.mutateEvidence || !auditService?.inspect) {
    throw new TypeError("Recovery audit planning membutuhkan evidence store dengan atomic mutateEvidence dan audit service");
  }

  function loadIntegrityAttestationKeys(input) {
    let source = input;
    if (source == null) {
      const configured = process.env.AGENTIC_INTEGRITY_ATTESTATION_PUBLIC_KEYS;
      if (configured) {
        try { source = JSON.parse(configured); } catch { source = {}; }
      }
    }
    if (typeof source === "string") {
      try { source = JSON.parse(source); } catch { source = {}; }
    }
    const result = new Map();
    if (!source || typeof source !== "object" || Array.isArray(source)) return result;
    for (const [keyId, configuredKey] of Object.entries(source).slice(0, 100)) {
      if (!/^[A-Za-z0-9._-]{1,80}$/.test(keyId)) continue;
      try {
        const key = configuredKey?.type === "public" ? configuredKey
          : createPublicKey(typeof configuredKey === "string" ? configuredKey.replace(/\\n/g, "\n") : configuredKey);
        if (key?.type === "public" && key.asymmetricKeyType === "ed25519") result.set(keyId, key);
      } catch { /* invalid/untrusted key material is ignored; use fails closed */ }
    }
    return result;
  }

  const trustedIntegrityAttestationKeys = loadIntegrityAttestationKeys(integrityAttestationPublicKeys);
  const configuredIntegrityAttestationKeys = new Map(trustedIntegrityAttestationKeys);
  if (attestationTrustAnchor != null && (typeof attestationTrustAnchor.read !== "function"
    || typeof attestationTrustAnchor.compareAndSet !== "function")) {
    throw new TypeError("attestationTrustAnchor harus menyediakan read(ownerId) dan compareAndSet(ownerId, expectedDigest, candidate)");
  }
  function verifyIntegrityAttestationSignature(payload, signature, keyId) {
    const key = trustedIntegrityAttestationKeys.get(String(keyId || ""));
    if (!key || typeof signature !== "string" || signature.length > MAX_INTEGRITY_ATTESTATION_SIGNATURE_BYTES * 2) return false;
    let bytes;
    try { bytes = Buffer.from(signature, "base64url"); } catch { return false; }
    if (bytes.length !== 64) return false;
    try { return verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes); } catch { return false; }
  }

  function publicKeyPem(key) {
    return key.export({ type: "spki", format: "pem" }).toString();
  }

  function keyFingerprint(key) {
    const keyObject = key?.type === "public" ? key : createPublicKey(key);
    return sha256(keyObject.export({ type: "spki", format: "der" }).toString("base64"));
  }

  function parseEd25519PublicKey(value) {
    const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
    if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_KEY_INVALID", "Trusted key harus berupa public key Ed25519", 400);
    }
    return key;
  }

  function verifyTrustPayloadSignature(payload, signature, key) {
    if (typeof signature !== "string" || signature.length < 80 || signature.length > MAX_INTEGRITY_ATTESTATION_SIGNATURE_BYTES * 2) return false;
    let bytes;
    try { bytes = Buffer.from(signature, "base64url"); } catch { return false; }
    if (bytes.length !== 64) return false;
    try { return verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes); } catch { return false; }
  }

  function attestationTrustPolicyId(ownerId) {
    return `ledger-integrity-trust-policy-${sha256(canonical({ domain: "agentic-v4-ledger-integrity-trust-policy", ownerId })).slice(0, 32)}`;
  }

  function attestationTrustChallengeId(ownerId, challengeId) {
    return `ledger-integrity-trust-challenge-${sha256(canonical({ domain: "agentic-v4-ledger-integrity-trust-challenge", ownerId, challengeId })).slice(0, 32)}`;
  }

  function trustSnapshotDigest(snapshot) { return sha256(canonical(snapshot)); }

  function configuredTrustKeyEntries() {
    return [...configuredIntegrityAttestationKeys.entries()].map(([keyId, key]) => ({
      keyId, publicKeyPem: publicKeyPem(key), fingerprint: keyFingerprint(key)
    })).sort((a, b) => a.keyId.localeCompare(b.keyId)).slice(0, MAX_ATTESTATION_TRUST_KEYS);
  }

  function validateAttestationTrustPolicyRecord(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_POLICY_INTEGRITY_FAILED", "Trust policy attestation tidak valid; verifikasi baru ditolak", 409); };
    if (!record || record.kind !== "recovery-reconciliation-attestation-trust-policy" || record.ownerId !== ownerId
      || record.id !== attestationTrustPolicyId(ownerId) || !record.snapshot || record.snapshot.schemaVersion !== 1
      || record.snapshot.ownerId !== ownerId || !Number.isSafeInteger(record.snapshot.revision) || record.snapshot.revision < 0
      || !Array.isArray(record.snapshot.keys) || record.snapshot.keys.length > MAX_ATTESTATION_TRUST_KEYS
      || !Array.isArray(record.snapshot.history) || record.snapshot.history.length > MAX_ATTESTATION_TRUST_HISTORY
      || record.snapshot.revision !== record.snapshot.history.length
      || !isDigest(record.snapshot.bootstrapDigest) || record.digest !== trustSnapshotDigest(record.snapshot)) fail();
    const ids = new Set();
    for (const entry of record.snapshot.keys) {
      if (!entry || typeof entry.keyId !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(entry.keyId) || ids.has(entry.keyId)
        || typeof entry.publicKeyPem !== "string" || !isDigest(entry.fingerprint)
        || !["active", "revoked"].includes(entry.status)
        || !Number.isSafeInteger(entry.addedAtRevision) || entry.addedAtRevision < 0 || entry.addedAtRevision > record.snapshot.revision
        || (entry.status === "active" && entry.revokedAtRevision !== null)
        || (entry.status === "revoked" && (!Number.isSafeInteger(entry.revokedAtRevision) || entry.revokedAtRevision <= entry.addedAtRevision
          || entry.revokedAtRevision > record.snapshot.revision))) fail();
      ids.add(entry.keyId);
      let key;
      try { key = parseEd25519PublicKey(entry.publicKeyPem); } catch { fail(); }
      if (keyFingerprint(key) !== entry.fingerprint) fail();
      trustedIntegrityAttestationKeys.set(entry.keyId, key);
    }
    return record.snapshot;
  }

  async function ensureAttestationTrustPolicy(ownerId) {
    assertOwner(ownerId);
    const id = attestationTrustPolicyId(ownerId);
    let record = await store.getEvidence(ownerId, id);
    if (record) return validateAttestationTrustPolicyRecord(record, ownerId);
    const entries = configuredTrustKeyEntries();
    const now = bounded(clock(), 64);
    const snapshot = { schemaVersion: 1, ownerId, revision: 0, bootstrapDigest: sha256(canonical(entries)),
      keys: entries.map(entry => ({ ...entry, status: "active", addedAtRevision: 0, revokedAtRevision: null })), history: [] };
    const candidate = { id, ownerId, kind: "recovery-reconciliation-attestation-trust-policy", createdAt: now,
      digest: trustSnapshotDigest(snapshot), snapshot, provenance: { source: "recovery-audit-planning", schemaVersion: 1, ownerScoped: true } };
    try {
      await store.putEvidence(ownerId, candidate, { overwrite: false });
      record = await store.getEvidence(ownerId, id) || candidate;
    } catch {
      record = await store.getEvidence(ownerId, id);
      if (!record) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_POLICY_UNAVAILABLE", "Trust policy tidak dapat diinisialisasi", 503);
    }
    return validateAttestationTrustPolicyRecord(record, ownerId);
  }

  function activeTrustKey(snapshot, keyId) {
    return snapshot.keys.find(entry => entry.keyId === keyId && entry.status === "active") || null;
  }

  function trustQuorum(snapshot) {
    const activeCount = snapshot.keys.filter(entry => entry.status === "active").length;
    return activeCount ? Math.floor(activeCount / 2) + 1 : 0;
  }

  function trustEventHash(event) {
    const { eventHash, ...unsigned } = event;
    return sha256(canonical(unsigned));
  }

  function trustGenesis(ownerId) {
    return sha256(canonical({ domain: "agentic-v4-attestation-trust-genesis", ownerId }));
  }

  function trustAnchorId(ownerId, challengeId) {
    return `ledger-integrity-trust-anchor-enrollment-${sha256(canonical({ domain: "agentic-v4-trust-anchor-enrollment", ownerId, challengeId })).slice(0, 32)}`;
  }

  function trustTransitionJournalId(ownerId, transitionId) {
    return `ledger-integrity-trust-transition-journal-${sha256(canonical({ domain: "agentic-v4-trust-transition-journal", ownerId, transitionId })).slice(0, 32)}`;
  }

  function trustTransitionJournalEventHash(event) {
    const { eventHash, ...unsigned } = event || {};
    return sha256(canonical(unsigned));
  }

  function trustTransitionJournalGenesis(ownerId, id) {
    return sha256(canonical({ domain: "agentic-v4-trust-transition-journal-genesis", ownerId, id }));
  }

  function validateTrustTransitionJournal(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_INVALID", "Cross-store trust transition journal tidak valid", 409); };
    const snapshot = record?.snapshot;
    const statuses = new Set(["prepared", "local_committed", "challenge_applied", "anchor_pending", "completed", "blocked"]);
    if (!record || record.kind !== "recovery-reconciliation-attestation-trust-transition-journal" || record.ownerId !== ownerId
      || record.id !== trustTransitionJournalId(ownerId, snapshot?.transitionId) || !snapshot || snapshot.schemaVersion !== 1
      || snapshot.ownerId !== ownerId || typeof snapshot.transitionId !== "string" || snapshot.transitionId.length > MAX_ID
      || typeof snapshot.challengeId !== "string" || snapshot.challengeId.length > MAX_ID
      || !["rotate", "revoke"].includes(snapshot.action) || typeof snapshot.keyId !== "string" || snapshot.keyId.length > 80
      || !isDigest(snapshot.payloadDigest) || !isDigest(snapshot.expectedPolicyDigest)
      || !Number.isSafeInteger(snapshot.expectedRevision) || snapshot.expectedRevision < 0
      || !statuses.has(snapshot.status) || !Number.isFinite(Date.parse(snapshot.createdAt)) || !Number.isFinite(Date.parse(snapshot.updatedAt))
      || !Array.isArray(snapshot.history) || snapshot.history.length < 1 || snapshot.history.length > 12
      || record.digest !== trustSnapshotDigest(snapshot)) fail();
    let previousHash = trustTransitionJournalGenesis(ownerId, record.id);
    for (let index = 0; index < snapshot.history.length; index += 1) {
      const event = snapshot.history[index];
      if (!event || event.sequence !== index + 1 || event.previousHash !== previousHash
        || !statuses.has(event.status) || !Number.isFinite(Date.parse(event.at)) || !event.details || typeof event.details !== "object"
        || Array.isArray(event.details) || event.eventHash !== trustTransitionJournalEventHash(event)) fail();
      previousHash = event.eventHash;
    }
    if (snapshot.history.at(-1)?.status !== snapshot.status) fail();
    return snapshot;
  }

  function trustAnchorDigest(anchor) {
    const { digest, ...unsigned } = anchor || {};
    return sha256(canonical(unsigned));
  }

  function trustStateAtRevision(snapshot, revision) {
    if (!Number.isSafeInteger(revision) || revision < 0 || revision > snapshot.revision) return null;
    const bootstrapKeys = snapshot.keys.filter(item => item.addedAtRevision === 0)
      .map(item => ({ keyId: item.keyId, publicKeyPem: item.publicKeyPem, fingerprint: item.fingerprint }))
      .sort((a, b) => a.keyId.localeCompare(b.keyId));
    const keys = bootstrapKeys.map(item => ({ ...item, status: "active", addedAtRevision: 0, revokedAtRevision: null }));
    const history = snapshot.history.slice(0, revision).map(item => structuredClone(item));
    for (let index = 0; index < history.length; index += 1) {
      const event = history[index];
      const payload = event?.payload;
      if (payload?.action === "rotate") {
        if (keys.some(item => item.keyId === payload.keyId)) return null;
        keys.push({ keyId: payload.keyId, publicKeyPem: payload.publicKeyPem, fingerprint: payload.keyFingerprint,
          status: "active", addedAtRevision: index + 1, revokedAtRevision: null });
      } else if (payload?.action === "revoke") {
        const target = keys.find(item => item.keyId === payload.keyId && item.status === "active");
        if (!target) return null;
        target.status = "revoked";
        target.revokedAtRevision = index + 1;
      } else return null;
    }
    const state = { schemaVersion: 1, ownerId: snapshot.ownerId, revision,
      bootstrapDigest: snapshot.bootstrapDigest, keys, history };
    return { revision, trustDigest: trustSnapshotDigest(state), headHash: history.at(-1)?.eventHash || trustGenesis(snapshot.ownerId),
      bootstrapDigest: snapshot.bootstrapDigest };
  }

  function validateTrustAnchor(anchor, ownerId) {
    if (!anchor || typeof anchor !== "object" || anchor.schemaVersion !== 1 || anchor.ownerId !== ownerId
      || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
      || !Number.isSafeInteger(anchor.revision) || anchor.revision < 0
      || !isDigest(anchor.trustDigest) || !isDigest(anchor.headHash) || !isDigest(anchor.bootstrapDigest)
      || (anchor.previousAnchorDigest !== null && !isDigest(anchor.previousAnchorDigest))
      || ((anchor.anchorSequence === 1) !== (anchor.previousAnchorDigest === null))
      || !Number.isFinite(Date.parse(anchor.anchoredAt))
      || !["genesis", "trust_transition", "reconciliation", "quorum_enrollment", "cross_store_recovery"].includes(anchor.reason)
      || (anchor.enrollmentChallengeId != null && (typeof anchor.enrollmentChallengeId !== "string" || anchor.enrollmentChallengeId.length > MAX_ID))
      || anchor.digest !== trustAnchorDigest(anchor)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_INVALID", "External trust anchor tidak valid atau digest-nya berubah", 409);
    }
    return anchor;
  }

  function makeTrustAnchor(ownerId, snapshot, previous, reason, enrollmentChallengeId = null) {
    const anchorState = trustStateAtRevision(snapshot, snapshot.revision);
    if (!anchorState) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_HISTORY_INVALID", "Trust history tidak dapat diproyeksikan ke external anchor", 409);
    const unsigned = { schemaVersion: 1, ownerId, anchorSequence: previous ? previous.anchorSequence + 1 : 1,
      revision: snapshot.revision, trustDigest: anchorState.trustDigest, headHash: anchorState.headHash,
      bootstrapDigest: snapshot.bootstrapDigest, previousAnchorDigest: previous?.digest || null,
      anchoredAt: bounded(clock(), 64), reason, enrollmentChallengeId: enrollmentChallengeId || null };
    if (!Number.isFinite(Date.parse(unsigned.anchoredAt))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock external trust anchor tidak valid", 500);
    return { ...unsigned, digest: trustAnchorDigest(unsigned) };
  }

  function anchorFailureCode(status) {
    if (status === "rollback_detected") return "RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ROLLBACK_DETECTED";
    if (status === "mismatch" || status === "invalid") return "RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_MISMATCH";
    if (status === "missing") return "RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_MISSING";
    if (status === "behind_registry") return "RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_BEHIND_REGISTRY";
    return "RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_UNAVAILABLE";
  }

  async function inspectExternalTrustAnchor(ownerId, snapshot, { initializeGenesis = false } = {}) {
    if (!attestationTrustAnchor) return { status: "not_configured", configured: false, rollbackProtectionEnabled: false,
      ownerId, localRevision: snapshot.revision, anchorRevision: null, mutationAllowed: true, readOnly: true };
    let anchor;
    try { anchor = await attestationTrustAnchor.read(ownerId); }
    catch (error) { return { status: "unavailable", configured: true, rollbackProtectionEnabled: true, ownerId,
      localRevision: snapshot.revision, anchorRevision: null, mutationAllowed: false, errorCode: bounded(error?.code || "EXTERNAL_ANCHOR_READ_FAILED", 80), readOnly: true }; }
    if (anchor == null && initializeGenesis && snapshot.revision === 0 && snapshot.history.length === 0) {
      try {
        const candidate = makeTrustAnchor(ownerId, snapshot, null, "genesis");
        const outcome = await attestationTrustAnchor.compareAndSet(ownerId, null, candidate);
        anchor = outcome === true || outcome?.applied === true
          ? await attestationTrustAnchor.read(ownerId)
          : outcome?.anchor ?? await attestationTrustAnchor.read(ownerId);
      } catch (error) {
        return { status: "unavailable", configured: true, rollbackProtectionEnabled: true, ownerId,
          localRevision: snapshot.revision, anchorRevision: null, mutationAllowed: false,
          errorCode: bounded(error?.code || "EXTERNAL_ANCHOR_WRITE_FAILED", 80), readOnly: true };
      }
    }
    if (anchor == null) return { status: "missing", configured: true, rollbackProtectionEnabled: true, ownerId,
      localRevision: snapshot.revision, anchorRevision: null, mutationAllowed: false, readOnly: true };
    try { validateTrustAnchor(anchor, ownerId); }
    catch (error) { return { status: "invalid", configured: true, rollbackProtectionEnabled: true, ownerId,
      localRevision: snapshot.revision, anchorRevision: Number.isSafeInteger(anchor?.revision) ? anchor.revision : null,
      mutationAllowed: false, errorCode: bounded(error?.code || "EXTERNAL_ANCHOR_INVALID", 80), readOnly: true }; }
    if (anchor.bootstrapDigest !== snapshot.bootstrapDigest) return { status: "mismatch", configured: true, rollbackProtectionEnabled: true,
      ownerId, localRevision: snapshot.revision, anchorRevision: anchor.revision, anchorDigest: anchor.digest,
      mutationAllowed: false, readOnly: true };
    if (anchor.revision > snapshot.revision) return { status: "rollback_detected", configured: true, rollbackProtectionEnabled: true,
      ownerId, localRevision: snapshot.revision, anchorRevision: anchor.revision, anchorDigest: anchor.digest,
      mutationAllowed: false, readOnly: true };
    const stateAtAnchor = trustStateAtRevision(snapshot, anchor.revision);
    if (!stateAtAnchor || stateAtAnchor.trustDigest !== anchor.trustDigest || stateAtAnchor.headHash !== anchor.headHash
      || stateAtAnchor.bootstrapDigest !== anchor.bootstrapDigest) {
      return { status: "mismatch", configured: true, rollbackProtectionEnabled: true, ownerId,
        localRevision: snapshot.revision, anchorRevision: anchor.revision, anchorDigest: anchor.digest,
        mutationAllowed: false, readOnly: true };
    }
    if (anchor.revision < snapshot.revision) return { status: "behind_registry", configured: true, rollbackProtectionEnabled: true,
      ownerId, localRevision: snapshot.revision, anchorRevision: anchor.revision, anchorDigest: anchor.digest,
      mutationAllowed: false, readOnly: true };
    return { status: "anchored", configured: true, rollbackProtectionEnabled: true, ownerId,
      localRevision: snapshot.revision, anchorRevision: anchor.revision, anchorDigest: anchor.digest,
      anchorSequence: anchor.anchorSequence, mutationAllowed: true, readOnly: true };
  }

  async function assertExternalTrustAnchorCurrent(ownerId, snapshot, { initializeGenesis = true } = {}) {
    const status = await inspectExternalTrustAnchor(ownerId, snapshot, { initializeGenesis });
    if (status.status === "anchored" || status.status === "not_configured") return status;
    const code = anchorFailureCode(status.status);
    const message = status.status === "rollback_detected"
      ? "Trust registry lokal berada di revision yang lebih lama daripada external anchor; operasi trust diblokir"
      : status.status === "behind_registry"
        ? "External trust anchor tertinggal dari registry lokal; jalankan rekonsiliasi anchor setelah audit trust bersih"
        : status.status === "missing"
          ? "External trust anchor belum diinisialisasi; registry non-genesis memerlukan enrollment quorum eksplisit"
          : status.status === "mismatch" || status.status === "invalid"
            ? "External trust anchor tidak cocok dengan trust registry; pemulihan otomatis ditolak"
            : "External trust anchor tidak tersedia; operasi trust diblokir fail-closed";
    throw new AgenticError(code, message, status.status === "unavailable" ? 503 : 409, { anchorStatus: status.status,
      localRevision: status.localRevision, anchorRevision: status.anchorRevision, rollbackProtectionEnabled: status.rollbackProtectionEnabled });
  }

  async function advanceExternalTrustAnchor(ownerId, snapshot, reason = "trust_transition", enrollmentChallengeId = null) {
    if (!attestationTrustAnchor) return { status: "not_configured", configured: false, mutationAllowed: true, readOnly: true };
    const currentStatus = await inspectExternalTrustAnchor(ownerId, snapshot, { initializeGenesis: snapshot.revision === 0 && snapshot.history.length === 0 });
    if (currentStatus.status === "anchored" || currentStatus.status === "not_configured") return currentStatus;
    if (currentStatus.status !== "behind_registry" && !(currentStatus.status === "missing" && enrollmentChallengeId)) return currentStatus;
    let previous = null;
    try {
      previous = await attestationTrustAnchor.read(ownerId);
      if (previous != null) validateTrustAnchor(previous, ownerId);
      if (previous == null && !enrollmentChallengeId && !(snapshot.revision === 0 && snapshot.history.length === 0)) return currentStatus;
      if (previous != null) {
        const state = trustStateAtRevision(snapshot, previous.revision);
        if (!state || state.trustDigest !== previous.trustDigest || state.headHash !== previous.headHash
          || previous.revision >= snapshot.revision) return currentStatus;
      }
      const candidate = makeTrustAnchor(ownerId, snapshot, previous, reason, enrollmentChallengeId);
      const outcome = await attestationTrustAnchor.compareAndSet(ownerId, previous?.digest || null, candidate);
      const reread = await inspectExternalTrustAnchor(ownerId, snapshot);
      if (outcome === true || outcome?.applied === true) return reread;
      return reread;
    } catch (error) {
      return { status: "unavailable", configured: true, rollbackProtectionEnabled: true, ownerId,
        localRevision: snapshot.revision, anchorRevision: previous?.revision ?? null, mutationAllowed: false,
        errorCode: bounded(error?.code || "EXTERNAL_ANCHOR_ADVANCE_FAILED", 80), readOnly: true };
    }
  }

  async function createTrustTransitionJournal(ownerId, challengeRecordId, payload) {
    const id = trustTransitionJournalId(ownerId, payload.transitionId);
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      const snapshot = validateTrustTransitionJournal(existing, ownerId);
      if (snapshot.challengeId !== challengeRecordId || snapshot.payloadDigest !== sha256(canonical(payload))
        || snapshot.expectedRevision !== payload.policyRevision || snapshot.expectedPolicyDigest !== payload.policyDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_CONFLICT", "Journal transition sudah terikat pada intent berbeda", 409);
      }
      if (snapshot.status !== "prepared") {
        throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_RECOVERY_REQUIRED", "Trust transition memiliki hasil lintas-store yang belum dapat diulang; jalankan recovery journal", 409,
          { journalId: id, status: snapshot.status });
      }
      return existing;
    }
    const journals = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-attestation-trust-transition-journal");
    if (journals.length >= MAX_TRUST_TRANSITION_JOURNALS) throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_LIMIT", "Batas journal trust transition tercapai", 409);
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock trust transition journal tidak valid", 500);
    const details = { challengeId: challengeRecordId, action: payload.action, keyId: payload.keyId,
      expectedRevision: payload.policyRevision, expectedPolicyDigest: payload.policyDigest, payloadDigest: sha256(canonical(payload)) };
    const firstEvent = { sequence: 1, status: "prepared", at: now, previousHash: trustTransitionJournalGenesis(ownerId, id), details };
    firstEvent.eventHash = trustTransitionJournalEventHash(firstEvent);
    const snapshot = { schemaVersion: 1, ownerId, transitionId: payload.transitionId, challengeId: challengeRecordId,
      action: payload.action, keyId: payload.keyId, payloadDigest: details.payloadDigest,
      expectedRevision: payload.policyRevision, expectedPolicyDigest: payload.policyDigest,
      status: "prepared", createdAt: now, updatedAt: now, localRevision: null, localDigest: null,
      eventHash: null, anchorStatus: null, anchorDigest: null, resultCode: null, history: [firstEvent] };
    const record = { id, ownerId, kind: "recovery-reconciliation-attestation-trust-transition-journal", createdAt: now,
      digest: trustSnapshotDigest(snapshot), snapshot,
      provenance: { source: "recovery-audit-planning", schemaVersion: 1, ownerScoped: true, protocol: "external-anchor-cross-store-v1" } };
    try { await store.putEvidence(ownerId, record, { overwrite: false }); }
    catch (error) {
      const concurrent = await store.getEvidence(ownerId, id);
      if (!concurrent) throw error;
      const concurrentSnapshot = validateTrustTransitionJournal(concurrent, ownerId);
      if (concurrentSnapshot.payloadDigest !== details.payloadDigest || concurrentSnapshot.status !== "prepared") throw new AgenticError(
        "RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_CONFLICT", "Journal trust transition bersaing dengan intent lain", 409);
      return concurrent;
    }
    return record;
  }

  async function updateTrustTransitionJournal(ownerId, journalId, nextStatus, details = {}) {
    const allowed = {
      prepared: new Set(["local_committed", "blocked"]),
      local_committed: new Set(["challenge_applied", "anchor_pending", "completed", "blocked"]),
      challenge_applied: new Set(["anchor_pending", "completed", "blocked"]),
      anchor_pending: new Set(["anchor_pending", "completed", "blocked"]),
      completed: new Set(), blocked: new Set()
    };
    const allowedDetailKeys = new Set(["localRevision", "localDigest", "eventHash", "anchorStatus", "anchorDigest", "resultCode"]);
    const patch = {};
    for (const [key, value] of Object.entries(details || {})) {
      if (!allowedDetailKeys.has(key)) continue;
      if (key === "localRevision") patch[key] = Number.isSafeInteger(value) && value >= 0 ? value : null;
      else if (value == null) patch[key] = null;
      else patch[key] = bounded(value, key === "resultCode" ? 100 : 128);
    }
    return store.mutateEvidence(ownerId, journalId, current => {
      const snapshot = validateTrustTransitionJournal(current, ownerId);
      const changed = Object.entries(patch).some(([key, value]) => canonical(snapshot[key] ?? null) !== canonical(value));
      if (snapshot.status === nextStatus && !changed) return { write: false, result: structuredClone(snapshot) };
      if (snapshot.status === "completed") return { write: false, result: structuredClone(snapshot) };
      if (snapshot.status === "blocked") {
        if (nextStatus === "blocked") return { write: false, result: structuredClone(snapshot) };
        throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_TERMINAL", "Journal trust transition sudah terminal", 409);
      }
      if (!allowed[snapshot.status]) throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_TERMINAL", "Journal trust transition sudah terminal", 409);
      if (snapshot.status !== nextStatus && !allowed[snapshot.status].has(nextStatus)) {
        throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_TRANSITION_INVALID", "Perubahan fase journal trust transition tidak diizinkan", 409,
          { from: snapshot.status, to: nextStatus });
      }
      if (snapshot.history.length >= 12) throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_JOURNAL_HISTORY_LIMIT", "Riwayat journal trust transition penuh", 409);
      const now = bounded(clock(), 64);
      if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock trust transition journal tidak valid", 500);
      const unsigned = { sequence: snapshot.history.length + 1, status: nextStatus, at: now,
        previousHash: snapshot.history.at(-1).eventHash, details: Object.fromEntries(Object.entries(patch)) };
      const event = { ...unsigned, eventHash: trustTransitionJournalEventHash(unsigned) };
      const updated = { ...snapshot, ...patch, status: nextStatus, updatedAt: now, history: [...snapshot.history, event] };
      const value = { ...current, snapshot: updated, digest: trustSnapshotDigest(updated) };
      return { value, result: structuredClone(updated) };
    });
  }

  async function markTrustTransitionChallengeApplied(ownerId, journalSnapshot, transitionEvent) {
    const resultRevision = transitionEvent.revision;
    const appliedAt = bounded(clock(), 64);
    return store.mutateEvidence(ownerId, journalSnapshot.challengeId, current => {
      if (!current || current.kind !== "recovery-reconciliation-attestation-trust-challenge" || current.ownerId !== ownerId
        || !current.snapshot || current.digest !== trustSnapshotDigest(current.snapshot)
        || current.snapshot.payload?.transitionId !== journalSnapshot.transitionId
        || sha256(canonical(current.snapshot.payload)) !== journalSnapshot.payloadDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_CHALLENGE_BINDING_FAILED", "Challenge tidak cocok dengan transition journal", 409);
      }
      if (current.snapshot.status === "applied") {
        if (current.snapshot.resultRevision !== resultRevision || current.snapshot.result?.eventHash !== transitionEvent.eventHash) {
          throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_CHALLENGE_RESULT_MISMATCH", "Hasil challenge berbeda dari trust history", 409);
        }
        return { write: false, result: current.snapshot };
      }
      if (current.snapshot.status !== "issued") throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_TRANSITION_CHALLENGE_NOT_RECOVERABLE", "Challenge tidak berada pada status yang dapat direkonsiliasi", 409);
      const next = { ...current.snapshot, status: "applied", appliedAt, resultRevision,
        result: { action: journalSnapshot.action, keyId: journalSnapshot.keyId, eventHash: transitionEvent.eventHash } };
      return { value: { ...current, snapshot: next, digest: trustSnapshotDigest(next) }, result: next };
    });
  }

  function trustTransitionJournalSummary(record, snapshot) {
    return { id: record.id, transitionId: snapshot.transitionId, challengeId: snapshot.challengeId,
      action: snapshot.action, keyId: snapshot.keyId, status: snapshot.status, createdAt: snapshot.createdAt,
      updatedAt: snapshot.updatedAt, expectedRevision: snapshot.expectedRevision, localRevision: snapshot.localRevision,
      anchorStatus: snapshot.anchorStatus, anchorDigest: snapshot.anchorDigest, resultCode: snapshot.resultCode,
      eventCount: snapshot.history.length };
  }

  async function getMutationOutcomeLedgerAttestationTrustCrossStoreRecoveryStatus(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, MAX_TRUST_TRANSITION_RECOVERY_LIMIT);
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-attestation-trust-transition-journal")
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || String(a.id).localeCompare(String(b.id)));
    const items = [], findings = [];
    const counts = { prepared: 0, local_committed: 0, challenge_applied: 0, anchor_pending: 0, completed: 0, blocked: 0, invalid: 0 };
    for (const record of records.slice(0, limit)) {
      try {
        const snapshot = validateTrustTransitionJournal(record, ownerId);
        counts[snapshot.status] = (counts[snapshot.status] || 0) + 1;
        items.push(trustTransitionJournalSummary(record, snapshot));
      } catch (error) {
        counts.invalid += 1;
        findings.push({ code: "TRUST_TRANSITION_JOURNAL_INVALID", id: bounded(record?.id), errorCode: bounded(error?.code || "JOURNAL_INVALID", 100) });
      }
    }
    const pending = counts.prepared + counts.local_committed + counts.challenge_applied + counts.anchor_pending;
    return { status: findings.length || counts.blocked || counts.invalid ? "degraded" : pending ? "recovery_required" : records.length ? "healthy" : "empty",
      items, counts, total: records.length, limit, truncated: records.length > limit, pendingCount: pending,
      findings: findings.slice(0, 100), mutationAllowed: false, readOnly: true };
  }

  async function recoverMutationOutcomeLedgerAttestationTrustCrossStoreTransitions(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, MAX_TRUST_TRANSITION_RECOVERY_LIMIT);
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-attestation-trust-transition-journal")
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)) || String(a.id).localeCompare(String(b.id)));
    const outcomes = [];
    const selected = records.slice(0, limit);
    let recovered = 0, pending = 0, blocked = 0, skipped = 0, scanned = 0;
    for (const record of selected) {
      scanned += 1;
      let journal;
      try { journal = validateTrustTransitionJournal(record, ownerId); }
      catch (error) {
        blocked += 1;
        outcomes.push({ id: bounded(record?.id), status: "blocked", code: bounded(error?.code || "JOURNAL_INVALID", 100) });
        continue;
      }
      if (["completed", "blocked"].includes(journal.status)) { skipped += 1; continue; }
      const policy = await ensureAttestationTrustPolicy(ownerId);
      const matchingEvents = policy.history.filter(event => event?.payload?.transitionId === journal.transitionId);
      if (matchingEvents.length === 0) {
        if (journal.status === "prepared") {
          pending += 1;
          const ageMs = Math.max(0, Date.parse(bounded(clock(), 64)) - Date.parse(journal.createdAt));
          outcomes.push({ id: record.id, status: "awaiting_local_commit", stale: ageMs >= boundedInteger(options.staleAfterMs, DEFAULT_TRUST_TRANSITION_STALE_MS, 1000, 86_400_000),
            ageMs: Number.isFinite(ageMs) ? ageMs : null, automaticAbortAllowed: false });
        } else {
          await updateTrustTransitionJournal(ownerId, record.id, "blocked", { resultCode: "LOCAL_TRANSITION_EVENT_MISSING" });
          blocked += 1;
          outcomes.push({ id: record.id, status: "blocked", code: "LOCAL_TRANSITION_EVENT_MISSING" });
        }
        continue;
      }
      const transitionEvent = matchingEvents[0];
      if (matchingEvents.length !== 1 || sha256(canonical(transitionEvent.payload)) !== journal.payloadDigest
        || transitionEvent.payload?.action !== journal.action || transitionEvent.payload?.keyId !== journal.keyId
        || transitionEvent.revision !== journal.expectedRevision + 1) {
        if (journal.status !== "blocked") await updateTrustTransitionJournal(ownerId, record.id, "blocked", { resultCode: "LOCAL_TRANSITION_BINDING_MISMATCH" });
        blocked += 1;
        outcomes.push({ id: record.id, status: "blocked", code: "LOCAL_TRANSITION_BINDING_MISMATCH" });
        continue;
      }
      const trustAudit = await auditMutationOutcomeLedgerAttestationTrust(ownerId, { limit: 200, includeExternalAnchor: false });
      if (trustAudit.truncated || trustAudit.findings.some(item => item.severity === "error")) {
        if (journal.status !== "blocked") await updateTrustTransitionJournal(ownerId, record.id, "blocked", { resultCode: "TRUST_REGISTRY_AUDIT_UNHEALTHY" });
        blocked += 1;
        outcomes.push({ id: record.id, status: "blocked", code: "TRUST_REGISTRY_AUDIT_UNHEALTHY" });
        continue;
      }
      if (journal.status === "prepared") journal = await updateTrustTransitionJournal(ownerId, record.id, "local_committed", {
        localRevision: transitionEvent.revision, localDigest: trustSnapshotDigest(policy), eventHash: transitionEvent.eventHash
      });
      let challengeError = null;
      try {
        await markTrustTransitionChallengeApplied(ownerId, journal, transitionEvent);
        if (["local_committed"].includes(journal.status)) journal = await updateTrustTransitionJournal(ownerId, record.id, "challenge_applied", {
          localRevision: transitionEvent.revision, localDigest: trustSnapshotDigest(policy), eventHash: transitionEvent.eventHash
        });
      } catch (error) { challengeError = bounded(error?.code || "CHALLENGE_RECONCILIATION_FAILED", 100); }
      let anchorStatus = await inspectExternalTrustAnchor(ownerId, policy, { initializeGenesis: policy.revision === 0 && policy.history.length === 0 });
      if (anchorStatus.status === "behind_registry") anchorStatus = await advanceExternalTrustAnchor(ownerId, policy, "cross_store_recovery");
      const anchorDetails = { anchorStatus: anchorStatus.status, anchorDigest: anchorStatus.anchorDigest || null,
        localRevision: policy.revision, localDigest: trustSnapshotDigest(policy), eventHash: transitionEvent.eventHash };
      if (challengeError) {
        if (journal.status !== "blocked") await updateTrustTransitionJournal(ownerId, record.id, "blocked", { ...anchorDetails, resultCode: challengeError });
        blocked += 1;
        outcomes.push({ id: record.id, status: "blocked", code: challengeError, anchorStatus: anchorStatus.status });
      } else if (["anchored", "not_configured"].includes(anchorStatus.status)) {
        journal = await updateTrustTransitionJournal(ownerId, record.id, "completed", { ...anchorDetails, resultCode: null });
        recovered += 1;
        outcomes.push({ id: record.id, status: "completed", anchorStatus: anchorStatus.status, localRevision: policy.revision });
      } else if (["behind_registry", "unavailable", "missing"].includes(anchorStatus.status)) {
        journal = await updateTrustTransitionJournal(ownerId, record.id, "anchor_pending", { ...anchorDetails,
          resultCode: anchorStatus.status === "missing" ? "ANCHOR_ENROLLMENT_REQUIRED" : "ANCHOR_NOT_CURRENT" });
        if (journal.status === "completed") {
          recovered += 1;
          outcomes.push({ id: record.id, status: "completed", anchorStatus: journal.anchorStatus, localRevision: policy.revision });
        } else {
          pending += 1;
          outcomes.push({ id: record.id, status: "anchor_pending", anchorStatus: anchorStatus.status, localRevision: policy.revision });
        }
      } else {
        journal = await updateTrustTransitionJournal(ownerId, record.id, "blocked", { ...anchorDetails, resultCode: `ANCHOR_${String(anchorStatus.status).toUpperCase()}` });
        blocked += 1;
        outcomes.push({ id: record.id, status: "blocked", anchorStatus: anchorStatus.status, localRevision: policy.revision });
      }
    }
    const truncated = records.length > limit;
    const status = blocked ? "degraded" : pending ? "pending" : truncated ? "partial" : recovered ? "recovered" : "no_op";
    return { status, scanned, total: records.length, truncated, recovered, pending, blocked, skipped, outcomes: outcomes.slice(0, limit),
      automaticLocalRollbackAllowed: false, automaticTransitionReplayAllowed: false, readOnly: false };
  }

  function trustAnchorHealthTelemetryId(ownerId) {
    return `ledger-integrity-trust-anchor-health-${sha256(canonical({ domain: "agentic-v4-trust-anchor-health", ownerId })).slice(0, 32)}`;
  }

  function trustAnchorHealthGenesis(ownerId, id) {
    return sha256(canonical({ domain: "agentic-v4-trust-anchor-health-genesis", ownerId, id }));
  }

  function trustAnchorHealthSampleHash(sample) {
    const { sampleHash, ...unsigned } = sample || {};
    return sha256(canonical(unsigned));
  }

  function validateTrustAnchorHealthTelemetry(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_RECONCILIATION_TRUST_ANCHOR_HEALTH_TELEMETRY_INVALID", "Riwayat telemetry external anchor tidak valid", 409); };
    const snapshot = record?.snapshot;
    if (!record || record.kind !== "recovery-reconciliation-trust-anchor-health-telemetry" || record.ownerId !== ownerId
      || record.id !== trustAnchorHealthTelemetryId(ownerId) || !snapshot || snapshot.schemaVersion !== 1
      || snapshot.ownerId !== ownerId || !Number.isSafeInteger(snapshot.baseSequence) || snapshot.baseSequence < 0
      || !isDigest(snapshot.baseHash) || !Number.isSafeInteger(snapshot.sequence) || snapshot.sequence < snapshot.baseSequence
      || !Array.isArray(snapshot.samples) || snapshot.samples.length > MAX_TRUST_ANCHOR_HEALTH_SAMPLES
      || snapshot.sequence !== snapshot.baseSequence + snapshot.samples.length || record.digest !== trustSnapshotDigest(snapshot)
      || (snapshot.baseSequence === 0 && snapshot.baseHash !== trustAnchorHealthGenesis(ownerId, record.id))) fail();
    let previousHash = snapshot.baseHash;
    let sequence = snapshot.baseSequence;
    for (const sample of snapshot.samples) {
      sequence += 1;
      if (!sample || sample.sequence !== sequence || sample.previousHash !== previousHash || !isDigest(sample.sampleHash)
        || sample.sampleHash !== trustAnchorHealthSampleHash(sample) || !Number.isFinite(Date.parse(sample.sampledAt))
        || !["healthy", "degraded", "unavailable", "not_configured"].includes(sample.status)
        || !["anchored", "not_configured", "missing", "behind_registry", "rollback_detected", "mismatch", "invalid", "unavailable"].includes(sample.anchorStatus)
        || !["healthy", "degraded", "unhealthy", "empty", "recovery_required", "partial", "unavailable"].includes(sample.journalAuditStatus)
        || !["healthy", "degraded", "unhealthy", "unavailable"].includes(sample.trustAuditStatus)
        || !Number.isSafeInteger(sample.latencyMs) || sample.latencyMs < 0 || sample.latencyMs > 300_000
        || !Number.isSafeInteger(sample.pendingCount) || sample.pendingCount < 0
        || typeof sample.providerConfigured !== "boolean") fail();
      previousHash = sample.sampleHash;
    }
    return snapshot;
  }

  async function appendTrustAnchorHealthSample(ownerId, sampleInput) {
    const id = trustAnchorHealthTelemetryId(ownerId);
    const genesis = trustAnchorHealthGenesis(ownerId, id);
    return store.mutateEvidence(ownerId, id, current => {
      let snapshot;
      if (current) snapshot = validateTrustAnchorHealthTelemetry(current, ownerId);
      else snapshot = { schemaVersion: 1, ownerId, baseSequence: 0, baseHash: genesis, sequence: 0, samples: [] };
      const sequence = snapshot.sequence + 1;
      const unsigned = { ...sampleInput, sequence, previousHash: snapshot.samples.at(-1)?.sampleHash || snapshot.baseHash };
      const sample = { ...unsigned, sampleHash: trustAnchorHealthSampleHash(unsigned) };
      let samples = [...snapshot.samples, sample];
      let baseSequence = snapshot.baseSequence, baseHash = snapshot.baseHash;
      if (samples.length > MAX_TRUST_ANCHOR_HEALTH_SAMPLES) {
        const removed = samples.shift();
        baseSequence = removed.sequence;
        baseHash = removed.sampleHash;
      }
      const updated = { schemaVersion: 1, ownerId, baseSequence, baseHash, sequence, samples };
      const value = { id, ownerId, kind: "recovery-reconciliation-trust-anchor-health-telemetry",
        createdAt: current?.createdAt || bounded(sample.sampledAt, 64), digest: trustSnapshotDigest(updated), snapshot: updated,
        provenance: { source: "recovery-audit-planning", schemaVersion: 1, ownerScoped: true, appendOnlySemantics: true } };
      return { value, result: structuredClone(sample) };
    });
  }

  async function auditMutationOutcomeLedgerAttestationTrustCrossStoreJournal(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 100, 1, MAX_CROSS_STORE_AUDIT_LIMIT);
    const all = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-attestation-trust-transition-journal")
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)) || String(a.id).localeCompare(String(b.id)));
    const selected = all.slice(0, limit);
    const findings = [];
    const counts = { prepared: 0, local_committed: 0, challenge_applied: 0, anchor_pending: 0, completed: 0, blocked: 0, invalid: 0 };
    let policyRecord = null, policy = null, trustAudit = { status: "unavailable", findings: [], truncated: true };
    try {
      policyRecord = await store.getEvidence(ownerId, attestationTrustPolicyId(ownerId));
      if (policyRecord) {
        policy = validateAttestationTrustPolicyRecord(policyRecord, ownerId);
        trustAudit = await auditMutationOutcomeLedgerAttestationTrust(ownerId, { limit: 200, includeExternalAnchor: false });
      } else if (selected.length) throw new Error("policy_missing");
    } catch (error) {
      findings.push({ code: "CROSS_STORE_TRUST_POLICY_UNAVAILABLE_OR_INVALID", severity: "error", errorCode: bounded(error?.code || "TRUST_POLICY_INVALID", 100) });
    }
    const eventIndex = new Map();
    if (policy) {
      for (const event of policy.history) {
        const transitionId = event?.payload?.transitionId;
        if (typeof transitionId !== "string") continue;
        if (!eventIndex.has(transitionId)) eventIndex.set(transitionId, []);
        eventIndex.get(transitionId).push(event);
      }
    }
    let oldestPendingAt = null, pendingCount = 0;
    for (const record of selected) {
      let journal;
      try { journal = validateTrustTransitionJournal(record, ownerId); }
      catch (error) {
        counts.invalid += 1;
        findings.push({ code: "CROSS_STORE_JOURNAL_INTEGRITY_FAILED", severity: "error", recordId: bounded(record?.id), errorCode: bounded(error?.code || "JOURNAL_INVALID", 100) });
        continue;
      }
      counts[journal.status] = (counts[journal.status] || 0) + 1;
      if (journal.status === "blocked") findings.push({ code: "CROSS_STORE_TRANSITION_BLOCKED", severity: "error", recordId: record.id, transitionId: journal.transitionId, resultCode: journal.resultCode || null });
      const events = eventIndex.get(journal.transitionId) || [];
      if (journal.status === "prepared" && events.length === 0) {
        pendingCount += 1;
        oldestPendingAt = !oldestPendingAt || Date.parse(journal.createdAt) < Date.parse(oldestPendingAt) ? journal.createdAt : oldestPendingAt;
        findings.push({ code: "CROSS_STORE_TRANSITION_AWAITING_LOCAL_COMMIT", severity: "warning", recordId: record.id, transitionId: journal.transitionId });
      } else if (journal.status === "prepared" && events.length === 1) {
        pendingCount += 1;
        oldestPendingAt = !oldestPendingAt || Date.parse(journal.createdAt) < Date.parse(oldestPendingAt) ? journal.createdAt : oldestPendingAt;
        findings.push({ code: "CROSS_STORE_JOURNAL_PHASE_LAGS_LOCAL_COMMIT", severity: "warning", recordId: record.id, transitionId: journal.transitionId });
      } else if (events.length !== 1) {
        findings.push({ code: "CROSS_STORE_LOCAL_EVENT_CARDINALITY_MISMATCH", severity: "error", recordId: record.id, transitionId: journal.transitionId, observed: events.length });
      } else {
        const event = events[0];
        if (sha256(canonical(event.payload)) !== journal.payloadDigest || event.payload?.action !== journal.action
          || event.payload?.keyId !== journal.keyId || event.revision !== journal.expectedRevision + 1
          || !isDigest(event.eventHash)) {
          findings.push({ code: "CROSS_STORE_LOCAL_EVENT_BINDING_MISMATCH", severity: "error", recordId: record.id, transitionId: journal.transitionId });
        }
      }
      const challenge = await store.getEvidence(ownerId, journal.challengeId);
      if (!challenge || challenge.kind !== "recovery-reconciliation-attestation-trust-challenge" || challenge.ownerId !== ownerId
        || !challenge.snapshot || challenge.digest !== trustSnapshotDigest(challenge.snapshot)
        || challenge.snapshot.payload?.transitionId !== journal.transitionId
        || sha256(canonical(challenge.snapshot.payload)) !== journal.payloadDigest) {
        findings.push({ code: "CROSS_STORE_CHALLENGE_BINDING_MISMATCH", severity: "error", recordId: record.id, transitionId: journal.transitionId });
      } else if (["challenge_applied", "anchor_pending", "completed"].includes(journal.status) && challenge.snapshot.status !== "applied") {
        findings.push({ code: "CROSS_STORE_CHALLENGE_STATUS_MISMATCH", severity: "error", recordId: record.id, transitionId: journal.transitionId });
      } else if (["local_committed"].includes(journal.status) && challenge.snapshot.status !== "applied") {
        oldestPendingAt = !oldestPendingAt || Date.parse(journal.createdAt) < Date.parse(oldestPendingAt) ? journal.createdAt : oldestPendingAt;
        findings.push({ code: "CROSS_STORE_CHALLENGE_RECONCILIATION_PENDING", severity: "warning", recordId: record.id, transitionId: journal.transitionId });
      }
      if (["local_committed", "challenge_applied", "anchor_pending"].includes(journal.status)) {
        pendingCount += 1;
        oldestPendingAt = !oldestPendingAt || Date.parse(journal.createdAt) < Date.parse(oldestPendingAt) ? journal.createdAt : oldestPendingAt;
      }
    }
    if (trustAudit.status === "unhealthy" || trustAudit.truncated) {
      // Trust-audit findings are summarized to avoid duplicating sensitive key material.
      findings.push({ code: "CROSS_STORE_TRUST_AUDIT_NOT_CLEAN", severity: "error", totalFindings: trustAudit.totalFindings ?? null, truncated: Boolean(trustAudit.truncated) });
    } else if (trustAudit.status === "degraded") {
      findings.push({ code: "CROSS_STORE_TRUST_AUDIT_DEGRADED", severity: "warning", totalFindings: trustAudit.totalFindings ?? null });
    }
    const truncated = all.length > selected.length;
    if (truncated) findings.push({ code: "CROSS_STORE_JOURNAL_AUDIT_TRUNCATED", severity: "error", total: all.length, checked: selected.length });
    let anchorStatus = { status: policy ? (attestationTrustAnchor ? "unavailable" : "not_configured") : "not_checked",
      configured: Boolean(attestationTrustAnchor), mutationAllowed: !attestationTrustAnchor, readOnly: true };
    if (policy) anchorStatus = await inspectExternalTrustAnchor(ownerId, policy);
    if (policy && anchorStatus.status !== "anchored" && anchorStatus.status !== "not_configured") {
      findings.push({ code: `CROSS_STORE_EXTERNAL_ANCHOR_${String(anchorStatus.status).toUpperCase()}`, severity: "error", anchorStatus: anchorStatus.status,
        localRevision: anchorStatus.localRevision ?? null, anchorRevision: anchorStatus.anchorRevision ?? null });
    }
    const hasError = findings.some(item => item.severity === "error");
    const hasWarning = findings.some(item => item.severity === "warning");
    const status = hasError ? "unhealthy" : pendingCount ? "recovery_required" : hasWarning ? "degraded" : all.length ? "healthy" : "empty";
    return { status, ownerId, checked: selected.length, total: all.length, truncated, counts, pendingCount,
      oldestPendingAt, trustAuditStatus: trustAudit.status, anchorStatus: anchorStatus.status,
      findings: findings.slice(0, boundedInteger(options.findingLimit, 100, 1, 200)), totalFindings: findings.length,
      findingsTruncated: findings.length > boundedInteger(options.findingLimit, 100, 1, 200), mutationAllowed: false,
      automaticRepairAllowed: false, readOnly: true };
  }

  async function getMutationOutcomeLedgerAttestationTrustAnchorHealth(ownerId, options = {}) {
    assertOwner(ownerId);
    const started = performance.now();
    let anchorStatus, trustAudit, journalAudit, sample = null;
    try {
      const policy = await ensureAttestationTrustPolicy(ownerId);
      anchorStatus = await inspectExternalTrustAnchor(ownerId, policy);
      trustAudit = await auditMutationOutcomeLedgerAttestationTrust(ownerId, { limit: 100, includeExternalAnchor: false });
      journalAudit = await auditMutationOutcomeLedgerAttestationTrustCrossStoreJournal(ownerId, { limit: boundedInteger(options.auditLimit, 100, 1, MAX_CROSS_STORE_AUDIT_LIMIT) });
    } catch (error) {
      const elapsed = Math.max(0, Math.min(300_000, Math.round(performance.now() - started)));
      const fallbackStatus = attestationTrustAnchor ? "unavailable" : "not_configured";
      const sampledAt = bounded(clock(), 64);
      const status = fallbackStatus === "unavailable" ? "unavailable" : "degraded";
      sample = { sampledAt, status, providerConfigured: Boolean(attestationTrustAnchor), anchorStatus: fallbackStatus,
        localRevision: null, anchorRevision: null, latencyMs: elapsed, journalAuditStatus: "unavailable", trustAuditStatus: "unavailable",
        pendingCount: 0, errorCode: bounded(error?.code || "HEALTH_CHECK_FAILED", 100) };
      let telemetryPersistenceStatus = "stored";
      try { await appendTrustAnchorHealthSample(ownerId, sample); } catch (telemetryError) { telemetryPersistenceStatus = "invalid_or_unavailable"; sample.errorCode = bounded(telemetryError?.code || "TELEMETRY_WRITE_FAILED", 100); }
      return { ...sample, configured: Boolean(attestationTrustAnchor), rollbackProtectionEnabled: Boolean(attestationTrustAnchor),
        telemetryPersistenceStatus, mutationAllowed: false, readOnly: false };
    }
    const elapsed = Math.max(0, Math.min(300_000, Math.round(performance.now() - started)));
    const providerConfigured = Boolean(attestationTrustAnchor);
    const journalPending = journalAudit.pendingCount || 0;
    let status = "healthy";
    if (!providerConfigured) status = "not_configured";
    else if (anchorStatus.status === "unavailable") status = "unavailable";
    else if (anchorStatus.status !== "anchored" || trustAudit.status !== "healthy"
      || ["unhealthy", "recovery_required", "degraded", "partial"].includes(journalAudit.status) || journalAudit.truncated) status = "degraded";
    const sampledAt = bounded(clock(), 64);
    sample = { sampledAt, status, providerConfigured, anchorStatus: anchorStatus.status,
      localRevision: Number.isSafeInteger(anchorStatus.localRevision) ? anchorStatus.localRevision : null,
      anchorRevision: Number.isSafeInteger(anchorStatus.anchorRevision) ? anchorStatus.anchorRevision : null,
      latencyMs: elapsed, journalAuditStatus: journalAudit.status,
      trustAuditStatus: trustAudit.status, pendingCount: journalPending,
      errorCode: anchorStatus.errorCode ? bounded(anchorStatus.errorCode, 100) : null };
    let telemetryPersistenceStatus = "stored";
    try { await appendTrustAnchorHealthSample(ownerId, sample); }
    catch (error) { telemetryPersistenceStatus = "invalid_or_unavailable"; sample.errorCode = bounded(error?.code || "TELEMETRY_WRITE_FAILED", 100); status = "degraded"; }
    return { ...sample, status, configured: providerConfigured, rollbackProtectionEnabled: providerConfigured,
      trustDigest: anchorStatus.anchorDigest || null, trustAuditStatus: trustAudit.status,
      journalAuditStatus: journalAudit.status, journalFindings: journalAudit.totalFindings,
      journalTotal: journalAudit.total, telemetryPersistenceStatus, mutationAllowed: false, readOnly: false };
  }

  async function listMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, MAX_TRUST_ANCHOR_HEALTH_SAMPLES);
    const id = trustAnchorHealthTelemetryId(ownerId);
    const record = await store.getEvidence(ownerId, id);
    if (!record) return { status: "empty", ownerId, total: 0, items: [], truncated: false, readOnly: true };
    let snapshot;
    try { snapshot = validateTrustAnchorHealthTelemetry(record, ownerId); }
    catch (error) { return { status: "unhealthy", ownerId, total: null, items: [], truncated: false,
      findings: [{ code: "TRUST_ANCHOR_HEALTH_TELEMETRY_INVALID", errorCode: bounded(error?.code || "TELEMETRY_INVALID", 100) }], readOnly: true }; }
    const items = snapshot.samples.slice(-limit).reverse().map(item => structuredClone(item));
    return { status: "healthy", ownerId, total: snapshot.sequence, retained: snapshot.samples.length,
      baseSequence: snapshot.baseSequence, items, limit, truncated: snapshot.sequence > items.length, readOnly: true };
  }

  async function getMutationOutcomeLedgerAttestationTrustAnchorStatus(ownerId) {
    assertOwner(ownerId);
    const snapshot = await ensureAttestationTrustPolicy(ownerId);
    return inspectExternalTrustAnchor(ownerId, snapshot);
  }

  async function reconcileMutationOutcomeLedgerAttestationTrustAnchor(ownerId) {
    assertOwner(ownerId);
    if (!attestationTrustAnchor) return { status: "not_configured", configured: false, rollbackProtectionEnabled: false,
      automaticTrustRepairAllowed: false, readOnly: false };
    const snapshot = await ensureAttestationTrustPolicy(ownerId);
    const trustAudit = await auditMutationOutcomeLedgerAttestationTrust(ownerId, { limit: 200, includeExternalAnchor: false });
    if (trustAudit.truncated || trustAudit.findings.some(item => item.severity === "error")) {
      return { status: "blocked_unhealthy_trust_registry", trustAudit, anchorStatus: await inspectExternalTrustAnchor(ownerId, snapshot),
        automaticTrustRepairAllowed: false, readOnly: false };
    }
    let status = await inspectExternalTrustAnchor(ownerId, snapshot, { initializeGenesis: snapshot.revision === 0 && snapshot.history.length === 0 });
    if (status.status === "anchored") return { status: "healthy", anchorStatus: status, trustAudit,
      automaticTrustRepairAllowed: false, readOnly: false };
    if (status.status === "missing" && snapshot.revision > 0) return { status: "enrollment_required", anchorStatus: status, trustAudit,
      enrollmentRequired: true, automaticTrustRepairAllowed: false, readOnly: false };
    if (status.status !== "behind_registry") return { status: "blocked", anchorStatus: status, trustAudit,
      automaticTrustRepairAllowed: false, readOnly: false };
    status = await advanceExternalTrustAnchor(ownerId, snapshot, "reconciliation");
    return { status: status.status === "anchored" ? "reconciled" : "blocked", anchorStatus: status, trustAudit,
      automaticTrustRepairAllowed: false, readOnly: false };
  }

  async function createMutationOutcomeLedgerAttestationTrustAnchorEnrollmentChallenge(ownerId, options = {}) {
    assertOwner(ownerId);
    if (!attestationTrustAnchor) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_NOT_CONFIGURED", "External trust anchor provider belum dikonfigurasi", 503);
    const snapshot = await ensureAttestationTrustPolicy(ownerId);
    if (snapshot.revision === 0 && snapshot.history.length === 0) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_GENESIS_AUTOMATIC", "Registry genesis dapat di-anchor secara otomatis; enrollment quorum hanya untuk registry yang sudah memiliki histori", 409);
    }
    let existingAnchor;
    try { existingAnchor = await attestationTrustAnchor.read(ownerId); }
    catch (error) { throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_UNAVAILABLE", "External anchor tidak dapat dibaca sebelum enrollment challenge", 503, { cause: bounded(error?.code || "ANCHOR_READ_FAILED", 80) }); }
    if (existingAnchor != null) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_ALREADY_EXISTS", "External trust anchor sudah ada", 409);
    const trustAudit = await auditMutationOutcomeLedgerAttestationTrust(ownerId, { limit: 200, includeExternalAnchor: false });
    if (trustAudit.truncated || trustAudit.findings.some(item => item.severity === "error")) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_REGISTRY_UNHEALTHY", "Trust registry harus lolos audit lengkap sebelum enrollment anchor", 409);
    }
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-attestation-trust-anchor-enrollment-challenge");
    const now = bounded(clock(), 64), nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock enrollment challenge tidak valid", 500);
    if (records.length >= MAX_ATTESTATION_TRUST_ANCHOR_CHALLENGES) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CHALLENGE_LIMIT", "Batas enrollment challenge tercapai", 409);
    const pending = records.filter(item => item.snapshot?.status === "issued" && Date.parse(item.snapshot?.payload?.expiresAt) > nowMs);
    if (pending.length >= MAX_PENDING_ATTESTATION_TRUST_ANCHOR_CHALLENGES) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_PENDING_LIMIT", "Terlalu banyak enrollment challenge yang masih aktif", 429);
    const ttlMs = boundedInteger(options.ttlMs, MAX_INTEGRITY_ATTESTATION_TTL_MS, 30_000, MAX_INTEGRITY_ATTESTATION_TTL_MS);
    const payload = { schemaVersion: 1, purpose: "agentic-v4-attestation-trust-anchor-enrollment", ownerId,
      revision: snapshot.revision, trustDigest: trustSnapshotDigest(snapshot), headHash: snapshot.history.at(-1)?.eventHash || trustGenesis(ownerId),
      bootstrapDigest: snapshot.bootstrapDigest, issuedAt: now, expiresAt: new Date(nowMs + ttlMs).toISOString(),
      nonce: randomUUID(), challengeId: randomUUID() };
    const id = trustAnchorId(ownerId, payload.challengeId);
    const challengeSnapshot = { schemaVersion: 1, status: "issued", payload, appliedAt: null, anchorDigest: null };
    const record = { id, ownerId, kind: "recovery-reconciliation-attestation-trust-anchor-enrollment-challenge", createdAt: now,
      digest: sha256(canonical(challengeSnapshot)), snapshot: challengeSnapshot,
      provenance: { source: "recovery-audit-planning", schemaVersion: 1, ownerScoped: true } };
    await store.putEvidence(ownerId, record, { overwrite: false });
    return { id, status: "issued", payload: structuredClone(payload), digest: record.digest,
      signatureAlgorithm: "Ed25519", canonicalization: "sorted-json-keys-v1", quorumRequired: trustQuorum(snapshot), readOnly: true };
  }

  async function initializeMutationOutcomeLedgerAttestationTrustAnchor(ownerId, challengeId, input = {}) {
    assertOwner(ownerId);
    assertRecordId(challengeId, "challengeId");
    if (!attestationTrustAnchor) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_NOT_CONFIGURED", "External trust anchor provider belum dikonfigurasi", 503);
    const id = challengeId.startsWith("ledger-integrity-trust-anchor-enrollment-") ? challengeId : trustAnchorId(ownerId, challengeId);
    const record = await store.getEvidence(ownerId, id);
    if (!record || record.kind !== "recovery-reconciliation-attestation-trust-anchor-enrollment-challenge" || record.ownerId !== ownerId
      || !record.snapshot || record.digest !== sha256(canonical(record.snapshot))) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CHALLENGE_INVALID", "Enrollment challenge tidak ditemukan atau tidak valid", 404);
    }
    const challenge = record.snapshot;
    const payload = challenge.payload;
    if (challenge.status === "applied") {
      let currentAnchor;
      try { currentAnchor = await attestationTrustAnchor.read(ownerId); }
      catch { throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_UNAVAILABLE", "External anchor tidak dapat diperiksa untuk replay enrollment", 503); }
      if (currentAnchor) {
        validateTrustAnchor(currentAnchor, ownerId);
        if (currentAnchor.enrollmentChallengeId === payload?.challengeId && currentAnchor.digest === challenge.anchorDigest) {
          return { status: "anchored", revision: currentAnchor.revision, anchorSequence: currentAnchor.anchorSequence,
            anchorDigest: currentAnchor.digest, challengeId: id, appliedAt: challenge.appliedAt, alreadyApplied: true, readOnly: true };
        }
      }
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CHALLENGE_USED", "Enrollment challenge sudah digunakan", 409);
    }
    if (challenge.status !== "issued") throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CHALLENGE_USED", "Enrollment challenge sudah digunakan", 409);
    validateAttestationPayloadTime(payload, bounded(clock(), 64));
    const snapshot = await ensureAttestationTrustPolicy(ownerId);
    if (payload?.purpose !== "agentic-v4-attestation-trust-anchor-enrollment" || payload.ownerId !== ownerId
      || payload.revision !== snapshot.revision || payload.trustDigest !== trustSnapshotDigest(snapshot)
      || payload.headHash !== (snapshot.history.at(-1)?.eventHash || trustGenesis(ownerId)) || payload.bootstrapDigest !== snapshot.bootstrapDigest) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CONTEXT_STALE", "Trust registry berubah setelah enrollment challenge diterbitkan", 409);
    }
    const trustAudit = await auditMutationOutcomeLedgerAttestationTrust(ownerId, { limit: 200, includeExternalAnchor: false });
    if (trustAudit.truncated || trustAudit.findings.some(item => item.severity === "error")) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_REGISTRY_UNHEALTHY", "Trust registry tidak lolos audit sebelum enrollment", 409);
    }
    const seen = new Set(), valid = [];
    for (const item of (Array.isArray(input.authorizations) ? input.authorizations : []).slice(0, MAX_ATTESTATION_TRUST_AUTHORIZERS)) {
      if (!item || typeof item.keyId !== "string" || seen.has(item.keyId)) continue;
      const entry = activeTrustKey(snapshot, item.keyId);
      if (!entry) continue;
      let key;
      try { key = parseEd25519PublicKey(entry.publicKeyPem); } catch { continue; }
      if (verifyTrustPayloadSignature(payload, item.signature, key)) { seen.add(item.keyId); valid.push(item.keyId); }
    }
    const required = trustQuorum(snapshot);
    if (valid.length < required) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_QUORUM_NOT_MET", "Enrollment anchor memerlukan quorum trusted key aktif", 403,
      { required, valid: valid.length });
    let currentAnchor;
    try { currentAnchor = await attestationTrustAnchor.read(ownerId); }
    catch (error) { throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_UNAVAILABLE", "External anchor tidak dapat dibaca sebelum enrollment", 503, { cause: bounded(error?.code || "ANCHOR_READ_FAILED", 80) }); }
    if (currentAnchor != null) {
      try { validateTrustAnchor(currentAnchor, ownerId); } catch (error) { throw error; }
      if (currentAnchor.enrollmentChallengeId === payload.challengeId && currentAnchor.revision === snapshot.revision
        && currentAnchor.trustDigest === trustSnapshotDigest(snapshot)) {
        return markTrustAnchorEnrollmentApplied(ownerId, id, record, currentAnchor);
      }
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_ALREADY_EXISTS", "Anchor telah dibuat oleh challenge lain", 409);
    }
    const candidate = makeTrustAnchor(ownerId, snapshot, null, "quorum_enrollment", payload.challengeId);
    let outcome;
    try { outcome = await attestationTrustAnchor.compareAndSet(ownerId, null, candidate); }
    catch (error) { throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_UNAVAILABLE", "External anchor gagal menyimpan enrollment", 503, { cause: bounded(error?.code || "ANCHOR_WRITE_FAILED", 80) }); }
    if (outcome !== true && outcome?.applied !== true) {
      currentAnchor = outcome?.anchor ?? await attestationTrustAnchor.read(ownerId);
      if (!currentAnchor || currentAnchor.enrollmentChallengeId !== payload.challengeId || currentAnchor.digest !== candidate.digest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CAS_CONFLICT", "External anchor berubah saat enrollment diproses", 409);
      }
    }
    try { currentAnchor = await attestationTrustAnchor.read(ownerId); }
    catch (error) { throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_UNAVAILABLE", "Enrollment tersimpan tetapi tidak dapat diverifikasi melalui external anchor", 503, { cause: bounded(error?.code || "ANCHOR_READ_FAILED", 80) }); }
    if (!currentAnchor || currentAnchor.digest !== candidate.digest) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_WRITE_UNVERIFIED", "External anchor tidak mengonfirmasi enrollment yang baru ditulis", 503);
    }
    validateTrustAnchor(currentAnchor, ownerId);
    return markTrustAnchorEnrollmentApplied(ownerId, id, record, currentAnchor);
  }

  async function markTrustAnchorEnrollmentApplied(ownerId, id, originalRecord, anchor) {
    const now = bounded(clock(), 64);
    const result = await store.mutateEvidence(ownerId, id, current => {
      if (!current || current.kind !== "recovery-reconciliation-attestation-trust-anchor-enrollment-challenge"
        || current.digest !== sha256(canonical(current.snapshot))) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CHALLENGE_INVALID", "Enrollment challenge berubah saat diproses", 409);
      if (current.snapshot.status === "applied" && current.snapshot.anchorDigest === anchor.digest) return { write: false, result: current.snapshot };
      if (current.snapshot.status !== "issued" || current.snapshot.payload.challengeId !== originalRecord.snapshot.payload.challengeId) {
        throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_ANCHOR_CHALLENGE_USED", "Enrollment challenge sudah digunakan", 409);
      }
      const snapshot = { ...current.snapshot, status: "applied", appliedAt: now, anchorDigest: anchor.digest };
      return { value: { ...current, snapshot, digest: sha256(canonical(snapshot)) }, result: snapshot };
    });
    return { status: "anchored", revision: anchor.revision, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      challengeId: id, appliedAt: result.appliedAt, readOnly: false };
  }

  async function getMutationOutcomeLedgerAttestationTrustPolicy(ownerId, options = {}) {
    const snapshot = await ensureAttestationTrustPolicy(ownerId);
    const anchorStatus = await inspectExternalTrustAnchor(ownerId, snapshot);
    const limit = boundedInteger(options.limit, 50, 1, 100);
    return {
      ownerId: bounded(ownerId), revision: snapshot.revision, digest: trustSnapshotDigest(snapshot),
      bootstrapDigest: snapshot.bootstrapDigest, externalAnchor: anchorStatus,
      activeKeyCount: snapshot.keys.filter(item => item.status === "active").length,
      revokedKeyCount: snapshot.keys.filter(item => item.status === "revoked").length,
      keys: snapshot.keys.map(item => ({ keyId: item.keyId, fingerprint: item.fingerprint, status: item.status,
        addedAtRevision: item.addedAtRevision, revokedAtRevision: item.revokedAtRevision })).sort((a, b) => a.keyId.localeCompare(b.keyId)),
      history: snapshot.history.slice(-limit).map(item => ({ sequence: item.sequence, revision: item.revision,
        action: item.payload?.action, keyId: item.payload?.keyId, keyFingerprint: item.payload?.keyFingerprint,
        at: item.payload?.issuedAt, eventHash: item.eventHash, authorizerKeyIds: item.authorizationSignatures.map(value => value.keyId) })),
      historyTotal: snapshot.history.length, historyTruncated: snapshot.history.length > limit,
      quorumRequired: trustQuorum(snapshot), readOnly: true
    };
  }

  async function createMutationOutcomeLedgerAttestationTrustTransitionChallenge(ownerId, input = {}) {
    assertOwner(ownerId);
    const snapshot = await ensureAttestationTrustPolicy(ownerId);
    await assertExternalTrustAnchorCurrent(ownerId, snapshot);
    const action = input.action;
    const keyId = typeof input.keyId === "string" ? input.keyId : "";
    if (!/^[A-Za-z0-9._-]{1,80}$/.test(keyId) || !["rotate", "revoke"].includes(action)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_TRANSITION_INVALID", "Transisi trust harus berupa rotate atau revoke dengan keyId valid", 400);
    }
    const active = snapshot.keys.filter(item => item.status === "active");
    if (!active.length) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_NO_ACTIVE_KEYS", "Tidak ada trusted key aktif untuk mengotorisasi perubahan trust", 409);
    let keyFingerprintValue = null;
    let pem = null;
    if (action === "rotate") {
      if (snapshot.keys.some(item => item.keyId === keyId)) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_KEY_ID_REUSED", "keyId tidak boleh digunakan kembali; pilih ID baru", 409);
      if (snapshot.keys.length >= MAX_ATTESTATION_TRUST_KEYS) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_KEY_LIMIT", "Batas jumlah trusted key telah tercapai", 409);
      let key;
      try { key = parseEd25519PublicKey(input.publicKey); } catch (error) { throw error; }
      pem = publicKeyPem(key);
      keyFingerprintValue = keyFingerprint(key);
    } else {
      const target = activeTrustKey(snapshot, keyId);
      if (!target) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_KEY_NOT_ACTIVE", "Hanya trusted key aktif yang dapat dicabut", 409);
      if (active.length <= 1) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_LAST_KEY", "Tambahkan dan verifikasi key pengganti sebelum mencabut satu-satunya trusted key aktif", 409);
      const reason = typeof input.reason === "string" ? input.reason.trim() : "";
      if (reason.length < 12 || reason.length > 240) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_REASON_INVALID", "Alasan pencabutan harus 12–240 karakter", 400);
      keyFingerprintValue = target.fingerprint;
    }
    const now = bounded(clock(), 64);
    const issuedMs = Date.parse(now);
    if (!Number.isFinite(issuedMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock trust transition tidak valid", 500);
    const existingChallenges = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-attestation-trust-challenge");
    if (existingChallenges.length >= MAX_ATTESTATION_TRUST_CHALLENGES) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CHALLENGE_CAPACITY", "Batas total trust transition challenge tercapai", 409);
    const pendingChallenges = existingChallenges.filter(item => item.snapshot?.status === "issued" && Date.parse(item.snapshot?.payload?.expiresAt) > issuedMs);
    if (pendingChallenges.length >= MAX_PENDING_ATTESTATION_TRUST_CHALLENGES) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_PENDING_LIMIT", "Terlalu banyak trust transition challenge yang masih aktif", 429);
    const ttlMs = boundedInteger(input.ttlMs, MAX_INTEGRITY_ATTESTATION_TTL_MS, 30_000, MAX_INTEGRITY_ATTESTATION_TTL_MS);
    const payload = {
      schemaVersion: 1, purpose: "agentic-v4-attestation-trust-transition", ownerId, action, keyId,
      keyFingerprint: keyFingerprintValue, publicKeyPem: pem,
      reason: action === "revoke" ? input.reason.trim() : null,
      policyRevision: snapshot.revision, policyDigest: trustSnapshotDigest(snapshot),
      issuedAt: now, expiresAt: new Date(issuedMs + ttlMs).toISOString(), nonce: randomUUID(), transitionId: randomUUID()
    };
    const challengeId = attestationTrustChallengeId(ownerId, payload.transitionId);
    const challengeSnapshot = { schemaVersion: 1, status: "issued", payload, appliedAt: null, resultRevision: null };
    const record = { id: challengeId, ownerId, kind: "recovery-reconciliation-attestation-trust-challenge", createdAt: now,
      digest: trustSnapshotDigest(challengeSnapshot), snapshot: challengeSnapshot,
      provenance: { source: "recovery-audit-planning", schemaVersion: 1, ownerScoped: true } };
    await store.putEvidence(ownerId, record, { overwrite: false });
    return { id: challengeId, status: "issued", payload: structuredClone(payload), digest: record.digest,
      authorization: { algorithm: "Ed25519", canonicalization: "sorted-json-keys-v1", requiredSignatures: trustQuorum(snapshot),
        signPayload: "canonical(payload)" },
      ...(action === "rotate" ? { proofOfPossession: { algorithm: "Ed25519", payload: { domain: "agentic-v4-attestation-trust-proof-of-possession", payload } } } : {}),
      readOnly: true };
  }

  async function applyMutationOutcomeLedgerAttestationTrustTransition(ownerId, challengeId, input = {}) {
    assertOwner(ownerId);
    assertRecordId(challengeId, "challengeId");
    const id = challengeId.startsWith("ledger-integrity-trust-challenge-") ? challengeId : attestationTrustChallengeId(ownerId, challengeId);
    const policyBefore = await ensureAttestationTrustPolicy(ownerId);
    await assertExternalTrustAnchorCurrent(ownerId, policyBefore);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.kind !== "recovery-reconciliation-attestation-trust-challenge" || challenge.ownerId !== ownerId) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CHALLENGE_NOT_FOUND", "Trust transition challenge tidak ditemukan", 404);
    }
    if (!challenge.snapshot || challenge.digest !== trustSnapshotDigest(challenge.snapshot)
      || challenge.snapshot.schemaVersion !== 1 || challenge.snapshot.status !== "issued") {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CHALLENGE_INVALID", "Trust transition challenge tidak valid atau sudah digunakan", 409);
    }
    const payload = challenge.snapshot.payload;
    const now = bounded(clock(), 64);
    validateAttestationPayloadTime({ issuedAt: payload?.issuedAt, expiresAt: payload?.expiresAt }, now);
    if (payload?.schemaVersion !== 1 || payload?.purpose !== "agentic-v4-attestation-trust-transition" || payload.ownerId !== ownerId
      || !["rotate", "revoke"].includes(payload.action) || payload.policyRevision !== policyBefore.revision
      || payload.policyDigest !== trustSnapshotDigest(policyBefore)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CONTEXT_STALE", "Trust policy berubah setelah challenge diterbitkan", 409);
    }
    const signatures = Array.isArray(input.authorizations) ? input.authorizations.slice(0, MAX_ATTESTATION_TRUST_AUTHORIZERS) : [];
    const seen = new Set();
    const validAuthorizations = [];
    let validCount = 0;
    for (const item of signatures) {
      if (!item || typeof item.keyId !== "string" || seen.has(item.keyId)) continue;
      const entry = activeTrustKey(policyBefore, item.keyId);
      if (!entry) continue;
      let key;
      try { key = parseEd25519PublicKey(entry.publicKeyPem); } catch { continue; }
      if (verifyTrustPayloadSignature(payload, item.signature, key)) {
        seen.add(item.keyId); validCount += 1; validAuthorizations.push({ keyId: item.keyId, signature: item.signature });
      }
    }
    const required = trustQuorum(policyBefore);
    if (validCount < required) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_QUORUM_NOT_MET", "Tanda tangan otorisasi belum memenuhi quorum trusted key aktif", 403,
      { required, valid: validCount });
    let newKey = null;
    if (payload.action === "rotate") {
      newKey = parseEd25519PublicKey(payload.publicKeyPem);
      if (keyFingerprint(newKey) !== payload.keyFingerprint
        || !verifyTrustPayloadSignature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload }, input.proofOfPossession, newKey)) {
        throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_PROOF_INVALID", "Proof-of-possession untuk key baru tidak valid", 403);
      }
    } else if (typeof payload.reason !== "string" || payload.reason.trim().length < 12 || payload.reason.length > 240) {
      throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_REASON_INVALID", "Alasan pencabutan tidak valid", 400);
    }
    const journalRecord = await createTrustTransitionJournal(ownerId, id, payload);
    const journalId = journalRecord.id;
    const policyId = attestationTrustPolicyId(ownerId);
    const result = await store.mutateEvidence(ownerId, policyId, current => {
      const currentSnapshot = validateAttestationTrustPolicyRecord(current, ownerId);
      if (currentSnapshot.revision !== payload.policyRevision || trustSnapshotDigest(currentSnapshot) !== payload.policyDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CONTEXT_STALE", "Trust policy berubah saat transisi diproses", 409);
      }
      if (currentSnapshot.history.length >= MAX_ATTESTATION_TRUST_HISTORY) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_HISTORY_LIMIT", "Trust history penuh; transisi ditolak", 409);
      const nextRevision = currentSnapshot.revision + 1;
      const keys = currentSnapshot.keys.map(item => structuredClone(item));
      if (payload.action === "rotate") {
        if (keys.some(item => item.keyId === payload.keyId)) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_KEY_ID_REUSED", "keyId sudah pernah digunakan", 409);
        keys.push({ keyId: payload.keyId, publicKeyPem: publicKeyPem(newKey), fingerprint: payload.keyFingerprint,
          status: "active", addedAtRevision: nextRevision, revokedAtRevision: null });
      } else {
        const target = keys.find(item => item.keyId === payload.keyId && item.status === "active");
        const activeCount = keys.filter(item => item.status === "active").length;
        if (!target) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_KEY_NOT_ACTIVE", "Key target sudah tidak aktif", 409);
        if (activeCount <= 1) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_LAST_KEY", "Transisi tidak boleh menghapus seluruh trusted key aktif", 409);
        target.status = "revoked";
        target.revokedAtRevision = nextRevision;
      }
      const previousHash = currentSnapshot.history.at(-1)?.eventHash || trustGenesis(ownerId);
      const event = { sequence: nextRevision, revision: nextRevision, previousHash, payload: structuredClone(payload),
        authorizationSignatures: validAuthorizations,
        proofOfPossession: payload.action === "rotate" ? input.proofOfPossession : null,
        appliedAt: now };
      event.eventHash = trustEventHash(event);
      const snapshot = { ...currentSnapshot, revision: nextRevision, keys, history: [...currentSnapshot.history, event] };
      const value = { ...current, snapshot, digest: trustSnapshotDigest(snapshot) };
      return { value, result: { status: "applied", action: payload.action, keyId: payload.keyId, revision: nextRevision,
        digest: value.digest, eventHash: event.eventHash, activeKeyCount: keys.filter(item => item.status === "active").length,
        revokedKeyCount: keys.filter(item => item.status === "revoked").length, readOnly: false } };
    });
    await updateTrustTransitionJournal(ownerId, journalId, "local_committed", {
      localRevision: result.revision, localDigest: result.digest, eventHash: result.eventHash
    });
    const appliedAt = bounded(clock(), 64);
    await store.mutateEvidence(ownerId, id, current => {
      if (!current || current.kind !== "recovery-reconciliation-attestation-trust-challenge"
        || current.digest !== trustSnapshotDigest(current.snapshot)) throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CHALLENGE_INVALID", "Challenge berubah setelah transisi diterapkan", 409);
      if (current.snapshot.status === "applied") return { write: false, result: current.snapshot.result };
      if (current.snapshot.status !== "issued" || current.snapshot.payload.transitionId !== payload.transitionId) {
        throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_CHALLENGE_INVALID", "Challenge sudah digunakan", 409);
      }
      const snapshot = { ...current.snapshot, status: "applied", appliedAt, resultRevision: result.revision, result: { action: result.action, keyId: result.keyId, eventHash: result.eventHash } };
      return { value: { ...current, snapshot, digest: trustSnapshotDigest(snapshot) }, result: snapshot.result };
    });
    await updateTrustTransitionJournal(ownerId, journalId, "challenge_applied", {
      localRevision: result.revision, localDigest: result.digest, eventHash: result.eventHash
    });
    const updatedPolicy = await ensureAttestationTrustPolicy(ownerId);
    const anchorStatus = await advanceExternalTrustAnchor(ownerId, updatedPolicy, "trust_transition");
    const journalStatus = ["anchored", "not_configured"].includes(anchorStatus.status) ? "completed"
      : ["behind_registry", "unavailable", "missing"].includes(anchorStatus.status) ? "anchor_pending" : "blocked";
    await updateTrustTransitionJournal(ownerId, journalId, journalStatus, {
      localRevision: result.revision, localDigest: result.digest, eventHash: result.eventHash,
      anchorStatus: anchorStatus.status, anchorDigest: anchorStatus.anchorDigest || null,
      resultCode: journalStatus === "blocked" ? `ANCHOR_${String(anchorStatus.status).toUpperCase()}`
        : journalStatus === "anchor_pending" ? "ANCHOR_NOT_CURRENT" : null
    });
    return { ...result, externalAnchorStatus: anchorStatus.status, externalAnchorRevision: anchorStatus.anchorRevision ?? null,
      crossStoreOperationId: journalId, crossStoreStatus: journalStatus,
      rollbackProtectionEnabled: Boolean(attestationTrustAnchor), mutationAllowed: anchorStatus.status === "anchored" || anchorStatus.status === "not_configured" };
  }

  async function auditMutationOutcomeLedgerAttestationTrust(ownerId, options = {}) {
    assertOwner(ownerId);
    const snapshot = await ensureAttestationTrustPolicy(ownerId);
    const findings = [];
    const add = (code, severity, keyId = null, relatedId = null) => findings.push({ code, severity, keyId, relatedId });
    let previousHash = trustGenesis(ownerId);
    const keyById = new Map(snapshot.keys.map(item => [item.keyId, item]));
    const configuredEntries = configuredTrustKeyEntries();
    const configuredDigest = sha256(canonical(configuredEntries));
    const bootstrapKeys = snapshot.keys.filter(item => item.addedAtRevision === 0)
      .map(item => ({ keyId: item.keyId, publicKeyPem: item.publicKeyPem, fingerprint: item.fingerprint }))
      .sort((a, b) => a.keyId.localeCompare(b.keyId));
    if (sha256(canonical(bootstrapKeys)) !== snapshot.bootstrapDigest) {
      add("ATTESTATION_TRUST_BOOTSTRAP_BASELINE_MISMATCH", "error");
    }
    if (configuredDigest === snapshot.bootstrapDigest && canonical(configuredEntries) !== canonical(bootstrapKeys)) {
      add("ATTESTATION_TRUST_BOOTSTRAP_KEY_SET_MISMATCH", "error");
    } else if (configuredDigest !== snapshot.bootstrapDigest) {
      add("ATTESTATION_TRUST_BOOTSTRAP_CONFIGURATION_DRIFT", "warning");
    }
    const replayKeys = bootstrapKeys.map(item => ({ ...item, status: "active", addedAtRevision: 0, revokedAtRevision: null }));
    const replayHistory = [];
    let historyReplayValid = true;
    for (let index = 0; index < snapshot.history.length; index += 1) {
      const event = snapshot.history[index];
      const revision = index + 1;
      const priorSnapshot = { schemaVersion: 1, ownerId, revision: revision - 1,
        bootstrapDigest: snapshot.bootstrapDigest, keys: structuredClone(replayKeys), history: structuredClone(replayHistory) };
      if (!event || event.sequence !== revision || event.revision !== revision || event.previousHash !== previousHash
        || event.eventHash !== trustEventHash(event) || !event.payload || event.payload.ownerId !== ownerId
        || event.payload.policyRevision !== revision - 1 || event.payload.policyDigest !== trustSnapshotDigest(priorSnapshot)
        || !isDigest(event.payload.policyDigest) || !Array.isArray(event.authorizationSignatures)) {
        add("ATTESTATION_TRUST_HISTORY_CHAIN_INVALID", "error", event?.payload?.keyId || null, String(revision));
        historyReplayValid = false;
        break;
      }
      const activeBefore = replayKeys.filter(item => item.status === "active");
      const required = activeBefore.length ? Math.floor(activeBefore.length / 2) + 1 : 0;
      const authorized = new Set();
      for (const item of event.authorizationSignatures) {
        const keyEntry = activeBefore.find(key => key.keyId === item.keyId);
        if (!keyEntry || authorized.has(item.keyId)) continue;
        let key;
        try { key = parseEd25519PublicKey(keyEntry.publicKeyPem); } catch { continue; }
        if (verifyTrustPayloadSignature(event.payload, item.signature, key)) authorized.add(item.keyId);
      }
      if (authorized.size < required) {
        add("ATTESTATION_TRUST_HISTORY_QUORUM_INVALID", "error", event.payload.keyId, String(revision));
        historyReplayValid = false;
        break;
      }
      if (event.payload.action === "rotate") {
        let newKey = null;
        try { newKey = parseEd25519PublicKey(event.payload.publicKeyPem); } catch {}
        if (replayKeys.some(item => item.keyId === event.payload.keyId) || replayKeys.length >= MAX_ATTESTATION_TRUST_KEYS
          || !newKey || keyFingerprint(newKey) !== event.payload.keyFingerprint
          || !verifyTrustPayloadSignature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: event.payload }, event.proofOfPossession, newKey)) {
          add("ATTESTATION_TRUST_ROTATION_PROOF_INVALID", "error", event.payload.keyId, String(revision));
          historyReplayValid = false;
          break;
        }
        replayKeys.push({ keyId: event.payload.keyId, publicKeyPem: publicKeyPem(newKey), fingerprint: event.payload.keyFingerprint,
          status: "active", addedAtRevision: revision, revokedAtRevision: null });
      } else if (event.payload.action === "revoke") {
        const target = replayKeys.find(item => item.keyId === event.payload.keyId && item.status === "active");
        const activeCount = replayKeys.filter(item => item.status === "active").length;
        if (!target || activeCount <= 1 || target.fingerprint !== event.payload.keyFingerprint
          || typeof event.payload.reason !== "string" || event.payload.reason.trim().length < 12 || event.payload.reason.length > 240) {
          add("ATTESTATION_TRUST_REVOCATION_HISTORY_INVALID", "error", event.payload.keyId, String(revision));
          historyReplayValid = false;
          break;
        }
        target.status = "revoked";
        target.revokedAtRevision = revision;
      } else {
        add("ATTESTATION_TRUST_HISTORY_ACTION_INVALID", "error", event.payload.keyId, String(revision));
        historyReplayValid = false;
        break;
      }
      previousHash = event.eventHash;
      replayHistory.push(structuredClone(event));
    }
    if (historyReplayValid && canonical(replayKeys) !== canonical(snapshot.keys)) {
      add("ATTESTATION_TRUST_KEY_STATE_MISMATCH", "error");
    }
    if (snapshot.keys.filter(item => item.status === "active").length === 0) add("NO_ACTIVE_TRUSTED_ATTESTATION_KEYS", "error");
    const allAttestations = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-ledger-integrity-attestation")
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)) || String(a.id).localeCompare(String(b.id)));
    const attestations = allAttestations.slice(0, MAX_ATTESTATION_TRUST_AUDIT_RECORDS);
    if (allAttestations.length > attestations.length) add("ATTESTATION_TRUST_AUDIT_TRUNCATED", "error", null, String(allAttestations.length));
    for (const record of attestations) {
      try {
        const attestation = validateAttestationRecord(record, ownerId);
        const key = keyById.get(attestation.payload.keyId);
        if (attestation.payload.trustRevision === undefined || attestation.payload.trustDigest === undefined) {
          add("ATTESTATION_MISSING_TRUST_BINDING", "warning", attestation.payload.keyId, record.id);
        }
        if (!key) add("ATTESTATION_KEY_MISSING_FROM_TRUST_HISTORY", "error", attestation.payload.keyId, record.id);
        else if (key.status === "revoked") add("ATTESTATION_SIGNED_BY_REVOKED_KEY", "warning", key.keyId, record.id);
      } catch (error) {
        add("ATTESTATION_RECORD_INTEGRITY_FAILED", "error", null, record.id);
      }
    }
    let externalAnchor = { status: "not_configured", configured: false, rollbackProtectionEnabled: false,
      ownerId, localRevision: snapshot.revision, anchorRevision: null, mutationAllowed: true, readOnly: true };
    if (options.includeExternalAnchor !== false && attestationTrustAnchor) {
      externalAnchor = await inspectExternalTrustAnchor(ownerId, snapshot);
      const anchorCodes = {
        missing: ["ATTESTATION_TRUST_EXTERNAL_ANCHOR_MISSING", "error"],
        unavailable: ["ATTESTATION_TRUST_EXTERNAL_ANCHOR_UNAVAILABLE", "error"],
        invalid: ["ATTESTATION_TRUST_EXTERNAL_ANCHOR_INVALID", "error"],
        rollback_detected: ["ATTESTATION_TRUST_EXTERNAL_ANCHOR_ROLLBACK_DETECTED", "error"],
        mismatch: ["ATTESTATION_TRUST_EXTERNAL_ANCHOR_MISMATCH", "error"],
        behind_registry: ["ATTESTATION_TRUST_EXTERNAL_ANCHOR_BEHIND_REGISTRY", "warning"]
      };
      const entry = anchorCodes[externalAnchor.status];
      if (entry) add(entry[0], entry[1], null, String(externalAnchor.anchorRevision ?? "missing"));
    }
    const severityOrder = { error: 0, warning: 1, info: 2 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || String(a.code).localeCompare(b.code) || String(a.keyId || "").localeCompare(String(b.keyId || "")));
    const limit = boundedInteger(options.limit, 100, 1, 200);
    const activeKeyCount = snapshot.keys.filter(item => item.status === "active").length;
    const anchorAllowed = externalAnchor.status === "anchored" || externalAnchor.status === "not_configured";
    return { status: findings.some(item => item.severity === "error") ? "unhealthy" : findings.length ? "degraded" : "healthy",
      ownerId, revision: snapshot.revision, trustDigest: trustSnapshotDigest(snapshot), activeKeyCount,
      revokedKeyCount: snapshot.keys.filter(item => item.status === "revoked").length,
      externalAnchor, rollbackProtectionEnabled: Boolean(attestationTrustAnchor),
      attestationCount: allAttestations.length, checkedAttestations: attestations.length, findings: findings.slice(0, limit), totalFindings: findings.length,
      truncated: findings.length > limit || allAttestations.length > attestations.length, mutationAllowed: !findings.some(item => item.severity === "error") && activeKeyCount > 0 && anchorAllowed,
      automaticTrustRepairAllowed: false, readOnly: true };
  }

  async function saveImmutable(ownerId, record) {
    const existing = await store.getEvidence(ownerId, record.id);
    if (existing) {
      if (existing.digest !== record.digest || existing.kind !== record.kind) {
        throw new AgenticError("RECOVERY_AUDIT_EVIDENCE_ID_COLLISION", "Evidence ID sudah digunakan oleh record yang berbeda", 409);
      }
      verifyDigest(existing, integrityCodeForKind(existing.kind));
      return existing;
    }
    try {
      await store.putEvidence(ownerId, record, { overwrite: false });
      return (await store.getEvidence(ownerId, record.id)) || record;
    } catch (error) {
      const raced = await store.getEvidence(ownerId, record.id);
      if (raced?.digest === record.digest && raced?.kind === record.kind) {
        verifyDigest(raced, integrityCodeForKind(raced.kind));
        return raced;
      }
      throw error;
    }
  }

  async function capture(ownerId, options = {}) {
    assertOwner(ownerId);
    const maxIssues = boundedInteger(options.maxEvidenceIssues, 250, 1, MAX_EVIDENCE_ISSUES);
    const auditLimit = boundedInteger(options.limit, 250, 1, MAX_AUDIT_LIMIT);
    const report = await auditService.inspect(ownerId, { limit: auditLimit });
    const sourceIssues = Array.isArray(report.issues) ? report.issues : [];
    const issues = sourceIssues.slice(0, maxIssues).map(safeIssue);
    const evidenceTruncated = sourceIssues.length > issues.length;
    const preconditions = await capturePreconditions(ownerId, issues);
    const snapshot = {
      schemaVersion: 1,
      ownerId: bounded(ownerId),
      capturedAt: bounded(report.checkedAt || clock(), 64),
      auditStatus: ["healthy", "degraded", "unhealthy"].includes(report.status) ? report.status : "degraded",
      readOnly: true,
      sourceAuditTruncated: report.truncated === true,
      evidenceTruncated,
      auditLimit,
      preconditionSchemaVersion: 1,
      preconditions,
      sourceIssueCount: Number.isSafeInteger(report.issueCount) ? report.issueCount : sourceIssues.length,
      includedIssueCount: issues.length,
      totals: {
        works: boundedInteger(report.totals?.works, 0, 0, Number.MAX_SAFE_INTEGER),
        executions: boundedInteger(report.totals?.executions, 0, 0, Number.MAX_SAFE_INTEGER),
        tasks: boundedInteger(report.totals?.tasks, 0, 0, Number.MAX_SAFE_INTEGER)
      },
      audited: {
        works: boundedInteger(report.audited?.works, 0, 0, Number.MAX_SAFE_INTEGER),
        executions: boundedInteger(report.audited?.executions, 0, 0, Number.MAX_SAFE_INTEGER),
        tasks: boundedInteger(report.audited?.tasks, 0, 0, Number.MAX_SAFE_INTEGER)
      },
      counts: {
        error: boundedInteger(report.counts?.error, 0, 0, Number.MAX_SAFE_INTEGER),
        warning: boundedInteger(report.counts?.warning, 0, 0, Number.MAX_SAFE_INTEGER),
        info: boundedInteger(report.counts?.info, 0, 0, Number.MAX_SAFE_INTEGER)
      },
      issues
    };
    const digest = sha256(canonical(snapshot));
    const record = {
      id: `recovery-audit-${digest.slice(0, 32)}`,
      ownerId,
      kind: "recovery-audit-evidence",
      createdAt: snapshot.capturedAt,
      digest,
      snapshot,
      provenance: { source: "recovery-audit-planning", schemaVersion: 1, capturedAt: snapshot.capturedAt }
    };
    const saved = await saveImmutable(ownerId, record);
    return publicEvidence(saved);
  }

  async function getEvidence(ownerId, evidenceId) {
    assertOwner(ownerId);
    assertRecordId(evidenceId, "evidenceId");
    const record = await store.getEvidence(ownerId, evidenceId);
    if (!record || record.kind !== "recovery-audit-evidence") {
      throw new AgenticError("RECOVERY_AUDIT_EVIDENCE_NOT_FOUND", "Recovery audit evidence tidak ditemukan", 404);
    }
    verifyDigest(record, "RECOVERY_AUDIT_EVIDENCE_INTEGRITY_FAILED");
    return publicEvidence(record);
  }

  async function listEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 200);
    const records = (await store.listEvidence(ownerId))
      .filter(record => record.kind === "recovery-audit-evidence")
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || String(a.id).localeCompare(String(b.id)));
    return { items: records.slice(0, limit).map(record => ({
      id: bounded(record.id), kind: record.kind, createdAt: bounded(record.createdAt, 64), digest: bounded(record.digest, 64),
      auditStatus: record.snapshot?.auditStatus || "degraded", issueCount: Number(record.snapshot?.sourceIssueCount) || 0,
      truncated: record.snapshot?.sourceAuditTruncated === true || record.snapshot?.evidenceTruncated === true
    })), total: records.length, limit, truncated: records.length > limit };
  }

  async function createPlan(ownerId, evidenceId, options = {}) {
    const evidence = await getEvidence(ownerId, evidenceId);
    const snapshot = evidence.snapshot;
    const maxActions = boundedInteger(options.maxActions, 50, 1, MAX_ACTIONS);
    const sourceTruncated = snapshot.sourceAuditTruncated || snapshot.evidenceTruncated;
    let actions;
    let omittedIssueCount = 0;
    if (sourceTruncated) {
      actions = [{
        id: "reconcile-001", issueRef: null,
        issueCode: snapshot.sourceAuditTruncated ? "AUDIT_RESULT_TRUNCATED" : "AUDIT_EVIDENCE_TRUNCATED",
        severity: "warning", priority: "high", target: { entityType: "audit", entityId: evidence.id, relatedId: null },
        operation: "rerun_audit", rationale: "The evidence set is incomplete; reconciliation proposals are withheld until a complete audit is captured.",
        steps: ["Rerun the owner-scoped audit with a sufficient record limit.", "Capture and verify fresh evidence before creating another plan."],
        preconditions: ["Do not repair records from incomplete evidence."],
        requiresHumanApproval: true, automaticExecutionAllowed: false, mutation: "none-until-separately-approved"
      }];
      omittedIssueCount = snapshot.sourceIssueCount;
    } else {
      const allIssues = snapshot.issues.slice().sort((a, b) => severityRank(a.severity) - severityRank(b.severity)
        || a.code.localeCompare(b.code) || a.entityType.localeCompare(b.entityType)
        || a.entityId.localeCompare(b.entityId) || String(a.relatedId || "").localeCompare(String(b.relatedId || "")));
      const preconditionByIssue = new Map((snapshot.preconditions?.issues || []).map(item => [item.issueRef, item]));
      actions = allIssues.slice(0, maxActions).map((issue, index) => planAction(issue, index, preconditionByIssue.get(issueReference(issue))));
      omittedIssueCount = Math.max(0, allIssues.length - actions.length);
    }
    const planCore = {
      schemaVersion: 2,
      ownerId: bounded(ownerId),
      evidenceId: evidence.id,
      evidenceDigest: evidence.digest,
      preconditionSchemaVersion: snapshot.preconditionSchemaVersion || null,
      generatedFromAuditAt: bounded(snapshot.capturedAt, 64),
      auditStatus: snapshot.auditStatus,
      readOnly: true,
      executionPolicy: "manual-review-only",
      automaticExecutionAllowed: false,
      requiresHumanApproval: true,
      maxActions,
      actionCount: actions.length,
      omittedIssueCount,
      truncated: sourceTruncated || omittedIssueCount > 0,
      actions
    };
    const digest = sha256(canonical(planCore));
    const record = {
      id: `recovery-plan-${digest.slice(0, 32)}`,
      ownerId,
      kind: "recovery-reconciliation-plan",
      createdAt: bounded(clock(), 64),
      digest,
      snapshot: planCore,
      provenance: { source: "recovery-audit-planning", evidenceId: evidence.id, evidenceDigest: evidence.digest, createdAt: bounded(clock(), 64) }
    };
    const saved = await saveImmutable(ownerId, record);
    return publicPlan(saved);
  }

  async function getPlan(ownerId, planId) {
    assertOwner(ownerId);
    assertRecordId(planId, "planId");
    const record = await store.getEvidence(ownerId, planId);
    if (!record || record.kind !== "recovery-reconciliation-plan") {
      throw new AgenticError("RECOVERY_RECONCILIATION_PLAN_NOT_FOUND", "Recovery reconciliation plan tidak ditemukan", 404);
    }
    verifyDigest(record, "RECOVERY_RECONCILIATION_PLAN_INTEGRITY_FAILED");
    return publicPlan(record);
  }

  async function revalidatePlan(ownerId, planId, options = {}) {
    assertOwner(ownerId);
    const planRecord = await store.getEvidence(ownerId, planId);
    if (!planRecord || planRecord.kind !== "recovery-reconciliation-plan") {
      throw new AgenticError("RECOVERY_RECONCILIATION_PLAN_NOT_FOUND", "Recovery reconciliation plan tidak ditemukan", 404);
    }
    verifyDigest(planRecord, "RECOVERY_RECONCILIATION_PLAN_INTEGRITY_FAILED");
    const plan = planRecord.snapshot;
    const evidence = await getEvidence(ownerId, plan.evidenceId);
    if (evidence.digest !== plan.evidenceDigest) {
      throw new AgenticError("RECOVERY_RECONCILIATION_PLAN_EVIDENCE_MISMATCH", "Plan tidak cocok dengan digest evidence sumber", 409);
    }
    const checkedAt = bounded(clock(), 64);
    const auditLimit = boundedInteger(options.limit, evidence.snapshot.auditLimit || 250, 1, MAX_AUDIT_LIMIT);
    const currentReport = await auditService.inspect(ownerId, { limit: auditLimit });
    const currentIssues = (Array.isArray(currentReport.issues) ? currentReport.issues : []).map(safeIssue);
    const currentIssueRefs = new Set(currentIssues.map(issueReference));
    const expectedIssues = Array.isArray(evidence.snapshot.issues) ? evidence.snapshot.issues : [];
    const expectedIssueRefs = new Set(expectedIssues.map(issueReference));
    const findings = [];
    const actionResults = [];
    const evidenceIncomplete = evidence.snapshot.sourceAuditTruncated === true
      || evidence.snapshot.evidenceTruncated === true
      || evidence.snapshot.preconditionSchemaVersion !== 1
      || !Array.isArray(evidence.snapshot.preconditions?.issues);
    const auditIncomplete = currentReport.truncated === true;
    const planIncomplete = plan.truncated === true;

    if (!evidenceIncomplete && !auditIncomplete && !planIncomplete) {
      const added = [...currentIssueRefs].filter(ref => !expectedIssueRefs.has(ref));
      const removed = [...expectedIssueRefs].filter(ref => !currentIssueRefs.has(ref));
      if (added.length || removed.length) {
        findings.push({ code: "AUDIT_FINDINGS_CHANGED", severity: "error", addedIssueCount: added.length, removedIssueCount: removed.length });
      }
    }

    const expectedStateByIssue = new Map((evidence.snapshot.preconditions?.issues || []).map(item => [item.issueRef, item]));
    for (const action of (Array.isArray(plan.actions) ? plan.actions : []).slice(0, MAX_ACTIONS)) {
      const mismatches = [];
      if (action.operation === "rerun_audit" || !action.issueRef) {
        actionResults.push({ actionId: bounded(action.id, 80), issueCode: bounded(action.issueCode, 80), status: "incomplete", mismatches: [{ code: "SOURCE_EVIDENCE_INCOMPLETE" }] });
        continue;
      }
      const expectedState = expectedStateByIssue.get(action.issueRef);
      if (!expectedState || !action.preconditionDigest || expectedState.digest !== action.preconditionDigest) {
        mismatches.push({ code: "EXPECTED_PRECONDITION_MISSING" });
      }
      if (!auditIncomplete && !currentIssueRefs.has(action.issueRef)) mismatches.push({ code: "FINDING_NO_LONGER_PRESENT" });
      if (expectedState) {
        for (const expectedRef of (Array.isArray(expectedState.records) ? expectedState.records : [])) {
          const current = await readRecordState(ownerId, expectedRef.entityType, expectedRef.id);
          if (!current || current.fingerprint !== expectedRef.fingerprint || current.exists !== expectedRef.exists || current.version !== expectedRef.version) {
            mismatches.push({ code: "RECORD_PRECONDITION_CHANGED", entityType: bounded(expectedRef.entityType, 40), entityId: bounded(expectedRef.id) });
          }
        }
        for (const expectedLease of (Array.isArray(expectedState.leases) ? expectedState.leases : [])) {
          const current = await readLeaseState(ownerId, expectedLease.workId);
          if (!current || current.fingerprint !== expectedLease.fingerprint) {
            mismatches.push({ code: "LEASE_PRECONDITION_CHANGED", entityType: "work", entityId: bounded(expectedLease.workId) });
          }
        }
      }
      const uniqueMismatches = dedupeMismatches(mismatches);
      actionResults.push({
        actionId: bounded(action.id, 80), issueCode: bounded(action.issueCode, 80),
        status: uniqueMismatches.length ? "stale" : "fresh", mismatches: uniqueMismatches
      });
    }

    if (evidenceIncomplete) findings.push({ code: "EVIDENCE_PRECONDITIONS_INCOMPLETE", severity: "warning" });
    if (auditIncomplete) findings.push({ code: "CURRENT_AUDIT_TRUNCATED", severity: "warning" });
    if (planIncomplete) findings.push({ code: "PLAN_TRUNCATED", severity: "warning" });
    if (actionResults.some(item => item.status === "stale") && !findings.some(item => item.code === "AUDIT_FINDINGS_CHANGED")) {
      findings.push({ code: "ACTION_PRECONDITIONS_STALE", severity: "error" });
    }

    let status = "fresh";
    if (findings.some(item => item.severity === "error") || actionResults.some(item => item.status === "stale")) status = "stale";
    else if (findings.length || actionResults.some(item => item.status === "incomplete")) status = "incomplete";
    const boundedFindings = findings.slice(0, 100).map(item => ({
      code: bounded(item.code, 80), severity: item.severity === "error" ? "error" : "warning",
      ...(Number.isSafeInteger(item.addedIssueCount) ? { addedIssueCount: item.addedIssueCount } : {}),
      ...(Number.isSafeInteger(item.removedIssueCount) ? { removedIssueCount: item.removedIssueCount } : {})
    }));
    const preconditionBindingDigest = sha256(canonical({
      schemaVersion: 1, ownerId: bounded(ownerId), planId: bounded(planRecord.id), planDigest: bounded(planRecord.digest, 64),
      evidenceId: bounded(evidence.id), evidenceDigest: bounded(evidence.digest, 64), status,
      actionBindings: (Array.isArray(plan.actions) ? plan.actions : []).slice(0, MAX_ACTIONS).map(action => ({
        id: bounded(action.id, 80), issueRef: action.issueRef == null ? null : bounded(action.issueRef, 80),
        preconditionDigest: action.preconditionDigest == null ? null : bounded(action.preconditionDigest, 64)
      })),
      actionResults: actionResults.map(item => ({
        actionId: item.actionId, status: item.status,
        mismatches: item.mismatches.map(mismatch => ({ code: mismatch.code, entityType: mismatch.entityType || null, entityId: mismatch.entityId || null }))
      })),
      findings: boundedFindings
    }));
    return {
      planId: bounded(planRecord.id), planDigest: bounded(planRecord.digest, 64),
      evidenceId: bounded(evidence.id), evidenceDigest: bounded(evidence.digest, 64),
      checkedAt, status, preconditionsSatisfied: status === "fresh",
      readyForHumanReview: status === "fresh", requiresHumanApproval: true,
      automaticExecutionAllowed: false, executionAllowed: false,
      preconditionBindingDigest, findings: boundedFindings, actionResults,
      actionCount: actionResults.length, currentAuditIssueCount: currentIssues.length,
      expectedAuditIssueCount: expectedIssues.length, readOnly: true
    };
  }

  async function captureRevalidationEvidence(ownerId, planId, options = {}) {
    assertOwner(ownerId);
    assertRecordId(planId, "planId");
    const result = await revalidatePlan(ownerId, planId, options);
    const snapshot = {
      schemaVersion: 1, ownerId: bounded(ownerId), planId: result.planId, planDigest: result.planDigest,
      evidenceId: result.evidenceId, evidenceDigest: result.evidenceDigest, checkedAt: result.checkedAt,
      status: result.status, preconditionsSatisfied: result.preconditionsSatisfied,
      readyForHumanReview: result.readyForHumanReview, requiresHumanApproval: true,
      automaticExecutionAllowed: false, executionAllowed: false,
      preconditionBindingDigest: result.preconditionBindingDigest,
      findings: structuredClone(result.findings), actionResults: structuredClone(result.actionResults),
      actionCount: result.actionCount, currentAuditIssueCount: result.currentAuditIssueCount,
      expectedAuditIssueCount: result.expectedAuditIssueCount, readOnly: true
    };
    const digest = sha256(canonical(snapshot));
    const record = {
      id: `revalidation-evidence-${digest.slice(0, 32)}`, ownerId, kind: "recovery-reconciliation-revalidation-evidence",
      createdAt: snapshot.checkedAt, digest, snapshot,
      provenance: { source: "recovery-audit-planning", planId: result.planId, planDigest: result.planDigest, checkedAt: result.checkedAt }
    };
    return publicRevalidationEvidence(await saveImmutable(ownerId, record));
  }

  async function getRevalidationEvidence(ownerId, evidenceId) {
    assertOwner(ownerId);
    assertRecordId(evidenceId, "evidenceId");
    const record = await store.getEvidence(ownerId, evidenceId);
    if (!record || record.kind !== "recovery-reconciliation-revalidation-evidence") {
      throw new AgenticError("RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_NOT_FOUND", "Revalidation evidence tidak ditemukan", 404);
    }
    verifyDigest(record, "RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_INTEGRITY_FAILED");
    return publicRevalidationEvidence(record);
  }

  async function listRevalidationEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 200);
    const records = (await store.listEvidence(ownerId))
      .filter(record => record.kind === "recovery-reconciliation-revalidation-evidence")
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || String(a.id).localeCompare(String(b.id)));
    return { items: records.slice(0, limit).map(record => ({
      id: bounded(record.id), kind: record.kind, createdAt: bounded(record.createdAt, 64),
      digest: bounded(record.digest, 64), planId: bounded(record.snapshot?.planId),
      planDigest: bounded(record.snapshot?.planDigest, 64), status: safeRevalidationStatus(record.snapshot?.status),
      preconditionBindingDigest: bounded(record.snapshot?.preconditionBindingDigest, 64)
    })), total: records.length, limit, truncated: records.length > limit };
  }

  async function approvePlan(ownerId, planId, revalidationEvidenceId, options = {}) {
    assertOwner(ownerId);
    assertRecordId(planId, "planId");
    assertRecordId(revalidationEvidenceId, "revalidationEvidenceId");
    const plan = await store.getEvidence(ownerId, planId);
    if (!plan || plan.kind !== "recovery-reconciliation-plan") {
      throw new AgenticError("RECOVERY_RECONCILIATION_PLAN_NOT_FOUND", "Recovery reconciliation plan tidak ditemukan", 404);
    }
    verifyDigest(plan, "RECOVERY_RECONCILIATION_PLAN_INTEGRITY_FAILED");
    const evidence = await store.getEvidence(ownerId, revalidationEvidenceId);
    if (!evidence || evidence.kind !== "recovery-reconciliation-revalidation-evidence") {
      throw new AgenticError("RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_NOT_FOUND", "Revalidation evidence tidak ditemukan", 404);
    }
    verifyDigest(evidence, "RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_INTEGRITY_FAILED");
    const captured = evidence.snapshot;
    if (captured.planId !== plan.id || captured.planDigest !== plan.digest
      || captured.evidenceId !== plan.snapshot?.evidenceId || captured.evidenceDigest !== plan.snapshot?.evidenceDigest) {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_PLAN_MISMATCH", "Revalidation evidence tidak terikat pada plan dan source evidence ini", 409);
    }
    if (captured.status !== "fresh" || captured.readyForHumanReview !== true || captured.executionAllowed !== false
      || captured.automaticExecutionAllowed !== false || !isDigest(captured.preconditionBindingDigest)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_REVALIDATION_NOT_FRESH", "Approval hanya dapat dibuat dari revalidation fresh yang lengkap", 409);
    }
    const current = await revalidatePlan(ownerId, planId, options);
    if (current.status !== "fresh" || current.preconditionBindingDigest !== captured.preconditionBindingDigest) {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_PRECONDITIONS_CHANGED", "Precondition berubah sejak revalidation evidence dibuat", 409);
    }
    const hasActionId = options.actionId !== undefined && options.actionId !== null;
    const hasMutationIntent = options.mutationIntent !== undefined && options.mutationIntent !== null;
    if (hasActionId !== hasMutationIntent) {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Approval mutasi harus mengikat actionId dan mutationIntent sekaligus", 400);
    }
    let actionBinding = null;
    if (hasActionId) {
      assertRecordId(options.actionId, "actionId");
      const action = (Array.isArray(plan.snapshot.actions) ? plan.snapshot.actions : []).find(item => item?.id === options.actionId);
      if (!action) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_ACTION_NOT_FOUND", "Action tidak ditemukan pada plan yang disetujui", 404);
      const normalizedIntent = normalizeMutationIntent(action, options.mutationIntent);
      actionBinding = {
        actionId: bounded(action.id, 80),
        mutationIntentDigest: sha256(canonical(normalizedIntent)),
        mutationTargetDigest: sha256(canonical(normalizedIntent.target))
      };
    }
    const approvedAt = bounded(clock(), 64);
    const approvedAtMs = Date.parse(approvedAt);
    if (!Number.isFinite(approvedAtMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock approval tidak valid", 500);
    const ttlMs = boundedInteger(options.ttlMs, 300_000, 1_000, 900_000);
    const snapshot = {
      schemaVersion: 1, ownerId: bounded(ownerId), planId: bounded(plan.id), planDigest: bounded(plan.digest, 64),
      sourceEvidenceId: bounded(plan.snapshot?.evidenceId), sourceEvidenceDigest: bounded(plan.snapshot?.evidenceDigest, 64),
      revalidationEvidenceId: bounded(evidence.id), revalidationEvidenceDigest: bounded(evidence.digest, 64),
      preconditionBindingDigest: bounded(captured.preconditionBindingDigest, 64),
      status: "approved", approvedBy: bounded(ownerId), approvedAt, expiresAt: new Date(approvedAtMs + ttlMs).toISOString(),
      ttlMs, ...(actionBinding || {}), humanApprovalSatisfied: true, automaticExecutionAllowed: false, executionAllowed: false, readOnly: true
    };
    const digest = sha256(canonical(snapshot));
    const record = {
      id: `reconciliation-approval-${digest.slice(0, 32)}`, ownerId, kind: "recovery-reconciliation-approval",
      createdAt: approvedAt, digest, snapshot,
      ...withApprovalGuardState(ownerId, `reconciliation-approval-${digest.slice(0, 32)}`, initialApprovalGuardState()),
      provenance: { source: "recovery-audit-planning", planId: plan.id, planDigest: plan.digest, revalidationEvidenceId: evidence.id, revalidationEvidenceDigest: evidence.digest }
    };
    return publicApproval(await saveImmutable(ownerId, record));
  }

  async function approveAction(ownerId, planId, revalidationEvidenceId, actionId, mutationIntent, options = {}) {
    return approvePlan(ownerId, planId, revalidationEvidenceId, { ...options, actionId, mutationIntent });
  }

  async function revokeApproval(ownerId, approvalId, options = {}) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    const reasonCode = normalizeRevocationReason(options.reasonCode);
    const outcome = await store.mutateEvidence(ownerId, approvalId, async current => {
      if (!current || current.kind !== "recovery-reconciliation-approval") {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
      }
      verifyDigest(current, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
      const guard = readApprovalGuardState(current);
      if (guard.activeMutation) {
        const code = guard.activeMutation.status === "indeterminate"
          ? "RECOVERY_RECONCILIATION_APPROVAL_MUTATION_OUTCOME_UNKNOWN"
          : "RECOVERY_RECONCILIATION_APPROVAL_MUTATION_IN_PROGRESS";
        throw new AgenticError(code, "Approval tidak dapat dicabut saat status mutasi belum terselesaikan", 409);
      }
      if (guard.revokedAt) return { write: false, result: { record: current, alreadyRevoked: true } };
      const revokedAt = bounded(clock(), 64);
      if (!Number.isFinite(Date.parse(revokedAt))) {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock pencabutan approval tidak valid", 500);
      }
      const nextGuard = {
        ...guard, revision: guard.revision + 1, revokedAt, revokedBy: ownerId, reasonCode
      };
      const updated = { ...current, ...withApprovalGuardState(ownerId, current.id, nextGuard) };
      return { value: updated, result: { record: updated, alreadyRevoked: false } };
    });
    const guard = readApprovalGuardState(outcome.record);
    return {
      approvalId: bounded(outcome.record.id), approvalDigest: bounded(outcome.record.digest, 64),
      status: guard.revokedAt ? "revoked" : "active", revokedAt: guard.revokedAt,
      revokedBy: guard.revokedBy, reasonCode: guard.reasonCode, alreadyRevoked: outcome.alreadyRevoked,
      mutationAllowed: false, automaticExecutionAllowed: false, readOnly: false
    };
  }

  async function runApprovedMutation(ownerId, approvalId, actionId, mutationIntent, mutator, options = {}) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    assertRecordId(actionId, "actionId");
    if (typeof mutator !== "function") throw new TypeError("runApprovedMutation membutuhkan mutation callback tepercaya");
    await assertMutationOutcomeLedgerMutationAllowed(ownerId);

    const claim = await store.mutateEvidence(ownerId, approvalId, async current => {
      if (!current || current.kind !== "recovery-reconciliation-approval") {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
      }
      verifyDigest(current, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
      const guard = readApprovalGuardState(current);
      if (guard.revokedAt) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_REVOKED", "Approval telah dicabut", 409);
      if (guard.activeMutation) {
        const code = guard.activeMutation.status === "indeterminate"
          ? "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_UNKNOWN"
          : "RECOVERY_RECONCILIATION_MUTATION_IN_PROGRESS";
        throw new AgenticError(code, "Mutation sebelumnya belum memiliki outcome yang pasti", 409);
      }
      if (guard.consumedActions.some(item => item.actionId === actionId)) {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_ACTION_ALREADY_CONSUMED", "Approval untuk action ini sudah digunakan", 409);
      }
      if (guard.consumedActions.length >= MAX_CONSUMED_ACTIONS) {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_ACTION_LIMIT", "Batas action yang dapat dikonsumsi approval telah tercapai", 409);
      }

      const verification = await verifyApproval(ownerId, approvalId, options);
      if (verification.status !== "valid") {
        const code = verification.status === "expired" ? "RECOVERY_RECONCILIATION_APPROVAL_EXPIRED"
          : verification.status === "revoked" ? "RECOVERY_RECONCILIATION_APPROVAL_REVOKED"
            : verification.status === "mutation_outcome_unknown" ? "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_UNKNOWN"
              : "RECOVERY_RECONCILIATION_APPROVAL_NOT_VALID";
        throw new AgenticError(code, `Approval tidak valid pada mutation boundary: ${verification.reasonCode || verification.status}`, 409);
      }

      const snapshot = current.snapshot;
      if (snapshot.actionId !== actionId || !isDigest(snapshot.mutationIntentDigest)) {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_NOT_BOUND", "Approval tidak terikat pada action dan mutation intent tertentu", 409);
      }
      const plan = await store.getEvidence(ownerId, snapshot.planId);
      if (!plan || plan.kind !== "recovery-reconciliation-plan") {
        throw new AgenticError("RECOVERY_RECONCILIATION_PLAN_NOT_FOUND", "Plan approval tidak ditemukan", 404);
      }
      verifyDigest(plan, "RECOVERY_RECONCILIATION_PLAN_INTEGRITY_FAILED");
      const action = (Array.isArray(plan.snapshot.actions) ? plan.snapshot.actions : []).find(item => item?.id === actionId);
      if (!action || action.issueRef == null || action.operation === "rerun_audit" || action.automaticExecutionAllowed !== false || action.requiresHumanApproval !== true) {
        throw new AgenticError("RECOVERY_RECONCILIATION_ACTION_NOT_MUTABLE", "Action ini tidak dapat digunakan sebagai batas mutasi", 409);
      }
      const normalizedIntent = normalizeMutationIntent(action, mutationIntent);
      const intentDigest = sha256(canonical(normalizedIntent));
      if (intentDigest !== snapshot.mutationIntentDigest
        || sha256(canonical(normalizedIntent.target)) !== snapshot.mutationTargetDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_INTENT_MISMATCH", "Mutation intent tidak sama dengan intent yang disetujui", 409);
      }
      if (options.expectedPreconditionBindingDigest !== undefined
        && options.expectedPreconditionBindingDigest !== snapshot.preconditionBindingDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_BINDING_MISMATCH", "Precondition binding yang diminta tidak cocok dengan approval", 409);
      }
      const sourceEvidence = await store.getEvidence(ownerId, plan.snapshot.evidenceId);
      if (!sourceEvidence || sourceEvidence.kind !== "recovery-audit-evidence") {
        throw new AgenticError("RECOVERY_AUDIT_EVIDENCE_NOT_FOUND", "Source evidence plan tidak ditemukan", 404);
      }
      verifyDigest(sourceEvidence, "RECOVERY_AUDIT_EVIDENCE_INTEGRITY_FAILED");
      const expectedPreconditions = (sourceEvidence.snapshot.preconditions?.issues || []).find(item => item.issueRef === action.issueRef) || null;
      if (!expectedPreconditions || expectedPreconditions.digest !== action.preconditionDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_PRECONDITIONS_INCOMPLETE", "Expected precondition untuk action tidak lengkap", 409);
      }
      const startedAt = bounded(clock(), 64);
      if (!Number.isFinite(Date.parse(startedAt))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock mutation tidak valid", 500);
      const idempotencyKey = sha256(canonical({
        ownerId, approvalId, actionId, intentDigest, planDigest: plan.digest,
        preconditionBindingDigest: snapshot.preconditionBindingDigest
      })).slice(0, 48);
      const claimId = randomUUID();
      const nextGuard = {
        ...guard, revision: guard.revision + 1,
        activeMutation: {
          status: "in_progress", claimId, actionId, intentDigest, idempotencyKey, startedAt,
          preconditionBindingDigest: snapshot.preconditionBindingDigest, planDigest: plan.digest
        }
      };
      return {
        value: { ...current, ...withApprovalGuardState(ownerId, current.id, nextGuard) },
        result: {
          ownerId, approvalId, actionId, intentDigest, idempotencyKey, claimId, startedAt,
          preconditionBindingDigest: snapshot.preconditionBindingDigest, planId: plan.id,
          action: structuredClone(action), mutationIntent: structuredClone(normalizedIntent),
          expectedPreconditions: structuredClone(expectedPreconditions), verification
        }
      };
    });

    const assertPreconditionsCurrent = async () => {
      const currentTrust = await ensureAttestationTrustPolicy(ownerId);
      await assertExternalTrustAnchorCurrent(ownerId, currentTrust);
      const latest = await revalidatePlan(ownerId, claim.planId, options);
      if (latest.status !== "fresh" || latest.preconditionBindingDigest !== claim.preconditionBindingDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_PRECONDITIONS_CHANGED", "Precondition berubah sebelum mutasi; callback wajib berhenti sebelum menulis state", 409);
      }
      return { checkedAt: latest.checkedAt, preconditionBindingDigest: latest.preconditionBindingDigest, readOnly: true };
    };

    const context = Object.freeze({
      ownerId: claim.ownerId, approvalId: claim.approvalId, actionId: claim.actionId, claimId: claim.claimId,
      idempotencyKey: claim.idempotencyKey, planId: claim.planId,
      preconditionBindingDigest: claim.preconditionBindingDigest,
      action: structuredClone(claim.action), mutationIntent: structuredClone(claim.mutationIntent),
      expectedPreconditions: structuredClone(claim.expectedPreconditions),
      assertPreconditionsCurrent
    });

    let mutationResult;
    let callbackInvoked = false;
    try {
      // Re-check after the durable claim and immediately before handing control
      // to trusted mutation code. The callback must still use record-version
      // CAS/fencing at its own write boundary.
      await assertPreconditionsCurrent();
      callbackInvoked = true;
      mutationResult = await mutator(context);
    } catch (error) {
      if (!callbackInvoked) {
        try {
          await store.mutateEvidence(ownerId, approvalId, async current => {
            if (!current || current.kind !== "recovery-reconciliation-approval") return { write: false, result: current };
            verifyDigest(current, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
            const guard = readApprovalGuardState(current);
            if (guard.activeMutation?.idempotencyKey !== claim.idempotencyKey
              || claimIdFor(ownerId, approvalId, guard.activeMutation) !== claim.claimId) return { write: false, result: current };
            const failedAt = bounded(clock(), 64);
            const nextGuard = {
              ...guard, revision: guard.revision + 1, activeMutation: null,
              lastMutation: { status: "not_started_preconditions_changed", actionId, at: failedAt, idempotencyKey: claim.idempotencyKey, claimId: claim.claimId }
            };
            return { value: { ...current, ...withApprovalGuardState(ownerId, current.id, nextGuard) }, result: true };
          });
        } catch {
          // If claim cleanup fails, the persisted in-progress claim remains fail-closed.
        }
        throw error;
      }
      try {
        await store.mutateEvidence(ownerId, approvalId, async current => {
          if (!current || current.kind !== "recovery-reconciliation-approval") throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Approval tidak ditemukan saat mencatat outcome mutasi", 404);
          verifyDigest(current, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
          const guard = readApprovalGuardState(current);
          if (guard.activeMutation?.idempotencyKey !== claim.idempotencyKey
              || claimIdFor(ownerId, approvalId, guard.activeMutation) !== claim.claimId) return { write: false, result: current };
          const failedAt = bounded(clock(), 64);
          const nextGuard = {
            ...guard, revision: guard.revision + 1,
            activeMutation: { ...guard.activeMutation, status: "indeterminate", failedAt, failureCode: bounded(error?.code || "MUTATION_CALLBACK_FAILED", 80) },
            lastMutation: { status: "indeterminate", actionId, at: failedAt, idempotencyKey: claim.idempotencyKey, claimId: claim.claimId }
          };
          return { value: { ...current, ...withApprovalGuardState(ownerId, current.id, nextGuard) }, result: true };
        });
      } catch {
        // The durable in-progress claim remains fail-closed if outcome persistence also fails.
      }
      throw error;
    }

    try {
      await store.mutateEvidence(ownerId, approvalId, async current => {
        if (!current || current.kind !== "recovery-reconciliation-approval") throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Approval tidak ditemukan saat menyelesaikan mutasi", 404);
        verifyDigest(current, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
        const guard = readApprovalGuardState(current);
        if (guard.activeMutation?.idempotencyKey !== claim.idempotencyKey
          || claimIdFor(ownerId, approvalId, guard.activeMutation) !== claim.claimId
          || guard.activeMutation.status !== "in_progress") {
          throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_UNKNOWN", "Claim mutasi berubah sebelum completion tersimpan", 409);
        }
        const completedAt = bounded(clock(), 64);
        const consumedActions = [...guard.consumedActions, {
          actionId, intentDigest: claim.intentDigest, consumedAt: completedAt, idempotencyKey: claim.idempotencyKey,
          claimId: claim.claimId
        }].slice(-MAX_CONSUMED_ACTIONS);
        const nextGuard = {
          ...guard, revision: guard.revision + 1, activeMutation: null, consumedActions,
          lastMutation: { status: "consumed", actionId, at: completedAt, idempotencyKey: claim.idempotencyKey, claimId: claim.claimId }
        };
        return { value: { ...current, ...withApprovalGuardState(ownerId, current.id, nextGuard) }, result: true };
      });
    } catch {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_UNKNOWN", "Mutasi callback telah kembali tetapi outcome belum dapat dipastikan tersimpan; jangan ulangi mutasi otomatis", 409);
    }
    return {
      authorization: {
        approvalId: bounded(approvalId), actionId: bounded(actionId, 80), idempotencyKey: claim.idempotencyKey,
        preconditionBindingDigest: bounded(claim.preconditionBindingDigest, 64), consumed: true,
        automaticExecutionAllowed: false, readOnly: false
      },
      result: mutationResult
    };
  }

  async function inspectMutationClaim(ownerId, approvalId, options = {}) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    const staleAfterMs = boundedInteger(options.staleAfterMs, 120_000, 1_000, 86_400_000);
    const record = await store.getEvidence(ownerId, approvalId);
    if (!record || record.kind !== "recovery-reconciliation-approval") {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
    }
    verifyDigest(record, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
    const guard = readApprovalGuardState(record);
    const checkedAt = bounded(clock(), 64);
    const checkedAtMs = Date.parse(checkedAt);
    if (!Number.isFinite(checkedAtMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock claim inspection tidak valid", 500);
    const active = guard.activeMutation;
    if (!active) return {
      approvalId: bounded(approvalId), status: "no_active_claim", checkedAt,
      lastMutationStatus: guard.lastMutation?.status || null,
      mutationResolutionCount: (guard.mutationResolutions || []).length,
      readOnly: true, automaticRetryAllowed: false
    };
    const startedAtMs = Date.parse(active.startedAt);
    const ageMs = Number.isFinite(startedAtMs) ? Math.max(0, checkedAtMs - startedAtMs) : null;
    const stale = active.status === "in_progress" && (ageMs === null || ageMs >= staleAfterMs);
    return {
      approvalId: bounded(approvalId), status: active.status === "indeterminate" ? "indeterminate" : "in_progress",
      claimId: bounded(claimIdFor(ownerId, approvalId, active), 80), actionId: bounded(active.actionId, 80),
      idempotencyKey: bounded(active.idempotencyKey, 64), startedAt: bounded(active.startedAt, 64),
      ageMs, stale, staleAfterMs, failureCode: active.failureCode == null ? null : bounded(active.failureCode, 80),
      planDigest: bounded(active.planDigest, 64), preconditionBindingDigest: bounded(active.preconditionBindingDigest, 64),
      checkedAt, resolutionRequired: active.status === "indeterminate" || stale,
      readOnly: true, automaticRetryAllowed: false
    };
  }

  async function recoverMutationClaim(ownerId, approvalId, options = {}) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    const staleAfterMs = boundedInteger(options.staleAfterMs, 120_000, 1_000, 86_400_000);
    const now = bounded(clock(), 64);
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock recovery claim tidak valid", 500);
    const result = await store.mutateEvidence(ownerId, approvalId, async current => {
      if (!current || current.kind !== "recovery-reconciliation-approval") {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
      }
      verifyDigest(current, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
      const guard = readApprovalGuardState(current);
      const active = guard.activeMutation;
      if (!active) return { write: false, result: { status: "no_active_claim", approvalId, lastMutationStatus: guard.lastMutation?.status || null } };
      const claimId = claimIdFor(ownerId, approvalId, active);
      if (active.status === "indeterminate") return { write: false, result: { status: "already_indeterminate", approvalId, claimId, failureCode: active.failureCode || null } };
      const startedAtMs = Date.parse(active.startedAt);
      const ageMs = Number.isFinite(startedAtMs) ? nowMs - startedAtMs : null;
      if (ageMs !== null && (ageMs < 0 || ageMs < staleAfterMs)) {
        return { write: false, result: { status: "not_stale", approvalId, claimId, ageMs: Math.max(0, ageMs), staleAfterMs } };
      }
      const failureCode = ageMs === null ? "INVALID_STARTED_AT" : "STALE_IN_PROGRESS_CLAIM_RECOVERED";
      const nextActive = {
        ...active, claimId, status: "indeterminate", recoveredAt: now,
        failureCode, recoveryReason: "OUTCOME_REQUIRES_EVIDENCE"
      };
      const nextGuard = {
        ...guard, revision: guard.revision + 1, activeMutation: nextActive,
        lastMutation: { status: "indeterminate_recovered", actionId: active.actionId, at: now,
          idempotencyKey: active.idempotencyKey, claimId, failureCode }
      };
      return {
        value: { ...current, ...withApprovalGuardState(ownerId, current.id, nextGuard) },
        result: { status: "recovered_to_indeterminate", approvalId, claimId, failureCode, recoveredAt: now,
          automaticRetryAllowed: false, readOnly: false }
      };
    });
    return structuredClone(result);
  }

  async function captureMutationOutcomeEvidence(ownerId, approvalId, input = {}) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    const approval = await store.getEvidence(ownerId, approvalId);
    if (!approval || approval.kind !== "recovery-reconciliation-approval") {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
    }
    verifyDigest(approval, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
    const guard = readApprovalGuardState(approval);
    const active = guard.activeMutation;
    if (!active || active.status !== "indeterminate") {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_CLAIM_NOT_INDETERMINATE", "Outcome evidence hanya dapat diikat pada claim indeterminate", 409);
    }
    const outcome = input?.outcome;
    if (!["applied", "not_applied", "unresolved"].includes(outcome)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_INVALID", "Outcome harus applied, not_applied, atau unresolved", 400);
    }
    const evidenceRef = typeof input.evidenceRef === "string" ? input.evidenceRef.trim() : "";
    if (!evidenceRef || evidenceRef.length > MAX_MUTATION_EVIDENCE_REF) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INVALID", "evidenceRef wajib berisi referensi bukti yang dibatasi panjangnya", 400);
    }
    if (!isDigest(input.evidenceDigest)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_DIGEST_INVALID", "evidenceDigest harus berupa SHA-256 hex", 400);
    }
    const verificationMethod = input.verificationMethod;
    if (!MUTATION_EVIDENCE_METHODS.has(verificationMethod)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_METHOD_INVALID", "verificationMethod tidak didukung", 400);
    }
    if (outcome !== "unresolved" && !OUTCOME_EVIDENCE_METHODS.has(verificationMethod)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INSUFFICIENT", "Outcome pasti membutuhkan sumber verifikasi selain operator_attestation saja", 409);
    }
    const attemptQuiescent = input.attemptQuiescent === true;
    const quiescenceEvidenceRef = typeof input.quiescenceEvidenceRef === "string" ? input.quiescenceEvidenceRef.trim() : "";
    const quiescenceEvidenceDigest = input.quiescenceEvidenceDigest;
    const quiescenceMethod = input.quiescenceMethod;
    if (outcome !== "unresolved" && (!attemptQuiescent || !quiescenceEvidenceRef
      || quiescenceEvidenceRef.length > MAX_MUTATION_EVIDENCE_REF || !isDigest(quiescenceEvidenceDigest)
      || !QUIESCENCE_EVIDENCE_METHODS.has(quiescenceMethod))) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_QUIESCENCE_EVIDENCE_INSUFFICIENT", "Outcome pasti membutuhkan bukti bahwa attempt sudah berhenti dan tidak dapat menulis lagi", 409);
    }
    if (outcome === "unresolved" && quiescenceEvidenceRef.length > MAX_MUTATION_EVIDENCE_REF) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_QUIESCENCE_EVIDENCE_INVALID", "Referensi quiescence terlalu panjang", 400);
    }
    const observedAt = typeof input.observedAt === "string" ? input.observedAt : "";
    const observedAtMs = Date.parse(observedAt);
    const startedAtMs = Date.parse(active.startedAt);
    if (!Number.isFinite(observedAtMs) || !Number.isFinite(startedAtMs) || observedAtMs < startedAtMs) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_OBSERVED_AT_INVALID", "observedAt harus valid dan tidak mendahului awal claim", 400);
    }
    const summary = typeof input.summary === "string" ? input.summary.trim() : "";
    if (!summary || summary.length > MAX_MUTATION_EVIDENCE_SUMMARY) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_SUMMARY_INVALID", "Summary evidence wajib ada dan dibatasi panjangnya", 400);
    }
    const capturedAt = bounded(clock(), 64);
    const capturedAtMs = Date.parse(capturedAt);
    if (!Number.isFinite(capturedAtMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock evidence tidak valid", 500);
    if (observedAtMs > capturedAtMs + 300_000) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_OBSERVED_AT_INVALID", "observedAt terlalu jauh di masa depan dibanding waktu capture", 400);
    }
    const claimId = claimIdFor(ownerId, approvalId, active);
    const snapshot = {
      schemaVersion: 1, ownerId: bounded(ownerId), approvalId: bounded(approvalId), approvalDigest: bounded(approval.digest, 64),
      claimId, idempotencyKey: bounded(active.idempotencyKey, 64), actionId: bounded(active.actionId, 80),
      intentDigest: bounded(active.intentDigest, 64), planDigest: bounded(active.planDigest, 64),
      preconditionBindingDigest: bounded(active.preconditionBindingDigest, 64), claimStartedAt: bounded(active.startedAt, 64),
      outcome, evidenceRef, evidenceDigest: input.evidenceDigest, verificationMethod,
      attemptQuiescent, quiescenceEvidenceRef: quiescenceEvidenceRef || null,
      quiescenceEvidenceDigest: isDigest(quiescenceEvidenceDigest) ? quiescenceEvidenceDigest : null,
      quiescenceMethod: QUIESCENCE_EVIDENCE_METHODS.has(quiescenceMethod) ? quiescenceMethod : null,
      observedAt: bounded(observedAt, 64), summary: bounded(summary, MAX_MUTATION_EVIDENCE_SUMMARY), capturedAt,
      automaticExecutionAllowed: false, readOnly: true
    };
    const digest = sha256(canonical(snapshot));
    const id = `mutation-outcome-evidence-${digest.slice(0, 32)}`;
    const record = {
      id, ownerId, kind: "recovery-reconciliation-mutation-outcome-evidence", createdAt: capturedAt,
      digest, snapshot, provenance: { source: "recovery-audit-planning", approvalId, claimId, idempotencyKey: active.idempotencyKey }
    };
    const saved = await saveImmutable(ownerId, record);
    await appendMutationOutcomeLedgerEvent(ownerId, ledgerEventFromOutcomeEvidence(saved));
    return publicMutationOutcomeEvidence(saved);
  }

  async function getMutationOutcomeEvidence(ownerId, evidenceId) {
    assertOwner(ownerId);
    assertRecordId(evidenceId, "evidenceId");
    const record = await store.getEvidence(ownerId, evidenceId);
    if (!record || record.kind !== "recovery-reconciliation-mutation-outcome-evidence") {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_NOT_FOUND", "Mutation outcome evidence tidak ditemukan", 404);
    }
    verifyDigest(record, "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED");
    return publicMutationOutcomeEvidence(record);
  }

  async function listMutationOutcomeEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 200);
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-mutation-outcome-evidence")
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || String(a.id).localeCompare(String(b.id)));
    return {
      items: records.slice(0, limit).map(record => {
        verifyDigest(record, "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED");
        return { id: bounded(record.id), kind: record.kind, createdAt: bounded(record.createdAt, 64), digest: bounded(record.digest, 64),
          approvalId: bounded(record.snapshot?.approvalId), claimId: bounded(record.snapshot?.claimId),
          actionId: bounded(record.snapshot?.actionId, 80), outcome: bounded(record.snapshot?.outcome, 24), readOnly: true };
      }), total: records.length, limit, truncated: records.length > limit
    };
  }

  async function resolveMutationClaim(ownerId, approvalId, evidenceId) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    assertRecordId(evidenceId, "evidenceId");
    const evidence = await store.getEvidence(ownerId, evidenceId);
    if (!evidence || evidence.kind !== "recovery-reconciliation-mutation-outcome-evidence") {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_NOT_FOUND", "Mutation outcome evidence tidak ditemukan", 404);
    }
    verifyDigest(evidence, "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED");
    const evidenceSnapshot = evidence.snapshot;
    const siblingOutcomeEvidence = (await store.listEvidence(ownerId)).filter(item =>
      item.kind === "recovery-reconciliation-mutation-outcome-evidence"
      && item.snapshot?.approvalId === approvalId && item.snapshot?.claimId === evidenceSnapshot.claimId);
    for (const sibling of siblingOutcomeEvidence) {
      verifyDigest(sibling, "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED");
    }
    if (new Set(siblingOutcomeEvidence.map(item => item.snapshot?.outcome)).size > 1) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_CONFLICTING_EVIDENCE", "Outcome evidence untuk claim yang sama saling bertentangan; resolusi ditahan untuk review", 409);
    }
    await assertMutationOutcomeLedgerMutationAllowed(ownerId);
    const preflightApproval = await store.getEvidence(ownerId, approvalId);
    if (!preflightApproval || preflightApproval.kind !== "recovery-reconciliation-approval") {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
    }
    verifyDigest(preflightApproval, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
    const preflightGuard = readApprovalGuardState(preflightApproval);
    if (evidenceSnapshot.ownerId !== ownerId || evidenceSnapshot.approvalId !== approvalId
      || evidenceSnapshot.approvalDigest !== preflightApproval.digest) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_BINDING_MISMATCH", "Evidence tidak terikat pada approval ini", 409);
    }
    const priorResolution = (preflightGuard.mutationResolutions || []).find(item => item.evidenceId === evidenceId);
    let resolutionClaimId;
    if (priorResolution) {
      resolutionClaimId = priorResolution.claimId;
      if (resolutionClaimId !== evidenceSnapshot.claimId || priorResolution.outcome !== evidenceSnapshot.outcome) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_BINDING_MISMATCH", "Riwayat resolusi tidak cocok dengan evidence", 409);
      }
      await appendMutationOutcomeLedgerEvent(ownerId, ledgerEventFromResolution("claim_resolution_started", preflightApproval,
        { ...evidenceSnapshot, id: evidence.id, digest: evidence.digest }, resolutionClaimId, bounded(clock(), 64)));
      await appendMutationOutcomeLedgerEvent(ownerId, ledgerEventFromResolution("claim_resolution_completed", preflightApproval,
        { ...evidenceSnapshot, id: evidence.id, digest: evidence.digest }, resolutionClaimId, priorResolution.resolvedAt,
        priorResolution.outcome === "applied" ? "resolved_applied" : priorResolution.outcome === "not_applied" ? "resolved_not_applied" : "unresolved"));
      return { status: "already_resolved", outcome: priorResolution.outcome, evidenceId, claimId: resolutionClaimId, resolvedAt: priorResolution.resolvedAt };
    }
    const preflightActive = preflightGuard.activeMutation;
    if (!preflightActive || preflightActive.status !== "indeterminate") {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_CLAIM_NOT_RESOLVABLE", "Tidak ada claim indeterminate yang dapat diselesaikan", 409);
    }
    resolutionClaimId = claimIdFor(ownerId, approvalId, preflightActive);
    if (evidenceSnapshot.claimId !== resolutionClaimId || evidenceSnapshot.idempotencyKey !== preflightActive.idempotencyKey
      || evidenceSnapshot.actionId !== preflightActive.actionId || evidenceSnapshot.intentDigest !== preflightActive.intentDigest
      || evidenceSnapshot.planDigest !== preflightActive.planDigest
      || evidenceSnapshot.preconditionBindingDigest !== preflightActive.preconditionBindingDigest
      || evidenceSnapshot.claimStartedAt !== preflightActive.startedAt) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_BINDING_MISMATCH", "Evidence tidak cocok dengan claim aktif", 409);
    }
    await appendMutationOutcomeLedgerEvent(ownerId, ledgerEventFromResolution("claim_resolution_started", preflightApproval,
      { ...evidenceSnapshot, id: evidence.id, digest: evidence.digest }, resolutionClaimId, bounded(clock(), 64)));
    const result = await store.mutateEvidence(ownerId, approvalId, async current => {
      if (!current || current.kind !== "recovery-reconciliation-approval") {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
      }
      verifyDigest(current, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
      const guard = readApprovalGuardState(current);
      const prior = (guard.mutationResolutions || []).find(item => item.evidenceId === evidenceId);
      if (prior) return { write: false, result: { status: "already_resolved", outcome: prior.outcome, evidenceId, claimId: prior.claimId, resolvedAt: prior.resolvedAt } };
      if (evidenceSnapshot.ownerId !== ownerId || evidenceSnapshot.approvalId !== approvalId
        || evidenceSnapshot.approvalDigest !== current.digest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_BINDING_MISMATCH", "Evidence tidak terikat pada approval ini", 409);
      }
      const active = guard.activeMutation;
      if (!active || active.status !== "indeterminate") {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_CLAIM_NOT_RESOLVABLE", "Tidak ada claim indeterminate yang dapat diselesaikan", 409);
      }
      const claimId = claimIdFor(ownerId, approvalId, active);
      if (evidenceSnapshot.claimId !== claimId || evidenceSnapshot.idempotencyKey !== active.idempotencyKey
        || evidenceSnapshot.actionId !== active.actionId || evidenceSnapshot.intentDigest !== active.intentDigest
        || evidenceSnapshot.planDigest !== active.planDigest
        || evidenceSnapshot.preconditionBindingDigest !== active.preconditionBindingDigest
        || evidenceSnapshot.claimStartedAt !== active.startedAt) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_BINDING_MISMATCH", "Evidence tidak cocok dengan claim aktif", 409);
      }
      if (guard.mutationResolutions.length >= MAX_MUTATION_RESOLUTIONS) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_RESOLUTION_LIMIT", "Batas riwayat resolusi mutasi tercapai", 409);
      }
      const resolvedAt = bounded(clock(), 64);
      if (!Number.isFinite(Date.parse(resolvedAt))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock resolusi tidak valid", 500);
      const outcome = evidenceSnapshot.outcome;
      let activeMutation = active;
      let consumedActions = guard.consumedActions;
      if (outcome === "applied") {
        if (guard.consumedActions.some(item => item.actionId === active.actionId)) {
          throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_ACTION_ALREADY_CONSUMED", "Action telah tercatat sebagai consumed", 409);
        }
        if (guard.consumedActions.length >= MAX_CONSUMED_ACTIONS) {
          throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_ACTION_LIMIT", "Batas action yang dapat dikonsumsi approval telah tercapai", 409);
        }
        consumedActions = [...guard.consumedActions, {
          actionId: active.actionId, intentDigest: active.intentDigest, consumedAt: resolvedAt,
          idempotencyKey: active.idempotencyKey, claimId
        }];
        activeMutation = null;
      } else if (outcome === "not_applied") {
        activeMutation = null;
      } else {
        activeMutation = { ...active, status: "indeterminate", lastResolutionAt: resolvedAt,
          lastResolutionEvidenceId: evidenceId, resolutionOutcome: "unresolved" };
      }
      const historyEntry = { claimId, evidenceId, outcome, resolvedAt, actionId: active.actionId, idempotencyKey: active.idempotencyKey };
      const nextGuard = {
        ...guard, revision: guard.revision + 1, activeMutation, consumedActions,
        mutationResolutions: [...guard.mutationResolutions, historyEntry],
        lastMutation: { status: outcome === "applied" ? "resolved_applied" : outcome === "not_applied" ? "resolved_not_applied" : "outcome_unresolved",
          actionId: active.actionId, at: resolvedAt, idempotencyKey: active.idempotencyKey, claimId, evidenceId }
      };
      return {
        value: { ...current, ...withApprovalGuardState(ownerId, current.id, nextGuard) },
        result: { status: outcome === "applied" ? "resolved_applied" : outcome === "not_applied" ? "resolved_not_applied" : "unresolved",
          outcome, approvalId, evidenceId, claimId, actionId: active.actionId, resolvedAt,
          actionConsumed: outcome === "applied", retryMayBeConsidered: outcome === "not_applied",
          automaticRetryAllowed: false, readOnly: false }
      };
    });
    let completedResult = result;
    if (result?.status === "already_resolved") {
      const latest = await store.getEvidence(ownerId, approvalId);
      const latestGuard = readApprovalGuardState(latest);
      const prior = (latestGuard.mutationResolutions || []).find(item => item.evidenceId === evidenceId);
      if (prior) completedResult = { ...result, claimId: prior.claimId, resolvedAt: prior.resolvedAt, outcome: prior.outcome };
    }
    await appendMutationOutcomeLedgerEvent(ownerId, ledgerEventFromResolution("claim_resolution_completed", preflightApproval,
      { ...evidenceSnapshot, id: evidence.id, digest: evidence.digest }, completedResult.claimId || resolutionClaimId,
      completedResult.resolvedAt || bounded(clock(), 64), completedResult.outcome === "applied" ? "resolved_applied"
        : completedResult.outcome === "not_applied" ? "resolved_not_applied" : completedResult.status === "unresolved" ? "unresolved"
          : completedResult.status));
    return structuredClone(completedResult);
  }

  function mutationOutcomeLedgerId(ownerId) {
    return `mutation-outcome-ledger-${sha256(canonical({ domain: "agentic-ai-v4-mutation-outcome-ledger", ownerId: bounded(ownerId) })).slice(0, 32)}`;
  }

  function mutationOutcomeLedgerGenesis(ownerId) {
    return sha256(canonical({ domain: "agentic-ai-v4-mutation-outcome-ledger-genesis", ownerId: bounded(ownerId), schemaVersion: 1 }));
  }

  function ledgerEntryHash(entry) {
    const { hash, ...body } = entry;
    return sha256(canonical(body));
  }

  function verifyMutationOutcomeLedgerRecord(record, ownerId) {
    const code = "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_INTEGRITY_FAILED";
    const fail = () => { throw new AgenticError(code, "Mutation outcome ledger chain atau digest tidak valid", 409); };
    if (!record || record.kind !== "recovery-reconciliation-mutation-outcome-ledger" || record.ownerId !== ownerId
      || record.id !== mutationOutcomeLedgerId(ownerId) || !record.snapshot || typeof record.snapshot !== "object"
      || record.snapshot.schemaVersion !== 1 || record.snapshot.ownerId !== ownerId
      || !Array.isArray(record.snapshot.entries) || record.snapshot.entries.length > MAX_MUTATION_OUTCOME_LEDGER_ENTRIES
      || record.snapshot.revision !== record.snapshot.entries.length || record.snapshot.truncated !== false
      || record.digest !== sha256(canonical(record.snapshot))) fail();
    let previousHash = mutationOutcomeLedgerGenesis(ownerId);
    const eventIds = new Set();
    for (let index = 0; index < record.snapshot.entries.length; index += 1) {
      const entry = record.snapshot.entries[index];
      if (!entry || typeof entry !== "object" || entry.ownerId !== ownerId
        || entry.sequence !== index + 1 || entry.previousHash !== previousHash
        || !isDigest(entry.hash) || entry.hash !== ledgerEntryHash(entry)
        || typeof entry.eventId !== "string" || !/^[a-f0-9]{64}$/.test(entry.eventId)
        || entry.eventId !== sha256(canonical({ ownerId: entry.ownerId, eventType: entry.eventType, approvalId: entry.approvalId,
          evidenceId: entry.evidenceId ?? null, claimId: entry.claimId ?? null }))
        || eventIds.has(entry.eventId)
        || !["outcome_evidence_captured", "claim_resolution_started", "claim_resolution_completed"].includes(entry.eventType)
        || entry.schemaVersion !== 1 || typeof entry.approvalId !== "string" || !entry.approvalId
        || typeof entry.approvalDigest !== "string" || !isDigest(entry.approvalDigest)
        || (entry.evidenceDigest !== null && !isDigest(entry.evidenceDigest))
        || (entry.idempotencyKeyDigest !== null && !isDigest(entry.idempotencyKeyDigest))
        || (entry.intentDigest !== null && !isDigest(entry.intentDigest))
        || (entry.preconditionBindingDigest !== null && !isDigest(entry.preconditionBindingDigest))
        || (entry.recoveryMethod != null && !["reconstructed_from_evidence", "reconstructed_from_approval_history"].includes(entry.recoveryMethod))
        || typeof entry.occurredAt !== "string" || !Number.isFinite(Date.parse(entry.occurredAt))) fail();
      eventIds.add(entry.eventId);
      previousHash = entry.hash;
    }
    if (record.snapshot.headHash !== previousHash) fail();
    return record.snapshot;
  }

  function makeMutationOutcomeLedgerEvent(input) {
    const event = {
      schemaVersion: 1,
      ownerId: bounded(input.ownerId),
      eventType: input.eventType,
      approvalId: bounded(input.approvalId),
      approvalDigest: bounded(input.approvalDigest, 64),
      evidenceId: input.evidenceId == null ? null : bounded(input.evidenceId),
      evidenceDigest: input.evidenceDigest == null ? null : bounded(input.evidenceDigest, 64),
      claimId: input.claimId == null ? null : bounded(input.claimId, 80),
      idempotencyKeyDigest: input.idempotencyKeyDigest == null ? null : bounded(input.idempotencyKeyDigest, 64),
      actionId: input.actionId == null ? null : bounded(input.actionId, 80),
      intentDigest: input.intentDigest == null ? null : bounded(input.intentDigest, 64),
      preconditionBindingDigest: input.preconditionBindingDigest == null ? null : bounded(input.preconditionBindingDigest, 64),
      outcome: input.outcome == null ? null : bounded(input.outcome, 24),
      resolutionStatus: input.resolutionStatus == null ? null : bounded(input.resolutionStatus, 40),
      recoveryMethod: input.recoveryMethod == null ? null : bounded(input.recoveryMethod, 60),
      occurredAt: bounded(input.occurredAt, 64)
    };
    if (!Number.isFinite(Date.parse(event.occurredAt)) || !event.approvalId || !isDigest(event.approvalDigest)
      || !["outcome_evidence_captured", "claim_resolution_started", "claim_resolution_completed"].includes(event.eventType)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_EVENT_INVALID", "Ledger event tidak lengkap atau tidak valid", 400);
    }
    if (event.eventType !== "outcome_evidence_captured" && (!event.evidenceId || !event.claimId || !["applied", "not_applied", "unresolved"].includes(event.outcome))) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_EVENT_INVALID", "Ledger resolution event tidak terikat pada evidence dan claim", 400);
    }
    if (event.eventType === "outcome_evidence_captured" && (!event.evidenceId || !isDigest(event.evidenceDigest) || !event.claimId
      || !["applied", "not_applied", "unresolved"].includes(event.outcome))) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_EVENT_INVALID", "Ledger capture event tidak terikat pada evidence", 400);
    }
    event.eventId = sha256(canonical({ ownerId: event.ownerId, eventType: event.eventType, approvalId: event.approvalId,
      evidenceId: event.evidenceId, claimId: event.claimId }));
    return event;
  }

  async function appendMutationOutcomeLedgerEvent(ownerId, input) {
    assertOwner(ownerId);
    const event = makeMutationOutcomeLedgerEvent({ ...input, ownerId });
    const ledgerId = mutationOutcomeLedgerId(ownerId);
    try {
      return await store.mutateEvidence(ownerId, ledgerId, async current => {
        let snapshot;
        if (current) {
          snapshot = verifyMutationOutcomeLedgerRecord(current, ownerId);
          const prior = snapshot.entries.find(item => item.eventId === event.eventId);
          if (prior) {
            const stableFields = ["schemaVersion", "ownerId", "eventType", "eventId", "approvalId", "approvalDigest", "evidenceId", "evidenceDigest", "claimId", "idempotencyKeyDigest", "actionId", "intentDigest", "preconditionBindingDigest", "outcome", "resolutionStatus"];
            if (stableFields.some(field => (prior[field] ?? null) !== (event[field] ?? null))) {
              throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_EVENT_COLLISION", "Ledger event ID telah digunakan oleh event dengan binding berbeda", 409);
            }
            return { write: false, result: structuredClone(prior) };
          }
        } else {
          const genesis = mutationOutcomeLedgerGenesis(ownerId);
          snapshot = { schemaVersion: 1, ownerId: bounded(ownerId), revision: 0, headHash: genesis, entries: [], truncated: false };
        }
        if (snapshot.entries.length >= MAX_MUTATION_OUTCOME_LEDGER_ENTRIES) {
          throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_CAPACITY_REACHED", "Ledger mencapai batas kapasitas; tidak ada event yang dibuang otomatis", 409);
        }
        const body = { ...event, sequence: snapshot.revision + 1, previousHash: snapshot.headHash };
        const entry = { ...body, hash: sha256(canonical(body)) };
        const nextSnapshot = { ...snapshot, revision: snapshot.revision + 1, headHash: entry.hash, entries: [...snapshot.entries, entry] };
        const record = {
          id: ledgerId, ownerId, kind: "recovery-reconciliation-mutation-outcome-ledger",
          createdAt: current?.createdAt || event.occurredAt, digest: sha256(canonical(nextSnapshot)), snapshot: nextSnapshot,
          provenance: { source: "recovery-audit-planning", schemaVersion: 1, appendOnly: true }
        };
        return { value: record, result: structuredClone(entry) };
      });
    } catch (error) {
      if (error?.code === "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_INTEGRITY_FAILED") {
        try {
          await recordMutationOutcomeLedgerEscalation(ownerId, [{ code: "MUTATION_OUTCOME_LEDGER_INTEGRITY_FAILED", severity: "error", entityType: "ledger", entityId: ledgerId }], null);
        } catch { /* Fail closed with the original ledger-integrity error. */ }
      }
      throw error;
    }
  }

  function ledgerEventFromOutcomeEvidence(record) {
    const snapshot = record.snapshot;
    return {
      eventType: "outcome_evidence_captured", approvalId: snapshot.approvalId, approvalDigest: snapshot.approvalDigest,
      evidenceId: record.id, evidenceDigest: record.digest, claimId: snapshot.claimId,
      idempotencyKeyDigest: sha256(String(snapshot.idempotencyKey || "")), actionId: snapshot.actionId,
      intentDigest: snapshot.intentDigest, preconditionBindingDigest: snapshot.preconditionBindingDigest,
      outcome: snapshot.outcome, occurredAt: snapshot.capturedAt
    };
  }

  function ledgerEventFromResolution(eventType, approval, evidenceSnapshot, claimId, occurredAt, resolutionStatus = null) {
    return {
      eventType, approvalId: approval.id, approvalDigest: approval.digest, evidenceId: evidenceSnapshot.id || null,
      evidenceDigest: evidenceSnapshot.digest || null, claimId,
      idempotencyKeyDigest: sha256(String(evidenceSnapshot.idempotencyKey || "")), actionId: evidenceSnapshot.actionId,
      intentDigest: evidenceSnapshot.intentDigest, preconditionBindingDigest: evidenceSnapshot.preconditionBindingDigest,
      outcome: evidenceSnapshot.outcome, resolutionStatus, occurredAt
    };
  }

  async function getMutationOutcomeLedger(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, mutationOutcomeLedgerId(ownerId));
    if (!record) return { status: "empty", revision: 0, entryCount: 0, headHash: mutationOutcomeLedgerGenesis(ownerId), truncated: false, readOnly: true };
    const snapshot = verifyMutationOutcomeLedgerRecord(record, ownerId);
    return { status: "healthy", revision: snapshot.revision, entryCount: snapshot.entries.length,
      headHash: snapshot.headHash, firstSequence: snapshot.entries.length ? 1 : null,
      lastSequence: snapshot.entries.length || null, truncated: snapshot.truncated, readOnly: true };
  }

  async function listMutationOutcomeLedgerEntries(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 200);
    const offset = boundedInteger(options.offset, 0, 0, MAX_MUTATION_OUTCOME_LEDGER_ENTRIES);
    const record = await store.getEvidence(ownerId, mutationOutcomeLedgerId(ownerId));
    if (!record) return { items: [], total: 0, limit, offset, truncated: false, status: "empty", readOnly: true };
    const snapshot = verifyMutationOutcomeLedgerRecord(record, ownerId);
    return { items: snapshot.entries.slice(offset, offset + limit).map(item => structuredClone(item)), total: snapshot.entries.length,
      limit, offset, truncated: offset + limit < snapshot.entries.length, status: "healthy", headHash: snapshot.headHash, readOnly: true };
  }

  async function auditMutationOutcomeLedger(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 100, 1, 200);
    const all = await store.listEvidence(ownerId);
    const evidenceRecords = all.filter(item => item.kind === "recovery-reconciliation-mutation-outcome-evidence");
    const approvals = all.filter(item => item.kind === "recovery-reconciliation-approval");
    const findings = [];
    let totalFindings = 0;
    let findingsTruncated = false;
    let hasError = false;
    let hasWarning = false;
    const add = (code, severity, entityType, entityId, relatedId = null) => {
      totalFindings += 1;
      if (severity === "error") hasError = true;
      if (severity === "warning") hasWarning = true;
      if (findings.length >= MAX_MUTATION_OUTCOME_LEDGER_FINDINGS) { findingsTruncated = true; return; }
      findings.push({ code, severity, entityType, entityId: bounded(entityId), relatedId: relatedId == null ? null : bounded(relatedId),
        message: bounded(code.toLowerCase().replaceAll("_", " "), MAX_MESSAGE) });
    };
    const record = await store.getEvidence(ownerId, mutationOutcomeLedgerId(ownerId));
    let snapshot = null;
    if (record) {
      try { snapshot = verifyMutationOutcomeLedgerRecord(record, ownerId); }
      catch { add("MUTATION_OUTCOME_LEDGER_INTEGRITY_FAILED", "error", "ledger", record.id); }
    }
    const entries = snapshot?.entries || [];
    const captures = entries.filter(item => item.eventType === "outcome_evidence_captured");
    const starts = entries.filter(item => item.eventType === "claim_resolution_started");
    const completions = entries.filter(item => item.eventType === "claim_resolution_completed");
    const captureById = new Map();
    for (const entry of captures) {
      if (captureById.has(entry.evidenceId)) add("DUPLICATE_EVIDENCE_CAPTURE_EVENT", "error", "evidence", entry.evidenceId);
      else captureById.set(entry.evidenceId, entry);
      const linked = evidenceRecords.find(item => item.id === entry.evidenceId);
      if (!linked) add("LEDGER_EVIDENCE_REFERENCE_MISSING", "error", "ledger_entry", entry.eventId, entry.evidenceId);
      else if (linked.digest !== entry.evidenceDigest || linked.snapshot?.claimId !== entry.claimId
        || linked.snapshot?.approvalId !== entry.approvalId || linked.snapshot?.outcome !== entry.outcome
        || linked.snapshot?.actionId !== entry.actionId || linked.snapshot?.intentDigest !== entry.intentDigest
        || linked.snapshot?.preconditionBindingDigest !== entry.preconditionBindingDigest
        || sha256(String(linked.snapshot?.idempotencyKey || "")) !== entry.idempotencyKeyDigest) {
        add("LEDGER_EVIDENCE_BINDING_MISMATCH", "error", "evidence", linked.id, entry.eventId);
      }
      const linkedApproval = approvals.find(item => item.id === entry.approvalId);
      if (!linkedApproval) add("LEDGER_APPROVAL_REFERENCE_MISSING", "error", "ledger_entry", entry.eventId, entry.approvalId);
      else if (linkedApproval.digest !== entry.approvalDigest) add("LEDGER_APPROVAL_BINDING_MISMATCH", "error", "approval", linkedApproval.id, entry.eventId);
    }
    for (const evidence of evidenceRecords) {
      try { verifyDigest(evidence, "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED"); }
      catch { add("OUTCOME_EVIDENCE_INTEGRITY_FAILED", "error", "evidence", evidence.id); continue; }
      const captured = captureById.get(evidence.id);
      if (!captured) add("OUTCOME_EVIDENCE_MISSING_FROM_LEDGER", "error", "evidence", evidence.id);
      else if (captured.evidenceDigest !== evidence.digest) add("OUTCOME_EVIDENCE_LEDGER_DIGEST_MISMATCH", "error", "evidence", evidence.id, captured.eventId);
    }
    const outcomesByClaim = new Map();
    for (const evidence of evidenceRecords) {
      const key = canonical({ approvalId: evidence.snapshot?.approvalId, claimId: evidence.snapshot?.claimId });
      if (!outcomesByClaim.has(key)) outcomesByClaim.set(key, new Map());
      const byOutcome = outcomesByClaim.get(key);
      if (byOutcome.has(evidence.snapshot?.outcome) === false) byOutcome.set(evidence.snapshot?.outcome, evidence.id);
      if (byOutcome.size > 1) add("CONFLICTING_OUTCOME_EVIDENCE_FOR_CLAIM", "error", "claim", evidence.snapshot?.claimId, evidence.id);
    }
    const approvalById = new Map(approvals.map(item => [item.id, item]));
    const guardByApprovalId = new Map();
    const resolutionKey = (approvalId, evidenceId, claimId, outcome) => canonical({ approvalId, evidenceId, claimId, outcome });
    const completionKeys = new Set(completions.map(item => resolutionKey(item.approvalId, item.evidenceId, item.claimId, item.outcome)));
    const startKeys = new Set(starts.map(item => resolutionKey(item.approvalId, item.evidenceId, item.claimId, item.outcome)));
    const captureSequence = new Map(captures.map(item => [item.evidenceId, item.sequence]));
    const startSequence = new Map(starts.map(item => [resolutionKey(item.approvalId, item.evidenceId, item.claimId, item.outcome), item.sequence]));
    for (const start of starts) {
      if ((captureSequence.get(start.evidenceId) ?? Number.MAX_SAFE_INTEGER) >= start.sequence) {
        add("LEDGER_EVENT_ORDER_INVALID", "error", "ledger_entry", start.eventId, start.evidenceId);
      }
    }
    for (const completion of completions) {
      const key = resolutionKey(completion.approvalId, completion.evidenceId, completion.claimId, completion.outcome);
      if ((startSequence.get(key) ?? Number.MAX_SAFE_INTEGER) >= completion.sequence
        || (captureSequence.get(completion.evidenceId) ?? Number.MAX_SAFE_INTEGER) >= completion.sequence) {
        add("LEDGER_EVENT_ORDER_INVALID", "error", "ledger_entry", completion.eventId, completion.evidenceId);
      }
    }
    for (const entry of [...starts, ...completions]) {
      const approval = approvalById.get(entry.approvalId);
      if (!approval) add("LEDGER_APPROVAL_REFERENCE_MISSING", "error", "ledger_entry", entry.eventId, entry.approvalId);
      else if (approval.digest !== entry.approvalDigest) add("LEDGER_APPROVAL_BINDING_MISMATCH", "error", "approval", approval.id, entry.eventId);
      const evidence = evidenceRecords.find(item => item.id === entry.evidenceId);
      if (!evidence) add("LEDGER_RESOLUTION_EVIDENCE_MISSING", "error", "ledger_entry", entry.eventId, entry.evidenceId);
      else if (evidence.digest !== entry.evidenceDigest || evidence.snapshot?.claimId !== entry.claimId
        || evidence.snapshot?.approvalId !== entry.approvalId || evidence.snapshot?.outcome !== entry.outcome
        || evidence.snapshot?.actionId !== entry.actionId || evidence.snapshot?.intentDigest !== entry.intentDigest
        || evidence.snapshot?.preconditionBindingDigest !== entry.preconditionBindingDigest
        || sha256(String(evidence.snapshot?.idempotencyKey || "")) !== entry.idempotencyKeyDigest) {
        add("LEDGER_RESOLUTION_EVIDENCE_BINDING_MISMATCH", "error", "evidence", evidence.id, entry.eventId);
      }
    }
    for (const approval of approvals) {
      let guard;
      try {
        verifyDigest(approval, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
        guard = readApprovalGuardState(approval);
        guardByApprovalId.set(approval.id, guard);
      } catch {
        guardByApprovalId.set(approval.id, null);
        add("APPROVAL_GUARD_INTEGRITY_FAILED", "error", "approval", approval.id);
        continue;
      }
      const seenResolutionKeys = new Set();
      for (const resolution of guard.mutationResolutions || []) {
        const key = resolutionKey(approval.id, resolution.evidenceId, resolution.claimId, resolution.outcome);
        if (seenResolutionKeys.has(key)) add("DUPLICATE_APPROVAL_RESOLUTION_HISTORY", "error", "approval", approval.id, resolution.evidenceId);
        seenResolutionKeys.add(key);
        const completion = completions.find(item => resolutionKey(item.approvalId, item.evidenceId, item.claimId, item.outcome) === key);
        if (!completion) add("CLAIM_RESOLUTION_MISSING_FROM_LEDGER", "error", "approval", approval.id, resolution.evidenceId);
        else if (completion.occurredAt !== resolution.resolvedAt) add("CLAIM_RESOLUTION_LEDGER_METADATA_MISMATCH", "error", "approval", approval.id, resolution.evidenceId);
      }
    }
    for (const start of starts) {
      const key = resolutionKey(start.approvalId, start.evidenceId, start.claimId, start.outcome);
      if (!completionKeys.has(key)) {
        const guard = guardByApprovalId.get(start.approvalId);
        const resolved = guard && (guard.mutationResolutions || []).some(item =>
          item.evidenceId === start.evidenceId && item.claimId === start.claimId && item.outcome === start.outcome);
        add(resolved ? "RESOLUTION_COMPLETION_EVENT_MISSING" : "RESOLUTION_INTENT_UNFINALIZED",
          resolved ? "error" : "warning", "ledger_entry", start.eventId, start.evidenceId);
      }
    }
    for (const completion of completions) {
      const key = resolutionKey(completion.approvalId, completion.evidenceId, completion.claimId, completion.outcome);
      if (!startKeys.has(key)) add("RESOLUTION_COMPLETION_WITHOUT_INTENT", "error", "ledger_entry", completion.eventId, completion.evidenceId);
      const guard = guardByApprovalId.get(completion.approvalId);
      const resolved = guard && (guard.mutationResolutions || []).some(item =>
        item.evidenceId === completion.evidenceId && item.claimId === completion.claimId && item.outcome === completion.outcome);
      if (!resolved) add("LEDGER_RESOLUTION_WITHOUT_APPROVAL_HISTORY", "error", "ledger_entry", completion.eventId, completion.approvalId);
    }
    if (!record && (evidenceRecords.length || approvals.some(item => {
      try { return (readApprovalGuardState(item).mutationResolutions || []).length > 0; } catch { return true; }
    }))) add("MUTATION_OUTCOME_LEDGER_MISSING", "error", "ledger", mutationOutcomeLedgerId(ownerId));
    const severityRank = { error: 0, warning: 1, info: 2 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.code.localeCompare(b.code)
      || a.entityId.localeCompare(b.entityId) || String(a.relatedId || "").localeCompare(String(b.relatedId || "")));
    const returned = findings.slice(0, limit);
    const status = hasError ? "unhealthy" : hasWarning ? "degraded" : record ? "healthy" : "empty";
    return {
      status, ownerId: bounded(ownerId), checkedAt: bounded(clock(), 64),
      ledger: { exists: Boolean(record), revision: snapshot?.revision ?? null, entryCount: snapshot?.entries.length ?? 0,
        headHash: snapshot?.headHash ?? null, chainVerified: Boolean(snapshot) },
      checked: { evidenceRecords: evidenceRecords.length, approvals: approvals.length, ledgerEntries: entries.length },
      findings: returned, totalFindings, truncated: findingsTruncated || totalFindings > returned.length,
      readOnly: true, automaticRepairAllowed: false, automaticExecutionAllowed: false
    };
  }

  function mutationOutcomeLedgerPolicyId(ownerId) {
    return `mutation-outcome-ledger-policy-${sha256(canonical({ domain: "agentic-ai-v4-mutation-outcome-ledger-policy", ownerId: bounded(ownerId) })).slice(0, 32)}`;
  }

  function emptyMutationOutcomeLedgerPolicy(ownerId) {
    return { schemaVersion: 1, ownerId: bounded(ownerId), revision: 0, status: "clear", activeIncident: null, history: [] };
  }

  function verifyPolicyAttestationReceipt(receipt, ownerId, entry) {
    if (!receipt || typeof receipt !== "object" || !receipt.payload || typeof receipt.payload !== "object"
      || typeof receipt.signature !== "string" || !isDigest(receipt.attestationDigest)) return false;
    const payload = receipt.payload;
    if (receipt.attestationDigest !== sha256(canonical({ payload, signature: receipt.signature }))
      || payload.schemaVersion !== 1 || payload.purpose !== "agentic-v4-mutation-outcome-ledger-clearance"
      || payload.ownerId !== ownerId || payload.incidentId !== entry.incidentId
      || payload.policyRevision !== entry.priorPolicyRevision || payload.attestationId !== receipt.attestationId
      || payload.keyId !== receipt.keyId
      || ((payload.trustRevision !== undefined || payload.trustDigest !== undefined)
        && (!Number.isSafeInteger(payload.trustRevision) || payload.trustRevision < 0 || !isDigest(payload.trustDigest)))
      || payload.ledgerRevision !== entry.ledgerRevision
      || payload.ledgerHeadHash !== entry.ledgerHeadHash || payload.ledgerDigest !== entry.ledgerDigest
      || payload.auditDigest !== entry.auditDigest || !isDigest(payload.auditDigest)
      || !Number.isSafeInteger(payload.ledgerRevision) || payload.ledgerRevision < 0
      || !isDigest(payload.ledgerHeadHash) || !isDigest(payload.ledgerDigest)
      || typeof payload.nonce !== "string" || payload.nonce.length < 16 || payload.nonce.length > 128
      || !Number.isFinite(Date.parse(payload.issuedAt)) || !Number.isFinite(Date.parse(payload.expiresAt))
      || Date.parse(payload.expiresAt) <= Date.parse(payload.issuedAt)
      || Date.parse(payload.expiresAt) - Date.parse(payload.issuedAt) > MAX_INTEGRITY_ATTESTATION_TTL_MS
      || !verifyIntegrityAttestationSignature(payload, receipt.signature, receipt.keyId)) return false;
    return true;
  }

  function verifyMutationOutcomeLedgerPolicyRecord(record, ownerId) {
    const fail = () => { throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_POLICY_INTEGRITY_FAILED", "Ledger escalation policy state atau quarantine transition tidak valid; mutation boundary tetap ditutup", 409); };
    if (!record || record.kind !== "recovery-reconciliation-mutation-outcome-ledger-policy" || record.ownerId !== ownerId
      || record.id !== mutationOutcomeLedgerPolicyId(ownerId) || !record.snapshot || record.snapshot.schemaVersion !== 1
      || record.snapshot.ownerId !== ownerId || !Number.isSafeInteger(record.snapshot.revision) || record.snapshot.revision < 0
      || !["clear", "quarantined"].includes(record.snapshot.status) || !Array.isArray(record.snapshot.history)
      || record.snapshot.history.length > MAX_MUTATION_OUTCOME_LEDGER_POLICY_HISTORY
      || record.snapshot.revision < record.snapshot.history.length
      || record.digest !== sha256(canonical(record.snapshot))) fail();
    const rank = value => value === "critical" ? 2 : value === "high" ? 1 : 0;
    let historicalActive = null;
    for (const entry of record.snapshot.history) {
      if (!entry || typeof entry !== "object" || typeof entry.incidentId !== "string" || !entry.incidentId
        || !Number.isFinite(Date.parse(entry.at)) || !["opened", "escalated", "acknowledged"].includes(entry.type)) fail();
      if (entry.type === "opened") {
        if (historicalActive || !["high", "critical"].includes(entry.level) || !Array.isArray(entry.reasonCodes)
          || !isDigest(entry.fingerprint)) fail();
        historicalActive = { id: entry.incidentId, level: entry.level };
      } else if (entry.type === "escalated") {
        if (!historicalActive || historicalActive.id !== entry.incidentId || !["high", "critical"].includes(entry.level)
          || rank(entry.level) < rank(historicalActive.level) || !Array.isArray(entry.reasonCodes) || !isDigest(entry.fingerprint)) fail();
        historicalActive.level = entry.level;
      } else {
        if (!historicalActive || historicalActive.id !== entry.incidentId || entry.priorLevel !== historicalActive.level) fail();
        if (historicalActive.level === "critical" && !verifyPolicyAttestationReceipt(entry.attestationReceipt, ownerId, entry)) fail();
        if (historicalActive.level !== "critical" && entry.attestationReceipt != null
          && !verifyPolicyAttestationReceipt(entry.attestationReceipt, ownerId, entry)) fail();
        historicalActive = null;
      }
    }
    if (record.snapshot.status === "clear") {
      if (record.snapshot.activeIncident !== null || historicalActive !== null
        || (record.snapshot.revision === 0 && record.snapshot.history.length !== 0)
        || (record.snapshot.revision > 0 && record.snapshot.history.at(-1)?.type !== "acknowledged")) fail();
    } else {
      const active = record.snapshot.activeIncident;
      if (!active || typeof active.id !== "string" || !["high", "critical"].includes(active.level)
        || active.mutationBlocked !== true || !Array.isArray(active.reasonCodes) || !active.reasonCodes.length
        || !Number.isSafeInteger(active.observationCount) || active.observationCount < 1
        || !Number.isFinite(Date.parse(active.openedAt)) || !Number.isFinite(Date.parse(active.lastDetectedAt))
        || !isDigest(active.lastAuditFingerprint) || active.acknowledgedAt !== null
        || !historicalActive || historicalActive.id !== active.id || historicalActive.level !== active.level
        || !["opened", "escalated"].includes(record.snapshot.history.at(-1)?.type)
        || record.snapshot.history.at(-1)?.incidentId !== active.id
        || canonical(record.snapshot.history.at(-1)?.reasonCodes || []) !== canonical(active.reasonCodes)) fail();
    }
    return record.snapshot;
  }

  function ledgerEscalationLevel(findings) {
    const recoverableGapCodes = new Set([
      "OUTCOME_EVIDENCE_MISSING_FROM_LEDGER", "CLAIM_RESOLUTION_MISSING_FROM_LEDGER",
      "RESOLUTION_COMPLETION_EVENT_MISSING", "RESOLUTION_INTENT_UNFINALIZED", "MUTATION_OUTCOME_LEDGER_MISSING"
    ]);
    return findings.some(item => !recoverableGapCodes.has(item.code) && item.severity !== "warning") ? "critical" : "high";
  }

  function normalizedLedgerEscalationFindings(findings, audit = null) {
    const items = (Array.isArray(findings) ? findings : []).slice(0, MAX_MUTATION_OUTCOME_LEDGER_POLICY_CODES).map(item => ({
      code: bounded(item?.code || "UNKNOWN_LEDGER_INTEGRITY_FINDING", 80),
      severity: item?.severity === "warning" ? "warning" : "error",
      entityType: bounded(item?.entityType || "ledger", 40),
      entityId: bounded(item?.entityId || mutationOutcomeLedgerId("unknown")),
      relatedId: item?.relatedId == null ? null : bounded(item.relatedId)
    }));
    if (audit?.truncated && !items.some(item => item.code === "MUTATION_OUTCOME_LEDGER_AUDIT_TRUNCATED")) {
      items.push({ code: "MUTATION_OUTCOME_LEDGER_AUDIT_TRUNCATED", severity: "error", entityType: "ledger", entityId: "audit", relatedId: null });
    }
    if (!items.length) items.push({ code: "MUTATION_OUTCOME_LEDGER_REQUIRES_REVIEW", severity: "error", entityType: "ledger", entityId: "audit", relatedId: null });
    return items.slice(0, MAX_MUTATION_OUTCOME_LEDGER_POLICY_CODES);
  }

  async function recordMutationOutcomeLedgerEscalation(ownerId, findings, audit = null) {
    assertOwner(ownerId);
    const normalized = normalizedLedgerEscalationFindings(findings, audit);
    const level = ledgerEscalationLevel(normalized);
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock eskalasi ledger tidak valid", 500);
    const policyId = mutationOutcomeLedgerPolicyId(ownerId);
    const fingerprint = sha256(canonical({ ownerId, level, reasons: normalized.map(item => ({ code: item.code, entityType: item.entityType, entityId: item.entityId, relatedId: item.relatedId })).sort((a, b) => canonical(a).localeCompare(canonical(b))),
      ledger: audit?.ledger ? { revision: audit.ledger.revision, headHash: audit.ledger.headHash, chainVerified: audit.ledger.chainVerified } : null,
      truncated: audit?.truncated === true }));
    const incidentId = `ledger-incident-${fingerprint.slice(0, 32)}`;
    return store.mutateEvidence(ownerId, policyId, async current => {
      const previous = current ? verifyMutationOutcomeLedgerPolicyRecord(current, ownerId) : emptyMutationOutcomeLedgerPolicy(ownerId);
      const active = previous.activeIncident;
      const rank = value => value === "critical" ? 2 : value === "high" ? 1 : 0;
      const mergedLevel = active && rank(active.level) > rank(level) ? active.level : level;
      const codes = [...new Set([...(active?.reasonCodes || []), ...normalized.map(item => item.code)])].slice(0, MAX_MUTATION_OUTCOME_LEDGER_POLICY_CODES);
      let nextActive;
      let history = previous.history;
      if (active) {
        nextActive = { ...active, level: mergedLevel, reasonCodes: codes, lastDetectedAt: now,
          observationCount: Math.min(1_000_000, (active.observationCount || 1) + 1), mutationBlocked: true,
          lastAuditFingerprint: fingerprint };
        if (mergedLevel !== active.level || codes.some(code => !active.reasonCodes.includes(code))) {
          if (history.length >= MAX_MUTATION_OUTCOME_LEDGER_POLICY_HISTORY) {
            throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_POLICY_CAPACITY_REACHED", "Riwayat eskalasi penuh; policy tidak boleh memangkas histori", 409);
          }
          history = [...history, { type: "escalated", incidentId: active.id, at: now, level: mergedLevel, reasonCodes: codes, fingerprint }];
        }
      } else {
        if (history.length >= MAX_MUTATION_OUTCOME_LEDGER_POLICY_HISTORY) {
          throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_POLICY_CAPACITY_REACHED", "Riwayat eskalasi penuh; policy tidak boleh memangkas histori", 409);
        }
        nextActive = { id: incidentId, level, reasonCodes: codes, openedAt: now, lastDetectedAt: now,
          observationCount: 1, mutationBlocked: true, lastAuditFingerprint: fingerprint, acknowledgedAt: null };
        history = [...history, { type: "opened", incidentId, at: now, level, reasonCodes: codes, fingerprint }];
      }
      const snapshot = { ...previous, revision: previous.revision + 1, status: "quarantined", activeIncident: nextActive, history };
      const value = { id: policyId, ownerId, kind: "recovery-reconciliation-mutation-outcome-ledger-policy",
        createdAt: current?.createdAt || now, digest: sha256(canonical(snapshot)), snapshot,
        provenance: { source: "recovery-audit-planning", schemaVersion: 1, ownerScoped: true } };
      return { value, result: { status: "quarantined", incident: structuredClone(nextActive), revision: snapshot.revision, readOnly: false } };
    });
  }

  async function readMutationOutcomeLedgerPolicy(ownerId) {
    assertOwner(ownerId);
    await ensureAttestationTrustPolicy(ownerId);
    const record = await store.getEvidence(ownerId, mutationOutcomeLedgerPolicyId(ownerId));
    if (!record) return emptyMutationOutcomeLedgerPolicy(ownerId);
    return verifyMutationOutcomeLedgerPolicyRecord(record, ownerId);
  }

  async function getMutationOutcomeLedgerEscalation(ownerId, options = {}) {
    assertOwner(ownerId);
    const snapshot = await readMutationOutcomeLedgerPolicy(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 100);
    return { status: snapshot.status, ownerId: bounded(ownerId), revision: snapshot.revision,
      activeIncident: snapshot.activeIncident ? structuredClone(snapshot.activeIncident) : null,
      history: snapshot.history.slice(-limit).map(item => structuredClone(item)),
      historyTotal: snapshot.history.length, historyTruncated: snapshot.history.length > limit,
      mutationBlocked: snapshot.status === "quarantined", automaticRepairAllowed: false, readOnly: true };
  }

  function integrityAttestationId(ownerId, attestationId) {
    return `ledger-integrity-attestation-${sha256(canonical({ domain: "agentic-v4-ledger-integrity-attestation", ownerId, attestationId })).slice(0, 32)}`;
  }

  function emptyLedgerAttestationDigest(ownerId) {
    return sha256(canonical({ domain: "agentic-v4-empty-ledger-attestation-binding", ownerId,
      revision: 0, headHash: mutationOutcomeLedgerGenesis(ownerId), truncated: false }));
  }

  function ledgerAttestationAuditDigest(audit) {
    return sha256(canonical({ domain: "agentic-v4-ledger-integrity-audit-attestation", schemaVersion: 1,
      ownerId: audit.ownerId, status: audit.status, ledger: audit.ledger, checked: audit.checked,
      findings: audit.findings, totalFindings: audit.totalFindings, truncated: audit.truncated }));
  }

  async function currentLedgerAttestationContext(ownerId, incidentId) {
    const policy = await readMutationOutcomeLedgerPolicy(ownerId);
    const active = policy.activeIncident;
    if (policy.status !== "quarantined" || !active || active.id !== incidentId) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_INCIDENT_MISMATCH", "Attestation hanya berlaku untuk incident quarantine yang aktif", 409);
    }
    const audit = await auditMutationOutcomeLedger(ownerId, { limit: MAX_MUTATION_OUTCOME_LEDGER_FINDINGS });
    if (audit.findings.length || audit.truncated || !["healthy", "empty"].includes(audit.status)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_AUDIT_NOT_CLEAN", "Attestation clearance memerlukan audit ledger bersih dan lengkap", 409,
        { status: audit.status, findingCount: audit.totalFindings, truncated: audit.truncated });
    }
    const record = await store.getEvidence(ownerId, mutationOutcomeLedgerId(ownerId));
    let ledgerBinding;
    if (record) {
      const snapshot = verifyMutationOutcomeLedgerRecord(record, ownerId);
      if (audit.ledger.revision !== snapshot.revision || audit.ledger.headHash !== snapshot.headHash || audit.ledger.chainVerified !== true) {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_CHANGED", "Ledger berubah ketika audit attestation sedang dihitung", 409);
      }
      ledgerBinding = { revision: snapshot.revision, headHash: snapshot.headHash, digest: record.digest };
    } else {
      if (audit.status !== "empty" || audit.findings.length || audit.truncated) {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_CHANGED", "Ledger kosong tidak cocok dengan hasil audit terkini", 409);
      }
      ledgerBinding = { revision: 0, headHash: mutationOutcomeLedgerGenesis(ownerId), digest: emptyLedgerAttestationDigest(ownerId) };
    }
    const policyAfter = await readMutationOutcomeLedgerPolicy(ownerId);
    if (policyAfter.status !== "quarantined" || policyAfter.revision !== policy.revision
      || policyAfter.activeIncident?.id !== incidentId || policyAfter.activeIncident?.level !== active.level) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_CHANGED", "Quarantine policy berubah ketika audit attestation sedang dihitung", 409);
    }
    return { policy, incident: active, audit, ledgerBinding, auditDigest: ledgerAttestationAuditDigest(audit) };
  }

  function validateAttestationPayloadTime(payload, now, { allowExpired = false } = {}) {
    const issued = Date.parse(payload?.issuedAt);
    const expires = Date.parse(payload?.expiresAt);
    const current = Date.parse(now);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || !Number.isFinite(current)
      || expires <= issued || expires - issued > MAX_INTEGRITY_ATTESTATION_TTL_MS
      || issued > current + 30_000 || current - issued > MAX_INTEGRITY_ATTESTATION_TTL_MS
      || (!allowExpired && expires <= current)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_EXPIRED_OR_INVALID", "Attestation tidak valid atau sudah kedaluwarsa", 409);
    }
  }

  function validateAttestationRecord(record, ownerId) {
    if (!record || record.kind !== "recovery-reconciliation-ledger-integrity-attestation" || record.ownerId !== ownerId
      || record.id !== integrityAttestationId(ownerId, record.snapshot?.payload?.attestationId) || !record.snapshot
      || !["issued", "verified"].includes(record.snapshot.status)
      || record.digest !== sha256(canonical(record.snapshot))) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_INTEGRITY_FAILED", "Attestation record tidak valid", 409);
    }
    const payload = record.snapshot.payload;
    if (!payload || payload.schemaVersion !== 1 || payload.purpose !== "agentic-v4-mutation-outcome-ledger-clearance"
      || payload.ownerId !== ownerId || payload.attestationId !== record.snapshot.payload.attestationId
      || typeof payload.incidentId !== "string" || !Number.isSafeInteger(payload.policyRevision) || payload.policyRevision < 1
      || !Number.isSafeInteger(payload.ledgerRevision) || payload.ledgerRevision < 0
      || !isDigest(payload.ledgerHeadHash) || !isDigest(payload.ledgerDigest) || !isDigest(payload.auditDigest)
      || typeof payload.nonce !== "string" || payload.nonce.length < 16 || payload.nonce.length > 128
      || typeof payload.keyId !== "string" || !trustedIntegrityAttestationKeys.has(payload.keyId)
      || ((payload.trustRevision !== undefined || payload.trustDigest !== undefined)
        && (!Number.isSafeInteger(payload.trustRevision) || payload.trustRevision < 0 || !isDigest(payload.trustDigest)))) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_INTEGRITY_FAILED", "Payload attestation tidak memenuhi skema tepercaya", 409);
    }
    if (record.snapshot.status === "verified") {
      if (typeof record.snapshot.signature !== "string" || !isDigest(record.snapshot.attestationDigest)
        || record.snapshot.attestationDigest !== sha256(canonical({ payload, signature: record.snapshot.signature }))
        || !verifyIntegrityAttestationSignature(payload, record.snapshot.signature, payload.keyId)
        || !Number.isFinite(Date.parse(record.snapshot.verifiedAt))) {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_SIGNATURE_INVALID", "Signature attestation tidak valid", 409);
      }
    } else if (record.snapshot.signature != null || record.snapshot.attestationDigest != null) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_INTEGRITY_FAILED", "Challenge yang belum diverifikasi tidak boleh berisi signature", 409);
    }
    return record.snapshot;
  }

  async function createMutationOutcomeLedgerAttestationChallenge(ownerId, incidentId, options = {}) {
    assertOwner(ownerId);
    assertRecordId(incidentId, "incidentId");
    const keyId = typeof options.keyId === "string" ? options.keyId : "";
    const trustSnapshot = await ensureAttestationTrustPolicy(ownerId);
    await assertExternalTrustAnchorCurrent(ownerId, trustSnapshot);
    if (!activeTrustKey(trustSnapshot, keyId)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_TRUST_NOT_CONFIGURED", "Tidak ada public key Ed25519 aktif dan tepercaya untuk keyId ini", 503);
    }
    const trustDigest = trustSnapshotDigest(trustSnapshot);
    const context = await currentLedgerAttestationContext(ownerId, incidentId);
    if (context.incident.level !== "critical") {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_NOT_REQUIRED", "External attestation challenge hanya diterbitkan untuk quarantine critical", 409);
    }
    const now = bounded(clock(), 64);
    const issuedMs = Date.parse(now);
    if (!Number.isFinite(issuedMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock attestation tidak valid", 500);
    const ttlMs = boundedInteger(options.ttlMs, MAX_INTEGRITY_ATTESTATION_TTL_MS, 30_000, MAX_INTEGRITY_ATTESTATION_TTL_MS);
    const payload = {
      schemaVersion: 1, purpose: "agentic-v4-mutation-outcome-ledger-clearance", ownerId: bounded(ownerId),
      incidentId: bounded(incidentId), policyRevision: context.policy.revision,
      ledgerRevision: context.ledgerBinding.revision, ledgerHeadHash: context.ledgerBinding.headHash,
      ledgerDigest: context.ledgerBinding.digest, auditDigest: context.auditDigest,
      trustRevision: trustSnapshot.revision, trustDigest,
      issuedAt: now, expiresAt: new Date(issuedMs + ttlMs).toISOString(),
      nonce: randomUUID(), attestationId: randomUUID(), keyId
    };
    const id = integrityAttestationId(ownerId, payload.attestationId);
    const snapshot = { schemaVersion: 1, status: "issued", payload, signature: null, attestationDigest: null, verifiedAt: null };
    const record = { id, ownerId, kind: "recovery-reconciliation-ledger-integrity-attestation", createdAt: now,
      digest: sha256(canonical(snapshot)), snapshot,
      provenance: { source: "recovery-audit-planning", schemaVersion: 1, ownerScoped: true, externallySigned: true } };
    await store.putEvidence(ownerId, record, { overwrite: false });
    return { id, status: "issued", payload: structuredClone(payload), digest: record.digest,
      signatureAlgorithm: "Ed25519", canonicalization: "sorted-json-keys-v1", readOnly: true };
  }

  async function submitMutationOutcomeLedgerAttestation(ownerId, attestationId, signature) {
    assertOwner(ownerId);
    assertRecordId(attestationId, "attestationId");
    if (typeof signature !== "string" || signature.length < 80 || signature.length > MAX_INTEGRITY_ATTESTATION_SIGNATURE_BYTES * 2) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_SIGNATURE_INVALID", "Signature Ed25519 tidak valid", 400);
    }
    const preflightTrust = await ensureAttestationTrustPolicy(ownerId);
    await assertExternalTrustAnchorCurrent(ownerId, preflightTrust);
    const trustPolicyId = attestationTrustPolicyId(ownerId);
    const id = attestationId.startsWith("ledger-integrity-attestation-") ? attestationId : integrityAttestationId(ownerId, attestationId);
    return store.mutateEvidence(ownerId, trustPolicyId, async trustRecord => {
      const trustBefore = validateAttestationTrustPolicyRecord(trustRecord, ownerId);
      await assertExternalTrustAnchorCurrent(ownerId, trustBefore);
      const result = await store.mutateEvidence(ownerId, id, async current => {
      if (!current) throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_NOT_FOUND", "Challenge attestation tidak ditemukan", 404);
      const snapshot = validateAttestationRecord(current, ownerId);
      if (snapshot.status !== "issued") {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_REPLAYED", "Challenge sudah digunakan; attestation tidak dapat diputar ulang", 409);
      }
      const payload = snapshot.payload;
      validateAttestationPayloadTime(payload, bounded(clock(), 64));
      const activeSigner = activeTrustKey(trustBefore, payload.keyId);
      if (!activeSigner || payload.trustRevision !== trustBefore.revision || payload.trustDigest !== trustSnapshotDigest(trustBefore)) {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_TRUST_REVOKED_OR_STALE", "Trust key dicabut atau trust policy berubah setelah challenge diterbitkan", 409);
      }
      if (!verifyIntegrityAttestationSignature(payload, signature, payload.keyId)) {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_SIGNATURE_INVALID", "Signature tidak cocok dengan payload atau public key tepercaya", 403);
      }
      const context = await currentLedgerAttestationContext(ownerId, payload.incidentId);
      if (context.policy.revision !== payload.policyRevision || context.ledgerBinding.revision !== payload.ledgerRevision
        || context.ledgerBinding.headHash !== payload.ledgerHeadHash || context.ledgerBinding.digest !== payload.ledgerDigest
        || context.auditDigest !== payload.auditDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_STALE", "Ledger, audit, atau quarantine policy berubah setelah challenge diterbitkan", 409);
      }
      const verifiedAt = bounded(clock(), 64);
      if (!Number.isFinite(Date.parse(verifiedAt))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock verifikasi attestation tidak valid", 500);
      const attestationDigest = sha256(canonical({ payload, signature }));
      const nextSnapshot = { ...snapshot, status: "verified", signature, attestationDigest, verifiedAt };
      const value = { ...current, snapshot: nextSnapshot, digest: sha256(canonical(nextSnapshot)) };
      return { value, result: { id: current.id, status: "verified", attestationId: payload.attestationId,
        incidentId: payload.incidentId, keyId: payload.keyId, attestationDigest, verifiedAt,
        expiresAt: payload.expiresAt, readOnly: true } };
      });
      return { write: false, result };
    });
  }

  async function getMutationOutcomeLedgerAttestation(ownerId, attestationId) {
    assertOwner(ownerId);
    await ensureAttestationTrustPolicy(ownerId);
    assertRecordId(attestationId, "attestationId");
    const id = attestationId.startsWith("ledger-integrity-attestation-") ? attestationId : integrityAttestationId(ownerId, attestationId);
    const record = await store.getEvidence(ownerId, id);
    if (!record) throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_NOT_FOUND", "Attestation tidak ditemukan", 404);
    const snapshot = validateAttestationRecord(record, ownerId);
    return { id: record.id, status: snapshot.status, payload: structuredClone(snapshot.payload),
      signature: snapshot.signature, attestationDigest: snapshot.attestationDigest, verifiedAt: snapshot.verifiedAt,
      digest: record.digest, readOnly: true };
  }

  async function listMutationOutcomeLedgerAttestations(ownerId, options = {}) {
    assertOwner(ownerId);
    await ensureAttestationTrustPolicy(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 100);
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === "recovery-reconciliation-ledger-integrity-attestation")
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || String(a.id).localeCompare(String(b.id)));
    return { items: records.slice(0, limit).map(record => {
      const snapshot = validateAttestationRecord(record, ownerId);
      return { id: record.id, status: snapshot.status, attestationId: snapshot.payload.attestationId,
        incidentId: snapshot.payload.incidentId, keyId: snapshot.payload.keyId,
        issuedAt: snapshot.payload.issuedAt, expiresAt: snapshot.payload.expiresAt,
        verifiedAt: snapshot.verifiedAt, attestationDigest: snapshot.attestationDigest };
    }), total: records.length, limit, truncated: records.length > limit, readOnly: true };
  }

  async function assertVerifiedAttestationCurrent(ownerId, attestationId, incidentId, policy) {
    const trustSnapshot = await ensureAttestationTrustPolicy(ownerId);
    await assertExternalTrustAnchorCurrent(ownerId, trustSnapshot);
    if (!attestationId) throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_REQUIRED", "Incident critical memerlukan external integrity attestation sebelum quarantine dapat dibuka", 409);
    const id = attestationId.startsWith("ledger-integrity-attestation-") ? attestationId : integrityAttestationId(ownerId, attestationId);
    const record = await store.getEvidence(ownerId, id);
    if (!record) throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_NOT_FOUND", "External integrity attestation tidak ditemukan", 404);
    const snapshot = validateAttestationRecord(record, ownerId);
    if (snapshot.status !== "verified" || snapshot.payload.incidentId !== incidentId
      || snapshot.payload.policyRevision !== policy.revision || !activeTrustKey(trustSnapshot, snapshot.payload.keyId)
      || snapshot.payload.trustRevision !== trustSnapshot.revision || snapshot.payload.trustDigest !== trustSnapshotDigest(trustSnapshot)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_STALE", "Attestation tidak terikat pada incident dan policy revision aktif", 409);
    }
    validateAttestationPayloadTime(snapshot.payload, bounded(clock(), 64));
    const context = await currentLedgerAttestationContext(ownerId, incidentId);
    if (context.policy.revision !== snapshot.payload.policyRevision || context.ledgerBinding.revision !== snapshot.payload.ledgerRevision
      || context.ledgerBinding.headHash !== snapshot.payload.ledgerHeadHash || context.ledgerBinding.digest !== snapshot.payload.ledgerDigest
      || context.auditDigest !== snapshot.payload.auditDigest) {
      throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_CONTEXT_STALE", "Attestation tidak lagi cocok dengan ledger dan audit terkini", 409);
    }
    return { record, snapshot, context };
  }

  async function assertMutationOutcomeLedgerMutationAllowed(ownerId) {
    const trustSnapshot = await ensureAttestationTrustPolicy(ownerId);
    await assertExternalTrustAnchorCurrent(ownerId, trustSnapshot);
    if (attestationTrustAnchor) {
      const trustAudit = await auditMutationOutcomeLedgerAttestationTrust(ownerId, { limit: 200, includeExternalAnchor: false });
      if (trustAudit.truncated || trustAudit.activeKeyCount < 1 || trustAudit.findings.some(item => item.severity === "error")) {
        throw new AgenticError("RECOVERY_RECONCILIATION_ATTESTATION_TRUST_REGISTRY_UNHEALTHY", "Mutation diblokir karena trust registry tidak lolos audit integritas", 409,
          { findingCount: trustAudit.totalFindings, activeKeyCount: trustAudit.activeKeyCount, truncated: trustAudit.truncated });
      }
    }
    const policy = await readMutationOutcomeLedgerPolicy(ownerId);
    if (policy.status === "quarantined") {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_QUARANTINED", "Mutation diblokir oleh ledger integrity escalation; lakukan recovery/acknowledgement eksplisit setelah audit bersih", 409,
        { incidentId: policy.activeIncident?.id, level: policy.activeIncident?.level });
    }
    const audit = await auditMutationOutcomeLedger(ownerId, { limit: MAX_MUTATION_OUTCOME_LEDGER_FINDINGS });
    if (audit.findings.length || audit.truncated || audit.status === "unhealthy" || audit.status === "degraded") {
      const recorded = await recordMutationOutcomeLedgerEscalation(ownerId, audit.findings, audit);
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_QUARANTINED", "Mutation diblokir karena audit ledger menemukan gap atau ketidaksesuaian", 409,
        { incidentId: recorded.incident?.id, level: recorded.incident?.level, findingCount: audit.totalFindings });
    }
    return { allowed: true, readOnly: true };
  }

  async function recoverMutationOutcomeLedgerGaps(ownerId, options = {}) {
    assertOwner(ownerId);
    const existingPolicy = await readMutationOutcomeLedgerPolicy(ownerId);
    if (existingPolicy.status === "quarantined" && existingPolicy.activeIncident?.level === "critical") {
      return { status: "blocked_tamper", recoveredEvents: 0, incidentId: existingPolicy.activeIncident.id,
        reasonCodes: existingPolicy.activeIncident.reasonCodes, automaticRepairAllowed: false, readOnly: false };
    }
    const audit = await auditMutationOutcomeLedger(ownerId, { limit: boundedInteger(options.limit, 200, 1, MAX_MUTATION_OUTCOME_LEDGER_FINDINGS) });
    if (!audit.findings.length && !audit.truncated && ["healthy", "empty"].includes(audit.status)) {
      return { status: "clean", recoveredEvents: 0, audit, policy: await getMutationOutcomeLedgerEscalation(ownerId), automaticRepairAllowed: false, readOnly: false };
    }
    const recoverable = new Set(["OUTCOME_EVIDENCE_MISSING_FROM_LEDGER", "CLAIM_RESOLUTION_MISSING_FROM_LEDGER",
      "RESOLUTION_COMPLETION_EVENT_MISSING", "MUTATION_OUTCOME_LEDGER_MISSING"]);
    const critical = audit.truncated || audit.findings.some(item => !recoverable.has(item.code));
    if (critical) {
      const recorded = await recordMutationOutcomeLedgerEscalation(ownerId, audit.findings, audit);
      return { status: "blocked_tamper_or_non_appendable_gap", recoveredEvents: 0, incidentId: recorded.incident?.id,
        level: recorded.incident?.level, findings: audit.findings.slice(0, 100), auditTruncated: audit.truncated,
        automaticRepairAllowed: false, readOnly: false };
    }
    const recorded = await recordMutationOutcomeLedgerEscalation(ownerId, audit.findings, audit);
    const all = await store.listEvidence(ownerId);
    const evidenceRecords = all.filter(item => item.kind === "recovery-reconciliation-mutation-outcome-evidence")
      .sort((a, b) => String(a.snapshot?.capturedAt).localeCompare(String(b.snapshot?.capturedAt)) || String(a.id).localeCompare(String(b.id)));
    const approvalRecords = all.filter(item => item.kind === "recovery-reconciliation-approval")
      .sort((a, b) => String(a.id).localeCompare(String(b.id)));
    const evidenceById = new Map();
    const approvalById = new Map();
    for (const evidence of evidenceRecords) {
      verifyDigest(evidence, "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED");
      const approval = await store.getEvidence(ownerId, evidence.snapshot?.approvalId);
      if (!approval || approval.kind !== "recovery-reconciliation-approval" || approval.digest !== evidence.snapshot?.approvalDigest) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_GAP_NOT_RECONSTRUCTABLE", "Evidence tidak memiliki approval otoritatif yang cocok", 409);
      }
      verifyDigest(approval, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
      evidenceById.set(evidence.id, evidence);
      approvalById.set(approval.id, approval);
    }
    for (const approval of approvalRecords) {
      verifyDigest(approval, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
      readApprovalGuardState(approval);
      approvalById.set(approval.id, approval);
    }
    let recoveredEvents = 0;
    for (const evidence of evidenceRecords) {
      const event = await appendMutationOutcomeLedgerEvent(ownerId, { ...ledgerEventFromOutcomeEvidence(evidence), recoveryMethod: "reconstructed_from_evidence" });
      if (event.recoveryMethod === "reconstructed_from_evidence") recoveredEvents += 1;
    }
    for (const approval of approvalRecords) {
      const guard = readApprovalGuardState(approval);
      const resolutions = [...(guard.mutationResolutions || [])].sort((a, b) => String(a.resolvedAt).localeCompare(String(b.resolvedAt)) || String(a.evidenceId).localeCompare(String(b.evidenceId)));
      for (const resolution of resolutions) {
        const evidence = evidenceById.get(resolution.evidenceId);
        if (!evidence || evidence.snapshot?.approvalId !== approval.id || evidence.snapshot?.claimId !== resolution.claimId
          || evidence.snapshot?.outcome !== resolution.outcome) {
          throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_GAP_NOT_RECONSTRUCTABLE", "Riwayat approval tidak memiliki evidence hasil yang cocok", 409);
        }
        const eventInput = { ...evidence.snapshot, id: evidence.id, digest: evidence.digest };
        const start = await appendMutationOutcomeLedgerEvent(ownerId, {
          ...ledgerEventFromResolution("claim_resolution_started", approval, eventInput, resolution.claimId, evidence.snapshot.capturedAt, null),
          recoveryMethod: "reconstructed_from_approval_history"
        });
        if (start.recoveryMethod === "reconstructed_from_approval_history") recoveredEvents += 1;
        const completion = await appendMutationOutcomeLedgerEvent(ownerId, {
          ...ledgerEventFromResolution("claim_resolution_completed", approval, eventInput, resolution.claimId, resolution.resolvedAt,
            resolution.outcome === "applied" ? "resolved_applied" : resolution.outcome === "not_applied" ? "resolved_not_applied" : "unresolved"),
          recoveryMethod: "reconstructed_from_approval_history"
        });
        if (completion.recoveryMethod === "reconstructed_from_approval_history") recoveredEvents += 1;
      }
    }
    const after = await auditMutationOutcomeLedger(ownerId, { limit: MAX_MUTATION_OUTCOME_LEDGER_FINDINGS });
    if (after.findings.length || after.truncated || !["healthy", "empty"].includes(after.status)) {
      const escalated = await recordMutationOutcomeLedgerEscalation(ownerId, after.findings, after);
      return { status: "recovery_incomplete", recoveredEvents, incidentId: escalated.incident?.id,
        audit: after, automaticRepairAllowed: false, readOnly: false };
    }
    return { status: "recovered", recoveredEvents, incidentId: recorded.incident?.id, audit: after,
      acknowledgementRequired: true, automaticRepairAllowed: false, readOnly: false };
  }

  async function acknowledgeMutationOutcomeLedgerEscalation(ownerId, incidentId, reason, attestationId = null) {
    assertOwner(ownerId);
    assertRecordId(incidentId, "incidentId");
    const acknowledgementReason = typeof reason === "string" ? reason.trim() : "";
    if (acknowledgementReason.length < 12 || acknowledgementReason.length > 240) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_ACKNOWLEDGEMENT_INVALID", "Alasan acknowledgement harus 12–240 karakter", 400);
    }
    const audit = await auditMutationOutcomeLedger(ownerId, { limit: MAX_MUTATION_OUTCOME_LEDGER_FINDINGS });
    if (audit.findings.length || audit.truncated || !["healthy", "empty"].includes(audit.status)) {
      throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_NOT_CLEAN", "Escalation tidak dapat ditutup sebelum audit ledger bersih dan lengkap", 409,
        { findingCount: audit.totalFindings, status: audit.status });
    }
    const now = bounded(clock(), 64);
    if (!Number.isFinite(Date.parse(now))) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock acknowledgement tidak valid", 500);
    const policyId = mutationOutcomeLedgerPolicyId(ownerId);
    const trustPolicyId = attestationTrustPolicyId(ownerId);
    return store.mutateEvidence(ownerId, trustPolicyId, async trustRecord => {
      validateAttestationTrustPolicyRecord(trustRecord, ownerId);
      const result = await store.mutateEvidence(ownerId, policyId, async current => {
      if (!current) throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_INCIDENT_NOT_FOUND", "Tidak ada escalation yang dapat di-acknowledge", 404);
      const previous = verifyMutationOutcomeLedgerPolicyRecord(current, ownerId);
      const active = previous.activeIncident;
      if (previous.status !== "quarantined" || !active || active.id !== incidentId) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_INCIDENT_MISMATCH", "Incident aktif tidak cocok dengan acknowledgement", 409);
      }
      if (previous.history.length >= MAX_MUTATION_OUTCOME_LEDGER_POLICY_HISTORY) {
        throw new AgenticError("RECOVERY_RECONCILIATION_MUTATION_OUTCOME_LEDGER_POLICY_CAPACITY_REACHED", "Riwayat eskalasi penuh; policy tidak boleh memangkas histori", 409);
      }
      let attestationReceipt = null;
      let attestationContext = null;
      if (active.level === "critical") {
        const verified = await assertVerifiedAttestationCurrent(ownerId, attestationId, incidentId, previous);
        attestationContext = verified.context;
        attestationReceipt = { attestationId: verified.snapshot.payload.attestationId, keyId: verified.snapshot.payload.keyId,
          payload: structuredClone(verified.snapshot.payload), signature: verified.snapshot.signature,
          attestationDigest: verified.snapshot.attestationDigest };
      } else if (attestationId != null) {
        throw new AgenticError("RECOVERY_RECONCILIATION_LEDGER_ATTESTATION_NOT_REQUIRED", "Attestation clearance hanya dipakai untuk incident critical", 400);
      }
      const acknowledgement = { type: "acknowledged", incidentId, at: now, reason: bounded(acknowledgementReason, 240),
        priorLevel: active.level, reasonCodes: active.reasonCodes, auditHeadHash: audit.ledger.headHash };
      if (attestationReceipt && attestationContext) Object.assign(acknowledgement, {
        priorPolicyRevision: previous.revision, ledgerRevision: attestationContext.ledgerBinding.revision,
        ledgerHeadHash: attestationContext.ledgerBinding.headHash, ledgerDigest: attestationContext.ledgerBinding.digest,
        auditDigest: attestationContext.auditDigest, attestationId: attestationReceipt.attestationId,
        attestationDigest: attestationReceipt.attestationDigest, keyId: attestationReceipt.keyId, attestationReceipt
      });
      const snapshot = { ...previous, revision: previous.revision + 1, status: "clear", activeIncident: null,
        history: [...previous.history, acknowledgement] };
      const value = { ...current, digest: sha256(canonical(snapshot)), snapshot };
      return { value, result: { status: "acknowledged", incidentId, acknowledgedAt: now, policyRevision: snapshot.revision,
        auditStatus: audit.status, attestationId: attestationReceipt?.attestationId || null,
        attestationDigest: attestationReceipt?.attestationDigest || null, mutationBlocked: false, readOnly: false } };
      });
      return { write: false, result };
    });
  }

  async function getApproval(ownerId, approvalId) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    const record = await store.getEvidence(ownerId, approvalId);
    if (!record || record.kind !== "recovery-reconciliation-approval") {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
    }
    verifyDigest(record, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
    return publicApproval(record);
  }

  async function listApprovals(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 200);
    const records = (await store.listEvidence(ownerId))
      .filter(record => record.kind === "recovery-reconciliation-approval")
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || String(a.id).localeCompare(String(b.id)));
    return { items: records.slice(0, limit).map(record => {
      verifyDigest(record, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
      const guard = readApprovalGuardState(record);
      return {
        id: bounded(record.id), kind: record.kind, createdAt: bounded(record.createdAt, 64),
        digest: bounded(record.digest, 64), planId: bounded(record.snapshot?.planId),
        planDigest: bounded(record.snapshot?.planDigest, 64),
        status: guard.revokedAt ? "revoked" : guard.activeMutation?.status === "indeterminate" ? "mutation_outcome_unknown"
          : guard.activeMutation ? "mutation_in_progress"
            : record.snapshot?.actionId && guard.consumedActions.some(item => item.actionId === record.snapshot.actionId) ? "consumed"
              : bounded(record.snapshot?.status, 24),
        expiresAt: bounded(record.snapshot?.expiresAt, 64), preconditionBindingDigest: bounded(record.snapshot?.preconditionBindingDigest, 64),
        actionId: bounded(record.snapshot?.actionId, 80), revokedAt: guard.revokedAt,
        consumedActionCount: guard.consumedActions.length
      };
    }), total: records.length, limit, truncated: records.length > limit };
  }

  async function verifyApproval(ownerId, approvalId, options = {}) {
    assertOwner(ownerId);
    assertRecordId(approvalId, "approvalId");
    const approval = await store.getEvidence(ownerId, approvalId);
    if (!approval || approval.kind !== "recovery-reconciliation-approval") {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND", "Recovery reconciliation approval tidak ditemukan", 404);
    }
    verifyDigest(approval, "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED");
    const guard = readApprovalGuardState(approval);
    const snapshot = approval.snapshot;
    const checkedAt = bounded(clock(), 64);
    const checkedAtMs = Date.parse(checkedAt);
    if (!Number.isFinite(checkedAtMs)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_CLOCK_INVALID", "Clock approval tidak valid", 500);
    if (guard.revokedAt) return approvalVerificationResult(approval, checkedAt, "revoked", "APPROVAL_REVOKED");
    if (guard.activeMutation?.status === "indeterminate") {
      return approvalVerificationResult(approval, checkedAt, "mutation_outcome_unknown", "MUTATION_OUTCOME_UNKNOWN");
    }
    if (guard.activeMutation) return approvalVerificationResult(approval, checkedAt, "mutation_in_progress", "MUTATION_IN_PROGRESS");
    if (snapshot.actionId && guard.consumedActions.some(item => item.actionId === snapshot.actionId)) {
      return approvalVerificationResult(approval, checkedAt, "consumed", "APPROVAL_ACTION_CONSUMED");
    }
    const expiresAtMs = Date.parse(snapshot.expiresAt);
    if (!Number.isFinite(expiresAtMs) || snapshot.status !== "approved" || snapshot.ownerId !== ownerId) {
      return approvalVerificationResult(approval, checkedAt, "incomplete", "APPROVAL_METADATA_INVALID");
    }
    if (checkedAtMs >= expiresAtMs) {
      return approvalVerificationResult(approval, checkedAt, "expired", "APPROVAL_EXPIRED");
    }
    const plan = await store.getEvidence(ownerId, snapshot.planId);
    if (!plan || plan.kind !== "recovery-reconciliation-plan") {
      return approvalVerificationResult(approval, checkedAt, "stale", "PLAN_MISSING");
    }
    verifyDigest(plan, "RECOVERY_RECONCILIATION_PLAN_INTEGRITY_FAILED");
    if (plan.digest !== snapshot.planDigest) return approvalVerificationResult(approval, checkedAt, "stale", "PLAN_DIGEST_CHANGED");
    if (snapshot.sourceEvidenceId !== plan.snapshot?.evidenceId || snapshot.sourceEvidenceDigest !== plan.snapshot?.evidenceDigest) {
      return approvalVerificationResult(approval, checkedAt, "stale", "SOURCE_EVIDENCE_BINDING_CHANGED");
    }
    const revalidationEvidence = await store.getEvidence(ownerId, snapshot.revalidationEvidenceId);
    if (!revalidationEvidence || revalidationEvidence.kind !== "recovery-reconciliation-revalidation-evidence") {
      return approvalVerificationResult(approval, checkedAt, "incomplete", "REVALIDATION_EVIDENCE_MISSING");
    }
    verifyDigest(revalidationEvidence, "RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_INTEGRITY_FAILED");
    if (revalidationEvidence.digest !== snapshot.revalidationEvidenceDigest
      || revalidationEvidence.snapshot?.preconditionBindingDigest !== snapshot.preconditionBindingDigest) {
      return approvalVerificationResult(approval, checkedAt, "stale", "APPROVAL_BINDING_CHANGED");
    }
    const current = await revalidatePlan(ownerId, snapshot.planId, options);
    if (current.status !== "fresh") return approvalVerificationResult(approval, current.checkedAt, current.status === "incomplete" ? "incomplete" : "stale", current.status === "incomplete" ? "CURRENT_PRECONDITIONS_INCOMPLETE" : "CURRENT_PRECONDITIONS_STALE", current.preconditionBindingDigest);
    if (current.preconditionBindingDigest !== snapshot.preconditionBindingDigest) {
      return approvalVerificationResult(approval, current.checkedAt, "stale", "CURRENT_PRECONDITION_BINDING_CHANGED", current.preconditionBindingDigest);
    }
    return approvalVerificationResult(approval, current.checkedAt, "valid", null, current.preconditionBindingDigest);
  }

  function approvalVerificationResult(approval, checkedAt, status, reasonCode, currentBindingDigest = null) {
    return {
      approvalId: bounded(approval.id), approvalDigest: bounded(approval.digest, 64),
      planId: bounded(approval.snapshot?.planId), planDigest: bounded(approval.snapshot?.planDigest, 64),
      checkedAt: bounded(checkedAt, 64), status, approvalValid: status === "valid",
      humanApprovalSatisfied: status === "valid", reasonCode,
      expectedPreconditionBindingDigest: bounded(approval.snapshot?.preconditionBindingDigest, 64),
      currentPreconditionBindingDigest: currentBindingDigest == null ? null : bounded(currentBindingDigest, 64),
      revoked: status === "revoked", mutationAllowed: status === "valid",
      automaticExecutionAllowed: false, executionAllowed: false, readOnly: true
    };
  }

  async function listPlans(ownerId, options = {}) {
    assertOwner(ownerId);
    const limit = boundedInteger(options.limit, 50, 1, 200);
    const records = (await store.listEvidence(ownerId))
      .filter(record => record.kind === "recovery-reconciliation-plan")
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)) || String(a.id).localeCompare(String(b.id)));
    return { items: records.slice(0, limit).map(record => ({
      id: bounded(record.id), kind: record.kind, createdAt: bounded(record.createdAt, 64), digest: bounded(record.digest, 64),
      evidenceId: bounded(record.snapshot?.evidenceId), actionCount: Number(record.snapshot?.actionCount) || 0,
      truncated: record.snapshot?.truncated === true
    })), total: records.length, limit, truncated: records.length > limit };
  }

  async function capturePreconditions(ownerId, issues) {
    const captured = [];
    for (const issue of issues) {
      const refs = new Map();
      if (RECORD_GETTERS[issue.entityType]) refs.set(`${issue.entityType}:${issue.entityId}`, { entityType: issue.entityType, id: issue.entityId });
      const relatedType = relatedEntityType(issue);
      if (relatedType && issue.relatedId) refs.set(`${relatedType}:${issue.relatedId}`, { entityType: relatedType, id: issue.relatedId });
      const records = [];
      for (const ref of [...refs.values()].sort((a, b) => a.entityType.localeCompare(b.entityType) || a.id.localeCompare(b.id))) {
        records.push(await readRecordState(ownerId, ref.entityType, ref.id));
      }
      const needsLease = String(issue.code || "").includes("LEASE") || String(issue.code || "").includes("WITHOUT_ACTIVE_LEASE");
      const leaseWorkIds = new Set();
      if (needsLease) {
        if (issue.entityType === "work") leaseWorkIds.add(issue.entityId);
        if (issue.entityType === "execution") {
          const execution = await store.getExecution(ownerId, issue.entityId);
          if (execution?.workId) leaseWorkIds.add(execution.workId);
        }
        if (issue.entityType !== "work" && issue.entityType !== "execution" && issue.relatedId) leaseWorkIds.add(issue.relatedId);
      }
      const leases = [];
      for (const workId of [...leaseWorkIds].sort()) leases.push(await readLeaseState(ownerId, workId));
      const state = { issueRef: issueReference(issue), records, leases };
      captured.push({ ...state, digest: sha256(canonical(state)) });
    }
    return { issues: captured.sort((a, b) => a.issueRef.localeCompare(b.issueRef)) };
  }

  async function readRecordState(ownerId, entityType, id) {
    const getter = RECORD_GETTERS[entityType];
    if (!getter || typeof id !== "string" || !id) return null;
    const record = await store[getter](ownerId, id);
    return safeRecordState(entityType, id, record);
  }

  async function readLeaseState(ownerId, workId) {
    if (!auditService?.inspect || !workId) return null;
    if (workExecutionLeaseService?.inspect) return safeLeaseState(workId, await workExecutionLeaseService.inspect(ownerId, workId));
    // Older audit-service adapters may not expose the lease service. Such
    // plans remain fail-closed because their lease preconditions cannot match.
    return safeLeaseState(workId, null);
  }

  function dedupeMismatches(items) {
    const seen = new Set();
    return items.filter(item => {
      const key = canonical(item);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).slice(0, 100);
  }

  function verifyDigest(record, code) {
    const actual = sha256(canonical(record.snapshot));
    if (actual !== record.digest || record.snapshot?.ownerId !== record.ownerId) {
      throw new AgenticError(code, "Digest atau owner recovery audit record tidak valid", 409);
    }
  }

  function publicEvidence(record) {
    return {
      id: bounded(record.id), kind: record.kind, ownerId: bounded(record.ownerId), createdAt: bounded(record.createdAt, 64),
      digest: bounded(record.digest, 64), snapshot: structuredClone(record.snapshot),
      provenance: structuredClone(record.provenance), readOnly: true
    };
  }

  function publicPlan(record) {
    return {
      id: bounded(record.id), kind: record.kind, ownerId: bounded(record.ownerId), createdAt: bounded(record.createdAt, 64),
      digest: bounded(record.digest, 64), plan: structuredClone(record.snapshot), provenance: structuredClone(record.provenance), readOnly: true
    };
  }

  return Object.freeze({
    capture, getEvidence, listEvidence, createPlan, getPlan, listPlans, revalidatePlan,
    captureRevalidationEvidence, getRevalidationEvidence, listRevalidationEvidence,
    approvePlan, approveAction, getApproval, listApprovals, verifyApproval, revokeApproval, runApprovedMutation,
    inspectMutationClaim, recoverMutationClaim, captureMutationOutcomeEvidence, getMutationOutcomeEvidence,
    listMutationOutcomeEvidence, resolveMutationClaim, getMutationOutcomeLedger, listMutationOutcomeLedgerEntries,
    auditMutationOutcomeLedger, getMutationOutcomeLedgerEscalation, recoverMutationOutcomeLedgerGaps,
    createMutationOutcomeLedgerAttestationChallenge, submitMutationOutcomeLedgerAttestation,
    getMutationOutcomeLedgerAttestation, listMutationOutcomeLedgerAttestations,
    getMutationOutcomeLedgerAttestationTrustPolicy, createMutationOutcomeLedgerAttestationTrustTransitionChallenge,
    applyMutationOutcomeLedgerAttestationTrustTransition, auditMutationOutcomeLedgerAttestationTrust,
    getMutationOutcomeLedgerAttestationTrustAnchorStatus, reconcileMutationOutcomeLedgerAttestationTrustAnchor,
    createMutationOutcomeLedgerAttestationTrustAnchorEnrollmentChallenge, initializeMutationOutcomeLedgerAttestationTrustAnchor,
    getMutationOutcomeLedgerAttestationTrustCrossStoreRecoveryStatus, recoverMutationOutcomeLedgerAttestationTrustCrossStoreTransitions,
    auditMutationOutcomeLedgerAttestationTrustCrossStoreJournal, getMutationOutcomeLedgerAttestationTrustAnchorHealth,
    listMutationOutcomeLedgerAttestationTrustAnchorHealthTelemetry, acknowledgeMutationOutcomeLedgerEscalation
  });
}

function integrityCodeForKind(kind) {
  if (kind === "recovery-audit-evidence") return "RECOVERY_AUDIT_EVIDENCE_INTEGRITY_FAILED";
  if (kind === "recovery-reconciliation-plan") return "RECOVERY_RECONCILIATION_PLAN_INTEGRITY_FAILED";
  if (kind === "recovery-reconciliation-revalidation-evidence") return "RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_INTEGRITY_FAILED";
  if (kind === "recovery-reconciliation-approval") return "RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED";
  if (kind === "recovery-reconciliation-mutation-outcome-evidence") return "RECOVERY_RECONCILIATION_MUTATION_OUTCOME_EVIDENCE_INTEGRITY_FAILED";
  return "RECOVERY_AUDIT_EVIDENCE_INTEGRITY_FAILED";
}

function isDigest(value) { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
function safeRevalidationStatus(value) { return ["fresh", "stale", "incomplete"].includes(value) ? value : "incomplete"; }

function publicRevalidationEvidence(record) {
  return {
    id: bounded(record.id), kind: record.kind, ownerId: bounded(record.ownerId), createdAt: bounded(record.createdAt, 64),
    digest: bounded(record.digest, 64), snapshot: structuredClone(record.snapshot),
    provenance: structuredClone(record.provenance), readOnly: true
  };
}

function publicApproval(record) {
  const guard = readApprovalGuardState(record);
  return {
    id: bounded(record.id), kind: record.kind, ownerId: bounded(record.ownerId), createdAt: bounded(record.createdAt, 64),
    digest: bounded(record.digest, 64), approval: structuredClone(record.snapshot),
    provenance: structuredClone(record.provenance),
    guard: {
      revision: guard.revision, revoked: Boolean(guard.revokedAt), revokedAt: guard.revokedAt,
      revokedBy: guard.revokedBy, reasonCode: guard.reasonCode,
      activeMutation: guard.activeMutation ? {
        status: guard.activeMutation.status, claimId: bounded(claimIdFor(record.ownerId, record.id, guard.activeMutation), 80),
        actionId: bounded(guard.activeMutation.actionId, 80), startedAt: bounded(guard.activeMutation.startedAt, 64),
        recoveredAt: guard.activeMutation.recoveredAt == null ? null : bounded(guard.activeMutation.recoveredAt, 64),
        failureCode: guard.activeMutation.failureCode == null ? null : bounded(guard.activeMutation.failureCode, 80)
      } : null,
      consumedActionCount: guard.consumedActions.length,
      mutationResolutionCount: (guard.mutationResolutions || []).length,
      lastMutationStatus: guard.lastMutation?.status || null
    },
    readOnly: true
  };
}

function claimIdFor(ownerId, approvalId, activeMutation) {
  if (typeof activeMutation?.claimId === "string" && activeMutation.claimId) return activeMutation.claimId;
  return sha256(canonical({ ownerId: bounded(ownerId), approvalId: bounded(approvalId), actionId: bounded(activeMutation?.actionId, 80),
    idempotencyKey: bounded(activeMutation?.idempotencyKey, 64), startedAt: bounded(activeMutation?.startedAt, 64) })).slice(0, 32);
}

function publicMutationOutcomeEvidence(record) {
  return {
    id: bounded(record.id), kind: record.kind, ownerId: bounded(record.ownerId), createdAt: bounded(record.createdAt, 64),
    digest: bounded(record.digest, 64), snapshot: structuredClone(record.snapshot), provenance: structuredClone(record.provenance),
    readOnly: true, automaticExecutionAllowed: false
  };
}

function initialApprovalGuardState() {
  return {
    schemaVersion: 1, revision: 0, revokedAt: null, revokedBy: null, reasonCode: null,
    activeMutation: null, consumedActions: [], lastMutation: null, mutationResolutions: []
  };
}

function approvalGuardDigest(ownerId, approvalId, state) {
  return sha256(canonical({ schemaVersion: 1, ownerId: bounded(ownerId), approvalId: bounded(approvalId), state }));
}

function withApprovalGuardState(ownerId, approvalId, state) {
  const safeState = structuredClone(state);
  return { guardState: safeState, guardStateDigest: approvalGuardDigest(ownerId, approvalId, safeState) };
}

function readApprovalGuardState(record) {
  if (!record || record.kind !== "recovery-reconciliation-approval") {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_INTEGRITY_FAILED", "Approval record tidak valid", 409);
  }
  if (record.guardState === undefined && record.guardStateDigest === undefined) return initialApprovalGuardState();
  const state = record.guardState;
  const valid = state && typeof state === "object" && !Array.isArray(state)
    && state.schemaVersion === 1 && Number.isSafeInteger(state.revision) && state.revision >= 0
    && (state.revokedAt === null || typeof state.revokedAt === "string")
    && (state.revokedBy === null || typeof state.revokedBy === "string")
    && (state.reasonCode === null || typeof state.reasonCode === "string")
    && (state.activeMutation === null || (typeof state.activeMutation === "object" && !Array.isArray(state.activeMutation)
      && ["in_progress", "indeterminate"].includes(state.activeMutation.status)
      && typeof state.activeMutation.actionId === "string" && isDigest(state.activeMutation.intentDigest)
      && typeof state.activeMutation.idempotencyKey === "string" && typeof state.activeMutation.startedAt === "string"
      && (state.activeMutation.claimId === undefined || (typeof state.activeMutation.claimId === "string" && state.activeMutation.claimId.length <= 80))))
    && Array.isArray(state.consumedActions) && state.consumedActions.length <= MAX_CONSUMED_ACTIONS
    && (state.mutationResolutions === undefined || (Array.isArray(state.mutationResolutions) && state.mutationResolutions.length <= MAX_MUTATION_RESOLUTIONS))
    && (state.lastMutation === null || (typeof state.lastMutation === "object" && !Array.isArray(state.lastMutation)));
  if (!valid || !isDigest(record.guardStateDigest)
    || record.guardStateDigest !== approvalGuardDigest(record.ownerId, record.id, state)) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_GUARD_INTEGRITY_FAILED", "Guard state approval rusak atau tidak cocok dengan digest", 409);
  }
  for (const item of state.consumedActions) {
    if (!item || typeof item.actionId !== "string" || !isDigest(item.intentDigest)
      || typeof item.idempotencyKey !== "string" || typeof item.consumedAt !== "string") {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_GUARD_INTEGRITY_FAILED", "Consumed-action ledger approval tidak valid", 409);
    }
  }
  for (const item of state.mutationResolutions || []) {
    if (!item || typeof item.claimId !== "string" || typeof item.evidenceId !== "string"
      || !["applied", "not_applied", "unresolved"].includes(item.outcome) || typeof item.resolvedAt !== "string") {
      throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_GUARD_INTEGRITY_FAILED", "Mutation resolution ledger approval tidak valid", 409);
    }
  }
  const normalized = structuredClone(state);
  if (!Array.isArray(normalized.mutationResolutions)) normalized.mutationResolutions = [];
  return normalized;
}

function normalizeRevocationReason(value) {
  const reason = value === undefined || value === null ? "OWNER_REVOKED" : String(value);
  if (!/^[A-Z0-9_]{1,80}$/.test(reason)) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_REVOCATION_REASON_INVALID", "reasonCode pencabutan harus berupa kode terbatas", 400);
  }
  return reason;
}

function normalizeMutationIntent(action, intent) {
  if (!intent || typeof intent !== "object" || Array.isArray(intent)
    || (Object.getPrototypeOf(intent) !== Object.prototype && Object.getPrototypeOf(intent) !== null)) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Mutation intent harus berupa object JSON", 400);
  }
  if (Object.keys(intent).some(key => !["actionId", "operation", "issueCode", "target", "change"].includes(key))) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Mutation intent memiliki field yang tidak diikat oleh approval", 400);
  }
  if (!intent.target || typeof intent.target !== "object" || Array.isArray(intent.target)
    || (Object.getPrototypeOf(intent.target) !== Object.prototype && Object.getPrototypeOf(intent.target) !== null)
    || Object.keys(intent.target).some(key => !["entityType", "entityId", "relatedId"].includes(key))) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Target mutation intent tidak valid", 400);
  }
  if (typeof intent.target.entityType !== "string" || intent.target.entityType.length > 40
    || typeof intent.target.entityId !== "string" || intent.target.entityId.length > MAX_ID
    || (intent.target.relatedId !== undefined && intent.target.relatedId !== null
      && (typeof intent.target.relatedId !== "string" || intent.target.relatedId.length > MAX_ID))) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Identifier target mutation intent tidak valid", 400);
  }
  const target = {
    entityType: intent.target.entityType,
    entityId: intent.target.entityId,
    relatedId: intent.target.relatedId == null ? null : intent.target.relatedId
  };
  const expectedTarget = {
    entityType: bounded(action?.target?.entityType, 40),
    entityId: bounded(action?.target?.entityId),
    relatedId: action?.target?.relatedId == null ? null : bounded(action.target.relatedId)
  };
  if (intent.actionId !== action?.id || intent.operation !== action?.operation || intent.issueCode !== action?.issueCode
    || canonical(target) !== canonical(expectedTarget)) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Action, operation, issue code, atau target mutation intent tidak cocok dengan plan", 409);
  }
  const change = sanitizeMutationValue(intent.change, 0);
  if (!change || typeof change !== "object" || Array.isArray(change) || Object.keys(change).length === 0) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Mutation intent harus menetapkan change yang eksplisit", 400);
  }
  const normalized = {
    schemaVersion: 1, actionId: bounded(action.id, 80), operation: bounded(action.operation, 80),
    issueCode: bounded(action.issueCode, 80), target, change
  };
  if (Buffer.byteLength(canonical(normalized), "utf8") > MAX_MUTATION_INTENT_BYTES) {
    throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_TOO_LARGE", "Mutation intent melewati batas ukuran", 413);
  }
  return normalized;
}

function sanitizeMutationValue(value, depth) {
  if (depth > 6) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Mutation intent terlalu dalam", 400);
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.length > 1000) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_TOO_LARGE", "String mutation intent melewati batas panjang", 413);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Mutation intent berisi angka tidak valid", 400);
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 50) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Array mutation intent terlalu besar", 400);
    return value.map(item => sanitizeMutationValue(item, depth + 1));
  }
  if (value && typeof value === "object"
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    const entries = Object.entries(value);
    if (entries.length > 50) throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Object mutation intent terlalu besar", 400);
    const out = {};
    for (const [key, item] of entries.sort(([a], [b]) => a.localeCompare(b))) {
      if (!key || key.length > 80 || ["__proto__", "prototype", "constructor"].includes(key)) {
        throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Key mutation intent tidak diizinkan", 400);
      }
      out[key] = sanitizeMutationValue(item, depth + 1);
    }
    return out;
  }
  throw new AgenticError("RECOVERY_RECONCILIATION_APPROVAL_MUTATION_INTENT_INVALID", "Mutation intent harus berisi nilai JSON terbatas", 400);
}

function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.length > MAX_ID || ownerId.trim() !== ownerId) {
    throw new AgenticError("RECOVERY_AUDIT_OWNER_REQUIRED", "Owner wajib ditentukan untuk recovery audit", 400);
  }
}

function assertRecordId(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > MAX_ID || value.trim() !== value) {
    throw new AgenticError("RECOVERY_AUDIT_RECORD_ID_INVALID", `${label} tidak valid`, 400);
  }
}

function boundedInteger(value, fallback, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(number)));
}

function severityRank(severity) {
  return severity === "error" ? 0 : severity === "warning" ? 1 : 2;
}
