import { createHash, createPublicKey, verify as verifySignature, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const CONTRACT_ID = "agentic-v4-trust-anchor-provider";
const MIGRATION_KIND = "recovery-slo-anchor-contract-migration-ledger";
const PLAN_KIND = "recovery-slo-anchor-contract-migration-plan";
const APPROVAL_KIND = "recovery-slo-anchor-contract-migration-approval";
const RETENTION_KIND = "recovery-slo-finalization-anchor-retained-evidence";
const MIGRATION_CHECKPOINT_KIND = "recovery-slo-anchor-contract-migration-checkpoint";
const MIGRATION_RECOVERY_KIND = "recovery-slo-anchor-contract-migration-recovery-journal";
const RUNBOOK_KEY_POLICY_KIND = "recovery-slo-runbook-signing-key-policy";
const RUNBOOK_KEY_CHALLENGE_KIND = "recovery-slo-runbook-signing-key-transition-challenge";
const RUNBOOK_KEY_REVOCATION_CHALLENGE_KIND = "recovery-slo-runbook-signing-key-revocation-challenge";
const RETENTION_POLICY_KIND = "recovery-slo-evidence-retention-policy";
const RETENTION_POLICY_PLAN_KIND = "recovery-slo-evidence-retention-policy-plan";
const RETENTION_POLICY_APPROVAL_KIND = "recovery-slo-evidence-retention-policy-approval";
const RETENTION_POLICY_CHECKPOINT_KIND = "recovery-slo-evidence-retention-policy-checkpoint";
const RUNBOOK_ATTESTATION_DOMAIN = "agentic-v4-signed-recovery-runbook-attestation";
const SUPPORTED = new Set(["1.0.0", "1.1.0"]);
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const MAX_RETENTION_RECORDS = 2000;
const MAX_ACTIVE_ARTIFACTS = 500;
const MAX_PRUNE = 100;
const MAX_MIGRATION_EVENTS = 100;
const MAX_RUNBOOK_BYTES = 1024 * 1024;

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const clone = value => value == null ? value : structuredClone(value);
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item);
  return out;
};
const digestRecord = record => { const value = clean(record); delete value.digest; return sha256(canonical(value)); };
const digestWithout = (value, field) => { const unsigned = clone(value); delete unsigned[field]; return sha256(canonical(unsigned)); };
const validReason = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
  && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
const ownerHash = ownerId => sha256(ownerId).slice(0, 48);
const migrationLedgerId = ownerId => `recovery-slo-anchor-contract-migration-ledger-${ownerHash(ownerId)}`;
const migrationPlanPrefix = "recovery-slo-anchor-contract-migration-plan-";
const migrationApprovalPrefix = "recovery-slo-anchor-contract-migration-approval-";
const retentionPrefix = "recovery-slo-finalization-anchor-retained-evidence-";
const migrationCheckpointId = ownerId => `recovery-slo-anchor-contract-migration-checkpoint-${ownerHash(ownerId)}`;
const migrationRecoveryPrefix = "recovery-slo-anchor-contract-migration-recovery-";
const migrationRecoveryId = (ownerId, planId) => `${migrationRecoveryPrefix}${sha256(`${ownerId}:${planId}`).slice(0, 40)}`;
const runbookKeyPolicyId = ownerId => `recovery-slo-runbook-signing-key-policy-${ownerHash(ownerId)}`;
const runbookKeyPolicyCheckpointId = ownerId => `recovery-slo-runbook-signing-key-policy-checkpoint-${ownerHash(ownerId)}`;
const runbookKeyChallengePrefix = "recovery-slo-runbook-signing-key-transition-";
const runbookKeyRevocationChallengePrefix = "recovery-slo-runbook-signing-key-revocation-";
const retentionPolicyId = ownerId => `recovery-slo-evidence-retention-policy-${ownerHash(ownerId)}`;
const retentionPolicyPlanPrefix = "recovery-slo-evidence-retention-policy-plan-";
const retentionPolicyApprovalPrefix = "recovery-slo-evidence-retention-policy-approval-";
const retentionPolicyCheckpointId = ownerId => `recovery-slo-evidence-retention-policy-checkpoint-${ownerHash(ownerId)}`;
const eventHash = event => sha256(canonical({ sequence: event.sequence, type: event.type, at: event.at,
  previousHash: event.previousHash, payload: event.payload }));
const genesisHash = (ownerId, id) => sha256(`agentic-v4-anchor-contract-migration:${ownerId}:${id}`);

function parsePublicKey(value) {
  const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
  if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Public key harus Ed25519");
  return key;
}
function verifyEd25519(key, payload, signature) {
  try {
    if (typeof signature !== "string" || !SIGNATURE.test(signature)) return false;
    const bytes = Buffer.from(signature, "base64url");
    return bytes.length === 64 && bytes.toString("base64url") === signature
      && verifySignature(null, Buffer.from(canonical(payload), "utf8"), key, bytes);
  } catch { return false; }
}
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_GOVERNANCE_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
  }
}

export function createRecoverySloFinalizationAnchorGovernanceService({
  store, clock = () => new Date().toISOString(), anchorEvidence, anchorOperations,
  defaultContractVersion = "1.0.0", runbookSigner = null, runbookKeyId = null, runbookPublicKeys = null,
  requireSignedRunbookAttestation = false, evidenceRetentionDays = 90, runbookRecoveryPublicKeys = null,
  recoveryJournalAnchor = null, retentionCheckpointAnchor = null
} = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || !store?.mutateEvidence
    || !anchorEvidence?.getRecoverySloFinalizationKeyPolicyAnchorContractStatus
    || !anchorEvidence?.getRecoverySloFinalizationKeyPolicyAnchorContractStatusForVersion
    || !anchorEvidence?.exportRecoverySloFinalizationAnchorRecoveryRunbook
    || !anchorEvidence?.verifyRecoverySloFinalizationAnchorRecoveryRunbook
    || !anchorEvidence?.exportRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence
    || !anchorEvidence?.verifyRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence
    || !anchorOperations?.listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence
    || !anchorOperations?.recordRecoverySloFinalizationAnchorEvidenceEvent
    || typeof clock !== "function") throw new TypeError("Governance service membutuhkan store, anchor evidence, anchor operations, dan clock");
  if (!SUPPORTED.has(defaultContractVersion)) throw new TypeError("Default contract version tidak didukung");
  if (!Number.isSafeInteger(evidenceRetentionDays) || evidenceRetentionDays < 1 || evidenceRetentionDays > 3650) {
    throw new TypeError("Evidence retention harus 1–3650 hari");
  }
  const keys = new Map();
  const keyEntries = runbookPublicKeys instanceof Map ? [...runbookPublicKeys.entries()]
    : runbookPublicKeys && typeof runbookPublicKeys === "object" && !Array.isArray(runbookPublicKeys) ? Object.entries(runbookPublicKeys) : [];
  for (const [id, value] of keyEntries.slice(0, 50)) {
    if (typeof id !== "string" || !KEY_ID.test(id)) continue;
    try { keys.set(id, parsePublicKey(value)); } catch { /* invalid public keys are never trusted */ }
  }
  const signingConfigured = runbookSigner != null || runbookKeyId != null || requireSignedRunbookAttestation;
  if (signingConfigured && (typeof runbookSigner !== "function" || typeof runbookKeyId !== "string"
    || !KEY_ID.test(runbookKeyId) || !keys.has(runbookKeyId))) {
    throw new TypeError("Signed runbook memerlukan signer, key ID, dan trusted public key Ed25519 yang cocok");
  }
  const runbookBootstrapDigest = sha256(canonical({ activeKeyId: runbookKeyId || null,
    keys: [...keys.entries()].map(([id, key]) => ({ keyId: id,
      publicKeyDer: key.export({ type: "spki", format: "der" }).toString("base64") })).sort((a, b) => a.keyId.localeCompare(b.keyId)) }));
  const recoveryKeys = new Map();
  const recoveryEntries = runbookRecoveryPublicKeys instanceof Map ? [...runbookRecoveryPublicKeys.entries()]
    : runbookRecoveryPublicKeys && typeof runbookRecoveryPublicKeys === "object" && !Array.isArray(runbookRecoveryPublicKeys) ? Object.entries(runbookRecoveryPublicKeys) : [];
  for (const [id, value] of recoveryEntries.slice(0, 50)) {
    if (typeof id !== "string" || !KEY_ID.test(id)) continue;
    try { recoveryKeys.set(id, parsePublicKey(value)); } catch { /* malformed recovery keys are never trusted */ }
  }
  const recoveryAuthorityDigest = sha256(canonical([...recoveryKeys.entries()].map(([keyId, key]) => ({ keyId,
    publicKeyDer: key.export({ type: "spki", format: "der" }).toString("base64") })).sort((a, b) => a.keyId.localeCompare(b.keyId))));
  const runbookPublicKeyDigests = new Set([...keys.values()].map(key => sha256(key.export({ type: "spki", format: "der" }).toString("base64"))));
  if ([...recoveryKeys.values()].some(key => runbookPublicKeyDigests.has(sha256(key.export({ type: "spki", format: "der" }).toString("base64"))))) {
    throw new TypeError("Runbook recovery authority harus memakai kunci Ed25519 yang terpisah dari signing key operasional");
  }
  if (recoveryJournalAnchor && typeof recoveryJournalAnchor.anchorRecoverySloRecoveryJournal !== "function") {
    throw new TypeError("Recovery journal anchor provider tidak valid");
  }

  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_GOVERNANCE_CLOCK_INVALID", "Clock governance tidak valid", 500);
    return new Date(value).toISOString();
  }
  async function assertOperatorEvidenceCapacity(ownerId, reserve = 1) {
    const audit = await anchorOperations.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_GOVERNANCE_OPERATOR_EVIDENCE_UNHEALTHY", "Operator evidence tidak sehat; operasi governance diblokir", 409);
    if ((audit.eventCount || 0) + reserve > 500) throw new AgenticError("RECOVERY_SLO_GOVERNANCE_OPERATOR_EVIDENCE_CAPACITY", "Operator evidence tidak memiliki kapasitas cukup untuk mencatat operasi secara lengkap", 409);
    return audit;
  }
  async function assertRetentionCapacity(ownerId) {
    const all = (await store.listEvidence(ownerId)).filter(item => item.kind === RETENTION_KIND);
    if (all.length >= MAX_RETENTION_RECORDS) throw new AgenticError("RECOVERY_SLO_EVIDENCE_RETENTION_CAPACITY", "Retained recovery evidence mencapai batas tombstone", 409);
    const activeCount = all.filter(item => item.status === "retained" && item.payload != null).length;
    if (activeCount >= MAX_ACTIVE_ARTIFACTS) throw new AgenticError("RECOVERY_SLO_EVIDENCE_RETENTION_ACTIVE_CAPACITY", "Retained recovery evidence mencapai batas payload aktif; prune evidence kedaluwarsa terlebih dahulu", 409);
    return { total: all.length, active: activeCount };
  }
  function event(sequence, type, at, previousHash, payload) {
    const item = { sequence, type, at, previousHash, payload };
    item.eventHash = eventHash(item);
    return item;
  }
  function makeGenesis(ownerId, version, at) {
    const id = migrationLedgerId(ownerId);
    const first = event(1, "contract_version_bootstrapped", at, genesisHash(ownerId, id), { activeVersion: version, reason: "Configured deployment baseline." });
    const record = { id, ownerId, kind: MIGRATION_KIND, schemaVersion: 1, revision: 1, activeVersion: version,
      events: [first], createdAt: at, updatedAt: at };
    record.digest = digestRecord(record);
    return record;
  }
  function validateMigrationLedger(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.id !== migrationLedgerId(ownerId) || record.kind !== MIGRATION_KIND
      || record.schemaVersion !== 1 || !SUPPORTED.has(record.activeVersion) || !Number.isSafeInteger(record.revision)
      || record.revision < 1 || !Array.isArray(record.events) || record.events.length !== record.revision
      || record.events.length > MAX_MIGRATION_EVENTS || !Number.isFinite(Date.parse(record.createdAt))
      || !Number.isFinite(Date.parse(record.updatedAt))) return { valid: false, code: "CONTRACT_MIGRATION_LEDGER_SHAPE_INVALID" };
    let previous = genesisHash(ownerId, record.id);
    for (let index = 0; index < record.events.length; index++) {
      const item = record.events[index];
      if (!item || item.sequence !== index + 1 || item.previousHash !== previous || typeof item.type !== "string"
        || !Number.isFinite(Date.parse(item.at)) || !item.payload || typeof item.payload !== "object"
        || item.eventHash !== eventHash(item)) return { valid: false, code: "CONTRACT_MIGRATION_LEDGER_CHAIN_INVALID" };
      if (index === 0 && (item.type !== "contract_version_bootstrapped" || item.payload.activeVersion !== record.events[0].payload.activeVersion)) {
        return { valid: false, code: "CONTRACT_MIGRATION_LEDGER_GENESIS_INVALID" };
      }
      previous = item.eventHash;
    }
    const last = record.events.at(-1);
    if (record.activeVersion !== last.payload.activeVersion || record.revision !== last.sequence || record.digest !== digestRecord(record)) {
      return { valid: false, code: "CONTRACT_MIGRATION_LEDGER_DIGEST_INVALID" };
    }
    return { valid: true, code: null };
  }
  function validateMigrationCheckpoint(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.id !== migrationCheckpointId(ownerId)
      || record.kind !== MIGRATION_CHECKPOINT_KIND || record.schemaVersion !== 1
      || !Number.isSafeInteger(record.highWaterRevision) || record.highWaterRevision < 1
      || !DIGEST.test(record.highWaterEventHash || "") || !SUPPORTED.has(record.activeVersion)
      || !Number.isFinite(Date.parse(record.updatedAt)) || record.digest !== digestRecord(record)) {
      return { valid: false, code: "CONTRACT_MIGRATION_CHECKPOINT_INVALID" };
    }
    return { valid: true };
  }
  function makeMigrationCheckpoint(ownerId, ledger, previous = null) {
    const unsigned = { id: migrationCheckpointId(ownerId), ownerId, kind: MIGRATION_CHECKPOINT_KIND, schemaVersion: 1,
      highWaterRevision: ledger.revision, highWaterEventHash: ledger.events.at(-1).eventHash,
      activeVersion: ledger.activeVersion, previousCheckpointDigest: previous?.digest || null,
      updatedAt: now(), provenance: previous ? "verified_advance" : "initial_observation" };
    return { ...unsigned, digest: digestRecord(unsigned) };
  }
  async function ensureMigrationCheckpoint(ownerId, ledger) {
    const id = migrationCheckpointId(ownerId);
    let checkpoint = await store.getEvidence(ownerId, id);
    if (!checkpoint) {
      const created = makeMigrationCheckpoint(ownerId, ledger);
      try { await store.putEvidence(ownerId, created, { overwrite: false }); }
      catch { /* a concurrent initializer may have won; read and validate below */ }
      checkpoint = await store.getEvidence(ownerId, id);
    }
    const check = validateMigrationCheckpoint(checkpoint, ownerId);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CHECKPOINT_UNHEALTHY", "Migration checkpoint tidak sehat", 409, { finding: check.code });
    if (checkpoint.highWaterRevision > ledger.revision) {
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_ROLLBACK_DETECTED", "Migration ledger berada di bawah high-water checkpoint", 409,
        { checkpointRevision: checkpoint.highWaterRevision, ledgerRevision: ledger.revision });
    }
    const historical = ledger.events[checkpoint.highWaterRevision - 1];
    if (!historical || historical.eventHash !== checkpoint.highWaterEventHash
      || (checkpoint.highWaterRevision === ledger.revision && checkpoint.activeVersion !== ledger.activeVersion)) {
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CHECKPOINT_MISMATCH", "Riwayat ledger tidak cocok dengan checkpoint tepercaya", 409,
        { checkpointRevision: checkpoint.highWaterRevision, ledgerRevision: ledger.revision });
    }
    if (ledger.revision > checkpoint.highWaterRevision) {
      const next = makeMigrationCheckpoint(ownerId, ledger, checkpoint);
      await store.putEvidence(ownerId, next, { expectedVersion: checkpoint._storage?.version });
      checkpoint = await store.getEvidence(ownerId, id);
      const after = validateMigrationCheckpoint(checkpoint, ownerId);
      if (!after.valid || checkpoint.highWaterRevision !== ledger.revision
        || checkpoint.highWaterEventHash !== ledger.events.at(-1).eventHash) {
        throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CHECKPOINT_WRITE_FAILED", "Checkpoint tidak dapat diverifikasi setelah diperbarui", 409);
      }
    }
    return checkpoint;
  }
  function migrationJournalEvent(sequence, type, at, previousHash, payload) {
    const item = { sequence, type, at, previousHash, payload };
    item.eventHash = sha256(canonical({ sequence, type, at, previousHash, payload }));
    return item;
  }
  function migrationJournalGenesis(ownerId, id) { return sha256(`agentic-v4-migration-recovery:${ownerId}:${id}`); }
  function validateMigrationJournal(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.kind !== MIGRATION_RECOVERY_KIND || record.schemaVersion !== 1
      || record.id !== migrationRecoveryId(ownerId, record.planId) || !DIGEST.test(record.planDigest || "")
      || !["applying", "recovery_required", "completed", "blocked"].includes(record.status)
      || !Number.isSafeInteger(record.revision) || !Array.isArray(record.events) || record.events.length !== record.revision
      || !record.events.length || record.events.length > 20) return { valid: false, code: "CONTRACT_MIGRATION_RECOVERY_JOURNAL_SHAPE_INVALID" };
    let previous = migrationJournalGenesis(ownerId, record.id);
    for (let i = 0; i < record.events.length; i++) {
      const item = record.events[i];
      if (item.sequence !== i + 1 || item.previousHash !== previous || !Number.isFinite(Date.parse(item.at))
        || item.eventHash !== sha256(canonical({ sequence: item.sequence, type: item.type, at: item.at, previousHash: item.previousHash, payload: item.payload }))) {
        return { valid: false, code: "CONTRACT_MIGRATION_RECOVERY_JOURNAL_CHAIN_INVALID" };
      }
      previous = item.eventHash;
    }
    if (record.status !== record.events.at(-1).payload?.status || record.digest !== digestRecord(record)) {
      return { valid: false, code: "CONTRACT_MIGRATION_RECOVERY_JOURNAL_DIGEST_INVALID" };
    }
    return { valid: true };
  }
  async function updateMigrationJournal(ownerId, plan, approval, status, details = {}) {
    const id = migrationRecoveryId(ownerId, plan.id);
    const at = now();
    let existingJournal = await store.getEvidence(ownerId, id);
    if (!existingJournal) {
      const first = migrationJournalEvent(1, "migration_recovery_started", at, migrationJournalGenesis(ownerId, id), {
        status: "applying", planId: plan.id, planDigest: plan.planDigest, approvalId: approval.id,
        approvalDigest: approval.digest, fromVersion: approval.fromVersion, targetVersion: approval.targetVersion,
        baselineRevision: details.baselineRevision ?? 0, baselineEventHash: details.baselineEventHash ?? null });
      const genesisUnsigned = { id, ownerId, kind: MIGRATION_RECOVERY_KIND, schemaVersion: 1, planId: plan.id,
        planDigest: plan.planDigest, approvalId: approval.id, approvalDigest: approval.digest,
        fromVersion: approval.fromVersion, targetVersion: approval.targetVersion,
        baselineRevision: details.baselineRevision ?? 0, baselineEventHash: details.baselineEventHash ?? null,
        status: "applying", revision: 1, events: [first], createdAt: at, updatedAt: at };
      const genesis = { ...genesisUnsigned, digest: digestRecord(genesisUnsigned) };
      try { await store.putEvidence(ownerId, genesis, { overwrite: false }); } catch { /* concurrent creator; validate the winner below */ }
      existingJournal = await store.getEvidence(ownerId, id);
      const genesisCheck = validateMigrationJournal(existingJournal, ownerId);
      if (!genesisCheck.valid || existingJournal.planDigest !== plan.planDigest || existingJournal.approvalDigest !== approval.digest) {
        throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_JOURNAL_UNHEALTHY", "Migration recovery journal genesis tidak valid", 409,
          { finding: genesisCheck.code || "CONTRACT_MIGRATION_RECOVERY_JOURNAL_BINDING_MISMATCH" });
      }
    }
    if (recoveryJournalAnchor?.configured) await recoveryJournalAnchor.anchorRecoverySloRecoveryJournal(ownerId, id);
    else if (recoveryJournalAnchor?.required) throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_REQUIRED", "External recovery journal anchor wajib tersedia", 503);
    const result = await store.mutateEvidence(ownerId, id, current => {
      let record = current;
      if (record) {
        const check = validateMigrationJournal(record, ownerId);
        if (!check.valid || record.planDigest !== plan.planDigest || record.approvalId !== approval.id) {
          throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_JOURNAL_UNHEALTHY", "Migration recovery journal tidak sehat", 409,
            { finding: check.code || "CONTRACT_MIGRATION_RECOVERY_JOURNAL_BINDING_MISMATCH" });
        }
        if (record.status === "completed") return { write: false, result: record };
        if (record.events.length >= 20) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_JOURNAL_CAPACITY", "Migration recovery journal mencapai batas transisi", 409);
      } else {
        throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_JOURNAL_GENESIS_MISSING", "Migration journal harus di-bootstrap sebelum transisi", 409);
      }
      const nextEvent = migrationJournalEvent(record.revision + 1, `migration_recovery_${status}`, at,
        record.events.at(-1).eventHash, { status, ...details });
      const unsigned = { ...clean(record), status, revision: nextEvent.sequence, events: [...record.events, nextEvent], updatedAt: at };
      const next = { ...unsigned, digest: digestRecord(unsigned) };
      return { value: next, result: next };
    });
    if (recoveryJournalAnchor?.configured) {
      await recoveryJournalAnchor.anchorRecoverySloRecoveryJournal(ownerId, id);
    } else if (recoveryJournalAnchor?.required) {
      throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_REQUIRED", "External recovery journal anchor wajib tersedia", 503);
    }
    return result;
  }
  async function listMigrationRecoveryJournals(ownerId) {
    const records = (await store.listEvidence(ownerId)).filter(item => item.kind === MIGRATION_RECOVERY_KIND);
    const out = [];
    for (const record of records) {
      const check = validateMigrationJournal(record, ownerId);
      if (!check.valid) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_JOURNAL_UNHEALTHY", "Migration recovery journal tidak sehat", 409, { finding: check.code });
      out.push(record);
    }
    return out;
  }
  async function getMigrationLedger(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, migrationLedgerId(ownerId));
    const checkpoint = await store.getEvidence(ownerId, migrationCheckpointId(ownerId));
    if (!record) {
      if (checkpoint) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_ROLLBACK_DETECTED", "Migration ledger hilang tetapi high-water checkpoint masih ada", 409);
      return null;
    }
    const audit = validateMigrationLedger(record, ownerId);
    if (!audit.valid) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_POLICY_UNHEALTHY", "Ledger migrasi kontrak tidak sehat; versi aktif tidak dapat dipercaya", 409, { finding: audit.code });
    await ensureMigrationCheckpoint(ownerId, record);
    return record;
  }
  async function getActiveContractVersion(ownerId) {
    const record = await getMigrationLedger(ownerId);
    const journals = await listMigrationRecoveryJournals(ownerId);
    if (recoveryJournalAnchor?.configured || recoveryJournalAnchor?.required) {
      for (const journal of journals) await recoveryJournalAnchor.assertRecoverySloRecoveryJournalAnchorTrusted(ownerId, journal.id);
    }
    const unresolved = journals.find(item => ["applying", "recovery_required", "blocked"].includes(item.status));
    if (unresolved) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_REQUIRED", "Migration memiliki recovery journal yang belum terselesaikan", 409,
      { journalId: unresolved.id, status: unresolved.status, planId: unresolved.planId });
    return record?.activeVersion ?? null;
  }
  async function currentContractStatus(ownerId) {
    return anchorEvidence.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(ownerId);
  }
  async function getLatestConformance(ownerId) {
    const listing = await anchorOperations.listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(ownerId, { limit: 100 });
    if (listing.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_OPERATOR_EVIDENCE_UNHEALTHY", "Operator evidence tidak sehat; migrasi kontrak ditolak", 409);
    const match = (listing.items || []).find(item => item.type === "provider_conformance_completed");
    if (!match || match.payload?.outcome !== "conformant" || !DIGEST.test(match.payload?.conformanceDigest || "")) return null;
    const age = Date.parse(now()) - Date.parse(match.at);
    if (!Number.isFinite(age) || age < 0 || age > 24 * 60 * 60 * 1000) return null;
    return { sequence: match.sequence, eventHash: match.eventHash, conformanceDigest: match.payload.conformanceDigest, completedAt: match.at };
  }
  async function assessTarget(ownerId, targetVersion) {
    if (!SUPPORTED.has(targetVersion)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_TARGET_UNSUPPORTED", "Target contract version tidak didukung", 400);
    const status = await anchorEvidence.getRecoverySloFinalizationKeyPolicyAnchorContractStatusForVersion(ownerId, targetVersion);
    if (status.status !== "compatible_declared") throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_TARGET_INCOMPATIBLE", "Provider belum mendeklarasikan kontrak target secara kompatibel", 409, { status: status.status, findings: status.findings });
    if (targetVersion === "1.1.0") {
      const conformance = await getLatestConformance(ownerId);
      if (!conformance) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CONFORMANCE_REQUIRED", "Migrasi ke 1.1.0 memerlukan conformance probe sukses dalam 24 jam terakhir", 409);
      return { status, conformance };
    }
    return { status, conformance: null };
  }
  async function planContractMigration(ownerId, input = {}) {
    assertOwner(ownerId);
    const reason = input.reason;
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_REASON_INVALID", "Alasan migrasi harus 12–240 karakter", 400);
    const current = await currentContractStatus(ownerId);
    const fromVersion = current.expectedVersion;
    const targetVersion = input.targetVersion;
    if (!SUPPORTED.has(targetVersion) || targetVersion === fromVersion) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_TARGET_INVALID", "Target harus versi berbeda yang didukung", 400);
    if (fromVersion === "1.1.0" && targetVersion === "1.0.0") throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_DOWNGRADE_BLOCKED", "Downgrade kontrak diblokir oleh kebijakan", 409);
    const currentOnlyVersionMismatch = current.status === "incompatible" && (current.findings || []).length > 0
      && (current.findings || []).every(item => item.code === "PROVIDER_CONTRACT_VERSION_MISMATCH");
    if (!currentOnlyVersionMismatch && !["compatible_declared", "compatible_legacy"].includes(current.status)) {
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_SOURCE_UNHEALTHY", "Kontrak sumber tidak dapat dibuktikan sehat", 409, { status: current.status, findings: current.findings });
    }
    const target = await assessTarget(ownerId, targetVersion);
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const createdAt = now();
    const unsigned = { id: `${migrationPlanPrefix}${randomUUID()}`, ownerId, kind: PLAN_KIND, schemaVersion: 1,
      fromVersion, targetVersion, reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + 30 * 60 * 1000).toISOString(),
      sourceStatus: { status: current.status, actualVersion: current.actualVersion },
      targetStatus: { status: target.status.status, actualVersion: target.status.actualVersion, findings: target.status.findings },
      conformance: target.conformance, status: "planned", approvalId: null, appliedAt: null };
    const planBase = { ...unsigned, planDigest: immutablePlanDigest(unsigned) };
    const plan = { ...planBase, digest: digestRecord(planBase) };
    await store.putEvidence(ownerId, plan, { overwrite: false });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "contract_migration_planned", {
      planId: plan.id, planDigest: plan.planDigest, fromVersion, targetVersion, conformanceDigest: target.conformance?.conformanceDigest || null, outcome: "planned" });
    return { status: "planned", plan, planDigest: plan.planDigest, confirmation: `APPROVE CONTRACT MIGRATION ${plan.planDigest.slice(0, 12)}`,
      approvalRequired: true, readOnly: false, mutationAllowed: false };
  }
  function immutablePlanDigest(plan) {
    const value = clone(plan);
    for (const field of ["digest", "planDigest", "status", "approvalId", "approvedAt", "appliedAt", "appliedRevision", "_storage"]) delete value[field];
    return sha256(canonical(value));
  }
  function validPlan(plan, ownerId) {
    return plan && plan.ownerId === ownerId && plan.kind === PLAN_KIND && plan.schemaVersion === 1
      && typeof plan.id === "string" && plan.id.startsWith(migrationPlanPrefix) && SUPPORTED.has(plan.fromVersion)
      && SUPPORTED.has(plan.targetVersion) && plan.fromVersion !== plan.targetVersion
      && Number.isFinite(Date.parse(plan.createdAt)) && Number.isFinite(Date.parse(plan.expiresAt))
      && DIGEST.test(plan.planDigest || "") && plan.planDigest === immutablePlanDigest(plan)
      && DIGEST.test(plan.digest || "") && plan.digest === digestRecord(plan);
  }
  async function approveContractMigration(ownerId, planId, input = {}) {
    assertOwner(ownerId);
    const plan = await store.getEvidence(ownerId, planId);
    if (!validPlan(plan, ownerId) || plan.status !== "planned") throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_PLAN_INVALID", "Plan migrasi tidak valid atau tidak lagi menunggu approval", 409);
    if (Date.parse(now()) > Date.parse(plan.expiresAt)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_PLAN_EXPIRED", "Plan migrasi sudah kedaluwarsa", 409);
    if (input.planDigest !== plan.planDigest || input.confirmation !== `APPROVE CONTRACT MIGRATION ${plan.planDigest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CONFIRMATION_INVALID", "Approval harus terikat pada digest plan dan konfirmasi yang tepat", 403);
    }
    if (!validReason(input.reason)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_APPROVAL_REASON_INVALID", "Alasan approval harus 12–240 karakter", 400);
    const status = await currentContractStatus(ownerId);
    if (status.expectedVersion !== plan.fromVersion) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_PLAN_STALE", "Contract version berubah setelah plan dibuat", 409);
    const target = await assessTarget(ownerId, plan.targetVersion);
    await assertOperatorEvidenceCapacity(ownerId, 1);
    if (canonical(target.conformance) !== canonical(plan.conformance)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CONFORMANCE_STALE", "Bukti conformance berubah atau kedaluwarsa", 409);
    const existingApproval = (await store.listEvidence(ownerId)).find(item => item.kind === APPROVAL_KIND && item.planDigest === plan.planDigest && item.status === "approved" && item.digest === digestRecord(item));
    if (existingApproval) return { status: "approved", idempotent: true, approval: { id: existingApproval.id, digest: existingApproval.digest, planId: existingApproval.planId, fromVersion: existingApproval.fromVersion, targetVersion: existingApproval.targetVersion, approvedAt: existingApproval.approvedAt, expiresAt: existingApproval.expiresAt }, readOnly: true, mutationAllowed: false };
    const createdAt = now();
    const unsigned = { id: `${migrationApprovalPrefix}${randomUUID()}`, ownerId, kind: APPROVAL_KIND, schemaVersion: 1,
      planId: plan.id, planDigest: plan.planDigest, fromVersion: plan.fromVersion, targetVersion: plan.targetVersion,
      reason: input.reason.trim(), approvedAt: createdAt, expiresAt: new Date(Date.parse(createdAt) + 30 * 60 * 1000).toISOString(), status: "approved" };
    const approval = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, approval, { overwrite: false });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "contract_migration_approved", {
      planId: plan.id, planDigest: plan.planDigest, approvalId: approval.id, approvalDigest: approval.digest,
      fromVersion: plan.fromVersion, targetVersion: plan.targetVersion, outcome: "approved" });
    return { status: "approved", approval: { id: approval.id, digest: approval.digest, planId: plan.id,
      fromVersion: approval.fromVersion, targetVersion: approval.targetVersion, approvedAt: approval.approvedAt, expiresAt: approval.expiresAt },
      readOnly: true, mutationAllowed: false };
  }
  async function applyContractMigration(ownerId, approvalId, input = {}, internal = {}) {
    assertOwner(ownerId);
    const approval = await store.getEvidence(ownerId, approvalId);
    if (!approval || approval.ownerId !== ownerId || approval.kind !== APPROVAL_KIND || approval.schemaVersion !== 1
      || approval.digest !== digestRecord(approval) || approval.status !== "approved") throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_APPROVAL_INVALID", "Approval migrasi tidak valid", 409);
    if (Date.parse(now()) > Date.parse(approval.expiresAt)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_APPROVAL_EXPIRED", "Approval migrasi sudah kedaluwarsa", 409);
    const plan = await store.getEvidence(ownerId, approval.planId);
    if (!validPlan(plan, ownerId) || plan.planDigest !== approval.planDigest || !["planned", "applied"].includes(plan.status)) {
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_PLAN_INVALID", "Plan dan approval tidak lagi cocok", 409);
    }
    if (plan.status !== "applied" && Date.parse(now()) > Date.parse(plan.expiresAt)) {
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_PLAN_EXPIRED", "Plan migrasi kedaluwarsa sebelum apply", 409);
    }
    if (input.expectedVersion !== approval.fromVersion || input.targetVersion !== approval.targetVersion) {
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_EXPECTATION_INVALID", "Konfirmasi versi sumber dan target tidak cocok", 409);
    }
    const rawLedgerBefore = await store.getEvidence(ownerId, migrationLedgerId(ownerId));
    if (rawLedgerBefore) {
      const rawCheck = validateMigrationLedger(rawLedgerBefore, ownerId);
      if (!rawCheck.valid) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_POLICY_UNHEALTHY", "Migration ledger tidak sehat", 409, { finding: rawCheck.code });
      await ensureMigrationCheckpoint(ownerId, rawLedgerBefore);
    }
    const current = internal.recoveryRetry
      ? await anchorEvidence.getRecoverySloFinalizationKeyPolicyAnchorContractStatusForVersion(ownerId, rawLedgerBefore?.activeVersion ?? defaultContractVersion)
      : await currentContractStatus(ownerId);
    if (current.expectedVersion !== approval.fromVersion) {
      const ledger = await getMigrationLedger(ownerId);
      if (ledger?.activeVersion === approval.targetVersion && ledger.events.some(item => item.payload?.planDigest === plan.planDigest)) {
        await ensureMigrationCheckpoint(ownerId, ledger);
        await updateMigrationJournal(ownerId, plan, approval, "completed", { recoveredFromCommittedLedger: true, migrationRevision: ledger.revision, migrationDigest: ledger.digest });
        if (plan.status !== "applied") {
          const currentPlan = await store.getEvidence(ownerId, plan.id);
          if (currentPlan?.status !== "applied") {
            const updatedUnsigned = { ...clean(currentPlan), status: "applied", appliedAt: now(), appliedRevision: ledger.revision };
            await store.putEvidence(ownerId, { ...updatedUnsigned, digest: digestRecord(updatedUnsigned) }, { expectedVersion: currentPlan?._storage?.version });
          }
        }
        return { status: "applied", idempotent: true, activeVersion: ledger.activeVersion, revision: ledger.revision,
          planId: plan.id, approvalId: approval.id, readOnly: false, mutationAllowed: false };
      }
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_STALE", "Contract version aktif berubah sejak approval", 409);
    }
    const target = await assessTarget(ownerId, approval.targetVersion);
    if (canonical(target.conformance) !== canonical(plan.conformance)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CONFORMANCE_STALE", "Conformance proof tidak lagi berlaku", 409);
    await assertOperatorEvidenceCapacity(ownerId, 2);
    const baselineLedger = await store.getEvidence(ownerId, migrationLedgerId(ownerId));
    const baselineCheck = baselineLedger ? validateMigrationLedger(baselineLedger, ownerId) : null;
    if (baselineLedger && !baselineCheck.valid) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_POLICY_UNHEALTHY", "Migration ledger tidak sehat sebelum apply", 409, { finding: baselineCheck.code });
    const journal = await updateMigrationJournal(ownerId, plan, approval, "applying", {
      baselineRevision: baselineLedger?.revision ?? 0, baselineEventHash: baselineLedger?.events?.at(-1)?.eventHash ?? null,
      recoveryRetry: internal.recoveryRetry === true });
    if (journal.status === "completed") {
      const existingLedger = await getMigrationLedger(ownerId);
      if (existingLedger?.activeVersion === approval.targetVersion && existingLedger.events.some(item => item.payload?.planDigest === plan.planDigest)) {
        return { status: "applied", idempotent: true, activeVersion: existingLedger.activeVersion, revision: existingLedger.revision,
          planId: plan.id, approvalId: approval.id, readOnly: false, mutationAllowed: false };
      }
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_JOURNAL_MISMATCH", "Journal completed tidak cocok dengan ledger", 409);
    }
    let applied;
    try {
      applied = await store.mutateEvidence(ownerId, migrationLedgerId(ownerId), currentRecord => {
        let ledger = currentRecord;
        if (ledger) {
          const audit = validateMigrationLedger(ledger, ownerId);
          if (!audit.valid) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_POLICY_UNHEALTHY", "Migration ledger tidak sehat", 409, { finding: audit.code });
        } else ledger = makeGenesis(ownerId, approval.fromVersion, now());
        if (ledger.activeVersion === approval.targetVersion && ledger.events.some(item => item.payload?.planDigest === plan.planDigest)) {
          return { write: false, result: { status: "applied", idempotent: true, ledger } };
        }
        if (ledger.activeVersion !== approval.fromVersion) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_STALE", "Ledger versi aktif berubah selama apply", 409);
        if (ledger.events.length >= MAX_MIGRATION_EVENTS) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_CAPACITY", "Migration ledger mencapai batas revision", 409);
        const at = now();
        const nextEvent = event(ledger.revision + 1, "contract_version_migrated", at, ledger.events.at(-1).eventHash, {
          activeVersion: approval.targetVersion, fromVersion: approval.fromVersion, targetVersion: approval.targetVersion,
          planId: plan.id, planDigest: plan.planDigest, approvalId: approval.id, approvalDigest: approval.digest,
          conformanceDigest: target.conformance?.conformanceDigest || null, reason: approval.reason });
        const unsigned = { ...ledger, revision: nextEvent.sequence, activeVersion: approval.targetVersion,
          events: [...ledger.events, nextEvent], updatedAt: at };
        const next = { ...unsigned, digest: digestRecord(unsigned) };
        return { value: next, result: { status: "applied", idempotent: false, ledger: next } };
      });
    } catch (error) {
      try { await updateMigrationJournal(ownerId, plan, approval, "recovery_required", { errorCode: error?.code || "MIGRATION_WRITE_FAILED" }); } catch { /* preserve the original failure; audit will detect journal damage */ }
      if (error instanceof AgenticError) throw error;
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_WRITE_FAILED", "Migration policy tidak dapat disimpan; recovery journal dipertahankan", 503);
    }
    const ledger = applied.ledger;
    if (!ledger || !validateMigrationLedger(ledger, ownerId).valid || ledger.activeVersion !== approval.targetVersion) {
      await updateMigrationJournal(ownerId, plan, approval, "recovery_required", { errorCode: "POSTWRITE_LEDGER_INVALID" });
      throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_POSTWRITE_INVALID", "Migration ledger gagal diverifikasi setelah penulisan", 409);
    }
    await ensureMigrationCheckpoint(ownerId, ledger);
    await updateMigrationJournal(ownerId, plan, approval, "completed", { migrationRevision: ledger.revision,
      migrationDigest: ledger.digest, idempotent: applied.idempotent === true });
    const planNow = await store.getEvidence(ownerId, plan.id);
    if (planNow && planNow.status !== "applied") {
      const unsigned = { ...clean(planNow), status: "applied", appliedAt: now(), appliedRevision: ledger.revision };
      await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: planNow._storage?.version });
    }
    if (applied.idempotent) return { status: "applied", idempotent: true, activeVersion: ledger.activeVersion,
      revision: ledger.revision, migrationDigest: ledger.digest, planId: plan.id, approvalId: approval.id,
      readOnly: false, mutationAllowed: false };
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "contract_migration_applied", {
      planId: plan.id, planDigest: plan.planDigest, approvalId: approval.id, approvalDigest: approval.digest,
      fromVersion: approval.fromVersion, targetVersion: approval.targetVersion, migrationRevision: ledger.revision,
      migrationDigest: ledger.digest, outcome: "applied" });
    const status = await currentContractStatus(ownerId);
    return { status: "applied", idempotent: applied.idempotent === true, activeVersion: ledger.activeVersion,
      revision: ledger.revision, migrationDigest: ledger.digest, contractStatus: status.status,
      planId: plan.id, approvalId: approval.id, readOnly: false, mutationAllowed: false };
  }
  async function recoverContractMigration(ownerId, planId, input = {}) {
    assertOwner(ownerId);
    const plan = await store.getEvidence(ownerId, planId);
    if (!validPlan(plan, ownerId)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_PLAN_INVALID", "Plan migrasi tidak valid untuk recovery", 409);
    const approvals = (await store.listEvidence(ownerId)).filter(item => item.kind === APPROVAL_KIND && item.planId === plan.id
      && item.planDigest === plan.planDigest && item.status === "approved" && item.digest === digestRecord(item));
    const approval = approvals.sort((a, b) => String(b.approvedAt).localeCompare(String(a.approvedAt)))[0];
    if (!approval) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_APPROVAL_INVALID", "Approval valid tidak ditemukan untuk recovery", 409);
    const journalId = migrationRecoveryId(ownerId, plan.id);
    let journal = await store.getEvidence(ownerId, journalId);
    if (journal) {
      const check = validateMigrationJournal(journal, ownerId);
      if (!check.valid || journal.planDigest !== plan.planDigest || journal.approvalDigest !== approval.digest) {
        throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_JOURNAL_UNHEALTHY", "Recovery journal tidak valid", 409, { finding: check.code || "BINDING_MISMATCH" });
      }
    }
    const ledger = await store.getEvidence(ownerId, migrationLedgerId(ownerId));
    const checkpoint = await store.getEvidence(ownerId, migrationCheckpointId(ownerId));
    if (ledger) {
      const ledgerCheck = validateMigrationLedger(ledger, ownerId);
      if (!ledgerCheck.valid) return { status: "blocked", finding: ledgerCheck.code, planId: plan.id, journalId, readOnly: true, mutationAllowed: false };
      if (checkpoint) {
        const cpCheck = validateMigrationCheckpoint(checkpoint, ownerId);
        if (!cpCheck.valid) return { status: "blocked", finding: cpCheck.code, planId: plan.id, journalId, readOnly: true, mutationAllowed: false };
        if (checkpoint.highWaterRevision > ledger.revision) return { status: "rollback_detected", finding: "CONTRACT_MIGRATION_ROLLBACK_DETECTED",
          checkpointRevision: checkpoint.highWaterRevision, ledgerRevision: ledger.revision, planId: plan.id, journalId,
          readOnly: true, mutationAllowed: false };
        const ancestor = ledger.events[checkpoint.highWaterRevision - 1];
        if (!ancestor || ancestor.eventHash !== checkpoint.highWaterEventHash) return { status: "blocked", finding: "CONTRACT_MIGRATION_CHECKPOINT_MISMATCH",
          planId: plan.id, journalId, readOnly: true, mutationAllowed: false };
      }
      const committed = ledger.activeVersion === approval.targetVersion
        && ledger.events.some(item => item.payload?.planDigest === plan.planDigest && item.payload?.approvalDigest === approval.digest);
      if (committed) {
        await ensureMigrationCheckpoint(ownerId, ledger);
        if (!journal) journal = await updateMigrationJournal(ownerId, plan, approval, "completed", {
          recoveredFromCommittedLedger: true, migrationRevision: ledger.revision, migrationDigest: ledger.digest });
        else if (journal.status !== "completed") journal = await updateMigrationJournal(ownerId, plan, approval, "completed", {
          recoveredFromCommittedLedger: true, migrationRevision: ledger.revision, migrationDigest: ledger.digest });
        const currentPlan = await store.getEvidence(ownerId, plan.id);
        if (currentPlan?.status !== "applied") {
          const unsigned = { ...clean(currentPlan), status: "applied", appliedAt: now(), appliedRevision: ledger.revision };
          await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: currentPlan?._storage?.version });
        }
        await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "contract_migration_recovered", {
          planId: plan.id, planDigest: plan.planDigest, journalId, migrationRevision: ledger.revision, outcome: "committed_state_reconciled" });
        return { status: "completed", recovered: true, activeVersion: ledger.activeVersion, revision: ledger.revision,
          planId: plan.id, journalId, readOnly: false, mutationAllowed: false };
      }
      if (ledger.activeVersion !== approval.fromVersion) return { status: "blocked", finding: "CONTRACT_MIGRATION_STATE_UNRECOGNIZED",
        activeVersion: ledger.activeVersion, planId: plan.id, journalId, readOnly: true, mutationAllowed: false };
      if (journal?.status === "completed") return { status: "rollback_detected", finding: "CONTRACT_MIGRATION_COMPLETED_JOURNAL_WITH_SOURCE_LEDGER",
        planId: plan.id, journalId, readOnly: true, mutationAllowed: false };
    } else if (checkpoint) {
      return { status: "rollback_detected", finding: "CONTRACT_MIGRATION_LEDGER_MISSING", planId: plan.id, journalId, readOnly: true, mutationAllowed: false };
    }
    if (!journal) journal = await updateMigrationJournal(ownerId, plan, approval, "recovery_required", {
      baselineRevision: ledger?.revision ?? 0, baselineEventHash: ledger?.events?.at(-1)?.eventHash ?? null,
      recoveredFromUncommittedState: true });
    else if (journal.status !== "recovery_required") journal = await updateMigrationJournal(ownerId, plan, approval, "recovery_required", {
      observedRevision: ledger?.revision ?? 0, observedEventHash: ledger?.events?.at(-1)?.eventHash ?? null });
    const confirmation = `RETRY CONTRACT MIGRATION ${plan.planDigest.slice(0, 12)}`;
    if (input.confirmation !== confirmation) return { status: "retry_required", planId: plan.id, journalId,
      confirmation, activeVersion: ledger?.activeVersion ?? defaultContractVersion, readOnly: true, mutationAllowed: false };
    if (Date.parse(now()) > Date.parse(approval.expiresAt)) throw new AgenticError("RECOVERY_SLO_CONTRACT_MIGRATION_APPROVAL_EXPIRED", "Approval kedaluwarsa; recovery tidak boleh menerapkan migrasi otomatis", 409);
    const result = await applyContractMigration(ownerId, approval.id, { expectedVersion: approval.fromVersion,
      targetVersion: approval.targetVersion }, { recoveryRetry: true });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "contract_migration_recovered", {
      planId: plan.id, planDigest: plan.planDigest, journalId, outcome: "explicit_retry_applied" });
    return { ...result, recovered: true, journalId };
  }
  async function auditContractMigration(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, migrationLedgerId(ownerId));
    const checkpoint = await store.getEvidence(ownerId, migrationCheckpointId(ownerId));
    if (!record) return { status: checkpoint ? "unhealthy" : "empty", ownerId, activeVersion: checkpoint ? null : defaultContractVersion,
      revision: 0, eventCount: 0, findings: checkpoint ? [{ code: "CONTRACT_MIGRATION_LEDGER_MISSING", severity: "error" }] : [],
      readOnly: true, mutationAllowed: false };
    const audit = validateMigrationLedger(record, ownerId);
    const findings = audit.valid ? [] : [{ code: audit.code, severity: "error" }];
    let checkpointStatus = "not_initialized";
    if (audit.valid && checkpoint) {
      const cpCheck = validateMigrationCheckpoint(checkpoint, ownerId);
      if (!cpCheck.valid) { checkpointStatus = "unhealthy"; findings.push({ code: cpCheck.code, severity: "error" }); }
      else if (checkpoint.highWaterRevision > record.revision) {
        checkpointStatus = "rollback_detected"; findings.push({ code: "RECOVERY_SLO_CONTRACT_MIGRATION_ROLLBACK_DETECTED", severity: "error" });
      } else if (record.events[checkpoint.highWaterRevision - 1]?.eventHash !== checkpoint.highWaterEventHash) {
        checkpointStatus = "mismatch"; findings.push({ code: "RECOVERY_SLO_CONTRACT_MIGRATION_CHECKPOINT_MISMATCH", severity: "error" });
      } else checkpointStatus = checkpoint.highWaterRevision === record.revision ? "healthy" : "behind_ledger";
    }
    let journals = [];
    try { journals = await listMigrationRecoveryJournals(ownerId); }
    catch (error) { findings.push({ code: error.code || "CONTRACT_MIGRATION_RECOVERY_JOURNAL_INVALID", severity: "error" }); }
    const unresolved = journals.filter(item => ["applying", "recovery_required", "blocked"].includes(item.status));
    if (unresolved.length) findings.push({ code: "CONTRACT_MIGRATION_RECOVERY_REQUIRED", severity: "warning", count: unresolved.length,
      journalIds: unresolved.slice(0, 10).map(item => item.id) });
    const hasErrors = findings.some(item => item.severity === "error");
    const checkpointNeedsRecovery = ["not_initialized", "behind_ledger"].includes(checkpointStatus);
    if (checkpointNeedsRecovery) findings.push({ code: "CONTRACT_MIGRATION_CHECKPOINT_ADVANCE_REQUIRED", severity: "warning" });
    return { status: hasErrors ? "unhealthy" : unresolved.length || checkpointNeedsRecovery ? "recovery_required" : "healthy", ownerId,
      activeVersion: audit.valid && !findings.some(item => item.severity === "error") ? record.activeVersion : null,
      revision: audit.valid ? record.revision : null, eventCount: record.events?.length ?? 0,
      digest: audit.valid ? record.digest : null, checkpointStatus, recoveryJournalCount: journals.length,
      findings: findings.slice(0, 50), readOnly: true, mutationAllowed: false };
  }

  function runbookKeyPolicyGenesis(ownerId, id) { return sha256(`agentic-v4-runbook-key-policy:${ownerId}:${id}`); }
  function publicKeyFromDer(value) {
    try {
      const key = createPublicKey({ key: Buffer.from(value, "base64"), format: "der", type: "spki" });
      return key.type === "public" && key.asymmetricKeyType === "ed25519" ? key : null;
    } catch { return null; }
  }
  function validateRunbookKeyPolicy(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.id !== runbookKeyPolicyId(ownerId)
      || record.kind !== RUNBOOK_KEY_POLICY_KIND || record.schemaVersion !== 1
      || record.bootstrapDigest !== runbookBootstrapDigest || !Number.isSafeInteger(record.revision)
      || record.revision < 1 || !Array.isArray(record.events) || record.events.length !== record.revision || record.events.length > 500
      || !Array.isArray(record.keys) || record.keys.length > 50 || !DIGEST.test(record.digest || "")) {
      return { valid: false, code: "RUNBOOK_KEY_POLICY_SHAPE_OR_BOOTSTRAP_INVALID" };
    }
    const ids = new Set();
    for (const key of record.keys) {
      if (!key || !KEY_ID.test(key.keyId || "") || ids.has(key.keyId) || !publicKeyFromDer(key.publicKeyDer)
        || !["active", "trusted", "retired", "revoked"].includes(key.status)
        || (key.bootstrapTrusted != null && typeof key.bootstrapTrusted !== "boolean")) return { valid: false, code: "RUNBOOK_KEY_POLICY_KEY_INVALID" };
      ids.add(key.keyId);
      for (const field of ["activatedAt", "retiredAt", "revokedAt", "invalidateBefore"]) {
        if (key[field] != null && !Number.isFinite(Date.parse(key[field]))) return { valid: false, code: "RUNBOOK_KEY_POLICY_KEY_TIME_INVALID" };
      }
    }
    const active = record.keys.filter(key => key.status === "active");
    if ((record.activeKeyId == null && active.length !== 0) || (record.activeKeyId != null && (active.length !== 1 || active[0].keyId !== record.activeKeyId))) {
      return { valid: false, code: "RUNBOOK_KEY_POLICY_ACTIVE_KEY_INVALID" };
    }
    let previous = runbookKeyPolicyGenesis(ownerId, record.id);
    for (let i = 0; i < record.events.length; i++) {
      const item = record.events[i];
      if (!item || item.sequence !== i + 1 || item.previousHash !== previous || !Number.isFinite(Date.parse(item.at))
        || item.eventHash !== eventHash(item)) return { valid: false, code: "RUNBOOK_KEY_POLICY_CHAIN_INVALID" };
      previous = item.eventHash;
    }
    const last = record.events.at(-1);
    if (last.payload?.activeKeyId !== record.activeKeyId || record.digest !== digestRecord(record)) {
      return { valid: false, code: "RUNBOOK_KEY_POLICY_DIGEST_INVALID" };
    }
    return { valid: true };
  }
  function validateRunbookKeyPolicyCheckpoint(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.id !== runbookKeyPolicyCheckpointId(ownerId)
      || record.kind !== "recovery-slo-runbook-signing-key-policy-checkpoint" || record.schemaVersion !== 1
      || !Number.isSafeInteger(record.highWaterRevision) || record.highWaterRevision < 1
      || !DIGEST.test(record.highWaterEventHash || "") || (record.activeKeyId != null && !KEY_ID.test(record.activeKeyId))
      || record.bootstrapDigest !== runbookBootstrapDigest || !Number.isFinite(Date.parse(record.updatedAt))
      || record.digest !== digestRecord(record)) return { valid: false, code: "RUNBOOK_KEY_POLICY_CHECKPOINT_INVALID" };
    return { valid: true };
  }
  function makeRunbookKeyPolicyCheckpoint(ownerId, policy, previous = null) {
    const unsigned = { id: runbookKeyPolicyCheckpointId(ownerId), ownerId,
      kind: "recovery-slo-runbook-signing-key-policy-checkpoint", schemaVersion: 1,
      highWaterRevision: policy.revision, highWaterEventHash: policy.events.at(-1).eventHash,
      activeKeyId: policy.activeKeyId, bootstrapDigest: policy.bootstrapDigest,
      previousCheckpointDigest: previous?.digest || null, updatedAt: now() };
    return { ...unsigned, digest: digestRecord(unsigned) };
  }
  async function ensureRunbookKeyPolicyCheckpoint(ownerId, policy) {
    const id = runbookKeyPolicyCheckpointId(ownerId);
    let checkpoint = await store.getEvidence(ownerId, id);
    if (!checkpoint) {
      const created = makeRunbookKeyPolicyCheckpoint(ownerId, policy);
      try { await store.putEvidence(ownerId, created, { overwrite: false }); } catch { /* concurrent bootstrap */ }
      checkpoint = await store.getEvidence(ownerId, id);
    }
    const check = validateRunbookKeyPolicyCheckpoint(checkpoint, ownerId);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_CHECKPOINT_UNHEALTHY", "Runbook key-policy checkpoint tidak sehat", 409, { finding: check.code });
    if (checkpoint.highWaterRevision > policy.revision) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_ROLLBACK_DETECTED", "Runbook key policy berada di bawah high-water checkpoint", 409,
      { checkpointRevision: checkpoint.highWaterRevision, policyRevision: policy.revision });
    const ancestor = policy.events[checkpoint.highWaterRevision - 1];
    if (!ancestor || ancestor.eventHash !== checkpoint.highWaterEventHash
      || (checkpoint.highWaterRevision === policy.revision && checkpoint.activeKeyId !== policy.activeKeyId)) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_CHECKPOINT_MISMATCH", "Runbook key-policy history tidak cocok dengan checkpoint", 409);
    }
    if (policy.revision > checkpoint.highWaterRevision) {
      const next = makeRunbookKeyPolicyCheckpoint(ownerId, policy, checkpoint);
      await store.putEvidence(ownerId, next, { expectedVersion: checkpoint._storage?.version });
      checkpoint = await store.getEvidence(ownerId, id);
      const after = validateRunbookKeyPolicyCheckpoint(checkpoint, ownerId);
      if (!after.valid || checkpoint.highWaterRevision !== policy.revision
        || checkpoint.highWaterEventHash !== policy.events.at(-1).eventHash) {
        throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_CHECKPOINT_WRITE_FAILED", "Checkpoint key policy gagal diverifikasi setelah rotasi", 409);
      }
    }
    return checkpoint;
  }
  async function getRunbookKeyPolicy(ownerId) {
    assertOwner(ownerId);
    if (!signingConfigured && keys.size === 0) return null;
    const id = runbookKeyPolicyId(ownerId);
    let record = await store.getEvidence(ownerId, id);
    if (!record) {
      const at = now();
      const policyKeys = [...keys.entries()].map(([keyId, key]) => ({ keyId,
        publicKeyDer: key.export({ type: "spki", format: "der" }).toString("base64"),
        status: keyId === runbookKeyId ? "active" : "trusted",
        // Preserve bootstrap provenance when a trusted-only key is later retired or revoked.
        bootstrapTrusted: keyId !== runbookKeyId,
        activatedAt: keyId === runbookKeyId ? "1970-01-01T00:00:00.000Z" : null,
        retiredAt: null, revokedAt: null, invalidateBefore: null }));
      const first = event(1, "runbook_key_policy_bootstrapped", at, runbookKeyPolicyGenesis(ownerId, id), {
        activeKeyId: runbookKeyId, bootstrapDigest: runbookBootstrapDigest, keyIds: policyKeys.map(item => item.keyId).sort() });
      const unsigned = { id, ownerId, kind: RUNBOOK_KEY_POLICY_KIND, schemaVersion: 1, bootstrapDigest: runbookBootstrapDigest,
        revision: 1, activeKeyId: runbookKeyId, keys: policyKeys, events: [first], createdAt: at, updatedAt: at };
      const created = { ...unsigned, digest: digestRecord(unsigned) };
      try { await store.putEvidence(ownerId, created, { overwrite: false }); } catch { /* concurrent bootstrap; validate winner */ }
      record = await store.getEvidence(ownerId, id);
    }
    const check = validateRunbookKeyPolicy(record, ownerId);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_UNHEALTHY", "Runbook signing-key policy tidak sehat atau bootstrap trust berubah", 409, { finding: check.code });
    await ensureRunbookKeyPolicyCheckpoint(ownerId, record);
    return record;
  }
  async function updateRunbookKeyPolicy(ownerId, current, nextKeys, nextActiveKeyId, type, payload) {
    const at = now();
    return store.mutateEvidence(ownerId, current.id, existing => {
      if (!existing) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_MISSING", "Runbook key policy hilang selama transisi", 409);
      const check = validateRunbookKeyPolicy(existing, ownerId);
      if (!check.valid) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_UNHEALTHY", "Runbook key policy tidak sehat", 409, { finding: check.code });
      if (existing.revision !== current.revision || existing.digest !== current.digest) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_STALE", "Runbook key policy berubah selama transisi", 409);
      if (existing.revision >= 500) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_CAPACITY", "Runbook key policy mencapai batas transisi", 409);
      const nextEvent = event(existing.revision + 1, type, at, existing.events.at(-1).eventHash,
        { ...payload, activeKeyId: nextActiveKeyId });
      const unsigned = { ...clean(existing), revision: nextEvent.sequence, activeKeyId: nextActiveKeyId,
        keys: nextKeys, events: [...existing.events, nextEvent], updatedAt: at };
      const next = { ...unsigned, digest: digestRecord(unsigned) };
      return { value: next, result: next };
    });
  }
  async function createRunbookKeyTransitionChallenge(ownerId, input = {}) {
    assertOwner(ownerId);
    if (!runbookSigner) throw new AgenticError("RECOVERY_SLO_RUNBOOK_SIGNER_REQUIRED", "Runbook key rotation membutuhkan external signer", 503);
    const policy = await getRunbookKeyPolicy(ownerId);
    const action = input.action || "rotate";
    if (!new Set(["rotate", "recover"]).has(action)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_ACTION_INVALID", "Action harus rotate atau recover", 400);
    if (input.expectedRevision !== policy.revision) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_STALE", "Revision key policy tidak cocok", 409);
    if (action === "rotate" && !policy.activeKeyId) throw new AgenticError("RECOVERY_SLO_RUNBOOK_ACTIVE_KEY_REQUIRED", "Tidak ada kunci aktif; gunakan recovery authority untuk memasang kunci pengganti", 409);
    if (action === "recover" && (policy.activeKeyId || !recoveryKeys.size)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_REQUIRED", "Recovery hanya diizinkan tanpa kunci aktif dan dengan recovery authority tepercaya", 409);
    if (!KEY_ID.test(input.newKeyId || "") || policy.keys.some(item => item.keyId === input.newKeyId)) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_NEW_KEY_ID_INVALID", "New key ID tidak valid atau sudah digunakan", 400);
    }
    if (!validReason(input.reason)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_REASON_INVALID", "Alasan rotasi harus 12–240 karakter", 400);
    let newPublicKey;
    try { newPublicKey = parsePublicKey(input.newPublicKey); } catch { throw new AgenticError("RECOVERY_SLO_RUNBOOK_NEW_PUBLIC_KEY_INVALID", "Public key baru harus Ed25519", 400); }
    const authorityKeyId = action === "recover" ? input.recoveryAuthorityKeyId : null;
    if (action === "recover" && (typeof authorityKeyId !== "string" || !recoveryKeys.has(authorityKeyId))) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_REQUIRED", "Recovery authority key ID tidak tepercaya", 403);
    }
    const newPublicKeyDer = newPublicKey.export({ type: "spki", format: "der" }).toString("base64");
    if (policy.keys.some(item => item.publicKeyDer === newPublicKeyDer)
      || [...recoveryKeys.values()].some(key => key.export({ type: "spki", format: "der" }).toString("base64") === newPublicKeyDer)) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_NEW_KEY_NOT_INDEPENDENT", "Kunci pengganti harus baru dan berbeda dari seluruh kunci lama serta recovery authority", 400);
    }
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const createdAt = now();
    const expiresAt = new Date(Date.parse(createdAt) + 10 * 60 * 1000).toISOString();
    const id = `${runbookKeyChallengePrefix}${randomUUID()}`;
    const basePayload = { domain: "agentic-v4-runbook-key-transition", schemaVersion: 1, ownerId, challengeId: id, action,
      expectedRevision: policy.revision, policyDigest: policy.digest, oldKeyId: policy.activeKeyId, newKeyId: input.newKeyId,
      newPublicKeyDer, reason: input.reason.trim(), recoveryAuthorityKeyId: authorityKeyId,
      recoveryAuthorityDigest: action === "recover" ? recoveryAuthorityDigest : null, createdAt, expiresAt };
    const authorizationPayload = { ...basePayload, purpose: action === "recover" ? "authorize_key_recovery" : "authorize_rotation" };
    const proofOfPossessionPayload = { ...basePayload, purpose: "proof_of_possession" };
    const unsigned = { id, ownerId, kind: RUNBOOK_KEY_CHALLENGE_KIND, schemaVersion: 1, action,
      expectedRevision: policy.revision, policyDigest: policy.digest, oldKeyId: policy.activeKeyId,
      newKeyId: input.newKeyId, newPublicKeyDer, reason: input.reason.trim(), recoveryAuthorityKeyId: authorityKeyId,
      recoveryAuthorityDigest: action === "recover" ? recoveryAuthorityDigest : null,
      createdAt, expiresAt, authorizationPayload, proofOfPossessionPayload, status: "prepared", appliedAt: null };
    const challengeDigest = sha256(canonical(unsigned));
    const challengeBase = { ...unsigned, challengeDigest };
    const challenge = { ...challengeBase, digest: digestRecord(challengeBase) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, action === "recover" ? "runbook_key_recovery_prepared" : "runbook_key_rotation_prepared", {
      challengeId: id, challengeDigest, oldKeyId: policy.activeKeyId, newKeyId: input.newKeyId, outcome: "prepared" });
    const label = action === "recover" ? "RUNBOOK KEY RECOVERY" : "RUNBOOK KEY ROTATION";
    return { status: "prepared", challenge: { id, challengeDigest, action, expectedRevision: policy.revision,
      oldKeyId: policy.activeKeyId, newKeyId: input.newKeyId, recoveryAuthorityKeyId: authorityKeyId,
      createdAt, expiresAt, authorizationPayload, proofOfPossessionPayload, status: "prepared" },
      confirmation: `APPROVE ${label} ${challengeDigest.slice(0, 12)}`, approvalRequired: true, readOnly: false, mutationAllowed: false };
  }
  async function applyRunbookKeyTransition(ownerId, challengeId, input = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== RUNBOOK_KEY_CHALLENGE_KIND
      || challenge.schemaVersion !== 1 || !["rotate", "recover"].includes(challenge.action) || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_CHALLENGE_INVALID", "Runbook key transition challenge tidak valid", 409);
    }
    const challengeBase = clean(challenge); delete challengeBase.digest; delete challengeBase.challengeDigest;
    if (challenge.challengeDigest !== sha256(canonical(challengeBase))) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_CHALLENGE_DIGEST_INVALID", "Digest challenge tidak valid", 409);
    const policy = await getRunbookKeyPolicy(ownerId);
    const committedEvent = policy.events.find(item => ["runbook_key_rotated", "runbook_key_recovered"].includes(item.type)
      && item.payload?.challengeId === challengeId && item.payload?.challengeDigest === challenge.challengeDigest && item.payload?.newKeyId === challenge.newKeyId);
    if (committedEvent) {
      if (challenge.status !== "applied") {
        const unsignedChallenge = { ...clean(challenge), status: "applied", appliedAt: committedEvent.at, appliedRevision: committedEvent.sequence };
        await store.putEvidence(ownerId, { ...unsignedChallenge, digest: digestRecord(unsignedChallenge) }, { expectedVersion: challenge._storage?.version });
      }
      return { status: "applied", idempotent: true, activeKeyId: policy.activeKeyId, appliedKeyId: challenge.newKeyId,
        revision: policy.revision, policyDigest: policy.digest, challengeId, recovered: challenge.status !== "applied",
        readOnly: false, mutationAllowed: false };
    }
    if (challenge.status === "applied") throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_CHALLENGE_STATE_MISMATCH", "Challenge menyatakan applied tetapi event transisi tidak ada dalam key policy", 409);
    if (Date.parse(now()) > Date.parse(challenge.expiresAt)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_CHALLENGE_EXPIRED", "Challenge runbook kedaluwarsa", 409);
    const label = challenge.action === "recover" ? "RUNBOOK KEY RECOVERY" : "RUNBOOK KEY ROTATION";
    if (input.confirmation !== `APPROVE ${label} ${challenge.challengeDigest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_CONFIRMATION_INVALID", "Konfirmasi transisi tidak cocok", 403);
    }
    if (policy.revision !== challenge.expectedRevision || policy.digest !== challenge.policyDigest || policy.activeKeyId !== challenge.oldKeyId) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_STALE", "Runbook key policy berubah setelah challenge dibuat", 409);
    }
    const newPublicKey = publicKeyFromDer(challenge.newPublicKeyDer);
    if (!newPublicKey || !verifyEd25519(newPublicKey, challenge.proofOfPossessionPayload, input.proofOfPossession)) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_PROOF_INVALID", "Transisi membutuhkan proof-of-possession kunci baru", 403);
    }
    if (challenge.action === "rotate") {
      const oldEntry = policy.keys.find(item => item.keyId === challenge.oldKeyId && item.status === "active");
      const oldPublicKey = oldEntry && publicKeyFromDer(oldEntry.publicKeyDer);
      if (!oldPublicKey || !verifyEd25519(oldPublicKey, challenge.authorizationPayload, input.authorizationSignature)) {
        throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_PROOF_INVALID", "Rotasi membutuhkan otorisasi kunci lama", 403);
      }
    } else {
      const authority = recoveryKeys.get(challenge.recoveryAuthorityKeyId);
      if (!authority || challenge.recoveryAuthorityDigest !== recoveryAuthorityDigest
        || !verifyEd25519(authority, challenge.authorizationPayload, input.recoveryAuthoritySignature)) {
        throw new AgenticError("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_INVALID", "Recovery membutuhkan signature dari recovery authority yang masih tepercaya", 403);
      }
      if (policy.activeKeyId) throw new AgenticError("RECOVERY_SLO_RUNBOOK_RECOVERY_STATE_INVALID", "Recovery key hanya dapat digunakan ketika tidak ada kunci aktif", 409);
    }
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const at = now();
    const nextKeys = policy.keys.map(item => challenge.action === "rotate" && item.keyId === challenge.oldKeyId
      ? { ...item, status: "retired", retiredAt: at }
      : item);
    nextKeys.push({ keyId: challenge.newKeyId, publicKeyDer: challenge.newPublicKeyDer, status: "active",
      activatedAt: at, retiredAt: null, revokedAt: null, invalidateBefore: null });
    let nextPolicy;
    try {
      nextPolicy = await updateRunbookKeyPolicy(ownerId, policy, nextKeys, challenge.newKeyId,
        challenge.action === "recover" ? "runbook_key_recovered" : "runbook_key_rotated", {
          challengeId, challengeDigest: challenge.challengeDigest, oldKeyId: challenge.oldKeyId, newKeyId: challenge.newKeyId,
          recoveryAuthorityKeyId: challenge.recoveryAuthorityKeyId || null, reason: challenge.reason, rotatedAt: at });
      await ensureRunbookKeyPolicyCheckpoint(ownerId, nextPolicy);
    } catch (error) {
      if (error instanceof AgenticError) throw error;
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_ROTATION_WRITE_FAILED", "Runbook key policy tidak dapat disimpan", 503);
    }
    const unsignedChallenge = { ...clean(challenge), status: "applied", appliedAt: at, appliedRevision: nextPolicy.revision };
    await store.putEvidence(ownerId, { ...unsignedChallenge, digest: digestRecord(unsignedChallenge) }, { expectedVersion: challenge._storage?.version });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId,
      challenge.action === "recover" ? "runbook_key_recovered" : "runbook_key_rotated", {
        challengeId, challengeDigest: challenge.challengeDigest, oldKeyId: challenge.oldKeyId,
        newKeyId: challenge.newKeyId, policyRevision: nextPolicy.revision, outcome: "applied" });
    return { status: "applied", idempotent: false, activeKeyId: nextPolicy.activeKeyId, revision: nextPolicy.revision,
      policyDigest: nextPolicy.digest, challengeId, readOnly: false, mutationAllowed: false };
  }
  async function createRunbookKeyRevocationChallenge(ownerId, input = {}) {
    assertOwner(ownerId);
    if (!recoveryKeys.size) throw new AgenticError("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_REQUIRED", "Runbook key revocation membutuhkan recovery authority tepercaya", 503);
    const policy = await getRunbookKeyPolicy(ownerId);
    if (!policy) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_NOT_INITIALIZED", "Runbook signing-key policy belum dikonfigurasi", 409);
    if (input.expectedRevision !== policy.revision) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_STALE", "Revision key policy tidak cocok", 409);
    const target = policy.keys.find(item => item.keyId === input.targetKeyId);
    if (!target || target.status === "revoked") throw new AgenticError("RECOVERY_SLO_RUNBOOK_REVOCATION_TARGET_INVALID", "Target key tidak tersedia atau sudah dicabut", 409);
    if (!validReason(input.reason)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_REASON_INVALID", "Alasan pencabutan harus 12–240 karakter", 400);
    const authorityKeyId = input.recoveryAuthorityKeyId;
    if (typeof authorityKeyId !== "string" || !recoveryKeys.has(authorityKeyId)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_REQUIRED", "Recovery authority key ID tidak tepercaya", 403);
    let invalidateBefore = null;
    if (input.invalidateBefore != null) {
      const cutoff = Date.parse(String(input.invalidateBefore));
      if (!Number.isFinite(cutoff) || cutoff > Date.parse(now())) throw new AgenticError("RECOVERY_SLO_RUNBOOK_COMPROMISE_CUTOFF_INVALID", "Compromise cutoff harus berupa timestamp valid yang tidak berada di masa depan", 400);
      invalidateBefore = new Date(cutoff).toISOString();
    }
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const createdAt = now();
    const expiresAt = new Date(Date.parse(createdAt) + 10 * 60 * 1000).toISOString();
    const id = `${runbookKeyRevocationChallengePrefix}${randomUUID()}`;
    const authorizationPayload = { domain: "agentic-v4-runbook-key-revocation", schemaVersion: 1, ownerId, challengeId: id,
      expectedRevision: policy.revision, policyDigest: policy.digest, targetKeyId: target.keyId,
      targetPublicKeyDigest: sha256(target.publicKeyDer), reason: input.reason.trim(), invalidateBefore,
      recoveryAuthorityKeyId: authorityKeyId, recoveryAuthorityDigest, createdAt, expiresAt, purpose: "authorize_revocation" };
    const unsigned = { id, ownerId, kind: RUNBOOK_KEY_REVOCATION_CHALLENGE_KIND, schemaVersion: 1, action: "revoke",
      expectedRevision: policy.revision, policyDigest: policy.digest, targetKeyId: target.keyId,
      targetPublicKeyDigest: sha256(target.publicKeyDer), reason: input.reason.trim(), invalidateBefore,
      recoveryAuthorityKeyId: authorityKeyId, recoveryAuthorityDigest, authorizationPayload, createdAt, expiresAt,
      status: "prepared", appliedAt: null };
    const challengeDigest = sha256(canonical(unsigned));
    const challengeBase = { ...unsigned, challengeDigest };
    const challenge = { ...challengeBase, digest: digestRecord(challengeBase) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "runbook_key_revocation_prepared", {
      challengeId: id, challengeDigest, targetKeyId: target.keyId, invalidateBefore, outcome: "prepared" });
    return { status: "prepared", challenge: { id, challengeDigest, targetKeyId: target.keyId, expectedRevision: policy.revision,
      invalidateBefore, recoveryAuthorityKeyId: authorityKeyId, authorizationPayload, createdAt, expiresAt, status: "prepared" },
      confirmation: `APPROVE RUNBOOK KEY REVOCATION ${challengeDigest.slice(0, 12)}`, approvalRequired: true,
      readOnly: false, mutationAllowed: false };
  }
  async function applyRunbookKeyRevocation(ownerId, challengeId, input = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== RUNBOOK_KEY_REVOCATION_CHALLENGE_KIND
      || challenge.schemaVersion !== 1 || challenge.action !== "revoke" || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_REVOCATION_CHALLENGE_INVALID", "Runbook key revocation challenge tidak valid", 409);
    }
    const base = clean(challenge); delete base.digest; delete base.challengeDigest;
    if (challenge.challengeDigest !== sha256(canonical(base))) throw new AgenticError("RECOVERY_SLO_RUNBOOK_REVOCATION_CHALLENGE_DIGEST_INVALID", "Digest revocation challenge tidak valid", 409);
    const policy = await getRunbookKeyPolicy(ownerId);
    const committed = policy.events.find(item => item.type === "runbook_key_revoked" && item.payload?.challengeId === challengeId
      && item.payload?.challengeDigest === challenge.challengeDigest && item.payload?.targetKeyId === challenge.targetKeyId);
    if (committed) return { status: "revoked", idempotent: true, targetKeyId: challenge.targetKeyId,
      activeKeyId: policy.activeKeyId, revision: policy.revision, challengeId, readOnly: false, mutationAllowed: false };
    if (challenge.status !== "prepared" || Date.parse(now()) > Date.parse(challenge.expiresAt)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_REVOCATION_CHALLENGE_EXPIRED", "Revocation challenge tidak lagi berlaku", 409);
    if (input.confirmation !== `APPROVE RUNBOOK KEY REVOCATION ${challenge.challengeDigest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_CONFIRMATION_INVALID", "Konfirmasi pencabutan tidak cocok", 403);
    }
    if (policy.revision !== challenge.expectedRevision || policy.digest !== challenge.policyDigest
      || challenge.recoveryAuthorityDigest !== recoveryAuthorityDigest) throw new AgenticError("RECOVERY_SLO_RUNBOOK_KEY_POLICY_STALE", "Key policy atau recovery authority berubah setelah challenge dibuat", 409);
    const authority = recoveryKeys.get(challenge.recoveryAuthorityKeyId);
    if (!authority || !verifyEd25519(authority, challenge.authorizationPayload, input.recoveryAuthoritySignature)) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_INVALID", "Pencabutan membutuhkan signature recovery authority", 403);
    }
    const target = policy.keys.find(item => item.keyId === challenge.targetKeyId);
    if (!target || target.status === "revoked" || sha256(target.publicKeyDer) !== challenge.targetPublicKeyDigest) {
      throw new AgenticError("RECOVERY_SLO_RUNBOOK_REVOCATION_TARGET_STALE", "Kunci target berubah atau sudah dicabut", 409);
    }
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const at = now();
    const nextKeys = policy.keys.map(item => item.keyId === target.keyId
      ? { ...item, bootstrapTrusted: item.bootstrapTrusted ?? (item.activatedAt == null && item.status === "trusted"),
        status: "revoked", revokedAt: at, invalidateBefore: challenge.invalidateBefore }
      : item);
    const nextActiveKeyId = policy.activeKeyId === target.keyId ? null : policy.activeKeyId;
    const nextPolicy = await updateRunbookKeyPolicy(ownerId, policy, nextKeys, nextActiveKeyId, "runbook_key_revoked", {
      challengeId, challengeDigest: challenge.challengeDigest, targetKeyId: target.keyId,
      targetPublicKeyDigest: challenge.targetPublicKeyDigest, recoveryAuthorityKeyId: challenge.recoveryAuthorityKeyId,
      recoveryAuthorityDigest: challenge.recoveryAuthorityDigest, invalidateBefore: challenge.invalidateBefore,
      reason: challenge.reason, revokedAt: at });
    await ensureRunbookKeyPolicyCheckpoint(ownerId, nextPolicy);
    const unsignedChallenge = { ...clean(challenge), status: "applied", appliedAt: at, appliedRevision: nextPolicy.revision };
    await store.putEvidence(ownerId, { ...unsignedChallenge, digest: digestRecord(unsignedChallenge) }, { expectedVersion: challenge._storage?.version });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "runbook_key_revoked", {
      challengeId, challengeDigest: challenge.challengeDigest, targetKeyId: target.keyId,
      invalidateBefore: challenge.invalidateBefore, policyRevision: nextPolicy.revision, outcome: "revoked" });
    return { status: "revoked", idempotent: false, targetKeyId: target.keyId, activeKeyId: nextPolicy.activeKeyId,
      invalidateBefore: challenge.invalidateBefore, revision: nextPolicy.revision, policyDigest: nextPolicy.digest,
      challengeId, readOnly: false, mutationAllowed: false };
  }
  async function auditRunbookKeyPolicy(ownerId) {
    assertOwner(ownerId);
    if (!signingConfigured && keys.size === 0) return { status: "not_configured", ownerId, readOnly: true, mutationAllowed: false, findings: [] };
    const policy = await store.getEvidence(ownerId, runbookKeyPolicyId(ownerId));
    if (!policy) return { status: "not_initialized", ownerId, activeKeyId: runbookKeyId || null, revision: 0,
      findings: [{ code: "RUNBOOK_KEY_POLICY_NOT_INITIALIZED", severity: "warning" }], readOnly: true, mutationAllowed: false };
    const check = validateRunbookKeyPolicy(policy, ownerId);
    const checkpoint = await store.getEvidence(ownerId, runbookKeyPolicyCheckpointId(ownerId));
    const findings = check.valid ? [] : [{ code: check.code, severity: "error" }];
    let checkpointStatus = "not_initialized";
    if (check.valid && checkpoint) {
      const cpCheck = validateRunbookKeyPolicyCheckpoint(checkpoint, ownerId);
      if (!cpCheck.valid) { checkpointStatus = "unhealthy"; findings.push({ code: cpCheck.code, severity: "error" }); }
      else if (checkpoint.highWaterRevision > policy.revision) {
        checkpointStatus = "rollback_detected"; findings.push({ code: "RUNBOOK_KEY_POLICY_ROLLBACK_DETECTED", severity: "error" });
      } else if (policy.events[checkpoint.highWaterRevision - 1]?.eventHash !== checkpoint.highWaterEventHash) {
        checkpointStatus = "mismatch"; findings.push({ code: "RUNBOOK_KEY_POLICY_CHECKPOINT_MISMATCH", severity: "error" });
      } else checkpointStatus = checkpoint.highWaterRevision === policy.revision ? "healthy" : "behind_policy";
    }
    if (checkpointStatus === "not_initialized" || checkpointStatus === "behind_policy") findings.push({ code: "RUNBOOK_KEY_POLICY_CHECKPOINT_ADVANCE_REQUIRED", severity: "warning" });
    const hasErrors = findings.some(item => item.severity === "error");
    return { status: hasErrors ? "unhealthy" : checkpointStatus === "healthy" ? "healthy" : "degraded", ownerId,
      activeKeyId: check.valid && !hasErrors ? policy.activeKeyId : null, revision: check.valid ? policy.revision : null,
      keyCount: check.valid ? policy.keys.length : 0, revokedKeyIds: check.valid ? policy.keys.filter(item => item.status === "revoked").map(item => item.keyId) : [],
      compromiseCutoffs: check.valid ? policy.keys.filter(item => item.status === "revoked" && item.invalidateBefore).map(item => ({ keyId: item.keyId, invalidateBefore: item.invalidateBefore })) : [],
      digest: check.valid ? policy.digest : null, checkpointStatus,
      findings: findings.slice(0, 50), readOnly: true, mutationAllowed: false };
  }

  function retentionPolicyGenesis(ownerId, id) { return sha256(`agentic-v4-retention-policy:${ownerId}:${id}`); }
  function validateRetentionPolicy(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.id !== retentionPolicyId(ownerId) || record.kind !== RETENTION_POLICY_KIND
      || record.schemaVersion !== 1 || !Number.isSafeInteger(record.revision) || record.revision < 1
      || !Number.isSafeInteger(record.retentionDays) || record.retentionDays < 1 || record.retentionDays > 3650
      || !Array.isArray(record.events) || record.events.length !== record.revision || record.events.length > 500
      || !DIGEST.test(record.digest || "")) return { valid: false, code: "RETENTION_POLICY_SHAPE_INVALID" };
    let previous = retentionPolicyGenesis(ownerId, record.id);
    for (let i = 0; i < record.events.length; i++) {
      const item = record.events[i];
      if (!item || item.sequence !== i + 1 || item.previousHash !== previous || !Number.isFinite(Date.parse(item.at))
        || item.eventHash !== eventHash(item)) return { valid: false, code: "RETENTION_POLICY_CHAIN_INVALID" };
      previous = item.eventHash;
    }
    if (record.events.at(-1).payload?.retentionDays !== record.retentionDays || record.digest !== digestRecord(record)) {
      return { valid: false, code: "RETENTION_POLICY_DIGEST_INVALID" };
    }
    return { valid: true };
  }
  function validateRetentionPolicyCheckpoint(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.id !== retentionPolicyCheckpointId(ownerId)
      || record.kind !== RETENTION_POLICY_CHECKPOINT_KIND || record.schemaVersion !== 1
      || !Number.isSafeInteger(record.highWaterRevision) || record.highWaterRevision < 1
      || !DIGEST.test(record.highWaterEventHash || "") || !Number.isSafeInteger(record.retentionDays)
      || record.retentionDays < 1 || record.retentionDays > 3650 || !Number.isFinite(Date.parse(record.updatedAt))
      || !["genesis", "legacy_enrollment", "advance"].includes(record.checkpointType)
      || (record.previousCheckpointDigest != null && !DIGEST.test(record.previousCheckpointDigest))
      || record.digest !== digestRecord(record)) return { valid: false, code: "RETENTION_POLICY_CHECKPOINT_INVALID" };
    return { valid: true };
  }
  function makeRetentionPolicyCheckpoint(ownerId, policy, previous = null, checkpointType = "advance") {
    const unsigned = { id: retentionPolicyCheckpointId(ownerId), ownerId, kind: RETENTION_POLICY_CHECKPOINT_KIND,
      schemaVersion: 1, highWaterRevision: policy.revision, highWaterEventHash: policy.events.at(-1).eventHash,
      retentionDays: policy.retentionDays, checkpointType, previousCheckpointDigest: previous?.digest || null, updatedAt: now() };
    return { ...unsigned, digest: digestRecord(unsigned) };
  }
  async function ensureRetentionPolicyCheckpoint(ownerId, policy) {
    const id = retentionPolicyCheckpointId(ownerId);
    let checkpoint = await store.getEvidence(ownerId, id);
    if (!checkpoint) {
      // First observation is a one-time enrollment for deployments created before Batch 132.
      const type = policy.revision === 1 ? "genesis" : "legacy_enrollment";
      const created = makeRetentionPolicyCheckpoint(ownerId, policy, null, type);
      try { await store.putEvidence(ownerId, created, { overwrite: false }); } catch { /* concurrent enrollment; validate winner */ }
      checkpoint = await store.getEvidence(ownerId, id);
    }
    const check = validateRetentionPolicyCheckpoint(checkpoint, ownerId);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_CHECKPOINT_UNHEALTHY", "Retention policy checkpoint tidak sehat", 409, { finding: check.code });
    if (checkpoint.highWaterRevision > policy.revision) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_ROLLBACK_DETECTED", "Retention policy berada di bawah high-water checkpoint", 409,
      { checkpointRevision: checkpoint.highWaterRevision, policyRevision: policy.revision });
    const ancestor = policy.events[checkpoint.highWaterRevision - 1];
    if (!ancestor || ancestor.eventHash !== checkpoint.highWaterEventHash
      || (checkpoint.highWaterRevision === policy.revision && checkpoint.retentionDays !== policy.retentionDays)) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_CHECKPOINT_MISMATCH", "Retention policy history tidak cocok dengan checkpoint", 409);
    }
    if (policy.revision > checkpoint.highWaterRevision) {
      const next = makeRetentionPolicyCheckpoint(ownerId, policy, checkpoint, "advance");
      await store.putEvidence(ownerId, next, { expectedVersion: checkpoint._storage?.version });
      checkpoint = await store.getEvidence(ownerId, id);
      const after = validateRetentionPolicyCheckpoint(checkpoint, ownerId);
      if (!after.valid || checkpoint.highWaterRevision !== policy.revision
        || checkpoint.highWaterEventHash !== policy.events.at(-1).eventHash) {
        throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_CHECKPOINT_WRITE_FAILED", "Retention policy checkpoint gagal diverifikasi setelah perubahan", 409);
      }
    }
    if (retentionCheckpointAnchor?.configured || retentionCheckpointAnchor?.required) {
      await retentionCheckpointAnchor.ensureRecoverySloRetentionCheckpointAnchor(ownerId, checkpoint);
    }
    return checkpoint;
  }
  async function inspectRetentionPolicyCheckpoint(ownerId, policy) {
    const checkpoint = await store.getEvidence(ownerId, retentionPolicyCheckpointId(ownerId));
    if (!checkpoint) return { status: "not_initialized", checkpoint: null, finding: "RETENTION_POLICY_CHECKPOINT_NOT_INITIALIZED" };
    const check = validateRetentionPolicyCheckpoint(checkpoint, ownerId);
    if (!check.valid) return { status: "unhealthy", checkpoint: null, finding: check.code };
    if (checkpoint.highWaterRevision > policy.revision) return { status: "rollback_detected", checkpoint, finding: "RETENTION_POLICY_ROLLBACK_DETECTED" };
    const ancestor = policy.events[checkpoint.highWaterRevision - 1];
    if (!ancestor || ancestor.eventHash !== checkpoint.highWaterEventHash
      || (checkpoint.highWaterRevision === policy.revision && checkpoint.retentionDays !== policy.retentionDays)) {
      return { status: "mismatch", checkpoint, finding: "RETENTION_POLICY_CHECKPOINT_MISMATCH" };
    }
    const localStatus = checkpoint.highWaterRevision === policy.revision ? "healthy" : "behind_policy";
    if (retentionCheckpointAnchor?.configured || retentionCheckpointAnchor?.required) {
      const external = await retentionCheckpointAnchor.getRecoverySloRetentionCheckpointAnchorStatus(ownerId, checkpoint);
      return { status: localStatus, checkpoint, finding: null, externalAnchor: external,
        externalAnchorStatus: external.status, externalAnchorFinding: external.finding || null };
    }
    return { status: localStatus, checkpoint, finding: null, externalAnchorStatus: "not_configured" };
  }
  async function getRetentionPolicy(ownerId) {
    assertOwner(ownerId);
    const id = retentionPolicyId(ownerId);
    let policy = await store.getEvidence(ownerId, id);
    if (!policy) {
      const at = now();
      const first = event(1, "retention_policy_bootstrapped", at, retentionPolicyGenesis(ownerId, id), {
        retentionDays: evidenceRetentionDays, reason: "Configured deployment baseline." });
      const unsigned = { id, ownerId, kind: RETENTION_POLICY_KIND, schemaVersion: 1, revision: 1,
        retentionDays: evidenceRetentionDays, events: [first], createdAt: at, updatedAt: at };
      const created = { ...unsigned, digest: digestRecord(unsigned) };
      try { await store.putEvidence(ownerId, created, { overwrite: false }); } catch { /* concurrent bootstrap; read winner */ }
      policy = await store.getEvidence(ownerId, id);
    }
    const check = validateRetentionPolicy(policy, ownerId);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_UNHEALTHY", "Retention policy ledger tidak sehat", 409, { finding: check.code });
    await ensureRetentionPolicyCheckpoint(ownerId, policy);
    return policy;
  }
  function retentionPolicyPlanDigest(plan) {
    const value = clone(plan);
    for (const field of ["digest", "planDigest", "status", "approvalId", "appliedAt", "appliedRevision", "_storage"]) delete value[field];
    return sha256(canonical(value));
  }
  function validRetentionPolicyPlan(plan, ownerId) {
    return plan && plan.ownerId === ownerId && plan.kind === RETENTION_POLICY_PLAN_KIND && plan.schemaVersion === 1
      && plan.id?.startsWith(retentionPolicyPlanPrefix) && Number.isSafeInteger(plan.fromRevision)
      && Number.isSafeInteger(plan.fromRetentionDays) && Number.isSafeInteger(plan.targetRetentionDays)
      && plan.targetRetentionDays >= 1 && plan.targetRetentionDays <= 3650 && plan.scope === "future_artifacts_only"
      && DIGEST.test(plan.planDigest || "") && plan.planDigest === retentionPolicyPlanDigest(plan)
      && plan.digest === digestRecord(plan);
  }
  async function planRetentionPolicyChange(ownerId, input = {}) {
    assertOwner(ownerId);
    if (!validReason(input.reason)) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_REASON_INVALID", "Alasan perubahan retensi harus 12–240 karakter", 400);
    if (!Number.isSafeInteger(input.retentionDays) || input.retentionDays < 1 || input.retentionDays > 3650) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_TARGET_INVALID", "retentionDays harus 1–3650", 400);
    }
    const current = await getRetentionPolicy(ownerId);
    if (input.retentionDays === current.retentionDays) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_NO_CHANGE", "Target retensi sama dengan kebijakan aktif", 400);
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const at = now();
    const unsigned = { id: `${retentionPolicyPlanPrefix}${randomUUID()}`, ownerId, kind: RETENTION_POLICY_PLAN_KIND,
      schemaVersion: 1, fromRevision: current.revision, fromRetentionDays: current.retentionDays,
      targetRetentionDays: input.retentionDays, scope: "future_artifacts_only", reason: input.reason.trim(),
      createdAt: at, expiresAt: new Date(Date.parse(at) + 30 * 60 * 1000).toISOString(), status: "planned", approvalId: null, appliedAt: null };
    const base = { ...unsigned, planDigest: retentionPolicyPlanDigest(unsigned) };
    const plan = { ...base, digest: digestRecord(base) };
    await store.putEvidence(ownerId, plan, { overwrite: false });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "retention_policy_change_planned", {
      planId: plan.id, planDigest: plan.planDigest, fromRetentionDays: plan.fromRetentionDays,
      targetRetentionDays: plan.targetRetentionDays, outcome: "planned" });
    return { status: "planned", plan, planDigest: plan.planDigest,
      confirmation: `APPROVE RETENTION POLICY ${plan.planDigest.slice(0, 12)}`, approvalRequired: true,
      existingArtifactsAffected: false, readOnly: false, mutationAllowed: false };
  }
  async function approveRetentionPolicyChange(ownerId, planId, input = {}) {
    assertOwner(ownerId);
    const plan = await store.getEvidence(ownerId, planId);
    if (!validRetentionPolicyPlan(plan, ownerId) || plan.status !== "planned") throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_PLAN_INVALID", "Retention policy plan tidak valid", 409);
    if (Date.parse(now()) > Date.parse(plan.expiresAt)) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_PLAN_EXPIRED", "Retention policy plan kedaluwarsa", 409);
    if (input.planDigest !== plan.planDigest || input.confirmation !== `APPROVE RETENTION POLICY ${plan.planDigest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_CONFIRMATION_INVALID", "Konfirmasi harus terikat pada digest plan", 403);
    }
    if (!validReason(input.reason)) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_APPROVAL_REASON_INVALID", "Alasan approval harus 12–240 karakter", 400);
    const current = await getRetentionPolicy(ownerId);
    if (current.revision !== plan.fromRevision || current.retentionDays !== plan.fromRetentionDays) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_STALE", "Retention policy berubah sejak perencanaan", 409);
    const existingApproval = (await store.listEvidence(ownerId)).find(item => item.kind === RETENTION_POLICY_APPROVAL_KIND
      && item.planDigest === plan.planDigest && item.status === "approved" && item.digest === digestRecord(item));
    if (existingApproval) return { status: "approved", idempotent: true, approval: { id: existingApproval.id,
      digest: existingApproval.digest, planId: existingApproval.planId, planDigest: existingApproval.planDigest,
      fromRetentionDays: existingApproval.fromRetentionDays, targetRetentionDays: existingApproval.targetRetentionDays,
      expiresAt: existingApproval.expiresAt }, readOnly: true, mutationAllowed: false };
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const at = now();
    const unsigned = { id: `${retentionPolicyApprovalPrefix}${randomUUID()}`, ownerId, kind: RETENTION_POLICY_APPROVAL_KIND,
      schemaVersion: 1, planId: plan.id, planDigest: plan.planDigest, fromRevision: plan.fromRevision,
      fromRetentionDays: plan.fromRetentionDays, targetRetentionDays: plan.targetRetentionDays,
      reason: input.reason.trim(), approvedAt: at, expiresAt: new Date(Date.parse(at) + 30 * 60 * 1000).toISOString(), status: "approved" };
    const approval = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, approval, { overwrite: false });
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "retention_policy_change_approved", {
      planId: plan.id, planDigest: plan.planDigest, approvalId: approval.id, approvalDigest: approval.digest,
      targetRetentionDays: approval.targetRetentionDays, outcome: "approved" });
    return { status: "approved", approval: { id: approval.id, digest: approval.digest, planId: plan.id,
      planDigest: plan.planDigest, fromRetentionDays: approval.fromRetentionDays,
      targetRetentionDays: approval.targetRetentionDays, expiresAt: approval.expiresAt }, readOnly: true, mutationAllowed: false };
  }
  async function applyRetentionPolicyChange(ownerId, approvalId, input = {}) {
    assertOwner(ownerId);
    const approval = await store.getEvidence(ownerId, approvalId);
    if (!approval || approval.ownerId !== ownerId || approval.kind !== RETENTION_POLICY_APPROVAL_KIND
      || approval.schemaVersion !== 1 || approval.digest !== digestRecord(approval) || approval.status !== "approved") {
      throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_APPROVAL_INVALID", "Retention policy approval tidak valid", 409);
    }
    if (Date.parse(now()) > Date.parse(approval.expiresAt)) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_APPROVAL_EXPIRED", "Approval perubahan retensi kedaluwarsa", 409);
    if (input.expectedRevision !== approval.fromRevision || input.targetRetentionDays !== approval.targetRetentionDays) {
      throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_EXPECTATION_INVALID", "Ekspektasi revision atau target retensi tidak cocok", 409);
    }
    const plan = await store.getEvidence(ownerId, approval.planId);
    if (!validRetentionPolicyPlan(plan, ownerId) || plan.planDigest !== approval.planDigest) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_PLAN_INVALID", "Plan dan approval tidak cocok", 409);
    const current = await getRetentionPolicy(ownerId);
    if (current.revision !== approval.fromRevision || current.retentionDays !== approval.fromRetentionDays) {
      if (current.events.some(item => item.payload?.approvalDigest === approval.digest)) {
        const planNow = await store.getEvidence(ownerId, plan.id);
        if (planNow?.status !== "applied") {
          const unsigned = { ...clean(planNow), status: "applied", approvalId: approval.id, appliedAt: now(), appliedRevision: current.revision };
          await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: planNow?._storage?.version });
        }
        return { status: "applied", idempotent: true, retentionDays: current.retentionDays, revision: current.revision,
          planId: plan.id, approvalId: approval.id, readOnly: false, mutationAllowed: false };
      }
      throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_STALE", "Retention policy berubah sebelum apply", 409);
    }
    await assertOperatorEvidenceCapacity(ownerId, 1);
    let next;
    try {
      next = await store.mutateEvidence(ownerId, current.id, record => {
        const check = validateRetentionPolicy(record, ownerId);
        if (!check.valid) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_UNHEALTHY", "Retention policy tidak sehat selama apply", 409, { finding: check.code });
        if (record.revision !== approval.fromRevision || record.digest !== current.digest) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_STALE", "Retention policy berubah selama apply", 409);
        if (record.revision >= 500) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_CAPACITY", "Retention policy ledger mencapai batas revision", 409);
        const at = now();
        const nextEvent = event(record.revision + 1, "retention_policy_changed", at, record.events.at(-1).eventHash, {
          fromRetentionDays: record.retentionDays, retentionDays: approval.targetRetentionDays,
          planId: plan.id, planDigest: plan.planDigest, approvalId: approval.id, approvalDigest: approval.digest,
          scope: "future_artifacts_only", reason: approval.reason });
        const unsigned = { ...clean(record), revision: nextEvent.sequence, retentionDays: approval.targetRetentionDays,
          events: [...record.events, nextEvent], updatedAt: at };
        const changed = { ...unsigned, digest: digestRecord(unsigned) };
        return { value: changed, result: changed };
      });
    } catch (error) {
      if (error instanceof AgenticError) throw error;
      throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_WRITE_FAILED", "Retention policy tidak dapat disimpan", 503);
    }
    const checked = validateRetentionPolicy(next, ownerId);
    if (!checked.valid || next.retentionDays !== approval.targetRetentionDays) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_POSTWRITE_INVALID", "Retention policy gagal diverifikasi setelah apply", 409);
    await ensureRetentionPolicyCheckpoint(ownerId, next);
    const planNow = await store.getEvidence(ownerId, plan.id);
    if (planNow?.status !== "applied") {
      const unsigned = { ...clean(planNow), status: "applied", approvalId: approval.id, appliedAt: now(), appliedRevision: next.revision };
      await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: planNow?._storage?.version });
    }
    await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "recovery_evidence_retention_policy_changed", {
      planId: plan.id, planDigest: plan.planDigest, approvalId: approval.id, approvalDigest: approval.digest,
      fromRetentionDays: approval.fromRetentionDays, targetRetentionDays: next.retentionDays,
      policyRevision: next.revision, scope: "future_artifacts_only", outcome: "applied" });
    return { status: "applied", idempotent: false, retentionDays: next.retentionDays, revision: next.revision,
      policyDigest: next.digest, existingArtifactsAffected: false, readOnly: false, mutationAllowed: false };
  }
  async function auditRetentionPolicy(ownerId) {
    assertOwner(ownerId);
    const policy = await store.getEvidence(ownerId, retentionPolicyId(ownerId));
    if (!policy) return { status: "not_initialized", ownerId, retentionDays: evidenceRetentionDays, revision: 0,
      eventCount: 0, digest: null, checkpointStatus: "not_initialized",
      findings: [{ code: "RETENTION_POLICY_NOT_INITIALIZED", severity: "warning" }], readOnly: true, mutationAllowed: false };
    const check = validateRetentionPolicy(policy, ownerId);
    if (!check.valid) return { status: "unhealthy", ownerId, retentionDays: null, revision: null,
      eventCount: policy.events?.length ?? 0, digest: null, checkpointStatus: "unavailable",
      findings: [{ code: check.code, severity: "error" }], readOnly: true, mutationAllowed: false };
    const checkpoint = await inspectRetentionPolicyCheckpoint(ownerId, policy);
    const errorStatuses = new Set(["unhealthy", "rollback_detected", "mismatch"]);
    const externalErrors = new Set(["unavailable", "invalid", "rollback_detected", "rollback_suspected", "mismatch", "marker_invalid", "local_checkpoint_invalid", "enrollment_required", "not_configured"]);
    const externalStatus = checkpoint.externalAnchorStatus || "not_configured";
    const externalRequiredFailure = (retentionCheckpointAnchor?.required || retentionCheckpointAnchor?.configured) && externalErrors.has(externalStatus);
    const localStatus = errorStatuses.has(checkpoint.status) ? "unhealthy" : checkpoint.status === "healthy" ? "healthy" : "degraded";
    const status = externalRequiredFailure || localStatus === "unhealthy" ? "unhealthy"
      : localStatus === "healthy" && (!retentionCheckpointAnchor?.configured || externalStatus === "anchored") ? "healthy" : "degraded";
    const findings = [];
    if (checkpoint.finding) findings.push({ code: checkpoint.finding, severity: errorStatuses.has(checkpoint.status) ? "error" : "warning" });
    if (checkpoint.externalAnchorFinding) findings.push({ code: checkpoint.externalAnchorFinding, severity: externalRequiredFailure ? "error" : "warning" });
    if (externalStatus === "behind_local") findings.push({ code: "RETENTION_EXTERNAL_ANCHOR_ADVANCEMENT_REQUIRED", severity: "warning" });
    return { status, ownerId, retentionDays: policy.retentionDays, revision: policy.revision,
      eventCount: policy.events.length, digest: policy.digest, checkpointStatus: checkpoint.status,
      checkpointRevision: checkpoint.checkpoint?.highWaterRevision ?? null,
      externalAnchorStatus: externalStatus, externalAnchorRevision: checkpoint.externalAnchor?.anchorRevision ?? null,
      externalAnchorDigest: checkpoint.externalAnchor?.anchorDigest ?? null,
      historyNotProven: checkpoint.externalAnchor?.historyNotProven === true,
      findings, readOnly: true, mutationAllowed: false };
  }
  async function loadRetentionCheckpointForOperator(ownerId) {
    assertOwner(ownerId);
    const policyId = retentionPolicyId(ownerId);
    let policy = await store.getEvidence(ownerId, policyId);
    if (!policy) {
      policy = await getRetentionPolicy(ownerId);
    } else {
      const validPolicy = validateRetentionPolicy(policy, ownerId);
      if (!validPolicy.valid) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_UNHEALTHY", "Retention policy ledger tidak sehat", 409, { finding: validPolicy.code });
    }
    const id = retentionPolicyCheckpointId(ownerId);
    let checkpoint = await store.getEvidence(ownerId, id);
    if (!checkpoint) {
      const type = policy.revision === 1 ? "genesis" : "legacy_enrollment";
      const created = makeRetentionPolicyCheckpoint(ownerId, policy, null, type);
      try { await store.putEvidence(ownerId, created, { overwrite: false }); } catch { /* validate the concurrent winner */ }
      checkpoint = await store.getEvidence(ownerId, id);
    }
    const validCheckpoint = validateRetentionPolicyCheckpoint(checkpoint, ownerId);
    if (!validCheckpoint.valid) throw new AgenticError("RECOVERY_SLO_RETENTION_POLICY_CHECKPOINT_UNHEALTHY", "Retention policy checkpoint tidak sehat", 409, { finding: validCheckpoint.code });
    return { policy, checkpoint };
  }
  async function getRetentionCheckpointAnchorStatus(ownerId) {
    const { checkpoint } = await loadRetentionCheckpointForOperator(ownerId);
    if (!retentionCheckpointAnchor) return { status: "not_configured", ownerId, revision: checkpoint.highWaterRevision, required: false, readOnly: true, mutationAllowed: false };
    return retentionCheckpointAnchor.getRecoverySloRetentionCheckpointAnchorStatus(ownerId, checkpoint);
  }
  async function anchorRetentionCheckpoint(ownerId, input = {}) {
    const { checkpoint } = await loadRetentionCheckpointForOperator(ownerId);
    if (!retentionCheckpointAnchor) throw new AgenticError("RECOVERY_SLO_RETENTION_ANCHOR_REQUIRED", "External retention checkpoint anchor tidak dikonfigurasi", 503);
    return retentionCheckpointAnchor.anchorRecoverySloRetentionCheckpoint(ownerId, checkpoint, input);
  }
  async function reconcileRetentionCheckpointAnchor(ownerId) {
    const { checkpoint } = await loadRetentionCheckpointForOperator(ownerId);
    if (!retentionCheckpointAnchor) return { status: "not_configured", ownerId, reconciled: false, readOnly: true, mutationAllowed: false };
    return retentionCheckpointAnchor.reconcileRecoverySloRetentionCheckpointAnchor(ownerId, checkpoint);
  }


  async function recordRetainedArtifact(ownerId, artifactType, payload, sourceId) {
    assertOwner(ownerId);
    const retentionPolicy = await getRetentionPolicy(ownerId);
    const activeRetentionDays = retentionPolicy.retentionDays;
    const all = (await store.listEvidence(ownerId)).filter(item => item.kind === RETENTION_KIND);
    const payloadDigest = sha256(canonical(payload));
    const id = `${retentionPrefix}${sha256(`${ownerId}:${artifactType}:${sourceId}:${payloadDigest}`).slice(0, 48)}`;
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      if (existing.payloadDigest === payloadDigest && existing.status === "retained") return { id, payloadDigest, expiresAt: existing.expiresAt, idempotent: true };
      throw new AgenticError("RECOVERY_SLO_EVIDENCE_RETENTION_ID_CONFLICT", "Identitas retained evidence telah digunakan untuk payload berbeda", 409);
    }
    await assertRetentionCapacity(ownerId);
    const exportedAt = now();
    const unsigned = { id, ownerId, kind: RETENTION_KIND, schemaVersion: 1, artifactType, sourceId: String(sourceId).slice(0, 180),
      exportedAt, expiresAt: new Date(Date.parse(exportedAt) + activeRetentionDays * 86400_000).toISOString(),
      retentionDays: activeRetentionDays, retentionPolicyRevision: retentionPolicy.revision,
      status: "retained", payloadDigest, payload: clone(payload), tombstone: null };
    const record = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, record, { overwrite: false });
    return { id, payloadDigest, expiresAt: record.expiresAt, idempotent: false };
  }
  function validateRetentionRecord(record, ownerId) {
    if (!record || record.ownerId !== ownerId || record.kind !== RETENTION_KIND || record.schemaVersion !== 1
      || typeof record.id !== "string" || !record.id.startsWith(retentionPrefix) || !["retained", "expired"].includes(record.status)
      || !DIGEST.test(record.payloadDigest || "") || !Number.isFinite(Date.parse(record.exportedAt))
      || !Number.isFinite(Date.parse(record.expiresAt)) || !Number.isSafeInteger(record.retentionDays)
      || record.retentionDays < 1 || record.retentionDays > 3650
      || (record.retentionPolicyRevision != null && (!Number.isSafeInteger(record.retentionPolicyRevision) || record.retentionPolicyRevision < 1))) return { valid: false, code: "RECOVERY_EVIDENCE_RETENTION_SHAPE_INVALID" };
    if (record.status === "retained" && (record.payload == null || sha256(canonical(record.payload)) !== record.payloadDigest)) {
      return { valid: false, code: "RECOVERY_EVIDENCE_RETENTION_PAYLOAD_DIGEST_INVALID" };
    }
    if (record.status === "expired" && (record.payload !== null || !record.tombstone || record.tombstone.originalPayloadDigest !== record.payloadDigest
      || !DIGEST.test(record.tombstone.originalRecordDigest || "") || !Number.isFinite(Date.parse(record.tombstone.expiredAt)))) {
      return { valid: false, code: "RECOVERY_EVIDENCE_RETENTION_TOMBSTONE_INVALID" };
    }
    if (record.digest !== digestRecord(record)) return { valid: false, code: "RECOVERY_EVIDENCE_RETENTION_RECORD_DIGEST_INVALID" };
    return { valid: true, code: null };
  }
  async function listRetainedEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    const all = (await store.listEvidence(ownerId)).filter(item => item.kind === RETENTION_KIND);
    const audit = await auditRetainedEvidence(ownerId);
    const limitValue = Number(options.limit ?? 50);
    const limit = Number.isFinite(limitValue) ? Math.max(1, Math.min(100, Math.floor(limitValue))) : 50;
    return { ...audit, items: audit.status === "unhealthy" ? [] : all.sort((a, b) => String(b.exportedAt).localeCompare(String(a.exportedAt))).slice(0, limit).map(item => ({
      id: item.id, artifactType: item.artifactType, sourceId: item.sourceId, exportedAt: item.exportedAt, expiresAt: item.expiresAt,
      retentionDays: item.retentionDays, retentionPolicyRevision: item.retentionPolicyRevision ?? 1,
      status: item.status, payloadDigest: item.payloadDigest, tombstone: item.tombstone ? clone(item.tombstone) : null })) };
  }
  async function auditRetainedEvidence(ownerId) {
    assertOwner(ownerId);
    const all = (await store.listEvidence(ownerId)).filter(item => item.kind === RETENTION_KIND);
    const findings = [];
    const policyRecord = await store.getEvidence(ownerId, retentionPolicyId(ownerId));
    let policy = null;
    if (policyRecord) {
      const policyCheck = validateRetentionPolicy(policyRecord, ownerId);
      if (!policyCheck.valid) findings.push({ code: policyCheck.code, severity: "error" });
      else policy = policyRecord;
    } else if (all.some(record => record.retentionPolicyRevision != null)) {
      findings.push({ code: "RETENTION_POLICY_LEDGER_MISSING", severity: "error" });
    }
    if (policy) {
      for (const record of all) {
        const policyRevision = record.retentionPolicyRevision ?? 1;
        if (!Number.isSafeInteger(policyRevision) || policyRevision < 1 || policyRevision > policy.revision
          || !policy.events[policyRevision - 1]
          || (record.retentionPolicyRevision != null && policy.events[policyRevision - 1].payload?.retentionDays !== record.retentionDays)) {
          findings.push({ code: "RECOVERY_EVIDENCE_RETENTION_POLICY_REVISION_INVALID", severity: "error", recordId: record.id });
        }
      }
    }
    if (all.length > MAX_RETENTION_RECORDS) findings.push({ code: "RECOVERY_EVIDENCE_RETENTION_CAPACITY_EXCEEDED", severity: "error" });
    for (const record of all) {
      const check = validateRetentionRecord(record, ownerId);
      if (!check.valid) findings.push({ code: check.code, severity: "error", recordId: record.id });
    }
    if (findings.some(item => item.severity === "error")) return { status: "unhealthy", ownerId, recordCount: all.length,
      retainedCount: all.filter(item => item.status === "retained").length, expiredCount: all.filter(item => item.status === "expired").length,
      retentionDays: policy?.retentionDays ?? null, policyRevision: policy?.revision ?? null,
      findings: findings.slice(0, 50), readOnly: true, mutationAllowed: false };
    const dueCount = all.filter(item => item.status === "retained" && Date.parse(item.expiresAt) <= Date.parse(now())).length;
    const warnings = [];
    if (dueCount) warnings.push({ code: "RECOVERY_EVIDENCE_RETENTION_DUE", severity: "warning", count: dueCount });
    if (!policy) warnings.push({ code: "RETENTION_POLICY_NOT_INITIALIZED", severity: "warning" });
    return { status: dueCount || !policy ? "degraded" : "healthy", ownerId, recordCount: all.length,
      retainedCount: all.filter(item => item.status === "retained").length, expiredCount: all.filter(item => item.status === "expired").length,
      retentionDays: policy?.retentionDays ?? null, policyRevision: policy?.revision ?? null, dueCount, findings: warnings,
      readOnly: true, mutationAllowed: false };
  }
  async function pruneRetainedEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    const audit = await auditRetainedEvidence(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("RECOVERY_SLO_EVIDENCE_RETENTION_UNHEALTHY", "Retention ledger tidak sehat; prune diblokir", 409, { findings: audit.findings });
    const requested = Number(options.limit ?? 50);
    const limit = Number.isFinite(requested) ? Math.max(1, Math.min(MAX_PRUNE, Math.floor(requested))) : 50;
    const at = Date.parse(now());
    const candidates = (await store.listEvidence(ownerId)).filter(item => item.kind === RETENTION_KIND && item.status === "retained"
      && Date.parse(item.expiresAt) <= at).sort((a, b) => String(a.expiresAt).localeCompare(String(b.expiresAt))).slice(0, limit);
    if (candidates.length) await assertOperatorEvidenceCapacity(ownerId, 1);
    const pruned = [];
    for (const candidate of candidates) {
      const result = await store.mutateEvidence(ownerId, candidate.id, current => {
        if (!current || current.kind !== RETENTION_KIND || current.status !== "retained") return { write: false, result: { skipped: true } };
        const check = validateRetentionRecord(current, ownerId);
        if (!check.valid) throw new AgenticError("RECOVERY_SLO_EVIDENCE_RETENTION_UNHEALTHY", "Record retention berubah atau tidak valid selama prune", 409, { finding: check.code });
        if (Date.parse(current.expiresAt) > Date.parse(now())) return { write: false, result: { skipped: true } };
        const expiredAt = now();
        const unsigned = { ...clean(current), payload: null, status: "expired", tombstone: {
          originalPayloadDigest: current.payloadDigest, originalRecordDigest: current.digest, expiredAt,
          reason: "RETENTION_POLICY_ELAPSED", policyVersion: current.retentionPolicyRevision ?? 1 } };
        const next = { ...unsigned, digest: digestRecord(unsigned) };
        return { value: next, result: { pruned: true, id: current.id, payloadDigest: current.payloadDigest, expiredAt } };
      });
      if (result?.pruned) pruned.push(result);
    }
    if (pruned.length) await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "recovery_evidence_retention_pruned", {
      count: pruned.length, recordIds: pruned.slice(0, 20).map(item => item.id), outcome: "tombstoned" });
    const after = await auditRetainedEvidence(ownerId);
    return { status: after.status, ownerId, prunedCount: pruned.length, pruned, audit: after,
      readOnly: false, mutationAllowed: false };
  }

  function makeRunbookAttestationPayload(ownerId, runbook, issuedAt, keyId) {
    return { domain: RUNBOOK_ATTESTATION_DOMAIN, schemaVersion: 1, ownerId, runbookId: runbook.runbookId,
      runbookDigest: runbook.runbookDigest, issuedAt, keyId };
  }
  async function attestRunbook(ownerId, runbook) {
    if (!runbookSigner || !signingConfigured) {
      if (requireSignedRunbookAttestation) throw new AgenticError("RECOVERY_SLO_SIGNED_RUNBOOK_REQUIRED", "Runbook wajib ditandatangani tetapi signer tidak tersedia", 503);
      return runbook;
    }
    const policy = await getRunbookKeyPolicy(ownerId);
    const active = policy?.keys.find(item => item.keyId === policy.activeKeyId && item.status === "active");
    const activePublicKey = active && publicKeyFromDer(active.publicKeyDer);
    if (!active || !activePublicKey) throw new AgenticError("RECOVERY_SLO_RUNBOOK_ACTIVE_KEY_REQUIRED", "Runbook signing policy tidak memiliki kunci aktif yang valid", 409);
    const issuedAt = now();
    const payload = makeRunbookAttestationPayload(ownerId, runbook, issuedAt, active.keyId);
    let signerResult;
    try { signerResult = await runbookSigner(clone(payload)); }
    catch { throw new AgenticError("RECOVERY_SLO_RUNBOOK_SIGNER_FAILED", "External signer runbook gagal; ekspor tidak diturunkan menjadi unsigned", 503); }
    const signature = typeof signerResult === "string" ? signerResult : signerResult?.signature;
    const returnedKeyId = typeof signerResult === "object" && signerResult ? signerResult.keyId : null;
    if (returnedKeyId != null && returnedKeyId !== active.keyId) throw new AgenticError("RECOVERY_SLO_RUNBOOK_SIGNER_KEY_MISMATCH", "Signer runbook mengembalikan key ID yang tidak sesuai", 502);
    const unsigned = { domain: RUNBOOK_ATTESTATION_DOMAIN, schemaVersion: 1, ownerId, runbookId: runbook.runbookId,
      runbookDigest: runbook.runbookDigest, issuedAt, signing: { algorithm: "Ed25519", keyId: active.keyId }, signature };
    const attestation = { ...unsigned, attestationDigest: digestRecord(unsigned) };
    if (!verifyEd25519(activePublicKey, payload, signature)) throw new AgenticError("RECOVERY_SLO_RUNBOOK_SIGNATURE_INVALID", "Signer runbook menghasilkan signature yang tidak valid", 502);
    return { ...runbook, attestation };
  }
  async function verifyRunbookAttestation(ownerId, runbook) {
    const attestation = runbook?.attestation;
    if (!attestation) return { valid: !requireSignedRunbookAttestation, signed: false, status: requireSignedRunbookAttestation ? "signature_required" : "integrity_only", findings: requireSignedRunbookAttestation ? ["RECOVERY_RUNBOOK_SIGNATURE_REQUIRED"] : [] };
    if (attestation.domain !== RUNBOOK_ATTESTATION_DOMAIN || attestation.schemaVersion !== 1 || attestation.ownerId !== ownerId
      || attestation.runbookId !== runbook.runbookId || attestation.runbookDigest !== runbook.runbookDigest
      || !Number.isFinite(Date.parse(attestation.issuedAt)) || attestation.signing?.algorithm !== "Ed25519"
      || typeof attestation.signing?.keyId !== "string" || !KEY_ID.test(attestation.signing.keyId)
      || !DIGEST.test(attestation.attestationDigest || "")) return { valid: false, signed: true, status: "invalid", findings: ["RECOVERY_RUNBOOK_ATTESTATION_SHAPE_INVALID"] };
    const unsigned = clone(attestation); delete unsigned.attestationDigest;
    if (digestRecord(unsigned) !== attestation.attestationDigest) return { valid: false, signed: true, status: "invalid", findings: ["RECOVERY_RUNBOOK_ATTESTATION_DIGEST_INVALID"] };
    let policy;
    try { policy = await getRunbookKeyPolicy(ownerId); }
    catch (error) { return { valid: false, signed: true, status: "key_policy_unhealthy", findings: [error.code || "RUNBOOK_KEY_POLICY_UNHEALTHY"] }; }
    const entry = policy?.keys.find(item => item.keyId === attestation.signing.keyId);
    const key = entry && publicKeyFromDer(entry.publicKeyDer);
    if (!key || !entry) return { valid: false, signed: true, status: "untrusted_key", findings: ["RECOVERY_RUNBOOK_ATTESTATION_KEY_UNTRUSTED"] };
    const issuedMs = Date.parse(attestation.issuedAt);
    const activatedMs = entry.activatedAt == null ? NaN : Date.parse(entry.activatedAt);
    const retiredMs = entry.retiredAt == null ? Infinity : Date.parse(entry.retiredAt);
    const revokedMs = entry.revokedAt == null ? Infinity : Date.parse(entry.revokedAt);
    const invalidateMs = entry.invalidateBefore == null ? Infinity : Date.parse(entry.invalidateBefore);
    const bootstrapTrusted = (entry.bootstrapTrusted === true || (entry.status === "trusted" && entry.activatedAt == null))
      && issuedMs <= Date.parse(now());
    const activatedPeriod = Number.isFinite(activatedMs) && issuedMs >= activatedMs && issuedMs <= retiredMs;
    const historicalAuthorized = (bootstrapTrusted || activatedPeriod) && issuedMs < revokedMs && issuedMs < invalidateMs;
    const payload = { domain: RUNBOOK_ATTESTATION_DOMAIN, schemaVersion: 1, ownerId, runbookId: runbook.runbookId,
      runbookDigest: runbook.runbookDigest, issuedAt: attestation.issuedAt, keyId: attestation.signing.keyId };
    const signatureValid = verifyEd25519(key, payload, attestation.signature);
    const valid = signatureValid && historicalAuthorized;
    const status = !signatureValid ? "invalid_signature" : !historicalAuthorized ? "key_not_authorized_at_issue_time" : "valid_signed";
    return { valid, signed: true, status, keyId: attestation.signing.keyId, signatureValid,
      authorizedAtIssueTime: historicalAuthorized, currentKeyStatus: entry.status,
      findings: valid ? [] : [!signatureValid ? "RECOVERY_RUNBOOK_SIGNATURE_INVALID" : "RECOVERY_RUNBOOK_KEY_NOT_AUTHORIZED_AT_ISSUE_TIME"] };
  }
  async function exportRunbook(ownerId, options = {}) {
    assertOwner(ownerId);
    await assertRetentionCapacity(ownerId);
    await assertOperatorEvidenceCapacity(ownerId, 3);
    const result = await anchorEvidence.exportRecoverySloFinalizationAnchorRecoveryRunbook(ownerId, options);
    const runbook = await attestRunbook(ownerId, result.runbook);
    const byteLength = Buffer.byteLength(canonical(runbook), "utf8");
    const maxBytes = Number.isSafeInteger(options.maxBytes) ? Math.max(1024, Math.min(MAX_RUNBOOK_BYTES, options.maxBytes)) : MAX_RUNBOOK_BYTES;
    if (byteLength > maxBytes) throw new AgenticError("RECOVERY_SLO_RUNBOOK_SIZE_LIMIT", "Recovery runbook bertanda tangan melebihi batas ekspor", 413);
    const retention = await recordRetainedArtifact(ownerId, "recovery_runbook", runbook, runbook.runbookId);
    if (runbook.attestation) await anchorOperations.recordRecoverySloFinalizationAnchorEvidenceEvent(ownerId, "runbook_attested", {
      runbookId: runbook.runbookId, runbookDigest: runbook.runbookDigest, attestationDigest: runbook.attestation.attestationDigest,
      signatureKeyId: runbook.attestation.signing.keyId, retentionRecordId: retention.id, outcome: "signed" });
    return { ...result, runbook, signedRunbookAttestation: Boolean(runbook.attestation), attestation: runbook.attestation || null,
      retention: { id: retention.id, payloadDigest: retention.payloadDigest, expiresAt: retention.expiresAt },
      byteLength };
  }
  async function verifyRunbook(ownerId, runbook) {
    assertOwner(ownerId);
    const attestation = await verifyRunbookAttestation(ownerId, runbook);
    if (!attestation.valid) return { valid: false, runbookIntegrityValid: false, runbookAttestationValid: false,
      ownerId, findings: attestation.findings, attestation, readOnly: true, mutationAllowed: false };
    const base = await anchorEvidence.verifyRecoverySloFinalizationAnchorRecoveryRunbook(ownerId, runbook);
    return { ...base, valid: base.valid && attestation.valid, runbookAttestationValid: attestation.valid,
      signedRunbookAttestation: attestation.signed, attestation, readOnly: true, mutationAllowed: false };
  }
  async function exportContinuityEvidence(ownerId) {
    assertOwner(ownerId);
    await assertRetentionCapacity(ownerId);
    await assertOperatorEvidenceCapacity(ownerId, 1);
    const result = await anchorEvidence.exportRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence(ownerId);
    const payload = result.evidence ?? result.proof ?? result;
    const retention = await recordRetainedArtifact(ownerId, result.evidence ? "signed_continuity_evidence" : "continuity_proof", payload,
      result.evidence?.evidenceId ?? result.proof?.proofId ?? sha256(canonical(payload)).slice(0, 32));
    return { ...result, retention: { id: retention.id, payloadDigest: retention.payloadDigest, expiresAt: retention.expiresAt } };
  }

  return Object.freeze({ getActiveContractVersion, auditRecoverySloAnchorContractMigration: auditContractMigration,
    planRecoverySloFinalizationAnchorContractMigration: planContractMigration,
    approveRecoverySloFinalizationAnchorContractMigration: approveContractMigration,
    applyRecoverySloFinalizationAnchorContractMigration: applyContractMigration,
    recoverRecoverySloFinalizationAnchorContractMigration: recoverContractMigration,
    exportRecoverySloFinalizationAnchorRecoveryRunbook: exportRunbook,
    verifyRecoverySloFinalizationAnchorRecoveryRunbook: verifyRunbook,
    createRecoverySloRunbookTrustKeyTransitionChallenge: createRunbookKeyTransitionChallenge,
    applyRecoverySloRunbookTrustKeyTransition: applyRunbookKeyTransition,
    createRecoverySloRunbookTrustKeyRevocationChallenge: createRunbookKeyRevocationChallenge,
    applyRecoverySloRunbookTrustKeyRevocation: applyRunbookKeyRevocation,
    auditRecoverySloRunbookTrustKeyPolicy: auditRunbookKeyPolicy,
    getRecoverySloRecoveryJournalAnchorStatus: recoveryJournalAnchor?.getRecoverySloRecoveryJournalAnchorStatus || (async (ownerId) => ({ status: "not_configured", ownerId, readOnly: true, mutationAllowed: false })),
    anchorRecoverySloRecoveryJournal: recoveryJournalAnchor?.anchorRecoverySloRecoveryJournal || (async (ownerId) => ({ status: "not_configured", ownerId, readOnly: true, mutationAllowed: false })),
    reconcileRecoverySloRecoveryJournalAnchor: recoveryJournalAnchor?.reconcileRecoverySloRecoveryJournalAnchor || (async (ownerId) => ({ status: "not_configured", ownerId, readOnly: true, mutationAllowed: false })),
    auditRecoverySloRecoveryJournalAnchors: recoveryJournalAnchor?.auditRecoverySloRecoveryJournalAnchors || (async (ownerId) => ({ status: "not_configured", ownerId, readOnly: true, mutationAllowed: false })),
    exportRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence: exportContinuityEvidence,
    listRecoverySloRecoveryEvidenceRetention: listRetainedEvidence,
    auditRecoverySloRecoveryEvidenceRetention: auditRetainedEvidence,
    pruneRecoverySloRecoveryEvidenceRetention: pruneRetainedEvidence,
    auditRecoverySloEvidenceRetentionPolicy: auditRetentionPolicy,
    getRecoverySloRetentionCheckpointAnchorStatus: getRetentionCheckpointAnchorStatus,
    anchorRecoverySloRetentionCheckpoint: anchorRetentionCheckpoint,
    reconcileRecoverySloRetentionCheckpointAnchor: reconcileRetentionCheckpointAnchor,
    planRecoverySloEvidenceRetentionPolicyChange: planRetentionPolicyChange,
    approveRecoverySloEvidenceRetentionPolicyChange: approveRetentionPolicyChange,
    applyRecoverySloEvidenceRetentionPolicyChange: applyRetentionPolicyChange });
}
