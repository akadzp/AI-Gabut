import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const LEDGER_KIND = "recovery-slo-finalization-anchor-operator-evidence";
const CHALLENGE_KIND = "recovery-slo-finalization-anchor-conformance-challenge";
const MAX_EVENTS = 500;
const MAX_LIMIT = 100;
const DIGEST = /^[a-f0-9]{64}$/;
const CONFORMANCE_PREFIX = "__agentic_v4_conformance__";
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
function digestRecord(record) { const value = clean(record); delete value.digest; return sha256(canonical(value)); }
const ledgerId = ownerId => `recovery-slo-finalization-anchor-operator-evidence-${sha256(ownerId).slice(0, 48)}`;
const genesisHash = (ownerId, id) => sha256(`agentic-v4-finalization-anchor-operator-evidence:${ownerId}:${id}`);
const eventHash = event => sha256(canonical({ sequence: event.sequence, type: event.type, at: event.at,
  previousHash: event.previousHash, payload: event.payload }));
const reasonValid = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
  && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
function anchorDigest(anchor) { const unsigned = { ...anchor }; delete unsigned.digest; return sha256(canonical(unsigned)); }
function conformanceCandidate(ownerId, revision, previousAnchorDigest, reason) {
  const unsigned = { schemaVersion: 1, ownerId, anchorSequence: revision, revision,
    trustDigest: sha256(`agentic-v4-anchor-conformance-trust:${ownerId}:${revision}:${reason}`),
    headHash: sha256(`agentic-v4-anchor-conformance-head:${ownerId}:${revision}`),
    bootstrapDigest: sha256(`agentic-v4-anchor-conformance-bootstrap:${ownerId}`),
    previousAnchorDigest, anchoredAt: new Date(revision * 1000).toISOString(), reason };
  return { ...unsigned, digest: anchorDigest(unsigned) };
}
function sameJson(a, b) { return canonical(a) === canonical(b); }
async function probeFinalizationAnchorProvider(provider, ownerId) {
  const checks = [];
  const record = (name, passed, details = {}) => checks.push({ name, passed: passed === true, ...details });
  const read = () => provider.read(ownerId);
  const initial = await read();
  record("disposable_namespace_empty", initial == null);
  if (initial != null) return { conformant: false, ownerId, checks, findings: ["CONFORMANCE_NAMESPACE_NOT_EMPTY"], writesPerformed: 0 };
  const first = conformanceCandidate(ownerId, 1, null, "genesis");
  const created = await provider.compareAndSet(ownerId, null, first);
  const firstRead = await read();
  const firstApplied = created === true || created?.applied === true;
  record("genesis_anchor_schema_and_cas", firstApplied && sameJson(firstRead, first));
  if (!firstApplied || !sameJson(firstRead, first)) return { conformant: false, ownerId, checks,
    findings: ["CONFORMANCE_GENESIS_CAS_FAILED"], writesPerformed: firstApplied ? 1 : 0 };
  const stale = conformanceCandidate(ownerId, 1, null, "genesis");
  stale.trustDigest = sha256(`stale-${ownerId}`); stale.digest = anchorDigest(stale);
  let staleRejected = false;
  try { const result = await provider.compareAndSet(ownerId, null, stale); staleRejected = result !== true && result?.applied !== true; }
  catch { staleRejected = true; }
  const afterStale = await read();
  staleRejected = staleRejected && sameJson(afterStale, first);
  record("stale_genesis_cannot_overwrite", staleRejected);
  const second = conformanceCandidate(ownerId, 2, first.digest, "trust_transition");
  const advanced = await provider.compareAndSet(ownerId, first.digest, second);
  const secondRead = await read();
  const advancedOk = (advanced === true || advanced?.applied === true) && sameJson(secondRead, second);
  record("monotonic_revision_and_sequence_advance", advancedOk);
  if (!advancedOk) return { conformant: false, ownerId, checks, findings: ["CONFORMANCE_MONOTONIC_ADVANCE_FAILED"], writesPerformed: 1 };
  const competingA = conformanceCandidate(ownerId, 3, second.digest, "trust_transition");
  const competingB = conformanceCandidate(ownerId, 3, second.digest, "reconciliation");
  const race = await Promise.allSettled([provider.compareAndSet(ownerId, second.digest, competingA), provider.compareAndSet(ownerId, second.digest, competingB)]);
  const raceApplied = race.filter(item => item.status === "fulfilled" && (item.value === true || item.value?.applied === true)).length;
  const afterRace = await read();
  const raceWinnerValid = sameJson(afterRace, competingA) || sameJson(afterRace, competingB);
  record("concurrent_cas_has_exactly_one_winner", raceApplied === 1 && raceWinnerValid, { appliedCount: raceApplied });
  if (!raceWinnerValid) return { conformant: false, ownerId, checks, findings: ["CONFORMANCE_CONCURRENT_CAS_STATE_INVALID"], writesPerformed: 2 };
  const replay = conformanceCandidate(ownerId, afterRace.revision + 1, afterRace.digest, "trust_transition");
  let replayRejected = false;
  try { const result = await provider.compareAndSet(ownerId, first.digest, replay); replayRejected = result !== true && result?.applied !== true; }
  catch { replayRejected = true; }
  replayRejected = replayRejected && sameJson(await read(), afterRace);
  record("stale_digest_replay_rejected", replayRejected);
  const skipped = { ...conformanceCandidate(ownerId, afterRace.revision + 1, afterRace.digest, "trust_transition"), anchorSequence: afterRace.anchorSequence + 2 };
  skipped.digest = anchorDigest(skipped);
  let skippedRejected = false;
  try { const result = await provider.compareAndSet(ownerId, afterRace.digest, skipped); skippedRejected = result !== true && result?.applied !== true; }
  catch { skippedRejected = true; }
  skippedRejected = skippedRejected && sameJson(await read(), afterRace);
  record("sequence_gap_rejected", skippedRejected);
  const otherOwner = `${ownerId}:other`;
  let other = null;
  try { other = await provider.read(otherOwner); } catch { other = Symbol("read-failed"); }
  record("owner_scope_isolation", other == null);
  const findings = checks.filter(check => !check.passed).map(check => `CONFORMANCE_${check.name.toUpperCase()}`);
  return { conformant: findings.length === 0, ownerId, checks, findings, writesPerformed: 3,
    note: "Key-policy-specific behavioral probe; it cannot prove remote durability, administrator separation, or resistance to whole-service rollback." };
}
const EVENT_TYPES = new Set(["provider_conformance_prepared", "provider_conformance_started", "provider_conformance_completed",
  "provider_conformance_failed", "continuity_proof_created", "continuity_proof_verified", "reconciliation_requested",
  "reconciliation_completed", "reconciliation_blocked", "operator_note", "continuity_evidence_signed", "continuity_evidence_verified", "recovery_runbook_exported", "recovery_runbook_verified",
  "contract_migration_planned", "contract_migration_approved", "contract_migration_applied", "contract_migration_recovered",
  "runbook_attested", "runbook_key_rotation_prepared", "runbook_key_rotated", "recovery_evidence_retention_pruned",
  "retention_policy_change_planned", "retention_policy_change_approved", "recovery_evidence_retention_policy_changed",
  "runbook_key_revocation_prepared", "runbook_key_revoked", "runbook_key_recovery_prepared", "runbook_key_recovered"]);
function safePayload(input = {}) {
  const payload = {};
  for (const key of ["operationId", "reason", "outcome", "anchorStatus", "conformanceChallengeId", "conformanceDigest",
    "proofId", "proofDigest", "localRevision", "anchorRevision", "providerWritesPerformed", "contractVersion",
    "contractStatus", "evidenceId", "evidenceDigest", "runbookDigest", "signatureKeyId", "planId", "planDigest",
    "approvalId", "approvalDigest", "fromVersion", "targetVersion", "migrationDigest", "attestationDigest", "retentionRecordId",
    "challengeId", "challengeDigest", "oldKeyId", "newKeyId", "policyRevision", "fromRetentionDays", "targetRetentionDays",
    "scope", "journalId", "migrationRevision", "checkpointRevision", "ledgerRevision", "retentionDays", "revision",
    "existingArtifactsAffected", "recoveredFromCommittedLedger", "outcomeCode", "errorCode"]) {
    if (input[key] === undefined || input[key] === null) continue;
    if (["localRevision", "anchorRevision", "providerWritesPerformed", "migrationRevision", "checkpointRevision", "ledgerRevision",
      "policyRevision", "fromRetentionDays", "targetRetentionDays", "retentionDays", "revision", "count"].includes(key)) {
      if (Number.isSafeInteger(input[key]) && input[key] >= 0) payload[key] = input[key];
      continue;
    }
    if (typeof input[key] === "string") payload[key] = input[key].replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, key === "reason" ? 240 : 120);
  }
  if (Array.isArray(input.findings)) payload.findings = input.findings.slice(0, 20).map(value => String(value).replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 80));
  return payload;
}

export function createRecoverySloFinalizationAnchorOperations({ store, keyPolicy, externalAnchorProvider = null,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.mutateEvidence || !keyPolicy || typeof clock !== "function") {
    throw new TypeError("Anchor operations memerlukan evidence store, key-policy service, dan clock");
  }
  if (externalAnchorProvider != null && (typeof externalAnchorProvider.read !== "function"
    || typeof externalAnchorProvider.compareAndSet !== "function")) {
    throw new TypeError("External anchor provider harus menyediakan read() dan compareAndSet()");
  }
  function assertOwner(ownerId) {
    if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_ANCHOR_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
    }
  }
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_ANCHOR_CLOCK_INVALID", "Clock anchor operations tidak valid", 500);
    return new Date(value).toISOString();
  }
  function validateLedger(record, ownerId) {
    if (!record || record.id !== ledgerId(ownerId) || record.ownerId !== ownerId || record.kind !== LEDGER_KIND
      || record.schemaVersion !== 1 || !Number.isSafeInteger(record.revision) || record.revision < 1
      || !Array.isArray(record.events) || record.events.length < 1 || record.events.length > MAX_EVENTS
      || record.revision !== record.events.length || !Number.isFinite(Date.parse(record.createdAt))
      || !Number.isFinite(Date.parse(record.updatedAt))) return { valid: false, code: "OPERATOR_EVIDENCE_SHAPE_INVALID" };
    let previousHash = genesisHash(ownerId, record.id);
    for (let i = 0; i < record.events.length; i++) {
      const event = record.events[i];
      if (!event || event.sequence !== i + 1 || !EVENT_TYPES.has(event.type) || !Number.isFinite(Date.parse(event.at))
        || event.previousHash !== previousHash || !event.payload || typeof event.payload !== "object"
        || event.eventHash !== eventHash(event)) return { valid: false, code: "OPERATOR_EVIDENCE_CHAIN_INVALID" };
      previousHash = event.eventHash;
    }
    if (record.createdAt !== record.events[0].at || record.updatedAt !== record.events.at(-1).at
      || record.digest !== digestRecord(record)) return { valid: false, code: "OPERATOR_EVIDENCE_DIGEST_INVALID" };
    return { valid: true, code: null, record };
  }
  async function appendEvidence(ownerId, type, input = {}) {
    assertOwner(ownerId);
    if (!EVENT_TYPES.has(type)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_OPERATOR_EVENT_INVALID", "Jenis operator evidence tidak diizinkan", 400);
    const at = now();
    const payload = safePayload(input);
    const id = ledgerId(ownerId);
    const result = await store.mutateEvidence(ownerId, id, current => {
      let record;
      if (current == null) {
        record = { id, ownerId, kind: LEDGER_KIND, schemaVersion: 1, revision: 0, events: [], createdAt: at, updatedAt: at };
      } else {
        const check = validateLedger(current, ownerId);
        if (!check.valid) throw new AgenticError(`RECOVERY_SLO_FINALIZATION_${check.code}`, "Operator evidence ledger tidak valid; penulisan ditolak", 409);
        record = clean(current);
      }
      if (record.events.length >= MAX_EVENTS) throw new AgenticError("RECOVERY_SLO_FINALIZATION_OPERATOR_EVIDENCE_CAPACITY", "Operator evidence ledger mencapai kapasitas; penghapusan otomatis tidak diizinkan", 409);
      const previousHash = record.events.at(-1)?.eventHash ?? genesisHash(ownerId, id);
      const event = { sequence: record.events.length + 1, type, at, previousHash, payload };
      event.eventHash = eventHash(event);
      record.events.push(event); record.revision = record.events.length; record.updatedAt = at;
      if (record.events.length === 1) record.createdAt = at;
      record.digest = digestRecord(record);
      return { value: record, result: { sequence: event.sequence, eventHash: event.eventHash, ledgerDigest: record.digest } };
    });
    return result;
  }
  async function updateChallenge(ownerId, id, updater) {
    return store.mutateEvidence(ownerId, id, current => {
      if (!current || current.ownerId !== ownerId || current.kind !== CHALLENGE_KIND || current.digest !== digestRecord(current)) {
        throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CHALLENGE_INVALID", "Conformance challenge tidak valid", 409);
      }
      const decision = updater(clean(current));
      if (decision.write === false) return decision;
      const next = decision.value;
      next.digest = digestRecord(next);
      return { value: next, result: decision.result ?? next };
    });
  }
  async function prepareProviderConformance(ownerId, input = {}) {
    assertOwner(ownerId);
    if (!externalAnchorProvider) throw new AgenticError("RECOVERY_SLO_FINALIZATION_ANCHOR_PROVIDER_UNAVAILABLE", "External anchor provider tidak dikonfigurasi", 503);
    if (input.reason != null && !reasonValid(input.reason)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_REASON_INVALID", "Alasan conformance harus 12–240 karakter", 400);
    const createdAt = now();
    const challengeId = `recovery-slo-finalization-anchor-conformance-${randomUUID()}`;
    const unsigned = { id: challengeId, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1,
      disposableNamespace: `${CONFORMANCE_PREFIX}${randomUUID()}`, status: "issued", createdAt,
      expiresAt: new Date(Date.parse(createdAt) + 5 * 60_000).toISOString(), reason: String(input.reason || "Validate external anchor provider CAS behavior.").trim() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    const evidence = await appendEvidence(ownerId, "provider_conformance_prepared", { conformanceChallengeId: challengeId,
      reason: challenge.reason, outcome: "prepared" });
    return { challengeId, ownerId, disposableNamespace: challenge.disposableNamespace, createdAt, expiresAt: challenge.expiresAt,
      confirmation: `RUN CONFORMANCE ${challenge.digest.slice(0, 12)}`, operatorEvidenceSequence: evidence.sequence,
      writesToDisposableNamespace: true, writesToOwnerNamespace: false, readOnly: true, mutationAllowed: false };
  }
  async function runProviderConformance(ownerId, challengeId, input = {}) {
    assertOwner(ownerId);
    if (!externalAnchorProvider) throw new AgenticError("RECOVERY_SLO_FINALIZATION_ANCHOR_PROVIDER_UNAVAILABLE", "External anchor provider tidak dikonfigurasi", 503);
    if (typeof challengeId !== "string" || !challengeId.startsWith("recovery-slo-finalization-anchor-conformance-")) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CHALLENGE_INVALID", "Challenge ID tidak valid", 400);
    }
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CHALLENGE_INVALID", "Challenge tidak ditemukan atau integritasnya gagal", 409);
    }
    if (challenge.status === "completed") return { status: challenge.report?.conformant ? "conformant" : "nonconformant",
      report: challenge.report, idempotent: true, readOnly: true, mutationAllowed: false };
    if (challenge.status !== "issued" || Date.parse(now()) > Date.parse(challenge.expiresAt)) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CHALLENGE_EXPIRED", "Challenge sudah digunakan atau kedaluwarsa", 409);
    }
    if (input.confirmation !== `RUN CONFORMANCE ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CONFIRMATION_INVALID", "Konfirmasi conformance tidak cocok", 403);
    }
    const claimed = await updateChallenge(ownerId, challengeId, current => {
      if (current.status !== "issued" || current.digest !== challenge.digest) throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CHALLENGE_STALE", "Challenge sudah diklaim oleh operasi lain", 409);
      current.status = "running"; current.startedAt = now();
      return { value: current, result: current };
    });
    try {
      await appendEvidence(ownerId, "provider_conformance_started", { conformanceChallengeId: challengeId,
        reason: challenge.reason, outcome: "running" });
    } catch (error) {
      await updateChallenge(ownerId, challengeId, current => {
        current.status = "issued"; delete current.startedAt;
        return { value: current, result: current };
      }).catch(() => {});
      throw error;
    }
    try {
      const report = await probeFinalizationAnchorProvider(externalAnchorProvider, claimed.disposableNamespace);
      const saved = await updateChallenge(ownerId, challengeId, current => {
        if (current.status !== "running") throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CHALLENGE_STALE", "Status challenge berubah saat conformance", 409);
        current.status = "completed"; current.completedAt = now(); current.report = report;
        current.reportDigest = sha256(canonical(report));
        return { value: current, result: current };
      });
      const evidence = await appendEvidence(ownerId, "provider_conformance_completed", { conformanceChallengeId: challengeId,
        reason: challenge.reason, outcome: report.conformant ? "conformant" : "nonconformant",
        conformanceDigest: saved.reportDigest, providerWritesPerformed: report.writesPerformed,
        findings: report.findings || [] });
      return { status: report.conformant ? "conformant" : "nonconformant", report,
        reportDigest: saved.reportDigest, operatorEvidenceSequence: evidence.sequence,
        writesToDisposableNamespace: true, writesToOwnerNamespace: false, readOnly: true, mutationAllowed: false };
    } catch (error) {
      const errorCode = String(error?.code || "EXTERNAL_ANCHOR_CONFORMANCE_FAILED").slice(0, 80);
      await updateChallenge(ownerId, challengeId, current => {
        current.status = "failed"; current.completedAt = now(); current.errorCode = errorCode;
        return { value: current, result: current };
      }).catch(() => {});
      await appendEvidence(ownerId, "provider_conformance_failed", { conformanceChallengeId: challengeId,
        reason: challenge.reason, outcome: "failed", findings: [errorCode] }).catch(() => {});
      throw new AgenticError("RECOVERY_SLO_FINALIZATION_CONFORMANCE_FAILED", "External anchor provider conformance gagal; hasil dicatat tanpa membuka detail sensitif", 502, { errorCode });
    }
  }
  async function createContinuityProof(ownerId) {
    assertOwner(ownerId);
    const proof = await keyPolicy.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof(ownerId);
    const evidence = await appendEvidence(ownerId, "continuity_proof_created", { proofId: proof.proofId,
      proofDigest: proof.proofDigest, anchorStatus: proof.observedAnchorStatus,
      localRevision: proof.localPolicySnapshot?.revision, anchorRevision: proof.externalAnchorSnapshot?.revision,
      outcome: proof.claims?.anchorCurrent ? "anchored" : proof.observedAnchorStatus });
    return { proof, operatorEvidenceSequence: evidence.sequence, readOnly: true, mutationAllowed: false };
  }
  async function verifyContinuityProof(ownerId, proof) {
    assertOwner(ownerId);
    const result = keyPolicy.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof(ownerId, proof);
    const evidence = await appendEvidence(ownerId, "continuity_proof_verified", { proofId: proof?.proofId,
      proofDigest: proof?.proofDigest, anchorStatus: result.status, localRevision: result.localRevision,
      anchorRevision: result.anchorRevision, outcome: result.valid ? (result.continuityEstablished ? "valid_continuity" : "valid_but_not_anchored") : "invalid",
      findings: result.findings || [] });
    return { ...result, operatorEvidenceSequence: evidence.sequence };
  }
  async function reconcileAnchor(ownerId) {
    assertOwner(ownerId);
    const operationId = randomUUID();
    const before = await keyPolicy.getRecoverySloFinalizationKeyPolicyAnchorStatus(ownerId);
    await appendEvidence(ownerId, "reconciliation_requested", { operationId,
      reason: "Operator requested external anchor reconciliation.", anchorStatus: before.status,
      localRevision: before.localRevision, anchorRevision: before.anchorRevision, outcome: "requested" });
    try {
      const result = await keyPolicy.reconcileRecoverySloFinalizationKeyPolicyAnchor(ownerId);
      const type = result.status === "anchored" || result.status === "not_configured" ? "reconciliation_completed" : "reconciliation_blocked";
      const evidence = await appendEvidence(ownerId, type, { operationId,
        reason: "Reconciliation outcome recorded for operator review.", anchorStatus: result.status,
        localRevision: result.localRevision, anchorRevision: result.anchorRevision, outcome: result.status,
        findings: result.errorCode ? [result.errorCode] : [] });
      return { ...result, operatorEvidenceSequence: evidence.sequence, operationId };
    } catch (error) {
      await appendEvidence(ownerId, "reconciliation_blocked", { operationId,
        reason: "Reconciliation threw an error and was not considered successful.", outcome: "failed",
        findings: [String(error?.code || "RECONCILIATION_FAILED").slice(0, 80)] }).catch(() => {});
      throw error;
    }
  }
  async function recordOperatorNote(ownerId, input = {}) {
    assertOwner(ownerId);
    if (!reasonValid(input.reason)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_OPERATOR_NOTE_INVALID", "Catatan operator harus 12–240 karakter", 400);
    const status = await keyPolicy.getRecoverySloFinalizationKeyPolicyAnchorStatus(ownerId);
    const evidence = await appendEvidence(ownerId, "operator_note", { reason: input.reason.trim(), anchorStatus: status.status,
      localRevision: status.localRevision, anchorRevision: status.anchorRevision, outcome: "noted" });
    return { status: "recorded", evidenceSequence: evidence.sequence, anchorStatus: status.status,
      noteIsAuthorization: false, readOnly: false, mutationAllowed: false };
  }
  async function recordBatch129Evidence(ownerId, type, input = {}) {
    const allowed = new Set(["continuity_evidence_signed", "continuity_evidence_verified",
      "recovery_runbook_exported", "recovery_runbook_verified", "contract_migration_planned", "contract_migration_approved",
      "contract_migration_applied", "contract_migration_recovered", "runbook_attested", "runbook_key_rotation_prepared", "runbook_key_rotated",
      "recovery_evidence_retention_pruned", "retention_policy_change_planned", "retention_policy_change_approved",
      "recovery_evidence_retention_policy_changed", "runbook_key_revocation_prepared", "runbook_key_revoked",
      "runbook_key_recovery_prepared", "runbook_key_recovered"]);
    if (!allowed.has(type)) throw new AgenticError("RECOVERY_SLO_FINALIZATION_OPERATOR_EVENT_INVALID", "Jenis Batch 129 operator evidence tidak diizinkan", 400);
    return appendEvidence(ownerId, type, input);
  }
  async function auditOperatorEvidence(ownerId) {
    assertOwner(ownerId);
    const record = await store.getEvidence(ownerId, ledgerId(ownerId));
    if (!record) return { status: "empty", ownerId, eventCount: 0, pendingReconciliations: [], findings: [], readOnly: true, mutationAllowed: false };
    const check = validateLedger(record, ownerId);
    if (!check.valid) return { status: "unhealthy", ownerId, eventCount: record.events?.length ?? 0,
      findings: [{ code: check.code, severity: "error" }], pendingReconciliations: [], readOnly: true, mutationAllowed: false };
    const requests = new Map();
    for (const event of record.events) {
      const id = event.payload?.operationId;
      if (!id) continue;
      if (event.type === "reconciliation_requested") requests.set(id, event);
      if (["reconciliation_completed", "reconciliation_blocked"].includes(event.type)) requests.delete(id);
    }
    return { status: requests.size ? "degraded" : "healthy", ownerId, eventCount: record.events.length,
      revision: record.revision, digest: record.digest, lastEventHash: record.events.at(-1).eventHash,
      pendingReconciliations: [...requests.values()].map(event => ({ operationId: event.payload.operationId,
        requestedAt: event.at, observedAnchorStatus: event.payload.anchorStatus })).slice(0, 50), findings: requests.size ? [{ code: "RECONCILIATION_OUTCOME_PENDING", severity: "warning" }] : [],
      readOnly: true, mutationAllowed: false };
  }
  async function listOperatorEvidence(ownerId, options = {}) {
    assertOwner(ownerId);
    const audit = await auditOperatorEvidence(ownerId);
    if (audit.status === "unhealthy") return { ...audit, items: [] };
    const record = await store.getEvidence(ownerId, ledgerId(ownerId));
    const requested = Number(options.limit ?? 50);
    const limit = Number.isFinite(requested) ? Math.max(1, Math.min(MAX_LIMIT, Math.floor(requested))) : 50;
    const events = (record?.events || []).slice(-limit).reverse();
    return { ...audit, items: events.map(event => ({ sequence: event.sequence, type: event.type, at: event.at,
      eventHash: event.eventHash, payload: clean(event.payload) })) };
  }
  return Object.freeze({ prepareRecoverySloFinalizationKeyPolicyAnchorProviderConformance: prepareProviderConformance,
    runRecoverySloFinalizationKeyPolicyAnchorProviderConformance: runProviderConformance,
    createRecoverySloFinalizationKeyPolicyAnchorContinuityProof: createContinuityProof,
    verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof: verifyContinuityProof,
    reconcileRecoverySloFinalizationKeyPolicyAnchorWithOperatorEvidence: reconcileAnchor,
    recordRecoverySloFinalizationKeyPolicyAnchorOperatorNote: recordOperatorNote,
    auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence: auditOperatorEvidence,
    listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence: listOperatorEvidence,
    recordRecoverySloFinalizationAnchorEvidenceEvent: recordBatch129Evidence
  });
}
