import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const CHALLENGE_KIND = "recovery-slo-recovery-journal-anchor-conformance-challenge";
const PREFIX = "recovery-slo-recovery-journal-anchor-conformance-";
const DISPOSABLE_PREFIX = "__agentic_v4_recovery_journal_conformance__";
const DIGEST = /^[a-f0-9]{64}$/;
const MAX_REASON = 240;
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
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= MAX_REASON
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function candidate(scope, sequence, revision, previousDigest, nonce, at) {
  const unsigned = { ownerId: scope, kind: "recovery-journal-anchor-conformance-probe", schemaVersion: 1,
    anchorSequence: sequence, revision, previousAnchorDigest: previousDigest, nonce, createdAt: at };
  return { ...unsigned, digest: digestRecord(unsigned) };
}

export function createRecoverySloRecoveryJournalAnchorConformanceService({ store, provider = null,
  clock = () => new Date().toISOString(), onCompleted = null } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || typeof clock !== "function") {
    throw new TypeError("Recovery-journal conformance membutuhkan store dan clock yang valid");
  }
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_CLOCK_INVALID", "Clock conformance tidak valid", 500);
    return new Date(ms).toISOString();
  }
  function requireProvider() {
    if (!provider || typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") {
      throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_PROVIDER_UNAVAILABLE", "Recovery-journal anchor provider tidak tersedia atau tidak memenuhi interface CAS", 503);
    }
  }
  async function prepare(ownerId, input = {}) {
    assertOwner(ownerId); requireProvider();
    if (input.reason != null && !validReason(input.reason)) {
      throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_REASON_INVALID", "Alasan conformance harus 12–240 karakter", 400);
    }
    const createdAt = now();
    const id = `${PREFIX}${randomUUID()}`;
    const unsigned = { id, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "issued",
      disposableNamespace: `${DISPOSABLE_PREFIX}${randomUUID()}`, createdAt,
      expiresAt: new Date(Date.parse(createdAt) + 5 * 60_000).toISOString(),
      reason: String(input.reason || "Validate recovery-journal anchor provider behavior.").trim() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, ownerId, disposableNamespace: challenge.disposableNamespace,
      createdAt, expiresAt: challenge.expiresAt, confirmation: `RUN JOURNAL ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }
  async function saveChallenge(ownerId, current, patch) {
    const next = { ...clean(current), ...patch };
    next.digest = digestRecord(next);
    return store.putEvidence(ownerId, next, { expectedVersion: current._storage?.version });
  }
  async function run(ownerId, challengeId, input = {}) {
    assertOwner(ownerId); requireProvider();
    if (typeof challengeId !== "string" || !challengeId.startsWith(PREFIX)) {
      throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_CHALLENGE_INVALID", "Challenge ID tidak valid", 400);
    }
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_CHALLENGE_INVALID", "Challenge tidak ditemukan atau integritasnya gagal", 409);
    }
    if (challenge.status === "completed") {
      const retainedEvidence = typeof onCompleted === "function" ? await onCompleted(ownerId, challenge) : null;
      return { status: challenge.report?.conformant ? "conformant" : "nonconformant",
        report: challenge.report, reportDigest: challenge.reportDigest, retainedEvidence, idempotent: true, writesToDisposableNamespace: true,
        writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    }
    if (challenge.status !== "issued" || Date.parse(now()) > Date.parse(challenge.expiresAt)) {
      throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_CHALLENGE_EXPIRED", "Challenge sudah digunakan atau kedaluwarsa", 409);
    }
    if (input.confirmation !== `RUN JOURNAL ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_JOURNAL_CONFORMANCE_CONFIRMATION_INVALID", "Konfirmasi conformance tidak cocok", 403);
    }
    const running = await saveChallenge(ownerId, challenge, { status: "running", startedAt: now() });
    const checks = [];
    const findings = [];
    const record = (name, passed, detail = null) => {
      checks.push({ name, passed: Boolean(passed), ...(detail ? { detail: String(detail).slice(0, 180) } : {}) });
      if (!passed) findings.push({ code: `PROVIDER_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_FAILED`, severity: "error" });
    };
    const probeScope = running.disposableNamespace;
    const otherScope = `${probeScope}-isolated`;
    let writesPerformed = 0;
    let report;
    try {
      const info = provider.contractInfo && typeof provider.contractInfo === "object" ? {
        contractId: String(provider.contractInfo.contractId || "").slice(0, 100),
        version: String(provider.contractInfo.version || "").slice(0, 40),
        schemaVersion: Number.isSafeInteger(provider.contractInfo.schemaVersion) ? provider.contractInfo.schemaVersion : null,
        ownerScope: String(provider.contractInfo.ownerScope || "").slice(0, 80),
        casSemantics: String(provider.contractInfo.casSemantics || "").slice(0, 100),
        capabilities: Array.isArray(provider.contractInfo.capabilities) ? provider.contractInfo.capabilities.slice(0, 20).map(x => String(x).slice(0, 80)) : []
      } : null;
      const metadataValid = Boolean(info && info.contractId === "agentic-v4-trust-anchor-provider"
        && ["1.0.0", "1.1.0"].includes(info.version) && info.schemaVersion === 1
        && info.ownerScope === "ownerId" && info.casSemantics === "digest-compare-and-set"
        && info.capabilities.includes("read") && info.capabilities.includes("compareAndSet"));
      record("contract_metadata", metadataValid, "Provider must declare a supported contract and required CAS capabilities");
      const initial = await provider.read(probeScope);
      record("empty_namespace_read", initial == null, initial == null ? null : "Disposable namespace was not empty before probe");
      const first = candidate(probeScope, 1, 1, null, randomUUID(), now());
      const firstWrite = await provider.compareAndSet(probeScope, null, first);
      writesPerformed += firstWrite?.applied ? 1 : 0;
      record("genesis_cas", firstWrite?.applied === true, firstWrite?.applied ? null : "Genesis compare-and-set was not applied");
      const firstRead = await provider.read(probeScope);
      record("read_after_write", firstRead?.digest === first.digest && canonical(firstRead) === canonical(first), "Provider read must return the exact committed candidate");

      const staleCandidate = candidate(probeScope, 1, 1, null, randomUUID(), now());
      let staleRejected = false;
      try { const result = await provider.compareAndSet(probeScope, null, staleCandidate); staleRejected = result?.applied === false; }
      catch { staleRejected = true; }
      record("stale_cas_rejection", staleRejected, "A stale expected digest must never overwrite the committed anchor");
      const afterStale = await provider.read(probeScope);
      record("stale_cas_no_mutation", afterStale?.digest === first.digest, "Rejected stale CAS changed the stored anchor");

      const second = candidate(probeScope, 2, 2, first.digest, randomUUID(), now());
      const secondWrite = await provider.compareAndSet(probeScope, first.digest, second);
      writesPerformed += secondWrite?.applied ? 1 : 0;
      record("monotonic_advance", secondWrite?.applied === true, "Valid sequence/revision advance must succeed");
      const secondRead = await provider.read(probeScope);
      record("advance_read_after_write", secondRead?.digest === second.digest, "Advanced anchor was not returned consistently after write");

      const invalidSequence = candidate(probeScope, 4, 3, second.digest, randomUUID(), now());
      let sequenceRejected = false;
      try { const result = await provider.compareAndSet(probeScope, second.digest, invalidSequence); sequenceRejected = result?.applied === false; }
      catch { sequenceRejected = true; }
      record("monotonic_sequence_enforcement", sequenceRejected, "Provider must reject a skipped anchor sequence");
      const afterSequence = await provider.read(probeScope);
      record("sequence_rejection_no_mutation", afterSequence?.digest === second.digest, "Rejected sequence mutation changed the anchor");

      const wrongOwner = candidate(`${probeScope}-forged`, 3, 3, second.digest, randomUUID(), now());
      let ownerRejected = false;
      try { const result = await provider.compareAndSet(probeScope, second.digest, wrongOwner); ownerRejected = result?.applied === false; }
      catch { ownerRejected = true; }
      record("owner_binding_enforcement", ownerRejected, "Provider must reject a candidate whose owner scope differs from the requested scope");
      record("owner_namespace_isolation", (await provider.read(otherScope)) == null, "A separate namespace exposed another namespace's anchor");

      const left = candidate(probeScope, 3, 3, second.digest, randomUUID(), now());
      const right = candidate(probeScope, 3, 3, second.digest, randomUUID(), now());
      const concurrent = await Promise.all([left, right].map(async item => {
        try { const result = await provider.compareAndSet(probeScope, second.digest, item); return { applied: result?.applied === true, digest: item.digest }; }
        catch { return { applied: false, digest: item.digest }; }
      }));
      const winners = concurrent.filter(item => item.applied);
      writesPerformed += winners.length;
      record("concurrent_cas_single_winner", winners.length === 1, `Observed ${winners.length} successful writers; expected exactly one`);
      const finalRead = await provider.read(probeScope);
      record("concurrent_result_consistency", winners.length === 1 && finalRead?.digest === winners[0].digest,
        "Final read must match the single CAS winner");

      report = { schemaVersion: 1, providerContract: info, disposableNamespace: probeScope,
        completedAt: now(), checks, findings, checksPassed: checks.filter(item => item.passed).length,
        checksFailed: checks.filter(item => !item.passed).length, writesPerformed,
        writesToProductionNamespace: false, cleanupSupported: false,
        note: "Probe records use a disposable namespace and may remain if the provider has no deletion API." };
    } catch (error) {
      record("probe_execution", false, error?.code || error?.message || "Provider probe failed");
      report = { schemaVersion: 1, providerContract: null, disposableNamespace: probeScope,
        completedAt: now(), checks, findings, checksPassed: checks.filter(item => item.passed).length,
        checksFailed: checks.filter(item => !item.passed).length, writesPerformed,
        writesToProductionNamespace: false, cleanupSupported: false,
        errorCode: String(error?.code || "PROVIDER_PROBE_FAILED").slice(0, 80),
        note: "Probe records use a disposable namespace and may remain if the provider has no deletion API." };
    }
    report.conformant = report.checksFailed === 0;
    report.reportDigest = sha256(canonical(report));
    const completed = await saveChallenge(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest: report.reportDigest });
    const retainedEvidence = typeof onCompleted === "function" ? await onCompleted(ownerId, completed) : null;
    return { status: report.conformant ? "conformant" : "nonconformant", report: completed.report,
      reportDigest: completed.reportDigest, retainedEvidence, idempotent: false, writesToDisposableNamespace: true,
      writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }
  return Object.freeze({ prepareRecoverySloRecoveryJournalAnchorProviderConformance: prepare,
    runRecoverySloRecoveryJournalAnchorProviderConformance: run, configured: Boolean(provider) });
}
