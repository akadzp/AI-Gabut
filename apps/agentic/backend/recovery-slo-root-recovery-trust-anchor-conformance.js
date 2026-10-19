import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const KIND = "recovery-slo-root-recovery-trust-external-anchor";
const CHALLENGE_KIND = "recovery-slo-root-recovery-trust-anchor-conformance-challenge";
const PREFIX = "recovery-slo-root-recovery-trust-anchor-conformance-";
const DISPOSABLE_PREFIX = "__agentic_v4_root_recovery_trust_anchor_conformance__";
const DOMAIN = "root_recovery_trust";
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
  const out = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item);
  return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 40);
const scopeFor = ownerId => `${DISPOSABLE_PREFIX}${ownerHash(ownerId)}-${randomUUID()}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_OWNER_REQUIRED", "Owner root-trust conformance wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function anchorCandidate({ scope, probeOwnerId, sequence, revision, previousAnchorDigest, previousPolicyDigest, at, anchorType }) {
  const unsigned = { ownerId: scope, sourceOwnerHash: sha256(probeOwnerId), domain: DOMAIN, kind: KIND, schemaVersion: 1,
    anchorSequence: sequence, revision, policyDigest: sha256(canonical({ nonce: randomUUID(), scope, revision })),
    previousPolicyDigest, previousAnchorDigest, anchorType, historyNotProven: false, anchoredAt: at };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function same(a, b) { return canonical(a) === canonical(b); }

export function createRecoverySloRootRecoveryTrustAnchorConformanceService({ store, provider = null, retainedEvidenceService = null,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function"
    || retainedEvidenceService && typeof retainedEvidenceService.retainRecoverySloAnchorEvidence !== "function") {
    throw new TypeError("Root-recovery trust anchor conformance membutuhkan store, clock, dan retained-evidence service jika disediakan");
  }
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_CLOCK_INVALID", "Clock conformance tidak valid", 500);
    return new Date(ms).toISOString();
  }
  function requireProvider() {
    if (!provider || typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_PROVIDER_UNAVAILABLE", "Root-recovery trust anchor provider tidak tersedia atau tidak memenuhi interface CAS", 503);
    }
  }
  async function save(ownerId, current, patch) {
    const next = { ...clean(current), ...patch };
    next.digest = digestRecord(next);
    await store.putEvidence(ownerId, next, { expectedVersion: current?._storage?.version, ...(current ? {} : { overwrite: false }) });
    const saved = await store.getEvidence(ownerId, next.id);
    if (!saved || saved.digest !== digestRecord(saved) || saved.digest !== next.digest) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_CHALLENGE_WRITE_INVALID", "Challenge conformance gagal diverifikasi setelah penulisan", 409);
    }
    return saved;
  }
  async function retainCompleted(ownerId, challenge) {
    if (!retainedEvidenceService || challenge?.status !== "completed") return null;
    return retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: "root_recovery_trust_anchor_conformance",
      sourceId: challenge.id, payload: { schemaVersion: 1, ownerId, challengeId: challenge.id, challengeDigest: challenge.digest,
        sourceReportChallengeDigest: challenge.report?.challengeDigest || null, reportDigest: challenge.reportDigest, providerDomain: DOMAIN,
        conformanceStatus: challenge.report?.conformant ? "conformant" : "nonconformant",
        completedAt: challenge.completedAt, report: challenge.report } });
  }
  async function prepare(ownerId, { reason = "Validate root-recovery trust anchor provider behavior before relying on it." } = {}) {
    assertOwner(ownerId); requireProvider();
    if (!validReason(reason)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_REASON_INVALID", "Alasan conformance wajib 12–240 karakter", 400);
    const createdAt = now(), probeOwnerId = `${ownerId}:root-trust-conformance:${randomUUID()}`, disposableNamespace = scopeFor(probeOwnerId);
    const unsigned = { id: `${PREFIX}${randomUUID()}`, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "issued", probeOwnerId,
      probeOwnerHash: sha256(probeOwnerId), disposableNamespace, createdAt, expiresAt: new Date(Date.parse(createdAt) + 5 * 60_000).toISOString(), reason: reason.trim() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: challenge.id, ownerId, disposableNamespace, createdAt, expiresAt: challenge.expiresAt,
      challengeDigest: challenge.digest, confirmation: `RUN ROOT TRUST ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }
  async function run(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId); requireProvider();
    if (typeof id !== "string" || !id.startsWith(PREFIX)) throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_CHALLENGE_INVALID", "Challenge conformance tidak valid", 400);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_CHALLENGE_INVALID", "Challenge tidak ditemukan atau digest tidak valid", 409);
    }
    if (challenge.status === "completed") return { status: challenge.report?.conformant ? "conformant" : "nonconformant", report: challenge.report,
      reportDigest: challenge.reportDigest, retention: await retainCompleted(ownerId, challenge), idempotent: true,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    if (challenge.status !== "issued" || Date.parse(now()) > Date.parse(challenge.expiresAt)) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_CHALLENGE_EXPIRED", "Challenge conformance sudah digunakan atau kedaluwarsa", 409);
    }
    if (confirmation !== `RUN ROOT TRUST ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_CONFIRMATION_INVALID", "Konfirmasi conformance tidak cocok", 403);
    }
    const running = await save(ownerId, challenge, { status: "running", startedAt: now() });
    const checks = [], findings = [];
    const record = (name, passed, detail = null) => {
      checks.push({ name, passed: Boolean(passed), ...(detail ? { detail: String(detail).slice(0, 180) } : {}) });
      if (!passed) findings.push({ code: `ROOT_TRUST_ANCHOR_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_FAILED`, severity: "error" });
    };
    const scope = running.disposableNamespace, otherScope = `${scope}-isolated`, probeOwnerId = running.probeOwnerId;
    const providerIdentityFingerprint = typeof provider.providerIdentity === "string" && provider.providerIdentity.trim()
      ? sha256(provider.providerIdentity.trim()) : null;
    let providerContract = null, writesPerformed = 0;
    try {
      const raw = provider.contractInfo && typeof provider.contractInfo === "object" ? provider.contractInfo : null;
      providerContract = raw ? { contractId: String(raw.contractId || "").slice(0, 100), version: String(raw.version || "").slice(0, 40),
        schemaVersion: Number.isSafeInteger(raw.schemaVersion) ? raw.schemaVersion : null, ownerScope: String(raw.ownerScope || "").slice(0, 80),
        casSemantics: String(raw.casSemantics || "").slice(0, 100), capabilities: Array.isArray(raw.capabilities) ? raw.capabilities.slice(0, 30).map(x => String(x).slice(0, 80)) : [] } : null;
      record("provider_identity_present", Boolean(providerIdentityFingerprint), "Provider identity must be available for identity-drift auditing");
      const capabilities = ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"];
      const metadataValid = Boolean(providerContract && providerContract.contractId === "agentic-v4-trust-anchor-provider"
        && providerContract.version === "1.1.0" && providerContract.schemaVersion === 1 && providerContract.ownerScope === "ownerId"
        && providerContract.casSemantics === "digest-compare-and-set" && capabilities.every(item => providerContract.capabilities.includes(item)));
      record("contract_metadata", metadataValid, "Provider must declare the 1.1.0 owner-scoped CAS contract");
      const empty = await provider.read(scope);
      record("empty_disposable_namespace", empty == null, "Probe namespace must be empty before writes");
      const first = anchorCandidate({ scope, probeOwnerId, sequence: 1, revision: 1, previousAnchorDigest: null, previousPolicyDigest: null, at: now(), anchorType: "genesis" });
      const firstWrite = await provider.compareAndSet(scope, null, first); writesPerformed += firstWrite?.applied ? 1 : 0;
      const firstRead = await provider.read(scope);
      record("genesis_cas", firstWrite?.applied === true, "Genesis CAS should succeed in the disposable namespace");
      record("read_after_write", firstWrite?.applied === true && same(firstRead, first), "Provider must return the exact committed candidate");
      let staleRejected = false;
      try {
        const stale = anchorCandidate({ scope, probeOwnerId, sequence: 2, revision: 2, previousAnchorDigest: first.digest,
          previousPolicyDigest: first.policyDigest, at: now(), anchorType: "advance" });
        staleRejected = (await provider.compareAndSet(scope, null, stale))?.applied === false;
      } catch { staleRejected = true; }
      record("stale_cas_rejection", staleRejected, "Stale expected digest must not overwrite a committed anchor");
      record("stale_cas_no_mutation", (await provider.read(scope))?.digest === first.digest, "Rejected stale CAS must not mutate provider state");
      const second = anchorCandidate({ scope, probeOwnerId, sequence: 2, revision: 2, previousAnchorDigest: first.digest,
        previousPolicyDigest: first.policyDigest, at: now(), anchorType: "advance" });
      const secondWrite = await provider.compareAndSet(scope, first.digest, second); writesPerformed += secondWrite?.applied ? 1 : 0;
      record("monotonic_advance", secondWrite?.applied === true, "Next revision and sequence must advance");
      record("advance_read_after_write", (await provider.read(scope))?.digest === second.digest, "Advanced anchor must be immediately readable");
      const skipped = anchorCandidate({ scope, probeOwnerId, sequence: 4, revision: 3, previousAnchorDigest: second.digest,
        previousPolicyDigest: second.policyDigest, at: now(), anchorType: "advance" });
      let skipRejected = false;
      try { skipRejected = (await provider.compareAndSet(scope, second.digest, skipped))?.applied === false; } catch { skipRejected = true; }
      record("sequence_skip_rejection", skipRejected, "Provider must reject skipped anchor sequence");
      record("sequence_skip_no_mutation", (await provider.read(scope))?.digest === second.digest, "Rejected sequence skip must not mutate anchor");
      const wrongOwner = { ...anchorCandidate({ scope: `${scope}-forged`, probeOwnerId, sequence: 3, revision: 3,
        previousAnchorDigest: second.digest, previousPolicyDigest: second.policyDigest, at: now(), anchorType: "advance" }) };
      let ownerRejected = false;
      try { ownerRejected = (await provider.compareAndSet(scope, second.digest, wrongOwner))?.applied === false; } catch { ownerRejected = true; }
      record("owner_binding", ownerRejected, "Provider must reject candidate bound to another namespace");
      record("namespace_isolation", (await provider.read(otherScope)) == null, "Separate namespace must not expose probe records");
      const left = anchorCandidate({ scope, probeOwnerId, sequence: 3, revision: 3, previousAnchorDigest: second.digest,
        previousPolicyDigest: second.policyDigest, at: now(), anchorType: "advance" });
      const right = anchorCandidate({ scope, probeOwnerId, sequence: 3, revision: 3, previousAnchorDigest: second.digest,
        previousPolicyDigest: second.policyDigest, at: now(), anchorType: "advance" });
      const concurrent = await Promise.allSettled([left, right].map(item => provider.compareAndSet(scope, second.digest, item)));
      const winners = concurrent.filter(item => item.status === "fulfilled" && item.value?.applied).length; writesPerformed += winners;
      const after = await provider.read(scope);
      record("concurrent_cas_single_winner", winners === 1 && [left.digest, right.digest].includes(after?.digest), "Exactly one concurrent CAS should win");
      const shapeValid = Boolean(after && after.ownerId === scope && after.sourceOwnerHash === sha256(probeOwnerId) && after.domain === DOMAIN
        && after.kind === KIND && after.schemaVersion === 1 && DIGEST.test(after.policyDigest || "") && DIGEST.test(after.digest || "")
        && after.digest === digestRecord(after));
      record("anchor_shape_and_digest", shapeValid, "Anchor shape, owner binding, and digest must remain valid");
    } catch (error) {
      record("probe_execution", false, error?.code || error?.message || "Provider probe failed");
    }
    const reportUnsigned = { schemaVersion: 1, challengeId: running.id, challengeDigest: running.digest, ownerId, providerDomain: DOMAIN, providerContract,
      providerIdentityFingerprint, checkedAt: now(), status: findings.length ? "nonconformant" : "conformant", conformant: findings.length === 0,
      checks, findings, checksPassed: checks.filter(item => item.passed).length, checksFailed: checks.filter(item => !item.passed).length,
      writesPerformed, disposableNamespace: scope, writesToProductionNamespace: false,
      claims: { contractBehaviorTested: true, productionNamespaceUntouchedByDesign: true, infrastructureIndependenceProven: false } };
    const reportDigest = sha256(canonical(reportUnsigned)), report = { ...reportUnsigned, reportDigest };
    const completed = await save(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest });
    const retention = await retainCompleted(ownerId, completed);
    return { status: report.conformant ? "conformant" : "nonconformant", report, reportDigest, retention,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const records = (await store.listEvidence(ownerId)).filter(item => item?.kind === CHALLENGE_KIND && item.status === "completed");
    const all = await store.listEvidence(ownerId);
    const retained = all.filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record" && item.artifactType === "root_recovery_trust_anchor_conformance");
    const findings = [];
    for (const item of records) {
      const unsigned = item.report && Object.fromEntries(Object.entries(item.report).filter(([key]) => key !== "reportDigest"));
      if (item.digest !== digestRecord(item) || !item.report || item.reportDigest !== item.report.reportDigest
        || item.reportDigest !== sha256(canonical(unsigned)) || item.report.ownerId !== ownerId || item.report.providerDomain !== DOMAIN) {
        findings.push({ code: "ROOT_TRUST_CONFORMANCE_REPORT_INVALID", challengeId: item.id });
      }
      const evidence = retained.find(record => record.sourceId === item.id && (record.payload?.providerDomain === DOMAIN || record.status === "tombstone"));
      if (retainedEvidenceService && !evidence) findings.push({ code: "ROOT_TRUST_CONFORMANCE_EVIDENCE_NOT_RETAINED", challengeId: item.id });
      else if (evidence?.status === "retained" && (evidence.payload?.reportDigest !== item.reportDigest || evidence.payload?.challengeDigest !== item.digest)) {
        findings.push({ code: "ROOT_TRUST_CONFORMANCE_EVIDENCE_BINDING_INVALID", challengeId: item.id });
      }
    }
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, findings,
      retainedEvidenceChecked: Boolean(retainedEvidenceService), readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ prepareRecoverySloRootRecoveryTrustAnchorConformance: prepare,
    runRecoverySloRootRecoveryTrustAnchorConformance: run, auditRecoverySloRootRecoveryTrustAnchorConformance: audit, providerConfigured: Boolean(provider) });
}
