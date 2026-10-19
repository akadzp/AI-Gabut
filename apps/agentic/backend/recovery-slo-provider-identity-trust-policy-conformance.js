import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const CHALLENGE_KIND = "recovery-slo-provider-identity-trust-policy-anchor-conformance-challenge";
const PREFIX = "recovery-slo-provider-identity-trust-policy-conformance-";
const DISPOSABLE_PREFIX = "__agentic_v4_provider_identity_trust_policy_conformance__";
const ANCHOR_KIND = "recovery-slo-provider-identity-trust-policy-external-anchor";
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
const scopeFor = (ownerId, domain) => `provider-identity-trust-policy-${ownerHash(ownerId)}-${domain}`;
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_OWNER_REQUIRED", "Owner trust-policy conformance wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function candidate({ scope, sourceOwnerId, sequence, revision, previousAnchorDigest, previousPolicyDigest, nonce, at, anchorType }) {
  const unsigned = { ownerId: scope, sourceOwnerHash: sha256(sourceOwnerId), domain: "drift_event", kind: ANCHOR_KIND, schemaVersion: 1,
    anchorSequence: sequence, revision, policyDigest: sha256(canonical({ nonce, revision, scope })), previousPolicyDigest,
    previousAnchorDigest, anchorType, historyNotProven: false, anchoredAt: at };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function same(a, b) { return canonical(a) === canonical(b); }

export function createRecoverySloProviderIdentityTrustPolicyConformanceService({ store, provider = null, retainedEvidenceService = null,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function"
    || retainedEvidenceService && typeof retainedEvidenceService.retainRecoverySloAnchorEvidence !== "function") {
    throw new TypeError("Trust-policy anchor conformance membutuhkan store, clock, dan retained-evidence service jika disediakan");
  }
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_CLOCK_INVALID", "Clock conformance tidak valid", 500);
    return new Date(value).toISOString();
  }
  function requireProvider() {
    if (!provider || typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") {
      throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_PROVIDER_UNAVAILABLE", "Trust-policy anchor provider tidak tersedia atau tidak memenuhi interface CAS", 503);
    }
  }
  async function save(ownerId, current, patch) {
    const next = { ...clean(current), ...patch };
    next.digest = digestRecord(next);
    await store.putEvidence(ownerId, next, { expectedVersion: current?._storage?.version, ...(current ? {} : { overwrite: false }) });
    const saved = await store.getEvidence(ownerId, next.id);
    if (!saved || saved.digest !== digestRecord(saved) || saved.digest !== next.digest) {
      throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_CHALLENGE_WRITE_INVALID", "Challenge conformance gagal diverifikasi setelah penulisan", 409);
    }
    return saved;
  }
  async function retainCompleted(ownerId, challenge) {
    if (!retainedEvidenceService || challenge?.status !== "completed") return null;
    const report = challenge.report;
    return retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: "provider_conformance", sourceId: challenge.id,
      payload: { schemaVersion: 1, ownerId, challengeId: challenge.id, challengeDigest: challenge.digest, reportDigest: challenge.reportDigest,
        conformanceStatus: report?.conformant ? "conformant" : "nonconformant", providerDomain: "provider_identity_trust_policy",
        completedAt: challenge.completedAt, report } });
  }
  async function prepare(ownerId, input = {}) {
    assertOwner(ownerId); requireProvider();
    if (input.reason != null && !validReason(input.reason)) throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_REASON_INVALID", "Alasan conformance harus 12–240 karakter", 400);
    const createdAt = now(), probeOwnerId = `${ownerId}:trust-policy-conformance:${randomUUID()}`;
    const namespace = scopeFor(probeOwnerId, "drift_event");
    const unsigned = { id: `${PREFIX}${randomUUID()}`, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "issued",
      disposableNamespace: namespace, probeOwnerId, probeOwnerHash: sha256(probeOwnerId), createdAt,
      expiresAt: new Date(Date.parse(createdAt) + 5 * 60_000).toISOString(),
      reason: String(input.reason || "Validate external provider behavior for the identity trust-policy anchor.").trim() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: challenge.id, ownerId, disposableNamespace: namespace, createdAt, expiresAt: challenge.expiresAt,
      challengeDigest: challenge.digest, confirmation: `RUN TRUST POLICY ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }
  async function run(ownerId, id, input = {}) {
    assertOwner(ownerId); requireProvider();
    if (typeof id !== "string" || !id.startsWith(PREFIX)) throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_CHALLENGE_INVALID", "Challenge ID tidak valid", 400);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_CHALLENGE_INVALID", "Challenge tidak ditemukan atau digest tidak valid", 409);
    }
    if (challenge.status === "completed") return { status: challenge.report?.conformant ? "conformant" : "nonconformant", report: challenge.report,
      reportDigest: challenge.reportDigest, retention: await retainCompleted(ownerId, challenge), idempotent: true,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    if (challenge.status !== "issued" || Date.parse(now()) > Date.parse(challenge.expiresAt)) {
      throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_CHALLENGE_EXPIRED", "Challenge sudah digunakan atau kedaluwarsa", 409);
    }
    if (input.confirmation !== `RUN TRUST POLICY ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_TRUST_POLICY_CONFORMANCE_CONFIRMATION_INVALID", "Konfirmasi conformance tidak cocok", 403);
    }
    const running = await save(ownerId, challenge, { status: "running", startedAt: now() });
    const checks = [], findings = [];
    const record = (name, passed, detail = null) => {
      checks.push({ name, passed: Boolean(passed), ...(detail ? { detail: String(detail).slice(0, 180) } : {}) });
      if (!passed) findings.push({ code: `TRUST_POLICY_ANCHOR_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_FAILED`, severity: "error" });
    };
    const scope = running.disposableNamespace, otherScope = `${scope}-isolated`;
    const probeOwnerId = running.probeOwnerId;
    const providerIdentityFingerprint = typeof provider.providerIdentity === "string" && provider.providerIdentity.trim()
      ? sha256(provider.providerIdentity.trim()) : null;
    let providerContractDigest = null;
    let writesPerformed = 0;
    try {
      const raw = provider.contractInfo && typeof provider.contractInfo === "object" ? provider.contractInfo : null;
      const info = raw ? { contractId: String(raw.contractId || "").slice(0, 100), version: String(raw.version || "").slice(0, 40),
        schemaVersion: Number.isSafeInteger(raw.schemaVersion) ? raw.schemaVersion : null, ownerScope: String(raw.ownerScope || "").slice(0, 80),
        casSemantics: String(raw.casSemantics || "").slice(0, 100), capabilities: Array.isArray(raw.capabilities) ? raw.capabilities.slice(0, 30).map(x => String(x).slice(0, 80)) : [] } : null;
      providerContractDigest = info ? sha256(canonical(info)) : null;
      record("provider_identity_present", Boolean(providerIdentityFingerprint), "Provider identity must be available for drift monitoring");
      const requiredCapabilities = ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"];
      const metadataValid = Boolean(info && info.contractId === "agentic-v4-trust-anchor-provider" && info.version === "1.1.0"
        && info.schemaVersion === 1 && info.ownerScope === "ownerId" && info.casSemantics === "digest-compare-and-set"
        && requiredCapabilities.every(capability => info.capabilities.includes(capability)));
      record("contract_metadata", metadataValid, "Provider must declare the 1.1.0 owner-scoped CAS contract and required capabilities");
      const initial = await provider.read(scope);
      record("empty_namespace", initial == null, "Disposable namespace should be empty before probing");
      const first = candidate({ scope, sourceOwnerId: probeOwnerId, sequence: 1, revision: 1, previousAnchorDigest: null,
        previousPolicyDigest: null, nonce: randomUUID(), at: now(), anchorType: "genesis" });
      const firstWrite = await provider.compareAndSet(scope, null, first);
      writesPerformed += firstWrite?.applied ? 1 : 0;
      const firstRead = await provider.read(scope);
      record("genesis_cas", Boolean(firstWrite?.applied), "Initial CAS should succeed on an empty disposable namespace");
      record("consistent_read_after_write", Boolean(firstWrite?.applied) && same(firstRead, first), "Read after write must return the exact committed anchor");
      let staleRejected = false;
      try {
        const stale = candidate({ scope, sourceOwnerId: probeOwnerId, sequence: 2, revision: 2, previousAnchorDigest: first.digest,
          previousPolicyDigest: first.policyDigest, nonce: randomUUID(), at: now(), anchorType: "advance" });
        const result = await provider.compareAndSet(scope, null, stale);
        staleRejected = result?.applied === false;
      } catch { staleRejected = true; }
      record("stale_cas_rejection", staleRejected, "An outdated expected digest must not replace a current anchor");
      const second = candidate({ scope, sourceOwnerId: probeOwnerId, sequence: 2, revision: 2, previousAnchorDigest: first.digest,
        previousPolicyDigest: first.policyDigest, nonce: randomUUID(), at: now(), anchorType: "advance" });
      const secondWrite = await provider.compareAndSet(scope, first.digest, second);
      writesPerformed += secondWrite?.applied ? 1 : 0;
      record("monotonic_revision_and_sequence", Boolean(secondWrite?.applied) && second.anchorSequence === first.anchorSequence + 1
        && second.revision === first.revision + 1 && second.previousAnchorDigest === first.digest
        && second.previousPolicyDigest === first.policyDigest, "Revision, sequence, and digest links must advance monotonically");
      const isolated = await provider.read(otherScope);
      record("namespace_isolation", isolated == null, "A distinct namespace must not expose the probe record");
      const thirdA = candidate({ scope, sourceOwnerId: probeOwnerId, sequence: 3, revision: 3, previousAnchorDigest: second.digest,
        previousPolicyDigest: second.policyDigest, nonce: randomUUID(), at: now(), anchorType: "advance" });
      const thirdB = candidate({ scope, sourceOwnerId: probeOwnerId, sequence: 3, revision: 3, previousAnchorDigest: second.digest,
        previousPolicyDigest: second.policyDigest, nonce: randomUUID(), at: now(), anchorType: "advance" });
      const concurrent = await Promise.allSettled([provider.compareAndSet(scope, second.digest, thirdA), provider.compareAndSet(scope, second.digest, thirdB)]);
      const winners = concurrent.filter(item => item.status === "fulfilled" && item.value?.applied).length;
      writesPerformed += winners;
      const afterConcurrent = await provider.read(scope);
      record("concurrent_cas_single_winner", winners === 1 && [thirdA.digest, thirdB.digest].includes(afterConcurrent?.digest),
        "Exactly one concurrent CAS with the same expected digest must win");
      record("anchor_integrity_and_binding", Boolean(afterConcurrent && afterConcurrent.ownerId === scope && afterConcurrent.sourceOwnerHash === sha256(probeOwnerId)
        && afterConcurrent.domain === "drift_event" && afterConcurrent.kind === ANCHOR_KIND && DIGEST.test(afterConcurrent.digest || "")
        && afterConcurrent.digest === digestRecord(afterConcurrent)), "Probe anchor must preserve shape, owner binding, and digest integrity");
      const reportUnsigned = { schemaVersion: 1, challengeId: running.id, ownerId, providerDomain: "provider_identity_trust_policy",
        providerContract: info, providerIdentityFingerprint, providerContractDigest, checkedAt: now(), status: findings.length ? "nonconformant" : "conformant", conformant: findings.length === 0,
        checks, findings, writesPerformed, disposableNamespace: scope, writesToProductionNamespace: false,
        claims: { contractBehaviorTested: true, productionNamespaceUntouchedByDesign: true, infrastructureIndependenceProven: false } };
      const reportDigest = sha256(canonical(reportUnsigned));
      const report = { ...reportUnsigned, reportDigest };
      const completed = await save(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest });
      const retention = await retainCompleted(ownerId, completed);
      return { status: report.conformant ? "conformant" : "nonconformant", report, reportDigest, retention,
        writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    } catch (error) {
      const latest = await store.getEvidence(ownerId, running.id);
      if (latest?.status === "completed") throw error;
      const reportUnsigned = { schemaVersion: 1, challengeId: running.id, ownerId, providerDomain: "provider_identity_trust_policy",
        providerIdentityFingerprint, providerContractDigest, checkedAt: now(), status: "nonconformant", conformant: false, checks,
        findings: [...findings, { code: error?.code || "PROVIDER_PROBE_EXCEPTION", message: String(error?.message || "Provider probe failed").slice(0, 180) }],
        writesPerformed, disposableNamespace: scope, writesToProductionNamespace: false,
        claims: { contractBehaviorTested: true, productionNamespaceUntouchedByDesign: true, infrastructureIndependenceProven: false } };
      const reportDigest = sha256(canonical(reportUnsigned)), report = { ...reportUnsigned, reportDigest };
      const completed = await save(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest });
      const retention = await retainCompleted(ownerId, completed);
      return { status: "nonconformant", report, reportDigest, retention, writesToDisposableNamespace: true,
        writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    }
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const records = (await store.listEvidence(ownerId)).filter(item => item?.kind === CHALLENGE_KIND && item.status === "completed");
    const all = await store.listEvidence(ownerId);
    const retained = all.filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record" && item.artifactType === "provider_conformance");
    const findings = [];
    for (const item of records) {
      const reportWithoutDigest = item.report && Object.fromEntries(Object.entries(item.report).filter(([key]) => key !== "reportDigest"));
      if (item.digest !== digestRecord(item) || !item.report || item.reportDigest !== item.report.reportDigest
        || item.reportDigest !== sha256(canonical(reportWithoutDigest)) || item.report.ownerId !== ownerId
        || item.report.providerDomain !== "provider_identity_trust_policy") {
        findings.push({ code: "TRUST_POLICY_CONFORMANCE_REPORT_INVALID", challengeId: item.id });
      }
      const evidence = retained.find(record => record.sourceId === item.id && (record.payload?.providerDomain === "provider_identity_trust_policy" || record.status === "tombstone"));
      if (retainedEvidenceService && !evidence) findings.push({ code: "TRUST_POLICY_CONFORMANCE_EVIDENCE_NOT_RETAINED", challengeId: item.id });
      else if (evidence?.status === "retained" && (evidence.payload?.reportDigest !== item.reportDigest
        || evidence.payload?.challengeDigest !== item.digest || evidence.payload?.providerDomain !== "provider_identity_trust_policy")) {
        findings.push({ code: "TRUST_POLICY_CONFORMANCE_EVIDENCE_BINDING_INVALID", challengeId: item.id });
      }
    }
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, findings,
      retainedEvidenceChecked: Boolean(retainedEvidenceService), readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance: prepare,
    runRecoverySloProviderIdentityTrustPolicyAnchorConformance: run,
    auditRecoverySloProviderIdentityTrustPolicyAnchorConformance: audit, providerConfigured: Boolean(provider) });
}
