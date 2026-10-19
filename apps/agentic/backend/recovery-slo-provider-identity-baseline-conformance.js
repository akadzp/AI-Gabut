import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const CHALLENGE_KIND = "recovery-slo-provider-identity-baseline-anchor-conformance-challenge";
const PREFIX = "recovery-slo-provider-identity-baseline-conformance-";
const DISPOSABLE_PREFIX = "__agentic_v4_provider_identity_baseline_conformance__";
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
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_OWNER_REQUIRED", "Owner conformance wajib ditentukan", 400);
  }
}
function validReason(value) {
  return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
    && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}
function candidate(scope, sequence, revision, previousAnchorDigest, nonce, at) {
  const unsigned = { ownerId: scope, kind: "provider-identity-baseline-anchor-conformance-probe", schemaVersion: 1,
    anchorSequence: sequence, revision, previousAnchorDigest, nonce, createdAt: at };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function equal(a, b) { return canonical(a) === canonical(b); }

export function createRecoverySloProviderIdentityBaselineConformanceService({ store, provider = null, retainedEvidenceService = null,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || typeof clock !== "function"
    || retainedEvidenceService && typeof retainedEvidenceService.retainRecoverySloProviderIdentityBaselineConformanceEvidence !== "function") {
    throw new TypeError("Provider identity baseline conformance membutuhkan store, clock, dan retained-evidence service jika disediakan");
  }
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_CLOCK_INVALID", "Clock conformance tidak valid", 500);
    return new Date(ms).toISOString();
  }
  function requireProvider() {
    if (!provider || typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_PROVIDER_UNAVAILABLE", "Provider baseline anchor tidak tersedia atau tidak memenuhi interface CAS", 503);
    }
  }
  async function prepare(ownerId, input = {}) {
    assertOwner(ownerId); requireProvider();
    if (input.reason != null && !validReason(input.reason)) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_REASON_INVALID", "Alasan conformance harus 12–240 karakter", 400);
    const createdAt = now();
    const unsigned = { id: `${PREFIX}${randomUUID()}`, ownerId, kind: CHALLENGE_KIND, schemaVersion: 1, status: "issued",
      disposableNamespace: `${DISPOSABLE_PREFIX}${randomUUID()}`, createdAt,
      expiresAt: new Date(Date.parse(createdAt) + 5 * 60_000).toISOString(),
      reason: String(input.reason || "Validate provider identity baseline anchor behavior.").trim() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: challenge.id, ownerId, disposableNamespace: challenge.disposableNamespace,
      createdAt, expiresAt: challenge.expiresAt, challengeDigest: challenge.digest,
      confirmation: `RUN PROVIDER IDENTITY BASELINE CONFORMANCE ${challenge.digest.slice(0, 12)}`,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }
  async function saveChallenge(ownerId, current, patch) {
    const next = { ...clean(current), ...patch };
    next.digest = digestRecord(next);
    await store.putEvidence(ownerId, next, { expectedVersion: current._storage?.version });
    return store.getEvidence(ownerId, next.id);
  }
  async function retainCompleted(ownerId, challenge) {
    if (!retainedEvidenceService || challenge?.status !== "completed") return null;
    return retainedEvidenceService.retainRecoverySloProviderIdentityBaselineConformanceEvidence(ownerId, challenge);
  }
  async function run(ownerId, id, input = {}) {
    assertOwner(ownerId); requireProvider();
    if (typeof id !== "string" || !id.startsWith(PREFIX)) throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_CHALLENGE_INVALID", "Challenge ID tidak valid", 400);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== CHALLENGE_KIND || challenge.digest !== digestRecord(challenge)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_CHALLENGE_INVALID", "Challenge tidak ditemukan atau integritasnya gagal", 409);
    }
    if (challenge.status === "completed") {
      const retention = await retainCompleted(ownerId, challenge);
      return { status: challenge.report?.conformant ? "conformant" : "nonconformant",
        report: challenge.report, reportDigest: challenge.reportDigest, retention, idempotent: true, writesToDisposableNamespace: true,
        writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    }
    if (challenge.status !== "issued" || Date.parse(now()) > Date.parse(challenge.expiresAt)) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_CHALLENGE_EXPIRED", "Challenge sudah digunakan atau kedaluwarsa", 409);
    }
    if (input.confirmation !== `RUN PROVIDER IDENTITY BASELINE CONFORMANCE ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_CONFIRMATION_INVALID", "Konfirmasi conformance tidak cocok", 403);
    }
    const running = await saveChallenge(ownerId, challenge, { status: "running", startedAt: now() });
    const checks = [], findings = [];
    const record = (name, passed, detail = null) => {
      checks.push({ name, passed: Boolean(passed), ...(detail ? { detail: String(detail).slice(0, 180) } : {}) });
      if (!passed) findings.push({ code: `PROVIDER_IDENTITY_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_FAILED`, severity: "error" });
    };
    const scope = running.disposableNamespace, otherScope = `${scope}-isolated`;
    let writesPerformed = 0;
    try {
      const raw = provider.contractInfo && typeof provider.contractInfo === "object" ? provider.contractInfo : null;
      const info = raw ? { contractId: String(raw.contractId || "").slice(0, 100), version: String(raw.version || "").slice(0, 40),
        schemaVersion: Number.isSafeInteger(raw.schemaVersion) ? raw.schemaVersion : null, ownerScope: String(raw.ownerScope || "").slice(0, 80),
        casSemantics: String(raw.casSemantics || "").slice(0, 100), capabilities: Array.isArray(raw.capabilities) ? raw.capabilities.slice(0, 30).map(x => String(x).slice(0, 80)) : [] } : null;
      const metadataValid = Boolean(info && info.contractId === "agentic-v4-trust-anchor-provider" && ["1.0.0", "1.1.0"].includes(info.version)
        && info.schemaVersion === 1 && info.ownerScope === "ownerId" && info.casSemantics === "digest-compare-and-set"
        && info.capabilities.includes("read") && info.capabilities.includes("compareAndSet"));
      record("contract_metadata", metadataValid, "Provider must declare a supported owner-scoped CAS contract");
      const initial = await provider.read(scope);
      record("empty_namespace", initial == null, "Disposable namespace should be empty before probing");
      const first = candidate(scope, 1, 1, null, randomUUID(), now());
      const firstWrite = await provider.compareAndSet(scope, null, first);
      writesPerformed += firstWrite?.applied ? 1 : 0;
      const firstRead = await provider.read(scope);
      record("genesis_cas", Boolean(firstWrite?.applied), "Initial CAS should succeed on an empty disposable namespace");
      record("read_after_write", equal(firstRead, first), "Read after write must return the committed candidate exactly");
      let staleRejected = false;
      try {
        const stale = candidate(scope, 2, 2, first.digest, randomUUID(), now());
        const staleResult = await provider.compareAndSet(scope, null, stale);
        staleRejected = staleResult?.applied === false;
      } catch { staleRejected = true; }
      record("stale_cas_rejection", staleRejected, "A stale expected digest must never overwrite the current anchor");
      const second = candidate(scope, 2, 2, first.digest, randomUUID(), now());
      const secondWrite = await provider.compareAndSet(scope, first.digest, second);
      writesPerformed += secondWrite?.applied ? 1 : 0;
      record("monotonic_advance", Boolean(secondWrite?.applied) && second.anchorSequence === first.anchorSequence + 1
        && second.revision === first.revision + 1 && second.previousAnchorDigest === first.digest,
      "Revision and sequence must advance by exactly one with digest continuity");
      const isolatedRead = await provider.read(otherScope);
      record("owner_namespace_isolation", isolatedRead == null, "A separate owner namespace must not expose the probe record");
      const thirdA = candidate(scope, 3, 3, second.digest, randomUUID(), now());
      const thirdB = candidate(scope, 3, 3, second.digest, randomUUID(), now());
      const concurrent = await Promise.allSettled([provider.compareAndSet(scope, second.digest, thirdA), provider.compareAndSet(scope, second.digest, thirdB)]);
      writesPerformed += concurrent.filter(result => result.status === "fulfilled" && result.value?.applied).length;
      const winners = concurrent.filter(result => result.status === "fulfilled" && result.value?.applied).length;
      const afterConcurrent = await provider.read(scope);
      record("concurrent_cas_single_winner", winners === 1 && [thirdA.digest, thirdB.digest].includes(afterConcurrent?.digest),
        "Exactly one concurrent CAS using the same expected digest must win");
      record("anchor_shape_integrity", Boolean(afterConcurrent && afterConcurrent.ownerId === scope && DIGEST.test(afterConcurrent.digest || "")
        && afterConcurrent.digest === digestRecord(afterConcurrent)), "Stored probe anchor must retain owner binding and digest integrity");
      const reportUnsigned = { schemaVersion: 1, challengeId: running.id, ownerId, providerContract: info, checkedAt: now(),
        status: findings.length ? "nonconformant" : "conformant", conformant: findings.length === 0, checks, findings,
        writesPerformed, disposableNamespace: scope, writesToProductionNamespace: false, claims: { contractBehaviorTested: true,
          productionNamespaceUntouchedByDesign: true, backingInfrastructureIndependenceProven: false } };
      const reportDigest = sha256(canonical(reportUnsigned));
      const report = { ...reportUnsigned, reportDigest };
      const completed = await saveChallenge(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest });
      const retention = await retainCompleted(ownerId, completed);
      return { status: report.conformant ? "conformant" : "nonconformant", report, reportDigest, retention,
        writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    } catch (error) {
      const latest = await store.getEvidence(ownerId, running.id);
      if (latest?.status === "completed") throw error;
      const failure = { code: error?.code || "PROVIDER_PROBE_EXCEPTION", message: String(error?.message || "Provider probe failed").slice(0, 180) };
      const reportUnsigned = { schemaVersion: 1, challengeId: running.id, ownerId, checkedAt: now(), status: "nonconformant", conformant: false,
        checks, findings: [...findings, failure], writesPerformed, disposableNamespace: scope, writesToProductionNamespace: false,
        claims: { contractBehaviorTested: true, productionNamespaceUntouchedByDesign: true, backingInfrastructureIndependenceProven: false } };
      const reportDigest = sha256(canonical(reportUnsigned));
      const report = { ...reportUnsigned, reportDigest };
      const completed = await saveChallenge(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest });
      const retention = await retainCompleted(ownerId, completed);
      return { status: "nonconformant", report, reportDigest, retention, writesToDisposableNamespace: true, writesToProductionNamespace: false,
        readOnly: false, mutationAllowed: false };
    }
  }
  return Object.freeze({ prepareRecoverySloProviderIdentityBaselineAnchorConformance: prepare,
    runRecoverySloProviderIdentityBaselineAnchorConformance: run,
    auditRecoverySloProviderIdentityBaselineAnchorConformance: async ownerId => {
      assertOwner(ownerId);
      const records = (await store.listEvidence(ownerId)).filter(item => item?.kind === CHALLENGE_KIND && item.status === "completed");
      const findings = [];
      const retained = retainedEvidenceService ? (await store.listEvidence(ownerId)).filter(record =>
        record?.kind === "recovery-slo-anchor-evidence-retention-record" && record.artifactType === "provider_conformance") : null;
      for (const item of records) {
        if (item.digest !== digestRecord(item) || !item.report || item.reportDigest !== item.report.reportDigest
          || item.reportDigest !== sha256(canonical(Object.fromEntries(Object.entries(item.report).filter(([key]) => key !== "reportDigest"))))) {
          findings.push({ code: "PROVIDER_IDENTITY_CONFORMANCE_REPORT_INVALID", challengeId: item.id });
        }
        if (retainedEvidenceService) {
          const evidence = retained?.find(record => record.sourceId === item.id
            && (record.payload?.providerDomain === "provider_identity_baseline" || record.status === "tombstone"));
          if (!evidence) findings.push({ code: "PROVIDER_IDENTITY_CONFORMANCE_EVIDENCE_NOT_RETAINED", challengeId: item.id });
          else if (evidence.status === "retained" && (evidence.payload?.reportDigest !== item.reportDigest
            || evidence.payload?.challengeDigest !== item.digest)) findings.push({ code: "PROVIDER_IDENTITY_CONFORMANCE_EVIDENCE_BINDING_INVALID", challengeId: item.id });
        }
      }
      return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, findings,
        retainedEvidenceChecked: Boolean(retainedEvidenceService), readOnly: true, mutationAllowed: false };
    } });
}
