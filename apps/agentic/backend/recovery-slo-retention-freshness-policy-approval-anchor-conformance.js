import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const KIND = "retention-freshness-policy-approval-anchor-conformance-challenge";
const PREFIX = "retention-freshness-policy-approval-anchor-conformance-";
const DISPOSABLE_PREFIX = "__agentic_v4_freshness_approval_anchor_conformance__";
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
  const result = {}; for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = clean(item); return result;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const same = (a, b) => canonical(a) === canonical(b);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_OWNER_REQUIRED", "Owner conformance wajib ditentukan", 400);
}
function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }

export function createRecoverySloRetentionFreshnessPolicyApprovalAnchorConformanceService({ store, provider = null, retainedEvidenceService = null,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function"
    || retainedEvidenceService && typeof retainedEvidenceService.retainRecoverySloAnchorEvidence !== "function")
    throw new TypeError("Freshness-policy approval anchor conformance membutuhkan store dan clock");
  const now = () => {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_CLOCK_INVALID", "Clock conformance tidak valid", 500);
    return new Date(ms).toISOString();
  };
  function requireProvider() {
    if (!provider || typeof provider.read !== "function" || typeof provider.compareAndSet !== "function")
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_PROVIDER_UNAVAILABLE", "Freshness-policy approval anchor provider tidak tersedia", 503);
  }
  async function save(ownerId, current, patch) {
    const unsigned = { ...clean(current), ...patch };
    delete unsigned.digest;
    const next = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, next, current ? { expectedVersion: current._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, next.id);
    if (!saved || saved.digest !== digestRecord(saved) || saved.digest !== next.digest)
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_WRITE_INVALID", "Challenge conformance gagal diverifikasi", 409);
    return saved;
  }
  async function retain(ownerId, challenge) {
    if (!retainedEvidenceService || challenge.status !== "completed") return null;
    return retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: "retention_freshness_policy_approval_anchor_conformance",
      sourceId: challenge.id, payload: { schemaVersion: 1, ownerId, challengeId: challenge.id, challengeDigest: challenge.digest,
        reportDigest: challenge.reportDigest, providerIdentityFingerprint: challenge.report?.providerIdentityFingerprint || null,
        providerContractDigest: challenge.report?.providerContractDigest || null, status: challenge.report?.status, report: challenge.report } });
  }
  async function prepare(ownerId, { reason = "Validate freshness-policy approval anchor CAS behavior before relying on external checkpoints." } = {}) {
    assertOwner(ownerId); requireProvider();
    if (!validReason(reason)) throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_REASON_INVALID", "Alasan conformance wajib 12–240 karakter", 400);
    const createdAt = now(), probeOwnerId = `${ownerId}:freshness-approval-anchor-conformance:${randomUUID()}`;
    const namespace = `${DISPOSABLE_PREFIX}${sha256(probeOwnerId).slice(0, 32)}-${randomUUID()}`;
    const unsigned = { id: `${PREFIX}${randomUUID()}`, ownerId, kind: KIND, schemaVersion: 1, status: "issued", probeOwnerId,
      probeOwnerHash: sha256(probeOwnerId), disposableNamespace: namespace, reason: reason.trim(), createdAt,
      expiresAt: new Date(Date.parse(createdAt) + 5 * 60_000).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: challenge.id, challengeDigest: challenge.digest, disposableNamespace: namespace, createdAt, expiresAt: challenge.expiresAt,
      confirmation: `RUN FRESHNESS APPROVAL ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`,
      writesToDisposableNamespace: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
  }
  async function run(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId); requireProvider();
    const challenge = typeof id === "string" && id.startsWith(PREFIX) ? await store.getEvidence(ownerId, id) : null;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== KIND || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_CHALLENGE_INVALID", "Challenge conformance tidak ditemukan atau digest tidak valid", 409);
    if (challenge.status === "completed") return { status: challenge.report.status, report: challenge.report, reportDigest: challenge.reportDigest,
      retention: await retain(ownerId, challenge), idempotent: true, writesToProductionNamespace: false, readOnly: false, mutationAllowed: false };
    if (challenge.status !== "issued" || Date.parse(now()) >= Date.parse(challenge.expiresAt))
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_CHALLENGE_EXPIRED", "Challenge conformance sudah digunakan atau kedaluwarsa", 409);
    if (confirmation !== `RUN FRESHNESS APPROVAL ANCHOR CONFORMANCE ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_CONFORMANCE_CONFIRMATION_INVALID", "Konfirmasi conformance tidak cocok", 403);
    const running = await save(ownerId, challenge, { status: "running", startedAt: now() });
    const checks = [], findings = [];
    const record = (name, passed, detail = null) => {
      checks.push({ name, passed: Boolean(passed), ...(detail ? { detail: String(detail).slice(0, 160) } : {}) });
      if (!passed) findings.push({ code: `FRESHNESS_APPROVAL_ANCHOR_${name.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_FAILED` });
    };
    const scope = running.disposableNamespace, isolatedScope = `${scope}-isolated`;
    const providerIdentityFingerprint = typeof provider.providerIdentity === "string" && provider.providerIdentity.trim()
      ? sha256(provider.providerIdentity.trim()) : null;
    const raw = provider.contractInfo && typeof provider.contractInfo === "object" ? provider.contractInfo : null;
    const contract = raw ? { contractId: String(raw.contractId || "").slice(0, 100), version: String(raw.version || "").slice(0, 40),
      schemaVersion: Number.isSafeInteger(raw.schemaVersion) ? raw.schemaVersion : null, ownerScope: String(raw.ownerScope || "").slice(0, 80),
      casSemantics: String(raw.casSemantics || "").slice(0, 100), capabilities: Array.isArray(raw.capabilities) ? raw.capabilities.slice(0, 30).map(x => String(x).slice(0, 80)) : [] } : null;
    const contractDigest = contract ? sha256(canonical(contract)) : null;
    let writesPerformed = 0;
    const candidate = (sequence, previousAnchorDigest = null) => {
      const unsigned = { ownerId: scope, sourceOwnerHash: sha256(running.probeOwnerId), domain: "retention_freshness_policy_approval",
        kind: "recovery-slo-retention-freshness-policy-approval-external-anchor", schemaVersion: 1, anchorSequence: sequence,
        revision: sequence, sourceEventDigest: sha256(`probe-event-${sequence}-${running.digest}`), policyDigest: sha256(`probe-policy-${sequence}`),
        eventApprovedAt: now(), previousAnchorDigest, historyNotProven: false, anchoredAt: now() };
      return { ...unsigned, digest: digestRecord(unsigned) };
    };
    try {
      record("provider_identity_present", Boolean(providerIdentityFingerprint));
      const requiredCapabilities = ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"];
      record("contract_metadata", Boolean(contract && contract.contractId === "agentic-v4-trust-anchor-provider" && contract.version === "1.1.0"
        && contract.schemaVersion === 1 && contract.ownerScope === "ownerId" && contract.casSemantics === "digest-compare-and-set"
        && requiredCapabilities.every(item => contract.capabilities.includes(item))));
      record("empty_namespace", await provider.read(scope) == null);
      const first = candidate(1), firstWrite = await provider.compareAndSet(scope, null, first);
      writesPerformed += firstWrite?.applied ? 1 : 0;
      record("genesis_cas", firstWrite?.applied === true);
      record("read_after_write", firstWrite?.applied === true && same(await provider.read(scope), first));
      let staleRejected = false;
      try { staleRejected = (await provider.compareAndSet(scope, null, candidate(2)))?.applied === false; } catch { staleRejected = true; }
      record("stale_cas_rejection", staleRejected);
      record("stale_cas_no_mutation", same(await provider.read(scope), first));
      const second = candidate(2, first.digest), secondWrite = await provider.compareAndSet(scope, first.digest, second);
      writesPerformed += secondWrite?.applied ? 1 : 0;
      record("monotonic_sequence_and_linkage", secondWrite?.applied === true && same(await provider.read(scope), second));
      record("namespace_isolation", await provider.read(isolatedScope) == null);
      const a = candidate(3, second.digest), b = candidate(3, second.digest);
      const outcomes = await Promise.allSettled([provider.compareAndSet(scope, second.digest, a), provider.compareAndSet(scope, second.digest, b)]);
      const winners = outcomes.filter(item => item.status === "fulfilled" && item.value?.applied).length;
      writesPerformed += winners;
      const after = await provider.read(scope);
      record("concurrent_cas_single_winner", winners === 1 && [a.digest, b.digest].includes(after?.digest));
      record("anchor_digest_integrity", Boolean(after && after.digest === digestRecord(after) && after.ownerId === scope));
    } catch (error) { findings.push({ code: error?.code || "PROVIDER_PROBE_EXCEPTION", detail: String(error?.message || "Provider probe failed").slice(0, 160) }); }
    const unsignedReport = { schemaVersion: 1, challengeId: running.id, ownerId, providerDomain: "retention_freshness_policy_approval",
      providerIdentityFingerprint, providerContract: contract, providerContractDigest: contractDigest, checkedAt: now(),
      status: findings.length ? "nonconformant" : "conformant", conformant: findings.length === 0, checks, findings, writesPerformed,
      disposableNamespace: scope, writesToProductionNamespace: false, claims: { casBehaviorTested: true, disposableNamespaceUsed: true, infrastructureIndependenceProven: false } };
    const reportDigest = sha256(canonical(unsignedReport)), report = { ...unsignedReport, reportDigest };
    const completed = await save(ownerId, running, { status: "completed", completedAt: now(), report, reportDigest });
    return { status: report.status, report, reportDigest, retention: await retain(ownerId, completed), writesToProductionNamespace: false,
      readOnly: false, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const all = await store.listEvidence(ownerId), challenges = all.filter(item => item?.kind === KIND && item.ownerId === ownerId && item.status === "completed");
    const retained = all.filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record" && item.artifactType === "retention_freshness_policy_approval_anchor_conformance");
    const findings = [];
    for (const challenge of challenges) {
      const unsigned = challenge.report && Object.fromEntries(Object.entries(challenge.report).filter(([key]) => key !== "reportDigest"));
      if (challenge.digest !== digestRecord(challenge) || !challenge.report || challenge.reportDigest !== challenge.report.reportDigest
        || challenge.reportDigest !== sha256(canonical(unsigned)) || challenge.report.ownerId !== ownerId
        || challenge.report.providerDomain !== "retention_freshness_policy_approval")
        findings.push({ code: "FRESHNESS_APPROVAL_ANCHOR_CONFORMANCE_REPORT_INVALID", challengeId: challenge.id });
      if (retainedEvidenceService) {
        const evidence = retained.find(item => item.sourceId === challenge.id);
        const expectedPayload = { schemaVersion: 1, ownerId, challengeId: challenge.id, challengeDigest: challenge.digest,
          reportDigest: challenge.reportDigest, providerIdentityFingerprint: challenge.report?.providerIdentityFingerprint || null,
          providerContractDigest: challenge.report?.providerContractDigest || null, status: challenge.report?.status, report: challenge.report };
        const expectedPayloadDigest = sha256(canonical(expectedPayload));
        const retainedValid = evidence?.status === "retained" && evidence.digest === digestRecord(evidence)
          && evidence.payloadDigest === expectedPayloadDigest && canonical(evidence.payload) === canonical(expectedPayload);
        const tombstoneValid = evidence?.status === "tombstone" && evidence.digest === digestRecord(evidence) && evidence.payload == null
          && evidence.payloadDigest === expectedPayloadDigest && evidence.tombstone?.payloadDigest === expectedPayloadDigest
          && evidence.tombstone?.reason === "RETENTION_PERIOD_ELAPSED";
        if (!evidence) findings.push({ code: "FRESHNESS_APPROVAL_ANCHOR_CONFORMANCE_EVIDENCE_MISSING", challengeId: challenge.id });
        else if (!retainedValid && !tombstoneValid) findings.push({ code: "FRESHNESS_APPROVAL_ANCHOR_CONFORMANCE_EVIDENCE_BINDING_INVALID", challengeId: challenge.id });
      }
    }
    return { status: findings.length ? "unhealthy" : challenges.length ? "healthy" : "not_initialized", ownerId, total: challenges.length, findings,
      providerConfigured: Boolean(provider), readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ prepareRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance: prepare,
    runRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance: run,
    auditRecoverySloRetentionFreshnessPolicyApprovalAnchorConformance: audit });
}
