import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const ATTESTATION_DOMAIN = "agentic-v4-cross-domain-snapshot-audit-attestation";
const ATTESTATION_KIND = "recovery-slo-cross-domain-snapshot-audit-attestation";
const BASELINE_KIND = "recovery-slo-cross-domain-provider-identity-baseline";
const BASELINE_CHALLENGE_KIND = "recovery-slo-cross-domain-provider-identity-baseline-challenge";
const BASELINE_RECEIPT_KIND = "recovery-slo-cross-domain-provider-baseline-transition-receipt";
const REVIEW_CHALLENGE_KIND = "recovery-slo-cross-domain-retention-review-challenge";
const REVIEW_KIND = "recovery-slo-cross-domain-retention-review-approval";
const TTL_MS = 10 * 60 * 1000;
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
const baselineId = (ownerId, domain) => `${BASELINE_KIND}-${ownerHash(ownerId)}-${domain}`;
const validReason = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("CROSS_DOMAIN_AUDIT_OWNER_REQUIRED", "Owner audit lintas-domain wajib ditentukan", 400);
}
function keyMap(input) {
  const entries = input instanceof Map ? [...input] : input && typeof input === "object" ? Object.entries(input) : [];
  const out = new Map();
  for (const [id, value] of entries) {
    if (!KEY_ID.test(String(id))) throw new TypeError("Cross-domain audit signing key ID tidak valid");
    const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
    if (key?.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError("Cross-domain audit public key harus Ed25519");
    out.set(String(id), key);
  }
  return out;
}
function stableAudit(value) {
  if (Array.isArray(value)) return value.map(stableAudit);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (["checkedAt", "createdAt", "updatedAt", "ageMs", "ageDays"].includes(key)) continue;
    out[key] = stableAudit(item);
  }
  return out;
}

export function createRecoverySloCrossDomainSnapshotAuditGovernanceService({ store, governanceService, signer = null, keyId = null,
  publicKeys = null, required = false, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || !governanceService
    || typeof governanceService.auditRecoverySloCrossDomainSnapshotAnchorGovernance !== "function"
    || typeof governanceService.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention !== "function"
    || typeof governanceService.getRecoverySloCrossDomainSnapshotAnchorProviderSnapshot !== "function" || typeof clock !== "function") {
    throw new TypeError("Cross-domain audit governance membutuhkan store, governance service, dan clock");
  }
  const keys = keyMap(publicKeys);
  if (keyId != null && !KEY_ID.test(keyId)) throw new TypeError("Cross-domain audit signing key ID tidak valid");
  if (required && (!signer || !keyId || !keys.has(keyId))) throw new TypeError("Cross-domain audit attestation wajib memiliki signer dan trusted public key Ed25519");
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("CROSS_DOMAIN_AUDIT_CLOCK_INVALID", "Clock audit lintas-domain tidak valid", 500);
    return new Date(value).toISOString();
  }
  async function save(ownerId, unsigned, { expectedVersion, overwrite = false } = {}) {
    const base = { ...clean(unsigned), ownerId };
    delete base.digest;
    const record = { ...base, digest: digestRecord(base) };
    await store.putEvidence(ownerId, record, expectedVersion != null ? { expectedVersion } : { overwrite });
    const saved = await store.getEvidence(ownerId, record.id);
    if (!saved || saved.digest !== digestRecord(saved)) throw new AgenticError("CROSS_DOMAIN_AUDIT_RECORD_WRITE_FAILED", "Record audit lintas-domain gagal diverifikasi setelah penyimpanan", 409);
    return saved;
  }
  async function latestConformance(ownerId, domain) {
    const rows = await store.listEvidence(ownerId);
    const reportKind = "recovery-slo-cross-domain-snapshot-anchor-conformance-report";
    const challengeKind = "recovery-slo-cross-domain-snapshot-anchor-conformance-challenge";
    const reports = rows.filter(row => row?.ownerId === ownerId && row.kind === reportKind && row.domain === domain)
      .map(report => ({ report, challenge: rows.find(row => row?.ownerId === ownerId && row.kind === challengeKind && row.id === report.sourceId) }))
      .sort((a, b) => (Number(b.report.report?.conformanceSequence || 0) - Number(a.report.report?.conformanceSequence || 0))
        || (Number(b.challenge?._storage?.version || b.report._storage?.version || 0) - Number(a.challenge?._storage?.version || a.report._storage?.version || 0))
        || String(b.challenge?.completedAt || b.report.createdAt).localeCompare(String(a.challenge?.completedAt || a.report.createdAt))
        || String(b.report.id).localeCompare(String(a.report.id)));
    if (!reports.length) return { status: "not_initialized", report: null, findings: [{ code: "CROSS_DOMAIN_PROVIDER_CONFORMANCE_REPORT_MISSING" }] };
    const reportRecord = reports[0].report, challenge = reports[0].challenge;
    const valid = reportRecord.digest === digestRecord(reportRecord) && challenge && challenge.digest === digestRecord(challenge)
      && challenge.status === "completed" && challenge.reportDigest === reportRecord.reportDigest
      && challenge.report?.reportDigest === reportRecord.reportDigest && reportRecord.sourceDigest === challenge.digest
      && reportRecord.report?.ownerId === ownerId && reportRecord.report?.domain === domain
      && reportRecord.reportDigest === sha256(canonical(Object.fromEntries(Object.entries(reportRecord.report).filter(([key]) => key !== "reportDigest"))));
    if (!valid) return { status: "unhealthy", report: reportRecord, challenge, findings: [{ code: "CROSS_DOMAIN_PROVIDER_CONFORMANCE_REPORT_INVALID" }] };
    return { status: reportRecord.report.status === "conformant" ? "conformant" : "nonconformant", report: reportRecord, challenge, findings: [] };
  }
  async function auditProviderBaselineTransitionReceipts(ownerId, { allowPendingChallengeId = null } = {}) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const receipts = rows.filter(row => row?.ownerId === ownerId && row.kind === BASELINE_RECEIPT_KIND);
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === BASELINE_CHALLENGE_KIND);
    const findings = [], byDomain = new Map(), receiptById = new Map();
    for (const receipt of receipts) {
      if (receipt.digest !== digestRecord(receipt) || receipt.schemaVersion !== 1 || !governanceService.domains.includes(receipt.domain)
        || !Number.isSafeInteger(receipt.revision) || receipt.revision < 1 || receipt.sequence !== receipt.revision
        || !DIGEST.test(receipt.preparedChallengeDigest || "") || !DIGEST.test(receipt.baselineDigest || "")
        || (receipt.previousBaselineDigest !== null && !DIGEST.test(receipt.previousBaselineDigest || ""))
        || !DIGEST.test(receipt.providerIdentityFingerprint || "") || !DIGEST.test(receipt.providerContractDigest || "")
        || !DIGEST.test(receipt.sourceReportDigest || "") || (receipt.previousReceiptDigest !== null && !DIGEST.test(receipt.previousReceiptDigest || ""))
        || typeof receipt.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(receipt.issuedAt))) {
        findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_INVALID", receiptId: receipt.id });
        continue;
      }
      if (receiptById.has(receipt.id)) findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_DUPLICATE", receiptId: receipt.id });
      receiptById.set(receipt.id, receipt);
      const challenge = challenges.find(item => item.id === receipt.transitionChallengeId);
      const completedBinding = Boolean(challenge && challenge.status === "completed" && challenge.digest === digestRecord(challenge)
        && challenge.preparedChallengeDigest === receipt.preparedChallengeDigest
        && challenge.transitionReceiptId === receipt.id && challenge.transitionReceiptDigest === receipt.digest
        && challenge.resultRevision === receipt.revision && challenge.resultBaselineDigest === receipt.baselineDigest);
      const resumableBinding = Boolean(challenge && challenge.id === allowPendingChallengeId && challenge.status === "prepared"
        && challenge.digest === receipt.preparedChallengeDigest && challenge.expectedRevision === receipt.revision - 1
        && challenge.expectedBaselineDigest === receipt.previousBaselineDigest
        && challenge.expectedProviderIdentityFingerprint === receipt.providerIdentityFingerprint
        && challenge.expectedProviderContractDigest === receipt.providerContractDigest);
      if (!challenge || (!completedBinding && !resumableBinding)
        || challenge.expectedBaselineDigest !== receipt.previousBaselineDigest
        || challenge.expectedProviderIdentityFingerprint !== receipt.providerIdentityFingerprint
        || challenge.expectedProviderContractDigest !== receipt.providerContractDigest
        || challenge.sourceReportDigest !== receipt.sourceReportDigest) {
        findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_BINDING_INVALID", receiptId: receipt.id });
      }
      if (resumableBinding) {
        const currentBaseline = await store.getEvidence(ownerId, baselineId(ownerId, receipt.domain));
        if (!currentBaseline || currentBaseline.digest !== digestRecord(currentBaseline) || currentBaseline.digest !== receipt.baselineDigest
          || currentBaseline.sourceChallengeId !== challenge.id)
          findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_RESUME_BASELINE_INVALID", receiptId: receipt.id });
      }
      const list = byDomain.get(receipt.domain) || [];
      list.push(receipt); byDomain.set(receipt.domain, list);
    }
    for (const challenge of challenges) {
      if (challenge.id === allowPendingChallengeId && challenge.status === "prepared" && !challenge.transitionReceiptId && !challenge.transitionReceiptDigest) continue;
      if (challenge.transitionReceiptId || challenge.transitionReceiptDigest) {
        const receipt = receiptById.get(challenge.transitionReceiptId);
        if (!receipt || receipt.digest !== challenge.transitionReceiptDigest)
          findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_MISSING", challengeId: challenge.id });
      }
    }
    const receiptHeads = {};
    for (const [domain, list] of byDomain) {
      list.sort((a, b) => a.revision - b.revision || String(a.id).localeCompare(String(b.id)));
      let previous = null;
      for (let index = 0; index < list.length; index++) {
        const receipt = list[index];
        if (index && receipt.revision !== list[index - 1].revision + 1)
          findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_SEQUENCE_GAP", domain, receiptId: receipt.id });
        if (receipt.previousReceiptDigest !== (previous?.digest || null))
          findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_CHAIN_INVALID", domain, receiptId: receipt.id });
        if (!index && receipt.revision > 1 && !receipt.historyNotProven)
          findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_LEGACY_HISTORY_UNMARKED", domain, receiptId: receipt.id });
        previous = receipt;
      }
      if (previous) receiptHeads[domain] = { revision: previous.revision, digest: previous.digest, historyNotProven: previous.historyNotProven };
    }
    const orphaned = receipts.filter(receipt => !challenges.some(challenge => challenge.id === receipt.transitionChallengeId));
    for (const receipt of orphaned) findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_ORPHANED", receiptId: receipt.id });
    return { status: findings.length ? "unhealthy" : receipts.length ? "healthy" : "not_initialized", ownerId,
      receiptCount: receipts.length, receiptHeads, findings, readOnly: true, mutationAllowed: false };
  }

  async function ensureProviderBaselineTransitionReceipt(ownerId, challenge, baseline, preparedChallengeDigest) {
    const id = `${BASELINE_RECEIPT_KIND}-${ownerHash(ownerId).slice(0, 16)}-${sha256(challenge.domain).slice(0, 12)}-${baseline.revision}`;
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      const audit = await auditProviderBaselineTransitionReceipts(ownerId, { allowPendingChallengeId: challenge.id });
      if (audit.status === "unhealthy" || existing.digest !== digestRecord(existing)
        || existing.transitionChallengeId !== challenge.id || existing.preparedChallengeDigest !== preparedChallengeDigest
        || existing.baselineDigest !== baseline.digest)
        throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_CONFLICT", "Receipt transisi baseline yang sudah ada tidak cocok", 409);
      return existing;
    }
    const rows = await store.listEvidence(ownerId);
    const priorReceipts = rows.filter(row => row?.ownerId === ownerId && row.kind === BASELINE_RECEIPT_KIND && row.domain === challenge.domain)
      .sort((a, b) => a.revision - b.revision);
    const chainAudit = await auditProviderBaselineTransitionReceipts(ownerId);
    if (chainAudit.status === "unhealthy") throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_CHAIN_UNHEALTHY",
      "Histori receipt transisi baseline tidak sehat", 409, { findings: chainAudit.findings });
    const last = priorReceipts.at(-1) || null;
    if (last && last.revision >= baseline.revision) throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_SEQUENCE_CONFLICT",
      "Receipt baseline yang lebih baru sudah ada", 409);
    if (last && last.revision !== baseline.revision - 1) throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_CONTINUITY_UNPROVEN",
      "Histori receipt tidak berurutan; receipt baru tidak boleh memulai ulang rantai secara diam-diam", 409);
    const contiguous = Boolean(last && last.revision === baseline.revision - 1);
    const unsigned = { id, ownerId, kind: BASELINE_RECEIPT_KIND, schemaVersion: 1, domain: challenge.domain,
      sequence: baseline.revision, revision: baseline.revision, transitionChallengeId: challenge.id,
      preparedChallengeDigest, previousBaselineDigest: baseline.previousBaselineDigest, baselineDigest: baseline.digest,
      providerIdentityFingerprint: baseline.providerIdentityFingerprint, providerContractDigest: baseline.providerContractDigest,
      sourceReportDigest: baseline.sourceReportDigest, previousReceiptDigest: contiguous ? last.digest : null,
      historyNotProven: Boolean(baseline.historyNotProven || !contiguous), issuedAt: now() };
    const receipt = { ...unsigned, digest: digestRecord(unsigned) };
    try { await store.putEvidence(ownerId, receipt, { overwrite: false }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, id);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.baselineDigest !== baseline.digest
        || concurrent.preparedChallengeDigest !== preparedChallengeDigest)
        throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_WRITE_FAILED", "Receipt transisi baseline tidak dapat disimpan dengan aman", 409);
      return concurrent;
    }
    const saved = await store.getEvidence(ownerId, id);
    if (!saved || saved.digest !== digestRecord(saved)) throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_WRITE_FAILED",
      "Receipt transisi baseline gagal diverifikasi setelah penyimpanan", 409);
    return saved;
  }

  async function createAuditAttestation(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!signer || !keyId || !keys.has(keyId)) throw new AgenticError("CROSS_DOMAIN_AUDIT_SIGNER_REQUIRED", "Signer audit Ed25519 dan trusted public key belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("CROSS_DOMAIN_AUDIT_REASON_INVALID", "Alasan attestation wajib 12–240 karakter", 400);
    const audit = await governanceService.auditRecoverySloCrossDomainSnapshotAnchorGovernance(ownerId);
    const auditDigest = sha256(canonical(audit));
    const auditFingerprint = sha256(canonical(stableAudit(audit)));
    const unsigned = { domain: ATTESTATION_DOMAIN, schemaVersion: 1, attestationId: `cross-domain-snapshot-audit-${ownerHash(ownerId)}-${randomUUID()}`,
      ownerId, issuedAt: now(), reason: reason.trim(), auditStatus: audit.status, auditDigest, auditFingerprint,
      audit, signing: { algorithm: "Ed25519", keyId }, historyNotProven: true };
    const payload = { ...unsigned, attestationDigest: sha256(canonical(unsigned)) };
    let signed;
    try { signed = await signer(structuredClone(payload)); }
    catch { throw new AgenticError("CROSS_DOMAIN_AUDIT_SIGNER_FAILED", "External signer audit lintas-domain gagal", 502); }
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== keyId)
      throw new AgenticError("CROSS_DOMAIN_AUDIT_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID yang berbeda", 502);
    const signature = typeof signed === "string" ? signed : signed?.signature;
    const attestation = { ...payload, signature };
    const envelope = validateAttestation(ownerId, attestation);
    if (!envelope.valid) throw new AgenticError("CROSS_DOMAIN_AUDIT_SIGNATURE_INVALID", "Signature attestation audit tidak valid", 502, { findings: envelope.findings });
    const recordUnsigned = { id: attestation.attestationId, ownerId, kind: ATTESTATION_KIND, schemaVersion: 1, attestation, createdAt: now() };
    const record = await save(ownerId, recordUnsigned, { overwrite: false });
    return { status: "signed", attestation, retainedRecordId: record.id, auditStatus: audit.status, historyNotProven: true,
      readOnly: false, mutationAllowed: false };
  }
  function validateAttestation(ownerId, value) {
    const findings = [];
    if (!value || value.domain !== ATTESTATION_DOMAIN || value.schemaVersion !== 1 || value.ownerId !== ownerId
      || typeof value.attestationId !== "string" || !Number.isFinite(Date.parse(value.issuedAt)) || !validReason(value.reason)
      || !DIGEST.test(value.auditDigest || "") || !DIGEST.test(value.auditFingerprint || "") || !value.audit || value.audit.ownerId !== ownerId
      || value.auditStatus !== value.audit.status || !KEY_ID.test(value.signing?.keyId || "") || value.signing?.algorithm !== "Ed25519"
      || !DIGEST.test(value.attestationDigest || "") || !SIGNATURE.test(value.signature || "")) {
      return { valid: false, signatureValid: false, findings: [{ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_SCHEMA_INVALID" }] };
    }
    const unsigned = clean(value); delete unsigned.attestationDigest; delete unsigned.signature;
    const digestValid = value.attestationDigest === sha256(canonical(unsigned));
    if (!digestValid) findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_DIGEST_INVALID" });
    const key = keys.get(value.signing.keyId); let signatureValid = false;
    if (!key) findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_KEY_UNKNOWN" });
    else {
      try { signatureValid = verifySignature(null, Buffer.from(canonical({ ...unsigned, attestationDigest: value.attestationDigest }), "utf8"), key, Buffer.from(value.signature, "base64url")); }
      catch { signatureValid = false; }
      if (!signatureValid) findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_SIGNATURE_INVALID" });
    }
    if (sha256(canonical(value.audit)) !== value.auditDigest || sha256(canonical(stableAudit(value.audit))) !== value.auditFingerprint)
      findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_SNAPSHOT_INVALID" });
    return { valid: digestValid && signatureValid && findings.length === 0, signatureValid, findings };
  }
  async function verifyAuditAttestation(ownerId, valueOrId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const record = typeof valueOrId === "string" ? rows.find(row => row?.id === valueOrId && row.kind === ATTESTATION_KIND && row.ownerId === ownerId)
      : rows.find(row => row?.kind === ATTESTATION_KIND && row.ownerId === ownerId && row.attestation?.attestationId === valueOrId?.attestationId);
    const value = typeof valueOrId === "string" ? record?.attestation : valueOrId;
    const envelope = validateAttestation(ownerId, value);
    const retained = Boolean(record && record.digest === digestRecord(record) && record.attestation?.attestationDigest === value?.attestationDigest
      && record.id === value?.attestationId);
    if (!retained) envelope.findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_NOT_RETAINED" });
    let current = false;
    if (envelope.valid && retained) {
      const audit = await governanceService.auditRecoverySloCrossDomainSnapshotAnchorGovernance(ownerId);
      current = sha256(canonical(stableAudit(audit))) === value.auditFingerprint;
    }
    return { valid: envelope.valid && retained, signatureValid: envelope.signatureValid, historicallyValid: envelope.valid && retained,
      current, retained, auditStatusAtSigning: value?.auditStatus || null, findings: envelope.findings, readOnly: true, mutationAllowed: false };
  }
  async function auditAuditAttestations(ownerId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId), records = rows.filter(row => row?.ownerId === ownerId && row.kind === ATTESTATION_KIND), findings = [];
    for (const record of records) {
      if (record.digest !== digestRecord(record) || record.attestation?.attestationId !== record.id) findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_RECORD_INVALID", recordId: record.id });
      else {
        const result = validateAttestation(ownerId, record.attestation);
        if (!result.valid) findings.push({ code: "CROSS_DOMAIN_AUDIT_ATTESTATION_INVALID", recordId: record.id, details: result.findings });
      }
    }
    return { status: findings.length ? "unhealthy" : records.length ? "healthy" : "not_initialized", ownerId, recordCount: records.length, findings,
      readOnly: true, mutationAllowed: false };
  }

  async function prepareProviderBaseline(ownerId, { domain, reason } = {}) {
    assertOwner(ownerId);
    if (typeof domain !== "string" || !governanceService.domains.includes(domain)) throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_DOMAIN_UNKNOWN", "Domain provider tidak dikenal", 404);
    if (!validReason(reason)) throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_REASON_INVALID", "Alasan baseline wajib 12–240 karakter", 400);
    const [snapshot, conformance] = await Promise.all([Promise.resolve(governanceService.getRecoverySloCrossDomainSnapshotAnchorProviderSnapshot(domain)), latestConformance(ownerId, domain)]);
    if (!snapshot.providerConfigured || !snapshot.providerIdentityFingerprint || !snapshot.providerContractDigest)
      throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_PROVIDER_UNVERIFIABLE", "Identitas atau kontrak provider tidak dapat diverifikasi", 409);
    if (conformance.status !== "conformant" || conformance.report.report.providerIdentityFingerprint !== snapshot.providerIdentityFingerprint
      || conformance.report.report.providerContractDigest !== snapshot.providerContractDigest)
      throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_CONFORMANCE_REQUIRED", "Laporan conformance terbaru harus conformant dan cocok dengan provider terkini", 409);
    const id = baselineId(ownerId, domain), existing = await store.getEvidence(ownerId, id);
    if (existing && existing.digest !== digestRecord(existing)) throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_STATE_UNHEALTHY", "Baseline provider tersimpan tidak sehat", 409);
    if (existing && existing.providerIdentityFingerprint === snapshot.providerIdentityFingerprint && existing.providerContractDigest === snapshot.providerContractDigest)
      throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_NO_CHANGE", "Identitas dan kontrak provider sama dengan baseline aktif", 409);
    const createdAt = now(), expiresAt = new Date(Date.parse(createdAt) + TTL_MS).toISOString(), challengeId = `cross-domain-provider-baseline-challenge-${randomUUID()}`;
    const unsigned = { id: challengeId, ownerId, kind: BASELINE_CHALLENGE_KIND, schemaVersion: 1, status: "prepared", domain, reason: reason.trim(),
      expectedRevision: existing?.revision || 0, expectedBaselineDigest: existing?.digest || null, expectedProviderIdentityFingerprint: snapshot.providerIdentityFingerprint,
      expectedProviderContractDigest: snapshot.providerContractDigest, sourceReportId: conformance.report.id, sourceReportDigest: conformance.report.reportDigest,
      createdAt, expiresAt: new Date(Date.parse(createdAt) + TTL_MS).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId, domain, expectedRevision: challenge.expectedRevision, providerIdentityFingerprint: snapshot.providerIdentityFingerprint,
      providerContractDigest: snapshot.providerContractDigest, sourceReportDigest: challenge.sourceReportDigest, challengeDigest: challenge.digest,
      createdAt, expiresAt, confirmation: `ACCEPT PROVIDER BASELINE ${challenge.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function applyProviderBaseline(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== BASELINE_CHALLENGE_KIND || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_CHALLENGE_INVALID", "Challenge baseline provider tidak valid", 409);
    const current = await store.getEvidence(ownerId, baselineId(ownerId, challenge.domain));
    if (challenge.status === "completed" && current?.sourceChallengeId === challenge.id) {
      if (!challenge.transitionReceiptId && !challenge.transitionReceiptDigest)
        return { status: "accepted", baseline: current, transitionReceipt: null, historyNotProven: true, legacyTransitionReceiptMissing: true, idempotent: true };
      const receipt = await store.getEvidence(ownerId, challenge.transitionReceiptId);
      if (!receipt || receipt.digest !== digestRecord(receipt) || receipt.digest !== challenge.transitionReceiptDigest)
        throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECEIPT_MISSING", "Receipt transisi baseline yang selesai tidak tersedia atau tidak valid", 409);
      return { status: "accepted", baseline: current, transitionReceipt: receipt, idempotent: true };
    }
    if (challenge.status === "prepared" && current?.sourceChallengeId === challenge.id && current.revision === challenge.expectedRevision + 1
      && current.digest === digestRecord(current)) {
      const preparedDigest = challenge.digest;
      const receipt = await ensureProviderBaselineTransitionReceipt(ownerId, challenge, current, preparedDigest);
      const completedUnsigned = { ...clean(challenge), status: "completed", preparedChallengeDigest: preparedDigest,
        completedAt: challenge.completedAt || now(), resultRevision: current.revision, resultBaselineDigest: current.digest,
        transitionReceiptId: receipt.id, transitionReceiptDigest: receipt.digest };
      delete completedUnsigned.digest;
      const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
      try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, id);
        if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.status !== "completed"
          || concurrent.transitionReceiptDigest !== receipt.digest)
          throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_RECOVERY_CONFLICT", "Transisi baseline terputus dan tidak dapat dilanjutkan dengan aman", 409);
      }
      return { status: "accepted", baseline: current, transitionReceipt: receipt, idempotent: true, recovered: true };
    }
    if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `ACCEPT PROVIDER BASELINE ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_CONFIRMATION_INVALID", "Challenge baseline kedaluwarsa, sudah digunakan, atau konfirmasinya tidak cocok", 409);
    if ((current?.revision || 0) !== challenge.expectedRevision || (current?.digest || null) !== challenge.expectedBaselineDigest
      || current && current.digest !== digestRecord(current)) throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_STALE", "Baseline provider berubah sejak challenge dibuat", 409);
    const snapshot = governanceService.getRecoverySloCrossDomainSnapshotAnchorProviderSnapshot(challenge.domain);
    const conformance = await latestConformance(ownerId, challenge.domain);
    if (snapshot.providerIdentityFingerprint !== challenge.expectedProviderIdentityFingerprint || snapshot.providerContractDigest !== challenge.expectedProviderContractDigest
      || conformance.status !== "conformant" || conformance.report.id !== challenge.sourceReportId || conformance.report.reportDigest !== challenge.sourceReportDigest
      || conformance.report.report.providerIdentityFingerprint !== snapshot.providerIdentityFingerprint || conformance.report.report.providerContractDigest !== snapshot.providerContractDigest)
      throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_PROVIDER_DRIFT", "Provider atau laporan conformance berubah sejak challenge dibuat", 409);
    const unsigned = { id: baselineId(ownerId, challenge.domain), ownerId, kind: BASELINE_KIND, schemaVersion: 1, domain: challenge.domain,
      revision: challenge.expectedRevision + 1, previousBaselineDigest: current?.digest || null, providerIdentityFingerprint: snapshot.providerIdentityFingerprint,
      providerContractDigest: snapshot.providerContractDigest, contractVersion: snapshot.contractVersion, sourceReportId: conformance.report.id,
      sourceReportDigest: conformance.report.reportDigest, sourceChallengeId: challenge.id, reason: challenge.reason, acceptedAt: now(),
      historyNotProven: !current || Boolean(current.historyNotProven) };
    const saved = await save(ownerId, unsigned, current ? { expectedVersion: current._storage?.version } : { overwrite: false });
    const preparedChallengeDigest = challenge.digest;
    const receipt = await ensureProviderBaselineTransitionReceipt(ownerId, challenge, saved, preparedChallengeDigest);
    const completedUnsigned = { ...clean(challenge), status: "completed", preparedChallengeDigest, completedAt: now(),
      resultRevision: saved.revision, resultBaselineDigest: saved.digest, transitionReceiptId: receipt.id, transitionReceiptDigest: receipt.digest };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, id);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.status !== "completed"
        || concurrent.transitionReceiptDigest !== receipt.digest || concurrent.resultBaselineDigest !== saved.digest)
        throw new AgenticError("CROSS_DOMAIN_PROVIDER_BASELINE_TRANSITION_FINALIZE_CONFLICT", "Baseline tersimpan tetapi receipt transisi belum dapat difinalisasi", 409);
    }
    return { status: "accepted", baseline: saved, transitionReceipt: receipt, idempotent: false, readOnly: false, mutationAllowed: false };
  }
  async function auditProviderBaselines(ownerId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId), baselines = rows.filter(row => row?.ownerId === ownerId && row.kind === BASELINE_KIND), results = [], findings = [];
    const receiptAudit = await auditProviderBaselineTransitionReceipts(ownerId);
    if (receiptAudit.status === "unhealthy") findings.push(...receiptAudit.findings);
    for (const baseline of baselines) {
      if (baseline.digest !== digestRecord(baseline) || !Number.isSafeInteger(baseline.revision) || baseline.revision < 1
        || !DIGEST.test(baseline.providerIdentityFingerprint || "") || !DIGEST.test(baseline.providerContractDigest || "")
        || baseline.revision === 1 && baseline.previousBaselineDigest !== null || baseline.revision > 1 && !DIGEST.test(baseline.previousBaselineDigest || "")) {
        findings.push({ code: "CROSS_DOMAIN_PROVIDER_BASELINE_INVALID", domain: baseline.domain }); results.push({ domain: baseline.domain, status: "unhealthy" }); continue;
      }
      const snapshot = governanceService.getRecoverySloCrossDomainSnapshotAnchorProviderSnapshot(baseline.domain), conformance = await latestConformance(ownerId, baseline.domain);
      const matchesBaseline = snapshot.providerIdentityFingerprint === baseline.providerIdentityFingerprint && snapshot.providerContractDigest === baseline.providerContractDigest;
      const matchesConformance = conformance.status === "conformant" && conformance.report.report.providerIdentityFingerprint === snapshot.providerIdentityFingerprint
        && conformance.report.report.providerContractDigest === snapshot.providerContractDigest;
      const status = conformance.status !== "conformant" ? "unhealthy" : (!matchesBaseline || !matchesConformance) ? "drift_detected" : "healthy";
      if (status !== "healthy") findings.push({ code: status === "drift_detected" ? "CROSS_DOMAIN_PROVIDER_IDENTITY_DRIFT" : "CROSS_DOMAIN_PROVIDER_CONFORMANCE_NOT_CURRENT", domain: baseline.domain,
        baselineIdentityFingerprint: baseline.providerIdentityFingerprint, currentIdentityFingerprint: snapshot.providerIdentityFingerprint });
      results.push({ domain: baseline.domain, status, revision: baseline.revision, baselineDigest: baseline.digest,
        baselineIdentityFingerprint: baseline.providerIdentityFingerprint, currentIdentityFingerprint: snapshot.providerIdentityFingerprint,
        baselineContractDigest: baseline.providerContractDigest, currentContractDigest: snapshot.providerContractDigest,
        sourceReportDigest: baseline.sourceReportDigest, historyNotProven: baseline.historyNotProven });
    }
    const status = findings.some(item => item.code === "CROSS_DOMAIN_PROVIDER_BASELINE_INVALID" || item.code === "CROSS_DOMAIN_PROVIDER_CONFORMANCE_NOT_CURRENT") ? "unhealthy"
      : findings.length ? "drift_detected" : baselines.length ? "healthy" : "not_initialized";
    return { status: receiptAudit.status === "unhealthy" ? "unhealthy" : status, ownerId, baselineCount: baselines.length,
      transitionReceiptCount: receiptAudit.receiptCount, transitionReceiptAudit: receiptAudit, baselines: results, findings, readOnly: true, mutationAllowed: false };
  }

  async function prepareRetentionReview(ownerId, { recordIds = null, decision = "retain", reason } = {}) {
    assertOwner(ownerId);
    if (!validReason(reason)) throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REASON_INVALID", "Alasan review retensi wajib 12–240 karakter", 400);
    if (!["retain", "escalate"].includes(decision)) throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_DECISION_INVALID", "Keputusan review harus retain atau escalate", 400);
    const audit = await governanceService.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_SOURCE_UNHEALTHY", "Audit retensi sumber tidak sehat; review tidak dapat disiapkan", 409);
    const overdue = audit.retention.filter(item => item.retentionClass === "retention_overdue_review" && item.digestValid && DIGEST.test(item.recordDigest || ""));
    const ids = recordIds == null ? overdue.map(item => item.recordId) : recordIds;
    if (!Array.isArray(ids) || !ids.length || ids.length > 100 || new Set(ids).size !== ids.length)
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_TARGETS_INVALID", "Review memerlukan 1–100 record ID unik", 400);
    const selected = ids.map(id => overdue.find(item => item.recordId === id));
    if (selected.some(item => !item)) throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_TARGET_NOT_OVERDUE", "Semua target harus merupakan evidence yang ditandai untuk review retensi", 409);
    const targets = selected.map(item => ({ domain: item.domain, recordId: item.recordId, recordKind: item.recordKind, recordDigest: item.recordDigest }))
      .sort((a, b) => a.recordId.localeCompare(b.recordId));
    const createdAt = now(), expiresAt = new Date(Date.parse(createdAt) + TTL_MS).toISOString(), id = `cross-domain-retention-review-challenge-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: REVIEW_CHALLENGE_KIND, schemaVersion: 1, status: "prepared", decision, reason: reason.trim(),
      sourceAuditFingerprint: sha256(canonical(stableAudit(audit))), targets, targetsDigest: sha256(canonical(targets)), createdAt, expiresAt };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, decision, targets, targetsDigest: challenge.targetsDigest, challengeDigest: challenge.digest, createdAt, expiresAt,
      confirmation: `APPROVE RETENTION REVIEW ${challenge.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function applyRetentionReview(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    let challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== REVIEW_CHALLENGE_KIND || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_CHALLENGE_INVALID", "Challenge review retensi tidak valid", 409);
    const rowsBefore = await store.listEvidence(ownerId);
    const existingForChallenge = rowsBefore.filter(row => row?.ownerId === ownerId && row.kind === REVIEW_KIND && row.challengeId === id);
    if (challenge.status === "completed") {
      if (existingForChallenge.length === 1 && existingForChallenge[0].digest === digestRecord(existingForChallenge[0])
        && challenge.approvalId === existingForChallenge[0].id && challenge.approvalDigest === existingForChallenge[0].digest) {
        const approval = existingForChallenge[0];
        const guard = rowsBefore.find(row => row?.ownerId === ownerId && row.kind === "recovery-slo-cross-domain-retention-review-replay-guard"
          && row.id === approval.replayGuardId);
        const replayProtected = Boolean(guard && guard.digest === digestRecord(guard) && guard.status === "completed"
          && guard.approvalId === approval.id && guard.approvalDigest === approval.digest && approval.decisionReplayKey === guard.replayKey);
        return { status: "approved", approval, idempotent: true, replayProtected, replayHistoryUnproven: !replayProtected };
      }
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_CONFLICT", "Challenge review telah dikonsumsi tetapi bukti keputusan tidak tunggal dan konsisten", 409);
    }
    if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `APPROVE RETENTION REVIEW ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_CONFIRMATION_INVALID", "Challenge review kedaluwarsa, sudah digunakan, atau konfirmasinya tidak cocok", 409);
    const audit = await governanceService.auditRecoverySloExternalSnapshotCheckpointFreshnessAndRetention(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_SOURCE_UNHEALTHY", "Audit retensi berubah menjadi tidak sehat", 409);
    if (sha256(canonical(stableAudit(audit))) !== challenge.sourceAuditFingerprint)
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_AUDIT_STALE", "Snapshot audit retensi berubah sejak challenge disiapkan", 409);
    const currentItems = new Map(audit.retention.map(item => [item.recordId, item]));
    for (const target of challenge.targets) {
      const currentItem = currentItems.get(target.recordId), record = await store.getEvidence(ownerId, target.recordId);
      if (!currentItem || currentItem.retentionClass !== "retention_overdue_review" || currentItem.recordDigest !== target.recordDigest
        || !record || record.digest !== target.recordDigest || record.digest !== digestRecord(record))
        throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_TARGET_STALE", "Evidence target berubah sejak challenge disiapkan", 409);
    }

    // Reserve a deterministic one-time replay key before creating the decision record. A retry can
    // resume this exact challenge, but cannot create a second approval for the same decision.
    const replayKey = sha256(canonical({ ownerId, challengeId: challenge.id, challengeDigest: challenge.digest }));
    const replayId = `cross-domain-retention-review-replay-${replayKey.slice(0, 40)}`;
    let replay = await store.getEvidence(ownerId, replayId);
    if (replay && (replay.ownerId !== ownerId || replay.kind !== "recovery-slo-cross-domain-retention-review-replay-guard"
      || replay.challengeId !== challenge.id || replay.challengeDigest !== challenge.digest || replay.replayKey !== replayKey
      || replay.digest !== digestRecord(replay) || !["reserved", "completed"].includes(replay.status)))
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_GUARD_INVALID", "Replay guard review tidak valid atau tidak cocok dengan challenge", 409);
    if (replay?.status === "completed") {
      const existing = await store.getEvidence(ownerId, replay.approvalId);
      if (!existing || existing.digest !== digestRecord(existing) || existing.digest !== replay.approvalDigest
        || existing.challengeId !== challenge.id || existing.decisionReplayKey !== replayKey)
        throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_CONFLICT", "Replay guard completed tanpa approval konsisten", 409);
      // Continue below to finish a challenge that may have been interrupted after the guard was finalized.
    }
    if (!replay) {
      const replayUnsigned = { id: replayId, ownerId, kind: "recovery-slo-cross-domain-retention-review-replay-guard", schemaVersion: 1,
        status: "reserved", challengeId: challenge.id, challengeDigest: challenge.digest, replayKey, decision: challenge.decision,
        targetsDigest: challenge.targetsDigest, reservedAt: now() };
      const candidate = { ...replayUnsigned, digest: digestRecord(replayUnsigned) };
      try {
        await store.putEvidence(ownerId, candidate, { overwrite: false });
        replay = await store.getEvidence(ownerId, replayId);
      } catch {
        replay = await store.getEvidence(ownerId, replayId);
        if (!replay || replay.digest !== digestRecord(replay) || replay.challengeDigest !== challenge.digest || replay.replayKey !== replayKey)
          throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_RESERVATION_FAILED", "Replay key review tidak dapat direservasi secara aman", 409);
      }
    }

    const approvalId = `cross-domain-retention-review-${sha256(`${ownerId}\0${challenge.id}\0${challenge.digest}`).slice(0, 40)}`;
    let approval = await store.getEvidence(ownerId, approvalId), createdApproval = false;
    if (!approval) {
      const unsigned = { id: approvalId, ownerId, kind: REVIEW_KIND, schemaVersion: 1, status: "approved", challengeId: challenge.id,
        challengeDigest: challenge.digest, decision: challenge.decision, decisionReplayKey: replayKey, replayGuardId: replayId,
        reason: challenge.reason, sourceAuditFingerprint: challenge.sourceAuditFingerprint, targets: challenge.targets,
        targetsDigest: challenge.targetsDigest, approvedAt: now(), destructiveActionPerformed: false };
      try {
        approval = await save(ownerId, unsigned, { overwrite: false });
        createdApproval = true;
      } catch {
        approval = await store.getEvidence(ownerId, approvalId);
        if (!approval || approval.digest !== digestRecord(approval) || approval.challengeDigest !== challenge.digest
          || approval.decisionReplayKey !== replayKey || approval.targetsDigest !== challenge.targetsDigest)
          throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_CONFLICT", "Approval dengan replay key yang sama sudah ada dengan payload berbeda", 409);
      }
    } else if (approval.digest !== digestRecord(approval) || approval.challengeDigest !== challenge.digest
      || approval.decisionReplayKey !== replayKey || approval.targetsDigest !== challenge.targetsDigest || approval.replayGuardId !== replayId) {
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_CONFLICT", "Approval yang ada tidak cocok dengan keputusan yang diminta", 409);
    }

    if (replay.status !== "completed") {
      const replayUnsigned = { ...clean(replay), status: "completed", approvalId: approval.id, approvalDigest: approval.digest, completedAt: now() };
      delete replayUnsigned.digest;
      const completedReplay = { ...replayUnsigned, digest: digestRecord(replayUnsigned) };
      try { await store.putEvidence(ownerId, completedReplay, { expectedVersion: replay._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, replayId);
        if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.status !== "completed"
          || concurrent.approvalId !== approval.id || concurrent.approvalDigest !== approval.digest)
          throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_FINALIZE_CONFLICT", "Replay guard berubah saat finalisasi keputusan", 409);
      }
    } else if (replay.approvalId !== approval.id || replay.approvalDigest !== approval.digest) {
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_CONFLICT", "Replay guard telah terikat ke keputusan lain", 409);
    }

    challenge = await store.getEvidence(ownerId, id);
    if (challenge?.status !== "completed") {
      const completedUnsigned = { ...clean(challenge), status: "completed", preparedChallengeDigest: challenge.digest,
        completedAt: now(), approvalId: approval.id, approvalDigest: approval.digest };
      delete completedUnsigned.digest;
      const completedChallenge = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
      try { await store.putEvidence(ownerId, completedChallenge, { expectedVersion: challenge?._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, id);
        if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.status !== "completed"
          || concurrent.approvalId !== approval.id || concurrent.approvalDigest !== approval.digest)
          throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_CHALLENGE_FINALIZE_CONFLICT", "Challenge berubah saat finalisasi keputusan", 409);
      }
    } else if (challenge.approvalId !== approval.id || challenge.approvalDigest !== approval.digest) {
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_CONFLICT", "Challenge telah diselesaikan dengan keputusan lain", 409);
    }
    return { status: "approved", approval, idempotent: !createdApproval, replayProtected: true, destructiveActionPerformed: false,
      readOnly: false, mutationAllowed: false };
  }
  async function auditRetentionReviews(ownerId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId), challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === REVIEW_CHALLENGE_KIND),
      approvals = rows.filter(row => row?.ownerId === ownerId && row.kind === REVIEW_KIND),
      replayGuards = rows.filter(row => row?.ownerId === ownerId && row.kind === "recovery-slo-cross-domain-retention-review-replay-guard"),
      findings = [], reviews = [], byChallenge = new Map();
    for (const approval of approvals) byChallenge.set(approval.challengeId, [...(byChallenge.get(approval.challengeId) || []), approval]);
    let replayPending = false, replayHistoryUnproven = false;
    for (const approval of approvals) {
      const challenge = challenges.find(item => item.id === approval.challengeId), matching = byChallenge.get(approval.challengeId) || [];
      const replay = replayGuards.find(item => item.id === approval.replayGuardId);
      if (approval.digest !== digestRecord(approval) || !challenge || challenge.digest !== digestRecord(challenge) || challenge.status !== "completed"
        || challenge.approvalId !== approval.id || challenge.approvalDigest !== approval.digest || approval.targetsDigest !== sha256(canonical(approval.targets || []))) {
        findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_APPROVAL_INVALID", approvalId: approval.id });
        reviews.push({ approvalId: approval.id, status: "unhealthy" }); continue;
      }
      if (matching.length !== 1) findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_DUPLICATE_DECISION", challengeId: approval.challengeId, approvalCount: matching.length });
      const originalChallengeDigest = challenge.preparedChallengeDigest || replay?.challengeDigest || approval.challengeDigest || challenge.digest;
      const expectedReplayKey = sha256(canonical({ ownerId, challengeId: challenge.id, challengeDigest: originalChallengeDigest }));
      if ((challenge.preparedChallengeDigest || replay) && approval.challengeDigest !== originalChallengeDigest)
        findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_CHALLENGE_BINDING_INVALID", approvalId: approval.id });
      if (!replay) {
        replayHistoryUnproven = true;
        findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_HISTORY_UNPROVEN", approvalId: approval.id });
      } else if (replay.digest !== digestRecord(replay) || replay.replayKey !== expectedReplayKey || replay.challengeDigest !== originalChallengeDigest
        || replay.challengeId !== challenge.id || replay.status !== "completed" || replay.approvalId !== approval.id || replay.approvalDigest !== approval.digest
        || approval.decisionReplayKey !== expectedReplayKey || approval.replayGuardId !== replay.id) {
        findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_GUARD_INVALID", approvalId: approval.id, replayGuardId: replay.id });
      }
      let superseded = false;
      for (const target of approval.targets) {
        const current = await store.getEvidence(ownerId, target.recordId);
        if (!current) { findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_SOURCE_MISSING", approvalId: approval.id, recordId: target.recordId }); superseded = true; }
        else if (current.digest !== digestRecord(current)) findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_SOURCE_TAMPERED", approvalId: approval.id, recordId: target.recordId });
        else if (current.digest !== target.recordDigest) superseded = true;
      }
      reviews.push({ approvalId: approval.id, status: superseded ? "superseded" : "approved", decision: approval.decision,
        targetCount: approval.targets.length, targetsDigest: approval.targetsDigest, approvedAt: approval.approvedAt,
        replayProtected: Boolean(replay && replay.status === "completed" && replay.digest === digestRecord(replay)), destructiveActionPerformed: false });
    }
    for (const challenge of challenges) {
      if (challenge.digest !== digestRecord(challenge)) findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_CHALLENGE_INVALID", challengeId: challenge.id });
      if (challenge.status === "completed" && !(byChallenge.get(challenge.id) || []).length)
        findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_COMPLETED_CHALLENGE_WITHOUT_APPROVAL", challengeId: challenge.id });
    }
    for (const replay of replayGuards) {
      if (replay.digest !== digestRecord(replay) || !["reserved", "completed"].includes(replay.status)
        || !DIGEST.test(replay.replayKey || "") || !DIGEST.test(replay.challengeDigest || "")) {
        findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_GUARD_INVALID", replayGuardId: replay.id }); continue;
      }
      if (replay.status === "reserved") replayPending = true;
      if (replay.status === "completed" && !approvals.some(approval => approval.id === replay.approvalId && approval.digest === replay.approvalDigest))
        findings.push({ code: "CROSS_DOMAIN_RETENTION_REVIEW_REPLAY_APPROVAL_MISSING", replayGuardId: replay.id });
    }
    const integrityFailure = findings.some(item => item.code.includes("INVALID") || item.code.includes("TAMPERED")
      || item.code.includes("DUPLICATE_DECISION") || item.code.includes("WITHOUT_APPROVAL") || item.code.includes("REPLAY_APPROVAL_MISSING"));
    const status = integrityFailure ? "unhealthy" : replayPending ? "recoverable"
      : findings.length || reviews.some(item => item.status === "superseded") || replayHistoryUnproven ? "degraded"
      : approvals.length ? "healthy" : challenges.length ? "not_initialized" : "not_initialized";
    return { status, ownerId, challengeCount: challenges.length, approvalCount: approvals.length, replayGuardCount: replayGuards.length,
      replayPending, replayHistoryUnproven, reviews, findings, destructiveActionPerformed: false, readOnly: true, mutationAllowed: false };
  }


  async function auditProviderBaselineReceiptCompactionGuardrails(ownerId, { externalCheckpoint = null, sourceSnapshot = null } = {}) {
    assertOwner(ownerId);
    const [receiptAudit, baselineAudit, rows] = await Promise.all([
      auditProviderBaselineTransitionReceipts(ownerId), auditProviderBaselines(ownerId), store.listEvidence(ownerId)
    ]);
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === BASELINE_CHALLENGE_KIND);
    const receipts = rows.filter(row => row?.ownerId === ownerId && row.kind === BASELINE_RECEIPT_KIND);
    const recoveryCandidates = [];
    for (const challenge of challenges.filter(item => item.status === "prepared")) {
      const current = await store.getEvidence(ownerId, baselineId(ownerId, challenge.domain));
      const receipt = receipts.find(item => item.transitionChallengeId === challenge.id);
      const challengeValid = challenge.digest === digestRecord(challenge) && Number.isSafeInteger(challenge.expectedRevision)
        && (challenge.expectedBaselineDigest === null || DIGEST.test(challenge.expectedBaselineDigest || ""));
      const baselineValid = Boolean(current && current.digest === digestRecord(current) && current.sourceChallengeId === challenge.id
        && current.revision === challenge.expectedRevision + 1 && current.previousBaselineDigest === challenge.expectedBaselineDigest);
      const receiptValid = !receipt || receipt.digest === digestRecord(receipt) && receipt.baselineDigest === current?.digest
        && receipt.transitionChallengeId === challenge.id;
      if (challengeValid && baselineValid && receiptValid) recoveryCandidates.push({ challengeId: challenge.id, domain: challenge.domain,
        baselineDigest: current.digest, receiptId: receipt?.id || null, recoveryAllowed: true });
    }
    const sourceDigest = sourceSnapshot?.snapshot && sourceSnapshot.status === "healthy"
      ? sha256(canonical(sourceSnapshot.snapshot)) : null;
    const checkpointAligned = Boolean(externalCheckpoint?.status === "anchored"
      && externalCheckpoint.policyBindingStatus === "current"
      && externalCheckpoint.sourceCount === sourceSnapshot?.count && externalCheckpoint.sourceDigest === sourceDigest);
    const pendingChallenges = challenges.filter(item => item.status === "prepared").length;
    const blockers = [];
    if (receiptAudit.status !== "healthy") blockers.push("receipt_chain_not_healthy");
    if (baselineAudit.status !== "healthy") blockers.push("provider_baseline_not_healthy");
    if (!checkpointAligned) blockers.push("external_checkpoint_not_current");
    if (pendingChallenges) blockers.push("pending_transition_requires_recovery");
    if (recoveryCandidates.length) blockers.push("receipt_recovery_available");
    if (receiptAudit.receiptCount < 2) blockers.push("minimum_receipt_history_not_met");
    const eligible = blockers.length === 0;
    return { status: eligible ? "eligible" : receiptAudit.status === "unhealthy" || baselineAudit.status === "unhealthy" ? "unhealthy" : "blocked",
      ownerId, receiptCount: receiptAudit.receiptCount, receiptHeads: receiptAudit.receiptHeads, receiptAuditStatus: receiptAudit.status,
      baselineAuditStatus: baselineAudit.status, externalCheckpointStatus: externalCheckpoint?.status || "unavailable",
      externalCheckpointAligned: checkpointAligned, pendingChallengeCount: pendingChallenges, recoveryCandidates,
      compactionEligible: eligible, compactionPerformed: false, automaticCompactionAllowed: false,
      requiredPreservations: ["per-domain receipt head digest", "receipt count and revision ranges", "previous-receipt linkage",
        "historyNotProven flags", "source challenge and conformance report digests"],
      blockers, findings: [...receiptAudit.findings, ...baselineAudit.findings], readOnly: true, mutationAllowed: false,
      destructiveActionPerformed: false };
  }


  return Object.freeze({
    createRecoverySloCrossDomainSnapshotAuditAttestation: createAuditAttestation,
    verifyRecoverySloCrossDomainSnapshotAuditAttestation: verifyAuditAttestation,
    auditRecoverySloCrossDomainSnapshotAuditAttestations: auditAuditAttestations,
    prepareRecoverySloCrossDomainProviderIdentityBaseline: prepareProviderBaseline,
    applyRecoverySloCrossDomainProviderIdentityBaseline: applyProviderBaseline,
    auditRecoverySloCrossDomainProviderIdentityBaselines: auditProviderBaselines,
    auditRecoverySloCrossDomainProviderBaselineTransitionReceipts: auditProviderBaselineTransitionReceipts,
    auditRecoverySloCrossDomainProviderBaselineReceiptCompactionGuardrails: auditProviderBaselineReceiptCompactionGuardrails,
    prepareRecoverySloCrossDomainRetentionReview: prepareRetentionReview,
    applyRecoverySloCrossDomainRetentionReview: applyRetentionReview,
    auditRecoverySloCrossDomainRetentionReviews: auditRetentionReviews,
    configured: Boolean(signer && keyId && keys.has(keyId)),
    required
  });
}
