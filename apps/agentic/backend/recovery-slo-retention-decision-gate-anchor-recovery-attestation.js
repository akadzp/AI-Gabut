import { createHash, createPublicKey, randomUUID, verify as verifySignature } from "node:crypto";
import { AgenticError } from "./errors.js";

const DOMAIN = "agentic-v4-retention-decision-gate-anchor-recovery-attestation";
const ARTIFACT = "retention_decision_gate_anchor_recovery_attestation";
const INTENT_KIND = "recovery-slo-retention-decision-gate-anchor-recovery-intent";
const DIGEST = /^[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,80}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{80,100}$/;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const clean = value => {
  if (Array.isArray(value)) return value.map(clean);
  if (!value || typeof value !== "object") return value;
  const out = {}; for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item); return out;
};
const validReason = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240
  && !/[\u0000-\u001f\u007f]/.test(value);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_OWNER_REQUIRED", "Owner recovery attestation wajib ditentukan", 400);
}
function keyMap(input) {
  const entries = input instanceof Map ? [...input] : input && typeof input === "object" ? Object.entries(input) : [];
  const map = new Map();
  for (const [id, value] of entries) {
    if (!KEY_ID.test(String(id))) throw new TypeError("Decision-gate recovery key ID tidak valid");
    const key = value?.type === "public" ? value : createPublicKey(typeof value === "string" ? value.replace(/\\n/g, "\n") : value);
    if (key.asymmetricKeyType !== "ed25519") throw new TypeError("Decision-gate recovery public key harus Ed25519");
    map.set(String(id), key);
  }
  return map;
}

export function createRecoverySloRetentionDecisionGateAnchorRecoveryAttestationService({ store, anchorService, retainedEvidenceService,
  signer = null, keyId = null, publicKeys = null, required = false, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || !retainedEvidenceService?.retainRecoverySloAnchorEvidence || !retainedEvidenceService?.listRecoverySloRetainedAnchorEvidence
    || typeof anchorService?.getRecoverySloRetentionDecisionGateAnchorStatus !== "function"
    || typeof anchorService?.reconcileRecoverySloRetentionDecisionGateAnchor !== "function" || typeof clock !== "function") {
    throw new TypeError("Decision-gate recovery attestation membutuhkan anchor, retained evidence, store, dan clock");
  }
  const keys = keyMap(publicKeys);
  if (keyId != null && !KEY_ID.test(keyId)) throw new TypeError("Decision-gate recovery key ID tidak valid");
  if (required && (!signer || !keyId || !keys.has(keyId))) throw new TypeError("Decision-gate recovery attestation wajib memiliki signer dan trusted public key");
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_CLOCK_INVALID", "Clock recovery attestation tidak valid", 500);
    return new Date(time).toISOString();
  }
  function withTransition(intent, phase, at, updates = {}) {
    const unsigned = clean(intent || {});
    delete unsigned.digest;
    Object.assign(unsigned, clean(updates));
    let history = Array.isArray(intent?.transitionHistory) ? [...intent.transitionHistory] : [];
    if (!history.length) {
      const initialCreation = !intent?._storage && phase === "prepared" && intent?.status === "prepared";
      const seedPhase = initialCreation ? "prepared" : "legacy_history_unproven";
      const seedStatus = initialCreation ? "prepared" : (intent?.status || "prepared");
      const seedAt = Number.isFinite(Date.parse(intent?.createdAt)) ? intent.createdAt : at;
      const seedUnsigned = { sequence: 1, phase: seedPhase, stateStatus: seedStatus, at: seedAt, previousTransitionDigest: null };
      history = [{ ...seedUnsigned, transitionDigest: sha256(canonical(seedUnsigned)) }];
      if (!initialCreation) unsigned.historyNotProven = true;
      else {
        unsigned.transitionHistory = history;
        return { ...unsigned, digest: digestRecord(unsigned) };
      }
    }
    const previous = history.at(-1);
    const transitionUnsigned = { sequence: history.length + 1, phase, stateStatus: unsigned.status || intent?.status || "prepared",
      at, previousTransitionDigest: previous?.transitionDigest || null };
    history.push({ ...transitionUnsigned, transitionDigest: sha256(canonical(transitionUnsigned)) });
    unsigned.transitionHistory = history;
    return { ...unsigned, digest: digestRecord(unsigned) };
  }
  function envelopeCheck(ownerId, attestation) {
    const findings = [];
    if (!attestation || attestation.domain !== DOMAIN || attestation.schemaVersion !== 1 || attestation.ownerId !== ownerId
      || !validReason(attestation.reason) || !Number.isFinite(Date.parse(attestation.issuedAt)) || !attestation.before || !attestation.recovery
      || attestation.before.status !== "behind_local" || attestation.recovery.status !== "anchored"
      || !Number.isSafeInteger(attestation.recovery.anchorSequence) || attestation.recovery.anchorSequence < 1
      || !DIGEST.test(attestation.recovery.anchorDigest || "") || !DIGEST.test(attestation.before.anchorDigest || "")
      || !attestation.signing || attestation.signing.algorithm !== "Ed25519" || !KEY_ID.test(attestation.signing.keyId || "")
      || !DIGEST.test(attestation.attestationDigest || "") || !SIGNATURE.test(attestation.signature || "")) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_SHAPE_INVALID" });
    const unsigned = clean(attestation || {}); delete unsigned.attestationDigest; delete unsigned.signature;
    const digestValid = Boolean(attestation?.attestationDigest && sha256(canonical(unsigned)) === attestation.attestationDigest);
    if (!digestValid) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_DIGEST_INVALID" });
    const key = keys.get(attestation?.signing?.keyId); let signatureValid = false;
    if (!key) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_KEY_UNTRUSTED" });
    else {
      try { signatureValid = verifySignature(null, Buffer.from(canonical({ ...unsigned, attestationDigest: attestation.attestationDigest }), "utf8"), key,
        Buffer.from(attestation.signature || "", "base64url")); } catch { signatureValid = false; }
      if (!signatureValid) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_SIGNATURE_INVALID" });
    }
    return { valid: findings.length === 0 && digestValid && signatureValid, signatureValid, findings };
  }
  async function recover(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!validReason(reason)) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_REASON_INVALID", "Alasan pemulihan wajib 12–240 karakter", 400);
    if (!signer || !keyId || !keys.has(keyId)) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_SIGNER_NOT_CONFIGURED", "Signer dan trusted public key recovery belum dikonfigurasi", 503);
    const rows = await store.listEvidence(ownerId);
    const intents = rows.filter(item => item?.kind === INTENT_KIND && item.ownerId === ownerId).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
    for (const item of intents) {
      if (item.digest !== digestRecord(item)) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_INTENT_INVALID", "Recovery intent lokal tidak dapat diverifikasi", 409);
    }
    let pending = intents.filter(item => ["prepared", "anchor_reconciled"].includes(item.status)).at(-1) || null;
    const currentBefore = await anchorService.getRecoverySloRetentionDecisionGateAnchorStatus(ownerId);
    if (!pending && currentBefore.status === "anchored") {
      const completed = intents.filter(item => item.status === "completed").at(-1);
      if (completed?.reason === reason.trim() && completed.after?.anchorDigest === currentBefore.anchorDigest
        && completed.after?.anchorSequence === currentBefore.anchorSequence && completed.attestation) {
        return { status: "recovered_and_attested", attestation: completed.attestation, retention: completed.retention || null,
          before: completed.before, after: completed.after, idempotent: true, readOnly: false, mutationAllowed: false };
      }
      throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_NOT_PROVABLE", "Recovery hanya diizinkan untuk anchor yang tertinggal dengan kontinuitas yang dapat dibuktikan", 409,
        { status: currentBefore.status, findings: currentBefore.findings || [] });
    }
    if (!pending) {
      if (currentBefore.status !== "behind_local" || currentBefore.findings?.length) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_NOT_PROVABLE",
        "Recovery hanya diizinkan untuk anchor yang tertinggal dengan kontinuitas yang dapat dibuktikan", 409,
        { status: currentBefore.status, findings: currentBefore.findings || [] });
      const createdAt = now(), id = `decision-gate-recovery-intent-${randomUUID()}`;
      const unsignedIntent = { id, ownerId, kind: INTENT_KIND, schemaVersion: 1, status: "prepared", reason: reason.trim(), createdAt,
        before: { status: currentBefore.status, total: currentBefore.total, anchorSequence: currentBefore.anchorSequence,
          anchorDigest: currentBefore.anchorDigest, historyNotProven: currentBefore.historyNotProven ?? null } };
      pending = withTransition(unsignedIntent, "prepared", createdAt);
      await store.putEvidence(ownerId, pending, { overwrite: false });
      pending = await store.getEvidence(ownerId, id);
    } else if (pending.reason !== reason.trim()) {
      throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_PENDING", "Recovery intent sebelumnya belum selesai; gunakan alasan yang sama untuk melanjutkannya", 409,
        { intentId: pending.id, status: pending.status });
    }
    if (pending.status === "prepared" && !pending.after) {
      let observed = await anchorService.getRecoverySloRetentionDecisionGateAnchorStatus(ownerId);
      if (observed.status === "behind_local") {
        if (observed.anchorSequence !== pending.before.anchorSequence || observed.anchorDigest !== pending.before.anchorDigest || observed.total !== pending.before.total) {
          throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_SOURCE_CHANGED", "Decision-gate anchor berubah sejak recovery intent dibuat", 409,
            { intentId: pending.id, status: observed.status });
        }
        const reconciled = await anchorService.reconcileRecoverySloRetentionDecisionGateAnchor(ownerId);
        observed = await anchorService.getRecoverySloRetentionDecisionGateAnchorStatus(ownerId);
        if (reconciled.status !== "anchored" && reconciled.status !== "already_anchored") throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_POSTCHECK_FAILED",
          "Rekonsiliasi tidak menghasilkan anchor sehat", 409, { status: reconciled.status });
      }
      if (observed.status !== "anchored" || !DIGEST.test(observed.anchorDigest || "") || !Number.isSafeInteger(observed.anchorSequence)
        || observed.anchorSequence < pending.before.total) {
        throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_POSTCHECK_FAILED", "External decision-gate anchor belum sehat setelah rekonsiliasi", 409,
          { status: observed.status, findings: observed.findings || [] });
      }
      const reconciledAt = now();
      const next = withTransition(pending, "anchor_reconciled", reconciledAt, { status: "anchor_reconciled", after: { status: observed.status, total: observed.total,
        anchorSequence: observed.anchorSequence, anchorDigest: observed.anchorDigest, historyNotProven: observed.historyNotProven ?? null },
        anchorReconciledAt: reconciledAt });
      await store.putEvidence(ownerId, next, { expectedVersion: pending._storage?.version });
      pending = await store.getEvidence(ownerId, pending.id);
    }
    if (pending.status === "completed" && pending.attestation) return { status: "recovered_and_attested", attestation: pending.attestation,
      retention: pending.retention || null, before: pending.before, after: pending.after, idempotent: true, readOnly: false, mutationAllowed: false };
    if (pending.status !== "anchor_reconciled" || !pending.after) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_INTENT_INVALID", "Recovery intent belum mencapai checkpoint yang dapat ditandatangani", 409);
    const observedNow = await anchorService.getRecoverySloRetentionDecisionGateAnchorStatus(ownerId);
    if (observedNow.status !== "anchored" || observedNow.anchorSequence < pending.after.anchorSequence) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_ANCHOR_ROLLBACK",
      "External anchor tidak lagi membuktikan checkpoint hasil recovery", 409, { status: observedNow.status, findings: observedNow.findings || [] });
    let draft = pending.attestationDraft;
    if (!draft) {
      const issuedAt = now();
      const unsigned = { domain: DOMAIN, schemaVersion: 1, attestationId: `decision-gate-recovery-${randomUUID()}`, ownerId, issuedAt,
        reason: pending.reason, before: pending.before, recovery: { status: pending.after.status, total: pending.after.total,
          anchorSequence: pending.after.anchorSequence, anchorDigest: pending.after.anchorDigest, historyNotProven: pending.after.historyNotProven,
          anchored: Math.max(0, pending.after.anchorSequence - pending.before.anchorSequence) }, signing: { algorithm: "Ed25519", keyId } };
      draft = { ...unsigned, attestationDigest: sha256(canonical(unsigned)) };
      const next = withTransition(pending, "attestation_draft_persisted", now(), { attestationDraft: draft });
      await store.putEvidence(ownerId, next, { expectedVersion: pending._storage?.version });
      pending = await store.getEvidence(ownerId, pending.id);
      draft = pending.attestationDraft;
    }
    let signed;
    try { signed = await signer(structuredClone(draft)); }
    catch { throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_SIGNER_FAILED", "External signer recovery gagal; intent tersimpan untuk retry", 502); }
    if (signed && typeof signed === "object" && signed.keyId != null && signed.keyId !== keyId)
      throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_SIGNER_KEY_MISMATCH", "Signer mengembalikan key ID berbeda", 502);
    const signature = typeof signed === "string" ? signed : signed?.signature;
    const attestation = { ...draft, signature };
    if (!envelopeCheck(ownerId, attestation).valid) throw new AgenticError("RETENTION_DECISION_GATE_RECOVERY_SIGNATURE_INVALID", "Signature recovery tidak dapat diverifikasi", 502);
    const retention = await retainedEvidenceService.retainRecoverySloAnchorEvidence(ownerId, { artifactType: ARTIFACT,
      sourceId: attestation.attestationDigest, payload: attestation, retentionDays: 3650 });
    const completedAt = now();
    const completed = withTransition(pending, "completed", completedAt, { status: "completed", attestation, retention, completedAt });
    await store.putEvidence(ownerId, completed, { expectedVersion: pending._storage?.version });
    return { status: "recovered_and_attested", attestation, retention, before: pending.before, after: pending.after, idempotent: false,
      readOnly: false, mutationAllowed: false };
  }
  async function verify(ownerId, attestation) {
    assertOwner(ownerId);
    const envelope = envelopeCheck(ownerId, attestation);
    const listed = await retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true });
    const retention = listed.items.find(item => item?.artifactType === ARTIFACT && item.sourceId === attestation?.attestationDigest);
    const retained = Boolean(retention && retention.status === "retained" && retention.digest === digestRecord(retention)
      && retention.payloadDigest === sha256(canonical(attestation)) && canonical(retention.payload) === canonical(attestation));
    const findings = [...envelope.findings];
    if (!retained) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_NOT_RETAINED" });
    const current = await anchorService.getRecoverySloRetentionDecisionGateAnchorStatus(ownerId);
    const currentMatches = current.status === "anchored" && current.anchorDigest === attestation?.recovery?.anchorDigest
      && current.anchorSequence === attestation?.recovery?.anchorSequence;
    return { valid: envelope.valid && retained, signatureValid: envelope.signatureValid, historicallyValid: envelope.valid && retained,
      current: currentMatches, currentAnchorStatus: current.status, findings, readOnly: true, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [listed, overall] = await Promise.all([retainedEvidenceService.listRecoverySloRetainedAnchorEvidence(ownerId, { limit: 500, includePayload: true }),
      retainedEvidenceService.auditRecoverySloRetainedAnchorEvidence(ownerId)]);
    const records = listed.items.filter(item => item?.artifactType === ARTIFACT), findings = []; let valid = 0, current = 0, tombstones = 0;
    for (const record of records) {
      if (record.status === "tombstone") { tombstones++; continue; }
      const result = await verify(ownerId, record.payload);
      if (!result.historicallyValid) findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_INVALID", evidenceId: record.id, findings: result.findings });
      else { valid++; if (result.current) current++; }
    }
    if (overall.status !== "healthy") findings.push({ code: "RETENTION_DECISION_GATE_RECOVERY_ATTESTATION_RETENTION_AUDIT_UNHEALTHY" });
    return { status: findings.length ? "unhealthy" : "healthy", ownerId, total: records.length, valid, current, tombstones, findings, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ recoverAndAttestRecoverySloRetentionDecisionGateAnchor: recover,
    verifyRecoverySloRetentionDecisionGateAnchorRecoveryAttestation: verify,
    auditRecoverySloRetentionDecisionGateAnchorRecoveryAttestations: audit, configured: Boolean(signer && keyId && keys.has(keyId)), required });
}
