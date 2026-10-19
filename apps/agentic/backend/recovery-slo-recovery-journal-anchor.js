import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";

const JOURNAL_KIND = "recovery-slo-anchor-contract-migration-recovery-journal";
const ANCHOR_KIND = "recovery-slo-contract-migration-recovery-journal-anchor";
const DIGEST = /^[a-f0-9]{64}$/;
const MAX_RETRIES = 3;
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
const ownerHash = ownerId => sha256(ownerId).slice(0, 24);
const journalHash = journalId => sha256(journalId).slice(0, 24);
const anchorScope = (ownerId, journalId) => `recovery-journal-${ownerHash(ownerId)}-${journalHash(journalId)}`;
const journalGenesis = (ownerId, journalId) => sha256(`agentic-v4-migration-recovery:${ownerId}:${journalId}`);
const eventHash = event => sha256(canonical({ sequence: event.sequence, type: event.type, at: event.at,
  previousHash: event.previousHash, payload: event.payload }));

function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_OWNER_REQUIRED", "Owner wajib ditentukan", 400);
  }
}
function validateJournal(journal, ownerId, journalId) {
  if (!journal || journal.ownerId !== ownerId || journal.id !== journalId || journal.kind !== JOURNAL_KIND
    || journal.schemaVersion !== 1 || !Number.isSafeInteger(journal.revision) || journal.revision < 1
    || !Array.isArray(journal.events) || journal.events.length !== journal.revision || journal.events.length > 20
    || !DIGEST.test(journal.planDigest || "") || !DIGEST.test(journal.approvalDigest || "")
    || !["applying", "recovery_required", "completed", "blocked"].includes(journal.status)) {
    return { valid: false, code: "RECOVERY_JOURNAL_SHAPE_INVALID" };
  }
  let previous = journalGenesis(ownerId, journalId);
  for (let i = 0; i < journal.events.length; i++) {
    const item = journal.events[i];
    if (!item || item.sequence !== i + 1 || item.previousHash !== previous || !Number.isFinite(Date.parse(item.at))
      || item.eventHash !== eventHash(item)) return { valid: false, code: "RECOVERY_JOURNAL_CHAIN_INVALID" };
    previous = item.eventHash;
  }
  if (journal.status !== journal.events.at(-1)?.payload?.status || journal.digest !== digestRecord(journal)) {
    return { valid: false, code: "RECOVERY_JOURNAL_DIGEST_INVALID" };
  }
  return { valid: true };
}
function validateAnchor(anchor, scope, journalId) {
  if (!anchor || anchor.ownerId !== scope || anchor.kind !== ANCHOR_KIND || anchor.schemaVersion !== 1
    || anchor.journalIdHash !== journalHash(journalId) || !DIGEST.test(anchor.sourceOwnerHash || "")
    || !DIGEST.test(anchor.planDigest || "") || !DIGEST.test(anchor.approvalDigest || "")
    || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
    || !Number.isSafeInteger(anchor.revision) || anchor.revision < 1
    || !Number.isSafeInteger(anchor.journalRevision) || anchor.journalRevision !== anchor.revision
    || !DIGEST.test(anchor.journalDigest || "") || !DIGEST.test(anchor.eventHeadHash || "")
    || !["applying", "recovery_required", "completed", "blocked"].includes(anchor.journalStatus)
    || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
    || !Number.isFinite(Date.parse(anchor.anchoredAt)) || anchor.digest !== digestRecord(anchor)) {
    return { valid: false, code: "EXTERNAL_RECOVERY_JOURNAL_ANCHOR_INVALID" };
  }
  if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null)
    || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) {
    return { valid: false, code: "EXTERNAL_RECOVERY_JOURNAL_ANCHOR_CHAIN_INVALID" };
  }
  return { valid: true };
}

export function createRecoverySloRecoveryJournalAnchorService({ store, provider = null, required = false,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.listEvidence || !provider && required
    || provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function")
    || typeof clock !== "function") throw new TypeError("Recovery journal anchor membutuhkan store, provider CAS, dan clock yang valid");

  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_CLOCK_INVALID", "Clock journal anchor tidak valid", 500);
    return new Date(value).toISOString();
  }
  async function readJournal(ownerId, journalId) {
    const journal = await store.getEvidence(ownerId, journalId);
    if (!journal) throw new AgenticError("RECOVERY_SLO_JOURNAL_NOT_FOUND", "Recovery journal tidak ditemukan", 404);
    const check = validateJournal(journal, ownerId, journalId);
    if (!check.valid) throw new AgenticError("RECOVERY_SLO_JOURNAL_UNHEALTHY", "Recovery journal tidak valid", 409, { finding: check.code });
    return journal;
  }
  async function readExternal(ownerId, journalId) {
    const scope = anchorScope(ownerId, journalId);
    let anchor;
    try { anchor = await provider.read(scope); }
    catch (error) { return { status: "unavailable", anchor: null, finding: error?.code || "EXTERNAL_ANCHOR_READ_FAILED" }; }
    if (anchor == null) return { status: "missing", anchor: null, scope };
    const check = validateAnchor(anchor, scope, journalId);
    return check.valid ? { status: "present", anchor, scope } : { status: "invalid", anchor: null, scope, finding: check.code };
  }
  async function classify(ownerId, journal, external) {
    if (!provider) return { status: "not_configured", ownerId, journalId: journal.id, revision: journal.revision,
      required, readOnly: true, mutationAllowed: false, findings: required ? ["EXTERNAL_RECOVERY_JOURNAL_ANCHOR_REQUIRED"] : [] };
    if (external.status === "unavailable") return { status: "unavailable", ownerId, journalId: journal.id, revision: journal.revision,
      finding: external.finding, readOnly: true, mutationAllowed: false };
    if (external.status === "invalid") return { status: "invalid", ownerId, journalId: journal.id, revision: journal.revision,
      finding: external.finding, readOnly: true, mutationAllowed: false };
    if (external.status === "missing") return { status: journal.revision === 1 ? "missing" : "rollback_suspected", ownerId,
      journalId: journal.id, revision: journal.revision, finding: "EXTERNAL_RECOVERY_JOURNAL_ANCHOR_MISSING",
      readOnly: true, mutationAllowed: false };
    const anchor = external.anchor;
    if (anchor.sourceOwnerHash !== sha256(ownerId) || anchor.planDigest !== journal.planDigest || anchor.approvalDigest !== journal.approvalDigest) {
      return { status: "mismatch", ownerId, journalId: journal.id, revision: journal.revision,
        anchorRevision: anchor.journalRevision, finding: "EXTERNAL_RECOVERY_JOURNAL_BINDING_MISMATCH", readOnly: true, mutationAllowed: false };
    }
    if (anchor.journalRevision > journal.revision) return { status: "rollback_detected", ownerId, journalId: journal.id,
      revision: journal.revision, anchorRevision: anchor.journalRevision, finding: "EXTERNAL_RECOVERY_JOURNAL_ROLLBACK_DETECTED",
      readOnly: true, mutationAllowed: false };
    if (anchor.journalRevision === journal.revision) {
      const matches = anchor.journalDigest === journal.digest && anchor.eventHeadHash === journal.events.at(-1).eventHash
        && anchor.journalStatus === journal.status;
      return { status: matches ? "anchored" : "mismatch", ownerId, journalId: journal.id, revision: journal.revision,
        anchorRevision: anchor.journalRevision, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
        finding: matches ? null : "EXTERNAL_RECOVERY_JOURNAL_SAME_REVISION_MISMATCH", readOnly: true, mutationAllowed: false };
    }
    const ancestor = journal.events[anchor.journalRevision - 1];
    if (!ancestor || ancestor.eventHash !== anchor.eventHeadHash) return { status: "mismatch", ownerId, journalId: journal.id,
      revision: journal.revision, anchorRevision: anchor.journalRevision, finding: "EXTERNAL_RECOVERY_JOURNAL_ANCESTOR_MISMATCH",
      readOnly: true, mutationAllowed: false };
    return { status: "behind_local", ownerId, journalId: journal.id, revision: journal.revision,
      anchorRevision: anchor.journalRevision, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      readOnly: true, mutationAllowed: false };
  }
  async function getStatus(ownerId, journalId) {
    assertOwner(ownerId);
    const journal = await readJournal(ownerId, journalId);
    if (!provider) return classify(ownerId, journal, { status: "missing" });
    const external = await readExternal(ownerId, journalId);
    return classify(ownerId, journal, external);
  }
  async function anchorJournal(ownerId, journalId) {
    assertOwner(ownerId);
    const journal = await readJournal(ownerId, journalId);
    if (!provider) {
      if (required) throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_REQUIRED", "External recovery journal anchor wajib dikonfigurasi", 503);
      return { status: "not_configured", journalId, revision: journal.revision, readOnly: true, mutationAllowed: false };
    }
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const external = await readExternal(ownerId, journalId);
      if (external.status === "unavailable") throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_UNAVAILABLE", "External recovery journal anchor tidak tersedia", 503, { finding: external.finding });
      if (external.status === "invalid") throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_INVALID", "External recovery journal anchor tidak valid", 409, { finding: external.finding });
      if (external.status === "missing" && journal.revision !== 1) throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_MISSING", "Anchor hilang untuk journal yang telah memiliki histori; auto-enrollment ditolak", 409);
      if (external.status === "present") {
        const status = await classify(ownerId, journal, external);
        if (status.status === "anchored") return { ...status, idempotent: true };
        if (status.status !== "behind_local") throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_CONFLICT", "External recovery journal anchor tidak konsisten; pembaruan ditolak", 409, { status: status.status, finding: status.finding });
      }
      const previous = external.status === "present" ? external.anchor : null;
      const unsigned = { ownerId: external.scope || anchorScope(ownerId, journalId), kind: ANCHOR_KIND, schemaVersion: 1,
        sourceOwnerHash: sha256(ownerId), journalIdHash: journalHash(journalId), planDigest: journal.planDigest,
        approvalDigest: journal.approvalDigest, revision: journal.revision, journalRevision: journal.revision,
        journalDigest: journal.digest, eventHeadHash: journal.events.at(-1).eventHash, journalStatus: journal.status,
        anchorSequence: previous ? previous.anchorSequence + 1 : 1, previousAnchorDigest: previous?.digest || null, anchoredAt: now() };
      const candidate = { ...unsigned, digest: digestRecord(unsigned) };
      let result;
      try { result = await provider.compareAndSet(candidate.ownerId, previous?.digest ?? null, candidate); }
      catch (error) { throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_WRITE_FAILED", "External recovery journal anchor gagal ditulis", 503, { cause: error?.code || "PROVIDER_ERROR" }); }
      if (!result?.applied) continue;
      let after;
      try { after = await provider.read(candidate.ownerId); }
      catch (error) { throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_VERIFY_UNAVAILABLE", "Anchor ditulis tetapi pembacaan ulang gagal", 503, { cause: error?.code || "PROVIDER_ERROR" }); }
      const check = validateAnchor(after, candidate.ownerId, journalId);
      if (!check.valid || after.digest !== candidate.digest) throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_POSTWRITE_MISMATCH", "External recovery journal anchor gagal diverifikasi setelah penulisan", 409, { finding: check.code || "POSTWRITE_DIGEST_MISMATCH" });
      return { status: "anchored", ownerId, journalId, revision: journal.revision, anchorSequence: candidate.anchorSequence,
        anchorDigest: candidate.digest, idempotent: false, readOnly: false, mutationAllowed: false };
    }
    throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_CAS_CONFLICT", "External recovery journal anchor terus berubah; coba audit sebelum rekonsiliasi", 409);
  }
  async function reconcile(ownerId, journalId) {
    const before = await getStatus(ownerId, journalId);
    if (["rollback_detected", "rollback_suspected", "mismatch", "invalid", "unavailable"].includes(before.status)) {
      return { ...before, reconciled: false, reason: "TRUST_CONFLICT_REQUIRES_OPERATOR_REVIEW", readOnly: true, mutationAllowed: false };
    }
    try { return { ...(await anchorJournal(ownerId, journalId)), reconciled: true }; }
    catch (error) {
      return { status: "blocked", ownerId, journalId, reconciled: false, finding: error.code || "RECOVERY_SLO_JOURNAL_ANCHOR_RECONCILIATION_FAILED",
        message: error.message, readOnly: true, mutationAllowed: false };
    }
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const journals = (await store.listEvidence(ownerId)).filter(item => item.kind === JOURNAL_KIND);
    if (!provider) return { status: required ? "unhealthy" : "not_configured", ownerId, journalCount: journals.length,
      items: [], findings: required ? [{ code: "EXTERNAL_RECOVERY_JOURNAL_ANCHOR_REQUIRED", severity: "error" }] : [],
      readOnly: true, mutationAllowed: false };
    const items = [];
    for (const journal of journals.slice(0, 500)) {
      const check = validateJournal(journal, ownerId, journal.id);
      if (!check.valid) {
        items.push({ journalId: journal.id, status: "local_journal_invalid", finding: check.code });
        continue;
      }
      items.push(await getStatus(ownerId, journal.id));
    }
    const errors = items.filter(item => ["rollback_detected", "rollback_suspected", "mismatch", "invalid", "unavailable", "local_journal_invalid"].includes(item.status));
    const behind = items.filter(item => ["behind_local", "missing"].includes(item.status));
    return { status: errors.length ? "unhealthy" : behind.length ? "degraded" : "healthy", ownerId,
      journalCount: journals.length, anchoredCount: items.filter(item => item.status === "anchored").length,
      behindCount: behind.length, errorCount: errors.length, items, findings: [
        ...(errors.length ? [{ code: "RECOVERY_JOURNAL_ANCHOR_INTEGRITY_ERRORS", severity: "error", count: errors.length }] : []),
        ...(behind.length ? [{ code: "RECOVERY_JOURNAL_ANCHOR_ADVANCEMENT_REQUIRED", severity: "warning", count: behind.length }] : [])
      ], readOnly: true, mutationAllowed: false };
  }
  async function assertTrusted(ownerId, journalId) {
    if (!required && !provider) return true;
    const status = await getStatus(ownerId, journalId);
    if (status.status !== "anchored") throw new AgenticError("RECOVERY_SLO_JOURNAL_ANCHOR_NOT_TRUSTED",
      "Recovery journal tidak memiliki external anchor terkini yang valid", 409, { status: status.status, finding: status.finding || null });
    return true;
  }
  return Object.freeze({ getRecoverySloRecoveryJournalAnchorStatus: getStatus,
    anchorRecoverySloRecoveryJournal: anchorJournal,
    reconcileRecoverySloRecoveryJournalAnchor: reconcile,
    auditRecoverySloRecoveryJournalAnchors: audit,
    assertRecoverySloRecoveryJournalAnchorTrusted: assertTrusted,
    configured: Boolean(provider), required });
}
