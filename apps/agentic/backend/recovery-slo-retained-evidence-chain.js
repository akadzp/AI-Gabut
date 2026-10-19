import { createHash } from "node:crypto";
import { AgenticError } from "./errors.js";

const LEDGER_KIND = "recovery-slo-retained-evidence-chain-ledger";
const ANCHOR_KIND = "recovery-slo-retained-evidence-chain-anchor";
const MARKER_KIND = "recovery-slo-retained-evidence-chain-marker";
const DIGEST = /^[a-f0-9]{64}$/;
const MAX_RETRIES = 4;
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
const ledgerId = ownerId => `recovery-slo-retained-evidence-chain-${ownerHash(ownerId)}`;
const markerId = ownerId => `recovery-slo-retained-evidence-chain-marker-${ownerHash(ownerId)}`;
const scopeId = ownerId => `retained-evidence-chain-${ownerHash(ownerId)}`;
const eventDigest = event => { const copy = clean(event); delete copy.eventDigest; return sha256(canonical(copy)); };
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_OWNER_REQUIRED", "Owner evidence chain wajib ditentukan", 400);
  }
}
function validateLedger(ownerId, ledger) {
  if (!ledger || ledger.ownerId !== ownerId || ledger.id !== ledgerId(ownerId) || ledger.kind !== LEDGER_KIND
    || ledger.schemaVersion !== 1 || !Array.isArray(ledger.events) || !Number.isSafeInteger(ledger.sequence)
    || ledger.sequence !== ledger.events.length || !DIGEST.test(ledger.digest || "") || ledger.digest !== digestRecord(ledger)) {
    return { valid: false, code: "RETAINED_EVIDENCE_CHAIN_LEDGER_INVALID" };
  }
  const seen = new Set();
  let previous = null;
  for (let index = 0; index < ledger.events.length; index++) {
    const event = ledger.events[index];
    if (!event || event.ownerId !== ownerId || event.sequence !== index + 1
      || !["retained", "pruned"].includes(event.eventType) || typeof event.recordId !== "string" || !event.recordId
      || !DIGEST.test(event.recordDigest || "") || !DIGEST.test(event.payloadDigest || "")
      || !Number.isFinite(Date.parse(event.occurredAt)) || event.previousEventDigest !== previous
      || !DIGEST.test(event.eventDigest || "") || event.eventDigest !== eventDigest(event)) {
      return { valid: false, code: "RETAINED_EVIDENCE_CHAIN_EVENT_INVALID", sequence: index + 1 };
    }
    const key = `${event.recordId}:${event.eventType}`;
    if (seen.has(key)) return { valid: false, code: "RETAINED_EVIDENCE_CHAIN_DUPLICATE_EVENT", sequence: event.sequence };
    seen.add(key);
    previous = event.eventDigest;
  }
  if (ledger.headDigest !== (ledger.events.at(-1)?.eventDigest || null)) return { valid: false, code: "RETAINED_EVIDENCE_CHAIN_HEAD_INVALID" };
  return { valid: true };
}
function validateAnchor(anchor, scope, ownerId) {
  if (!anchor || anchor.ownerId !== scope || anchor.kind !== ANCHOR_KIND || anchor.schemaVersion !== 1
    || anchor.sourceOwnerHash !== sha256(ownerId) || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
    || !Number.isSafeInteger(anchor.eventSequence) || anchor.eventSequence < 1
    || !Number.isSafeInteger(anchor.revision) || anchor.revision !== anchor.eventSequence
    || !DIGEST.test(anchor.eventDigest || "") || !DIGEST.test(anchor.previousAnchorDigest || "") && anchor.previousAnchorDigest !== null
    || !Number.isFinite(Date.parse(anchor.anchoredAt)) || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) {
    return { valid: false, code: "RETAINED_EVIDENCE_CHAIN_EXTERNAL_ANCHOR_INVALID" };
  }
  if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null)
    || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) return { valid: false, code: "RETAINED_EVIDENCE_CHAIN_ANCHOR_LINK_INVALID" };
  return { valid: true };
}
function validateMarker(marker, ownerId) {
  if (!marker || marker.ownerId !== ownerId || marker.id !== markerId(ownerId) || marker.kind !== MARKER_KIND
    || marker.schemaVersion !== 1 || !DIGEST.test(marker.anchorDigest || "") || !Number.isSafeInteger(marker.anchorSequence)
    || marker.anchorSequence < 1 || !Number.isSafeInteger(marker.eventSequence) || marker.eventSequence < 1
    || !DIGEST.test(marker.eventDigest || "") || !Number.isFinite(Date.parse(marker.updatedAt))
    || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker)) return { valid: false, code: "RETAINED_EVIDENCE_CHAIN_MARKER_INVALID" };
  return { valid: true };
}

export function createRecoverySloRetainedEvidenceChainService({ store, provider = null, required = false,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function"
    || provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") || !provider && required) {
    throw new TypeError("Retained evidence chain membutuhkan store, clock, dan provider CAS jika diwajibkan");
  }
  const locks = new Map();
  function now() {
    const time = Date.parse(String(clock()));
    if (!Number.isFinite(time)) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_CLOCK_INVALID", "Clock retained evidence chain tidak valid", 500);
    return new Date(time).toISOString();
  }
  function withOwnerLock(ownerId, operation) {
    const previous = locks.get(ownerId) || Promise.resolve();
    const next = previous.catch(() => {}).then(operation);
    locks.set(ownerId, next);
    return next.finally(() => { if (locks.get(ownerId) === next) locks.delete(ownerId); });
  }
  async function readLedger(ownerId) {
    const ledger = await store.getEvidence(ownerId, ledgerId(ownerId));
    if (!ledger) return { ledger: null, status: "missing" };
    const check = validateLedger(ownerId, ledger);
    return check.valid ? { ledger, status: "present" } : { ledger: null, status: "invalid", finding: check.code };
  }
  async function saveLedger(ownerId, next, current) {
    await store.putEvidence(ownerId, next, current ? { expectedVersion: current._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, next.id);
    if (!validateLedger(ownerId, saved).valid || saved.digest !== next.digest) {
      throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_WRITE_VERIFY_FAILED", "Ledger evidence chain gagal diverifikasi setelah penulisan", 409);
    }
    return saved;
  }
  async function readMarker(ownerId) {
    const marker = await store.getEvidence(ownerId, markerId(ownerId));
    if (!marker) return { status: "missing", marker: null };
    const check = validateMarker(marker, ownerId);
    return check.valid ? { status: "present", marker } : { status: "invalid", marker: null, finding: check.code };
  }
  async function saveMarker(ownerId, anchor) {
    const id = markerId(ownerId);
    const current = await store.getEvidence(ownerId, id);
    const unsigned = { id, ownerId, kind: MARKER_KIND, schemaVersion: 1, anchorDigest: anchor.digest,
      anchorSequence: anchor.anchorSequence, eventSequence: anchor.eventSequence, eventDigest: anchor.eventDigest, updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, current ? { expectedVersion: current._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!validateMarker(saved, ownerId).valid || saved.anchorDigest !== anchor.digest) {
      throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_MARKER_WRITE_FAILED", "Marker evidence chain gagal diverifikasi", 409);
    }
    return saved;
  }
  async function readExternal(ownerId) {
    if (!provider) return { status: required ? "not_configured" : "not_required", anchor: null, scope: scopeId(ownerId) };
    const scope = scopeId(ownerId);
    let anchor;
    try { anchor = await provider.read(scope); }
    catch (error) { return { status: "unavailable", anchor: null, scope, finding: error?.code || "PROVIDER_READ_FAILED" }; }
    if (!anchor) return { status: "missing", anchor: null, scope };
    const check = validateAnchor(anchor, scope, ownerId);
    return check.valid ? { status: "present", anchor, scope } : { status: "invalid", anchor: null, scope, finding: check.code };
  }
  async function classify(ownerId, ledgerState) {
    const ledger = ledgerState.ledger;
    const markerState = await readMarker(ownerId);
    if (ledgerState.status === "invalid") return { status: "unhealthy", ownerId, finding: ledgerState.finding };
    if (!ledger || ledger.events.length === 0) return { status: provider ? "not_initialized" : "local_only", ownerId, sequence: 0 };
    if (markerState.status === "invalid") return { status: "unhealthy", ownerId, finding: markerState.finding };
    const external = await readExternal(ownerId);
    if (external.status === "not_required" || external.status === "not_configured") return { status: "local_only", ownerId,
      sequence: ledger.sequence, headDigest: ledger.headDigest, required, providerConfigured: false };
    if (external.status === "unavailable" || external.status === "invalid") return { status: "unhealthy", ownerId,
      sequence: ledger.sequence, finding: external.finding || external.status };
    if (external.status === "missing") {
      if (markerState.status === "present") return { status: "rollback_suspected", ownerId, sequence: ledger.sequence,
        markerSequence: markerState.marker.eventSequence, finding: "RETAINED_EVIDENCE_CHAIN_ANCHOR_MISSING_AFTER_ENROLLMENT" };
      if (ledger.sequence === 1) return { status: "anchor_pending", ownerId, sequence: ledger.sequence, headDigest: ledger.headDigest };
      return { status: "enrollment_required", ownerId, sequence: ledger.sequence, historyNotProven: true };
    }
    const anchor = external.anchor;
    if (anchor.eventSequence > ledger.sequence) return { status: "rollback_detected", ownerId, sequence: ledger.sequence,
      anchorEventSequence: anchor.eventSequence, finding: "EXTERNAL_CHAIN_ANCHOR_AHEAD_OF_LOCAL_LEDGER" };
    const anchoredEvent = ledger.events[anchor.eventSequence - 1];
    if (!anchoredEvent || anchoredEvent.eventDigest !== anchor.eventDigest) return { status: "mismatch", ownerId,
      sequence: ledger.sequence, anchorEventSequence: anchor.eventSequence, finding: "EXTERNAL_CHAIN_ANCHOR_NOT_IN_LOCAL_HISTORY" };
    if (markerState.status === "present") {
      const marker = markerState.marker;
      if (marker.anchorSequence > anchor.anchorSequence || marker.eventSequence > anchor.eventSequence) return { status: "rollback_suspected", ownerId,
        sequence: ledger.sequence, markerSequence: marker.eventSequence, anchorEventSequence: anchor.eventSequence };
      if (marker.anchorSequence === anchor.anchorSequence && marker.anchorDigest !== anchor.digest) return { status: "mismatch", ownerId,
        sequence: ledger.sequence, finding: "RETAINED_EVIDENCE_CHAIN_MARKER_MISMATCH" };
      if (marker.anchorSequence < anchor.anchorSequence
        && !(marker.anchorSequence + 1 === anchor.anchorSequence && anchor.previousAnchorDigest === marker.anchorDigest)) {
        return { status: "rollback_suspected", ownerId, sequence: ledger.sequence, finding: "RETAINED_EVIDENCE_CHAIN_MARKER_DISCONTINUITY" };
      }
    }
    return anchor.eventSequence === ledger.sequence
      ? { status: "anchored", ownerId, sequence: ledger.sequence, headDigest: ledger.headDigest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest }
      : { status: "behind_local", ownerId, sequence: ledger.sequence, headDigest: ledger.headDigest,
        anchorEventSequence: anchor.eventSequence, anchorDigest: anchor.digest };
  }
  async function advanceExternalAnchor(ownerId, ledger) {
    if (!provider) {
      if (required) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_REQUIRED", "External retained-evidence chain anchor diwajibkan", 503);
      return { status: "local_only", sequence: ledger.sequence };
    }
    const markerState = await readMarker(ownerId);
    if (markerState.status === "invalid") throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_MARKER_INVALID", "Marker chain tidak valid", 409);
    const scope = scopeId(ownerId);
    let external;
    try { external = await provider.read(scope); }
    catch (error) { throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_UNAVAILABLE", "External retained-evidence chain anchor tidak tersedia", 503, { cause: error?.code || "PROVIDER_READ_FAILED" }); }
    if (external == null) {
      if (markerState.status === "present") throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ROLLBACK_SUSPECTED", "External chain anchor hilang setelah enrollment", 409);
      if (ledger.sequence !== 1) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ENROLLMENT_REQUIRED", "Histori chain tidak dapat di-enroll otomatis", 409);
    } else {
      const check = validateAnchor(external, scope, ownerId);
      if (!check.valid) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_INVALID", "External chain anchor tidak valid", 409, { finding: check.code });
      if (external.eventSequence > ledger.sequence) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ROLLBACK_DETECTED", "External anchor lebih baru daripada ledger lokal", 409);
      const anchoredEvent = ledger.events[external.eventSequence - 1];
      if (!anchoredEvent || anchoredEvent.eventDigest !== external.eventDigest) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_MISMATCH", "Anchor tidak cocok dengan histori chain lokal", 409);
      if (markerState.status === "present") {
        const marker = markerState.marker;
        if (marker.anchorSequence > external.anchorSequence || marker.eventSequence > external.eventSequence
          || marker.anchorSequence === external.anchorSequence && marker.anchorDigest !== external.digest
          || marker.anchorSequence < external.anchorSequence
            && !(marker.anchorSequence + 1 === external.anchorSequence && external.previousAnchorDigest === marker.anchorDigest)) {
          throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ROLLBACK_SUSPECTED", "Marker lokal menunjukkan anchor rollback atau mismatch", 409);
        }
      }
    }
    let previous = external || null;
    const start = previous ? previous.eventSequence : 0;
    for (const event of ledger.events.slice(start)) {
      const unsigned = { ownerId: scope, kind: ANCHOR_KIND, schemaVersion: 1, sourceOwnerHash: sha256(ownerId),
        anchorSequence: previous ? previous.anchorSequence + 1 : 1, revision: event.sequence,
        eventSequence: event.sequence, eventDigest: event.eventDigest,
        previousAnchorDigest: previous?.digest || null, anchoredAt: now() };
      const candidate = { ...unsigned, digest: digestRecord(unsigned) };
      let result;
      try { result = await provider.compareAndSet(scope, previous?.digest ?? null, candidate); }
      catch (error) { throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_WRITE_FAILED", "External chain anchor gagal ditulis", 503, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
      if (!result?.applied) throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_CAS_CONFLICT", "External chain anchor berubah bersamaan; rekonsiliasi diperlukan", 409);
      let after;
      try { after = await provider.read(scope); }
      catch (error) { throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_VERIFY_UNAVAILABLE", "Pembacaan ulang external chain anchor gagal", 503, { cause: error?.code || "PROVIDER_READ_FAILED" }); }
      if (!validateAnchor(after, scope, ownerId).valid || after.digest !== candidate.digest) {
        throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_ANCHOR_POSTWRITE_MISMATCH", "External chain anchor gagal diverifikasi setelah penulisan", 409);
      }
      await saveMarker(ownerId, after);
      previous = after;
    }
    return { status: "anchored", sequence: ledger.sequence, anchorSequence: previous?.anchorSequence || 0, anchorDigest: previous?.digest || null };
  }
  async function appendRecord(ownerId, record, eventType) {
    assertOwner(ownerId);
    if (!record || record.ownerId !== ownerId || !record.id || !DIGEST.test(record.digest || "")
      || !DIGEST.test(record.payloadDigest || "") || !["retained", "tombstone"].includes(record.status)
      || eventType === "retained" && record.status !== "retained" || eventType === "pruned" && record.status !== "tombstone") {
      throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECORD_INVALID", "Record retained evidence tidak valid untuk chain", 409);
    }
    return withOwnerLock(ownerId, async () => {
      for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        const currentState = await readLedger(ownerId);
        if (currentState.status === "invalid") throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_LEDGER_INVALID", "Ledger chain tidak sehat; append ditolak", 409);
        const current = currentState.ledger;
        const events = current?.events || [];
        const sameRecord = events.filter(item => item.recordId === record.id);
        const latest = sameRecord.at(-1);
        if (latest && latest.eventType === eventType) {
          if (latest.recordDigest !== record.digest || latest.payloadDigest !== record.payloadDigest) {
            throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_RECORD_DIGEST_CONFLICT", "Record berbeda dari event chain yang sudah ada", 409);
          }
          const anchored = await advanceExternalAnchor(ownerId, current);
          return { idempotent: true, sequence: latest.sequence, anchorStatus: anchored.status };
        }
        if (eventType === "retained" && latest || eventType === "pruned" && (!latest || latest.eventType !== "retained")) {
          throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_TRANSITION_INVALID", "Transisi retained evidence tidak sesuai dengan chain", 409);
        }
        const unsignedEvent = { ownerId, sequence: events.length + 1, eventType, recordId: record.id,
          recordDigest: record.digest, payloadDigest: record.payloadDigest, status: record.status, occurredAt: now(),
          previousEventDigest: events.at(-1)?.eventDigest || null };
        const event = { ...unsignedEvent, eventDigest: eventDigest(unsignedEvent) };
        const unsignedLedger = { id: ledgerId(ownerId), ownerId, kind: LEDGER_KIND, schemaVersion: 1,
          sequence: event.sequence, events: [...events, event], headDigest: event.eventDigest, updatedAt: now() };
        const next = { ...unsignedLedger, digest: digestRecord(unsignedLedger) };
        try { await saveLedger(ownerId, next, current); }
        catch (error) {
          if (error?.code === "VERSION_CONFLICT" || error?.code === "STATE_RECORD_EXISTS") continue;
          throw error;
        }
        const anchored = await advanceExternalAnchor(ownerId, next);
        return { idempotent: false, sequence: event.sequence, eventDigest: event.eventDigest, anchorStatus: anchored.status };
      }
      throw new AgenticError("RECOVERY_SLO_EVIDENCE_CHAIN_CONFLICT", "Ledger evidence chain terus berubah; coba ulang setelah audit", 409);
    });
  }
  async function audit(ownerId, records = null) {
    assertOwner(ownerId);
    const state = await readLedger(ownerId);
    if (state.status === "invalid") return { status: "unhealthy", ownerId, sequence: null, findings: [{ code: state.finding }], readOnly: true, mutationAllowed: false };
    const ledger = state.ledger;
    const recordList = records || (await store.listEvidence(ownerId)).filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record");
    const findings = [];
    const latestById = new Map();
    for (const event of ledger?.events || []) latestById.set(event.recordId, event);
    const currentIds = new Set(recordList.map(item => item.id));
    for (const record of recordList) {
      const latest = latestById.get(record.id);
      if (!latest) findings.push({ code: "RETAINED_EVIDENCE_CHAIN_EVENT_MISSING", id: record.id });
      else if (latest.recordDigest !== record.digest || latest.payloadDigest !== record.payloadDigest || latest.status !== record.status) {
        findings.push({ code: "RETAINED_EVIDENCE_CHAIN_RECORD_DRIFT", id: record.id });
      }
    }
    for (const event of ledger?.events || []) if (!currentIds.has(event.recordId)) findings.push({ code: "RETAINED_EVIDENCE_CHAIN_RECORD_MISSING", id: event.recordId });
    const anchor = await classify(ownerId, state);
    if (["unhealthy", "rollback_suspected", "rollback_detected", "mismatch", "enrollment_required"].includes(anchor.status)) {
      findings.push({ code: `RETAINED_EVIDENCE_CHAIN_${anchor.status.toUpperCase()}`, detail: anchor.finding || null });
    }
    const status = findings.length ? "unhealthy" : anchor.status === "behind_local" || anchor.status === "anchor_pending" ? "degraded"
      : anchor.status === "local_only" ? "local_only" : anchor.status === "not_initialized" ? "not_initialized" : "healthy";
    return { status, ownerId, sequence: ledger?.sequence || 0, headDigest: ledger?.headDigest || null,
      providerConfigured: Boolean(provider), required, anchor, recordCount: recordList.length, findings, readOnly: true, mutationAllowed: false };
  }
  async function reconcile(ownerId) {
    assertOwner(ownerId);
    const state = await readLedger(ownerId);
    if (state.status === "invalid") return { status: "blocked", finding: state.finding, readOnly: true, mutationAllowed: false };
    if (!state.ledger || !state.ledger.sequence) return { status: "not_initialized", readOnly: true, mutationAllowed: false };
    try {
      const result = await advanceExternalAnchor(ownerId, state.ledger);
      return { ...result, readOnly: false, mutationAllowed: false };
    } catch (error) {
      return { status: "blocked", finding: error.code || "RETAINED_EVIDENCE_CHAIN_RECONCILIATION_FAILED",
        message: error.message, readOnly: true, mutationAllowed: false };
    }
  }
  async function history(ownerId) {
    assertOwner(ownerId);
    const state = await readLedger(ownerId);
    if (state.status === "invalid") return { status: "unhealthy", ownerId, sequence: null, events: [], findings: [{ code: state.finding }], readOnly: true, mutationAllowed: false };
    const auditResult = await audit(ownerId);
    return { status: auditResult.status, ownerId, sequence: state.ledger?.sequence || 0,
      headDigest: state.ledger?.headDigest || null, events: (state.ledger?.events || []).map(event => clean(event)),
      findings: auditResult.findings, readOnly: true, mutationAllowed: false };
  }
  async function verifyCheckpoint(ownerId, { sequence, headDigest } = {}) {
    assertOwner(ownerId);
    const state = await readLedger(ownerId);
    if (state.status === "invalid") return { valid: false, finding: state.finding, readOnly: true, mutationAllowed: false };
    if (!Number.isSafeInteger(sequence) || sequence < 1 || !DIGEST.test(headDigest || "") || !state.ledger || sequence > state.ledger.sequence) {
      return { valid: false, finding: "RETAINED_EVIDENCE_CHAIN_CHECKPOINT_INVALID", currentSequence: state.ledger?.sequence || 0,
        readOnly: true, mutationAllowed: false };
    }
    const event = state.ledger.events[sequence - 1];
    const valid = Boolean(event && event.sequence === sequence && event.eventDigest === headDigest);
    return { valid, sequence, headDigest, currentSequence: state.ledger.sequence, currentHeadDigest: state.ledger.headDigest || null,
      finding: valid ? null : "RETAINED_EVIDENCE_CHAIN_CHECKPOINT_NOT_IN_HISTORY", readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({
    recordRetainedEvidence: (ownerId, recordValue) => appendRecord(ownerId, recordValue, "retained"),
    recordPrunedEvidence: (ownerId, recordValue) => appendRecord(ownerId, recordValue, "pruned"),
    auditRecoverySloRetainedEvidenceChain: audit,
    getRecoverySloRetainedEvidenceChainStatus: async ownerId => classify(ownerId, await readLedger(ownerId)),
    reconcileRecoverySloRetainedEvidenceChainAnchor: reconcile,
    verifyRecoverySloRetainedEvidenceChainCheckpoint: verifyCheckpoint,
    getRecoverySloRetainedEvidenceChainHistory: history,
    providerConfigured: Boolean(provider), required
  });
}
