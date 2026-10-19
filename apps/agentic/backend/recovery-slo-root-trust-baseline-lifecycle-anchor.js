import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const ANCHOR_KIND = "recovery-slo-root-trust-baseline-lifecycle-external-anchor";
const MARKER_KIND = "recovery-slo-root-trust-baseline-lifecycle-anchor-marker";
const ENROLLMENT_KIND = "recovery-slo-root-trust-baseline-lifecycle-anchor-enrollment";
const ARTIFACT = "root_trust_conformance_baseline_lifecycle";
const DIGEST = /^[a-f0-9]{64}$/;
const TTL_MS = 10 * 60_000;
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
const scopeFor = ownerId => `root-trust-baseline-lifecycle-${ownerHash(ownerId)}`;
const markerId = ownerId => `root-trust-baseline-lifecycle-anchor-marker-${ownerHash(ownerId)}`;
const validReason = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200) {
    throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_OWNER_REQUIRED", "Owner baseline lifecycle anchor wajib ditentukan", 400);
  }
}
function same(a, b) { return canonical(a) === canonical(b); }

export function createRecoverySloRootTrustBaselineLifecycleAnchorService({ store, provider = null, lifecycleService, required = false,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence
    || typeof lifecycleService?.auditRecoverySloRootTrustConformanceBaselineLifecycle !== "function"
    || typeof clock !== "function" || provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function")
    || (required && !provider)) throw new TypeError("Root-trust baseline lifecycle anchor membutuhkan store, lifecycle audit, dan provider CAS jika diwajibkan");
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_CLOCK_INVALID", "Clock baseline lifecycle anchor tidak valid", 500);
    return new Date(ms).toISOString();
  }
  async function events(ownerId) {
    const audit = await lifecycleService.auditRecoverySloRootTrustConformanceBaselineLifecycle(ownerId);
    if (audit.status === "unhealthy") throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_SOURCE_UNHEALTHY", "Baseline lifecycle tidak sehat; external anchoring ditolak", 409, { findings: audit.findings });
    const records = (await store.listEvidence(ownerId)).filter(item => item?.kind === "recovery-slo-anchor-evidence-retention-record"
      && item.artifactType === ARTIFACT && item.status === "retained").sort((a, b) => Number(a.payload?.sequence || 0) - Number(b.payload?.sequence || 0));
    const result = [];
    for (let index = 0; index < records.length; index++) {
      const record = records[index], event = record.payload;
      if (!record || record.ownerId !== ownerId || record.digest !== digestRecord(record) || record.sourceId !== event?.eventDigest
        || record.payloadDigest !== sha256(canonical(event)) || event?.ownerId !== ownerId || event.sequence !== index + 1
        || !DIGEST.test(event.eventDigest || "") || !DIGEST.test(event.baselineDigest || "") || !DIGEST.test(event.reportDigest || "")
        || event.previousEventDigest !== (index ? result[index - 1].event.eventDigest : null)) {
        throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_EVENT_INVALID", "Event lifecycle baseline tidak dapat diverifikasi", 409, { sequence: event?.sequence ?? null });
      }
      result.push({ record, event });
    }
    if (audit.lifecycleEvents !== result.length) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_HISTORY_INCOMPLETE", "Jumlah event lifecycle tidak cocok dengan audit", 409);
    return result;
  }
  function validateAnchor(anchor, ownerId) {
    if (!anchor || anchor.ownerId !== scopeFor(ownerId) || anchor.sourceOwnerHash !== sha256(ownerId) || anchor.domain !== "root_trust_baseline_lifecycle"
      || anchor.kind !== ANCHOR_KIND || anchor.schemaVersion !== 1 || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1
      || anchor.revision !== anchor.anchorSequence || !DIGEST.test(anchor.sourceEventDigest || "") || !DIGEST.test(anchor.lifecycleRecordDigest || "")
      || !DIGEST.test(anchor.baselineDigest || "") || !Number.isFinite(Date.parse(anchor.eventCreatedAt))
      || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
      || typeof anchor.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(anchor.anchoredAt))
      || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) return { valid: false, code: "ROOT_TRUST_BASELINE_LIFECYCLE_EXTERNAL_ANCHOR_INVALID" };
    if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null) || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null)) {
      return { valid: false, code: "ROOT_TRUST_BASELINE_LIFECYCLE_EXTERNAL_CHAIN_INVALID" };
    }
    return { valid: true };
  }
  function validateMarker(marker, ownerId) {
    if (!marker || marker.id !== markerId(ownerId) || marker.ownerId !== ownerId || marker.kind !== MARKER_KIND || marker.schemaVersion !== 1
      || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1 || !DIGEST.test(marker.anchorDigest || "")
      || !DIGEST.test(marker.sourceEventDigest || "") || !Number.isFinite(Date.parse(marker.updatedAt))
      || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker)) return { valid: false, code: "ROOT_TRUST_BASELINE_LIFECYCLE_MARKER_INVALID" };
    return { valid: true };
  }
  async function readMarker(ownerId) {
    const marker = await store.getEvidence(ownerId, markerId(ownerId));
    if (!marker) return { status: "missing", marker: null };
    const checked = validateMarker(marker, ownerId);
    return checked.valid ? { status: "present", marker } : { status: "invalid", marker: null, finding: checked.code };
  }
  async function readRemote(ownerId) {
    if (!provider) return { status: required ? "unavailable" : "local_only", anchor: null };
    try {
      const anchor = await provider.read(scopeFor(ownerId));
      if (!anchor) return { status: "missing", anchor: null };
      const checked = validateAnchor(anchor, ownerId);
      return checked.valid ? { status: "present", anchor } : { status: "invalid", anchor: null, finding: checked.code };
    } catch (error) { return { status: "unavailable", anchor: null, finding: error?.code || "PROVIDER_READ_FAILED" }; }
  }
  async function saveMarker(ownerId, anchor) {
    const id = markerId(ownerId), old = await store.getEvidence(ownerId, id);
    const unsigned = { id, ownerId, kind: MARKER_KIND, schemaVersion: 1, anchorSequence: anchor.anchorSequence,
      anchorDigest: anchor.digest, sourceEventDigest: anchor.sourceEventDigest, updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, old ? { expectedVersion: old._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!validateMarker(saved, ownerId).valid || saved.anchorDigest !== anchor.digest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_MARKER_WRITE_FAILED", "Marker baseline lifecycle gagal diverifikasi", 409);
    }
    return saved;
  }
  async function append(ownerId, item, previous, historyNotProven) {
    const { event, record } = item, sequence = previous ? previous.anchorSequence + 1 : 1;
    const unsigned = { ownerId: scopeFor(ownerId), sourceOwnerHash: sha256(ownerId), domain: "root_trust_baseline_lifecycle", kind: ANCHOR_KIND,
      schemaVersion: 1, anchorSequence: sequence, revision: sequence, sourceEventDigest: event.eventDigest,
      lifecycleRecordDigest: record.digest, baselineDigest: event.baselineDigest, eventCreatedAt: event.createdAt,
      previousAnchorDigest: previous?.digest || null, historyNotProven: Boolean(historyNotProven || previous?.historyNotProven), anchoredAt: now() };
    const candidate = { ...unsigned, digest: digestRecord(unsigned) };
    let result;
    try { result = await provider.compareAndSet(scopeFor(ownerId), previous?.digest ?? null, candidate); }
    catch (error) { throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_WRITE_FAILED", "External baseline lifecycle anchor gagal ditulis", 503, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
    if (!result?.applied) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_CAS_CONFLICT", "External baseline lifecycle anchor berubah bersamaan", 409);
    const reread = await readRemote(ownerId);
    if (reread.status !== "present" || reread.anchor.digest !== candidate.digest) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_VERIFY_FAILED", "External baseline lifecycle anchor gagal diverifikasi setelah penulisan", 409);
    await saveMarker(ownerId, candidate);
    return candidate;
  }
  async function status(ownerId) {
    assertOwner(ownerId);
    const [all, markerState, remote] = await Promise.all([events(ownerId), readMarker(ownerId), readRemote(ownerId)]);
    const findings = [];
    if (markerState.status === "invalid") findings.push({ code: markerState.finding });
    if (remote.status === "local_only") return { status: required ? "unavailable" : findings.length ? "unhealthy" : "local_only", ownerId,
      total: all.length, anchorSequence: null, anchorDigest: null, historyNotProven: null, findings, providerConfigured: false, readOnly: true, mutationAllowed: false };
    if (remote.status === "unavailable" || remote.status === "invalid") return { status: "unhealthy", ownerId, total: all.length,
      anchorSequence: null, anchorDigest: null, historyNotProven: null, findings: [...findings, { code: remote.finding || remote.status }], readOnly: true, mutationAllowed: false };
    if (remote.status === "missing") {
      if (markerState.status === "present") findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_MISSING_AFTER_ENROLLMENT" });
      const missingStatus = markerState.status === "present" ? "rollback_suspected" : all.length === 0 ? "not_initialized" : all.length === 1 ? "anchor_pending" : "enrollment_required";
      return { status: markerState.status === "present" ? "rollback_suspected" : findings.length ? "unhealthy" : missingStatus, ownerId, total: all.length, anchorSequence: null, anchorDigest: null,
        historyNotProven: null, findings, readOnly: true, mutationAllowed: false };
    }
    if (markerState.status !== "present") findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_MARKER_MISSING" });
    const anchor = remote.anchor, index = all.findIndex(item => item.event.eventDigest === anchor.sourceEventDigest);
    if (index < 0) findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_EVENT_MISSING" });
    else if (anchor.anchorSequence !== index + 1 || anchor.lifecycleRecordDigest !== all[index].record.digest || anchor.baselineDigest !== all[index].event.baselineDigest) {
      findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_EVENT_MISMATCH" });
    }
    if (markerState.status === "present") {
      const marker = markerState.marker;
      if (marker.anchorSequence > anchor.anchorSequence) findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_ROLLBACK_SUSPECTED" });
      else if (marker.anchorSequence === anchor.anchorSequence && marker.anchorDigest !== anchor.digest) findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_MARKER_MISMATCH" });
      else if (marker.anchorSequence < anchor.anchorSequence && !(marker.anchorSequence + 1 === anchor.anchorSequence && anchor.previousAnchorDigest === marker.anchorDigest)) {
        findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_MARKER_DISCONTINUITY" });
      }
    }
    if (anchor.anchorSequence > all.length) findings.push({ code: "ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_AHEAD_OF_LOCAL_HISTORY" });
    const resultStatus = findings.length ? "unhealthy" : anchor.anchorSequence === all.length ? "anchored" : "behind_local";
    return { status: resultStatus, ownerId, total: all.length, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      anchoredEventDigest: anchor.sourceEventDigest, historyNotProven: anchor.historyNotProven, findings, readOnly: true, mutationAllowed: false };
  }
  async function anchorPending(ownerId) {
    assertOwner(ownerId);
    if (!provider) {
      if (required) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_REQUIRED", "External baseline lifecycle anchor diwajibkan", 503);
      return { status: "local_only", anchored: 0, readOnly: false, mutationAllowed: false };
    }
    const all = await events(ownerId), markerState = await readMarker(ownerId), remote = await readRemote(ownerId);
    if (["unavailable", "invalid"].includes(remote.status) || markerState.status === "invalid") {
      throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_UNHEALTHY", "External baseline lifecycle anchor tidak sehat", 409,
        { status: remote.status, finding: remote.finding || markerState.finding });
    }
    if (remote.status === "missing") {
      if (markerState.status === "present") throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ROLLBACK_SUSPECTED", "External baseline lifecycle anchor hilang setelah enrollment", 409);
      if (!all.length) return { status: "not_initialized", anchored: 0, readOnly: false, mutationAllowed: false };
      if (all.length > 1) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ENROLLMENT_REQUIRED", "Histori baseline yang belum di-anchor memerlukan enrollment eksplisit", 409, { count: all.length });
      const first = await append(ownerId, all[0], null, true);
      return { status: "anchored", anchored: 1, anchorSequence: 1, anchorDigest: first.digest, historyNotProven: true, readOnly: false, mutationAllowed: false };
    }
    if (markerState.status !== "present") throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_MARKER_MISSING", "Marker lokal hilang; anchor tidak dapat dipercaya otomatis", 409);
    let previous = remote.anchor;
    const index = all.findIndex(item => item.event.eventDigest === previous.sourceEventDigest);
    if (index < 0 || previous.anchorSequence !== index + 1 || previous.lifecycleRecordDigest !== all[index].record.digest
      || previous.baselineDigest !== all[index].event.baselineDigest || previous.anchorSequence > all.length) {
      throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_MISMATCH", "External anchor tidak cocok dengan histori lifecycle", 409);
    }
    const marker = markerState.marker;
    if (marker.anchorSequence > previous.anchorSequence || marker.anchorSequence === previous.anchorSequence && marker.anchorDigest !== previous.digest
      || marker.anchorSequence < previous.anchorSequence && !(marker.anchorSequence + 1 === previous.anchorSequence && previous.previousAnchorDigest === marker.anchorDigest)) {
      throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ROLLBACK_SUSPECTED", "Marker lokal menunjukkan rollback atau diskontinuitas", 409);
    }
    if (marker.anchorSequence < previous.anchorSequence) await saveMarker(ownerId, previous);
    let count = 0;
    for (const item of all.slice(index + 1)) { previous = await append(ownerId, item, previous, false); count++; }
    return { status: count ? "anchored" : "already_anchored", anchored: count, anchorSequence: previous.anchorSequence,
      anchorDigest: previous.digest, historyNotProven: previous.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function prepareEnrollment(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!provider) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_NOT_CONFIGURED", "External lifecycle anchor belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ANCHOR_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const state = await status(ownerId);
    if (state.status !== "enrollment_required") throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ENROLLMENT_BLOCKED", "Enrollment hanya berlaku untuk histori lokal yang belum di-anchor", 409, { status: state.status });
    const all = await events(ownerId), createdAt = now(), id = `root-trust-baseline-lifecycle-enrollment-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: ENROLLMENT_KIND, schemaVersion: 1, status: "prepared", expectedCount: all.length,
      expectedHeadDigest: all.at(-1)?.event.eventDigest || null, reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + TTL_MS).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, challengeDigest: challenge.digest, expectedCount: challenge.expectedCount, createdAt, expiresAt: challenge.expiresAt,
      confirmation: `ENROLL ROOT TRUST BASELINE LIFECYCLE ANCHOR ${challenge.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function applyEnrollment(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== ENROLLMENT_KIND || challenge.status !== "prepared"
      || challenge.digest !== digestRecord(challenge) || Date.parse(now()) >= Date.parse(challenge.expiresAt)
      || confirmation !== `ENROLL ROOT TRUST BASELINE LIFECYCLE ANCHOR ${challenge.digest.slice(0, 12)}`) {
      throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ENROLLMENT_CHALLENGE_INVALID", "Challenge enrollment tidak valid, kedaluwarsa, atau konfirmasi tidak cocok", 409);
    }
    const state = await status(ownerId), all = await events(ownerId), remote = await readRemote(ownerId), markerState = await readMarker(ownerId);
    if (state.status !== "enrollment_required" || remote.status !== "missing" || markerState.status !== "missing"
      || all.length !== challenge.expectedCount || all.at(-1)?.event.eventDigest !== challenge.expectedHeadDigest) {
      throw new AgenticError("ROOT_TRUST_BASELINE_LIFECYCLE_ENROLLMENT_STALE", "Histori berubah sejak enrollment disiapkan atau anchor tidak lagi kosong", 409);
    }
    let previous = null;
    for (const item of all) previous = await append(ownerId, item, previous, true);
    const current = await store.getEvidence(ownerId, id);
    const applied = { ...clean(current), status: "applied", appliedAt: now(), anchoredHeadDigest: previous?.digest || null };
    applied.digest = digestRecord(applied);
    await store.putEvidence(ownerId, applied, { expectedVersion: current._storage?.version });
    return { status: "enrolled", anchored: all.length, anchorSequence: previous?.anchorSequence || 0, anchorDigest: previous?.digest || null,
      historyNotProven: true, readOnly: false, mutationAllowed: false };
  }
  return Object.freeze({ getRecoverySloRootTrustBaselineLifecycleAnchorStatus: status,
    anchorPendingRecoverySloRootTrustBaselineLifecycle: anchorPending,
    reconcileRecoverySloRootTrustBaselineLifecycleAnchor: anchorPending,
    prepareRecoverySloRootTrustBaselineLifecycleAnchorEnrollment: prepareEnrollment,
    applyRecoverySloRootTrustBaselineLifecycleAnchorEnrollment: applyEnrollment,
    providerConfigured: Boolean(provider), required });
}
