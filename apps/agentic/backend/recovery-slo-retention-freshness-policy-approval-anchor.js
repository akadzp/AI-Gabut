import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

const ANCHOR_KIND = "recovery-slo-retention-freshness-policy-approval-external-anchor";
const MARKER_KIND = "recovery-slo-retention-freshness-policy-approval-anchor-marker";
const ENROLLMENT_KIND = "recovery-slo-retention-freshness-policy-approval-anchor-enrollment";
const STATE_KIND = "recovery-slo-retention-freshness-policy-approval-state";
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
  const out = {}; for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item); return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const stateId = ownerId => `retention-freshness-policy-approval-${sha256(ownerId).slice(0, 40)}`;
const scopeFor = ownerId => `retention-freshness-policy-approval-${sha256(ownerId).slice(0, 40)}`;
const markerId = ownerId => `retention-freshness-policy-approval-anchor-marker-${sha256(ownerId).slice(0, 40)}`;
const policyDigest = policy => sha256(canonical({ schemaVersion: 1, maxAgeMs: policy?.maxAgeMs, futureSkewMs: policy?.futureSkewMs }));
const validReason = value => typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value);
function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_OWNER_REQUIRED", "Owner freshness-policy anchor wajib ditentukan", 400);
}

export function createRecoverySloRetentionFreshnessPolicyApprovalAnchorService({ store, approvalService, provider = null, required = false,
  clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence
    || typeof approvalService?.auditRecoverySloRetentionFreshnessPolicyApprovals !== "function"
    || typeof clock !== "function" || (provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function"))
    || (required && !provider)) throw new TypeError("Freshness-policy approval anchor membutuhkan store, approval audit, dan provider CAS jika diwajibkan");
  function now() {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_CLOCK_INVALID", "Clock freshness-policy anchor tidak valid", 500);
    return new Date(ms).toISOString();
  }
  function validateState(ownerId, state) {
    if (!state || state.id !== stateId(ownerId) || state.ownerId !== ownerId || state.kind !== STATE_KIND || state.schemaVersion !== 1
      || !Number.isSafeInteger(state.revision) || state.revision < 1 || !Array.isArray(state.events) || state.revision !== state.events.length
      || state.digest !== digestRecord(state)) return false;
    let previous = null;
    for (let i = 0; i < state.events.length; i++) {
      const event = state.events[i], unsigned = clean(event || {}); delete unsigned.eventDigest;
      if (!event || event.sequence !== i + 1 || event.previousEventDigest !== previous || !DIGEST.test(event.eventDigest || "")
        || sha256(canonical(unsigned)) !== event.eventDigest || event.ownerId !== ownerId || event.domain !== "agentic-v4-retention-freshness-policy-approval"
        || !DIGEST.test(event.fromPolicyDigest || "") || !DIGEST.test(event.toPolicyDigest || "")
        || policyDigest(event.toPolicy) !== event.toPolicyDigest || !DIGEST.test(event.challengeDigest || "")
        || !Number.isFinite(Date.parse(event.approvedAt))) return false;
      previous = event.eventDigest;
    }
    return state.approvedPolicy?.digest === state.events.at(-1)?.toPolicyDigest
      && state.approvedPolicy.digest === policyDigest(state.approvedPolicy);
  }
  async function ledger(ownerId) {
    const state = await store.getEvidence(ownerId, stateId(ownerId));
    if (!state) return { status: "not_initialized", state: null, events: [] };
    if (!validateState(ownerId, state)) return { status: "unhealthy", state: null, events: [] };
    return { status: "present", state, events: state.events };
  }
  function validateAnchor(anchor, ownerId) {
    if (!anchor || anchor.ownerId !== scopeFor(ownerId) || anchor.sourceOwnerHash !== sha256(ownerId)
      || anchor.domain !== "retention_freshness_policy_approval" || anchor.kind !== ANCHOR_KIND || anchor.schemaVersion !== 1
      || !Number.isSafeInteger(anchor.anchorSequence) || anchor.anchorSequence < 1 || anchor.revision !== anchor.anchorSequence
      || !DIGEST.test(anchor.sourceEventDigest || "") || !DIGEST.test(anchor.policyDigest || "")
      || !Number.isFinite(Date.parse(anchor.eventApprovedAt)) || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
      || typeof anchor.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(anchor.anchoredAt))
      || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) return { valid: false, code: "RETENTION_FRESHNESS_POLICY_EXTERNAL_ANCHOR_INVALID" };
    if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null) || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null))
      return { valid: false, code: "RETENTION_FRESHNESS_POLICY_EXTERNAL_ANCHOR_CHAIN_INVALID" };
    return { valid: true };
  }
  function validateMarker(marker, ownerId) {
    if (!marker || marker.id !== markerId(ownerId) || marker.ownerId !== ownerId || marker.kind !== MARKER_KIND || marker.schemaVersion !== 1
      || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1 || !DIGEST.test(marker.anchorDigest || "")
      || !DIGEST.test(marker.sourceEventDigest || "") || !Number.isFinite(Date.parse(marker.updatedAt))
      || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker)) return { valid: false, code: "RETENTION_FRESHNESS_POLICY_ANCHOR_MARKER_INVALID" };
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
    if (!validateMarker(saved, ownerId).valid || saved.anchorDigest !== anchor.digest)
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_MARKER_WRITE_FAILED", "Marker freshness-policy anchor gagal diverifikasi", 409);
    return saved;
  }
  async function append(ownerId, event, previous, historyNotProven) {
    const candidateUnsigned = { ownerId: scopeFor(ownerId), sourceOwnerHash: sha256(ownerId), domain: "retention_freshness_policy_approval",
      kind: ANCHOR_KIND, schemaVersion: 1, anchorSequence: previous ? previous.anchorSequence + 1 : 1,
      revision: previous ? previous.revision + 1 : 1, sourceEventDigest: event.eventDigest, policyDigest: event.toPolicyDigest,
      eventApprovedAt: event.approvedAt, previousAnchorDigest: previous?.digest || null,
      historyNotProven: Boolean(historyNotProven || previous?.historyNotProven), anchoredAt: now() };
    const candidate = { ...candidateUnsigned, digest: digestRecord(candidateUnsigned) };
    let result;
    try { result = await provider.compareAndSet(scopeFor(ownerId), previous?.digest ?? null, candidate); }
    catch (error) { throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_WRITE_FAILED", "External freshness-policy approval anchor gagal ditulis", 503, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
    if (!result?.applied) throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_CAS_CONFLICT", "External freshness-policy approval anchor berubah bersamaan", 409);
    const reread = await readRemote(ownerId);
    if (reread.status !== "present" || reread.anchor.digest !== candidate.digest)
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_VERIFY_FAILED", "External freshness-policy approval anchor gagal diverifikasi setelah penulisan", 409);
    await saveMarker(ownerId, candidate);
    return candidate;
  }
  async function status(ownerId) {
    assertOwner(ownerId);
    const [local, markerState, remote] = await Promise.all([ledger(ownerId), readMarker(ownerId), readRemote(ownerId)]);
    const findings = [];
    if (local.status === "unhealthy") return { status: "unhealthy", ownerId, revision: null, anchorSequence: null,
      findings: [{ code: "RETENTION_FRESHNESS_POLICY_APPROVAL_LEDGER_INVALID" }], providerConfigured: Boolean(provider), readOnly: true, mutationAllowed: false };
    if (markerState.status === "invalid") return { status: "unhealthy", ownerId, revision: local.state?.revision ?? 0, anchorSequence: null,
      anchorDigest: null, historyNotProven: null, findings: [{ code: markerState.finding }], providerConfigured: Boolean(provider), readOnly: true, mutationAllowed: false };
    if (remote.status === "local_only") return { status: required ? "unavailable" : findings.length ? "unhealthy" : "local_only", ownerId,
      revision: local.state?.revision ?? 0, anchorSequence: null, anchorDigest: null, historyNotProven: null, findings,
      providerConfigured: false, readOnly: true, mutationAllowed: false };
    if (["unavailable", "invalid"].includes(remote.status)) return { status: "unhealthy", ownerId, revision: local.state?.revision ?? 0,
      anchorSequence: null, anchorDigest: null, historyNotProven: null, findings: [...findings, { code: remote.finding || remote.status }],
      providerConfigured: Boolean(provider), readOnly: true, mutationAllowed: false };
    if (remote.status === "missing") {
      if (markerState.status === "present") findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_MISSING_AFTER_ENROLLMENT" });
      const missingStatus = markerState.status === "present" ? "rollback_suspected" : local.events.length === 0 ? "not_initialized" : local.events.length === 1 ? "anchor_pending" : "enrollment_required";
      return { status: markerState.status === "present" ? "rollback_suspected" : missingStatus, ownerId, revision: local.state?.revision ?? 0,
        anchorSequence: null, anchorDigest: null, historyNotProven: null, findings, providerConfigured: Boolean(provider), readOnly: true, mutationAllowed: false };
    }
    if (markerState.status !== "present") findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_MARKER_MISSING" });
    const anchor = remote.anchor, index = local.events.findIndex(event => event.eventDigest === anchor.sourceEventDigest);
    if (index < 0) findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_EVENT_MISSING" });
    else if (anchor.anchorSequence !== index + 1 || anchor.policyDigest !== local.events[index].toPolicyDigest
      || anchor.eventApprovedAt !== local.events[index].approvedAt) findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_EVENT_MISMATCH" });
    if (markerState.status === "present") {
      const marker = markerState.marker;
      if (marker.anchorSequence > anchor.anchorSequence) findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_ROLLBACK_SUSPECTED" });
      else if (marker.anchorSequence === anchor.anchorSequence && marker.anchorDigest !== anchor.digest) findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_MARKER_MISMATCH" });
      else if (marker.anchorSequence < anchor.anchorSequence && !(marker.anchorSequence + 1 === anchor.anchorSequence && anchor.previousAnchorDigest === marker.anchorDigest))
        findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_MARKER_DISCONTINUITY" });
    }
    if (anchor.anchorSequence > local.events.length) findings.push({ code: "RETENTION_FRESHNESS_POLICY_ANCHOR_AHEAD_OF_LOCAL_HISTORY" });
    const resultStatus = findings.length ? "unhealthy" : anchor.anchorSequence === local.events.length ? "anchored" : "behind_local";
    return { status: resultStatus, ownerId, revision: local.state?.revision ?? 0, anchorSequence: anchor.anchorSequence,
      anchorDigest: anchor.digest, anchoredEventDigest: anchor.sourceEventDigest, historyNotProven: anchor.historyNotProven,
      findings, providerConfigured: Boolean(provider), readOnly: true, mutationAllowed: false };
  }
  async function anchorPending(ownerId) {
    assertOwner(ownerId);
    if (!provider) {
      if (required) throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_REQUIRED", "External freshness-policy approval anchor diwajibkan", 503);
      return { status: "local_only", anchored: 0, readOnly: false, mutationAllowed: false };
    }
    const local = await ledger(ownerId), markerState = await readMarker(ownerId), remote = await readRemote(ownerId);
    if (local.status === "unhealthy" || ["unavailable", "invalid"].includes(remote.status) || markerState.status === "invalid")
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_UNHEALTHY", "Ledger atau external freshness-policy anchor tidak sehat", 409,
        { localStatus: local.status, remoteStatus: remote.status, finding: remote.finding || markerState.finding });
    if (remote.status === "missing") {
      if (markerState.status === "present") throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_ROLLBACK_SUSPECTED", "External approval anchor hilang setelah enrollment", 409);
      if (!local.events.length) return { status: "not_initialized", anchored: 0, readOnly: false, mutationAllowed: false };
      if (local.events.length > 1) throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_ENROLLMENT_REQUIRED", "Histori approval yang belum di-anchor memerlukan enrollment eksplisit", 409, { count: local.events.length });
      const first = await append(ownerId, local.events[0], null, true);
      return { status: "anchored", anchored: 1, anchorSequence: 1, anchorDigest: first.digest, historyNotProven: true, readOnly: false, mutationAllowed: false };
    }
    if (markerState.status !== "present") throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_MARKER_MISSING", "Marker lokal hilang; external approval anchor tidak dapat dipercaya otomatis", 409);
    let previous = remote.anchor;
    const index = local.events.findIndex(event => event.eventDigest === previous.sourceEventDigest);
    if (index < 0 || previous.anchorSequence !== index + 1 || previous.policyDigest !== local.events[index].toPolicyDigest
      || previous.eventApprovedAt !== local.events[index].approvedAt || previous.anchorSequence > local.events.length)
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_MISMATCH", "External approval anchor tidak cocok dengan histori lokal", 409);
    const marker = markerState.marker;
    if (marker.anchorSequence > previous.anchorSequence || marker.anchorSequence === previous.anchorSequence && marker.anchorDigest !== previous.digest
      || marker.anchorSequence < previous.anchorSequence && !(marker.anchorSequence + 1 === previous.anchorSequence && previous.previousAnchorDigest === marker.anchorDigest))
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_ROLLBACK_SUSPECTED", "Marker lokal menunjukkan rollback atau diskontinuitas", 409);
    if (marker.anchorSequence < previous.anchorSequence) await saveMarker(ownerId, previous);
    let count = 0;
    for (const event of local.events.slice(index + 1)) { previous = await append(ownerId, event, previous, false); count++; }
    return { status: count ? "anchored" : "already_anchored", anchored: count, anchorSequence: previous.anchorSequence,
      anchorDigest: previous.digest, historyNotProven: previous.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function prepareEnrollment(ownerId, { reason } = {}) {
    assertOwner(ownerId);
    if (!provider) throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_NOT_CONFIGURED", "External freshness-policy approval anchor belum dikonfigurasi", 503);
    if (!validReason(reason)) throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const current = await status(ownerId);
    if (current.status !== "enrollment_required") throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_ENROLLMENT_BLOCKED", "Enrollment hanya berlaku untuk histori lokal yang belum di-anchor", 409, { status: current.status });
    const local = await ledger(ownerId), createdAt = now(), id = `retention-freshness-policy-anchor-enrollment-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: ENROLLMENT_KIND, schemaVersion: 1, status: "prepared", expectedCount: local.events.length,
      expectedHeadDigest: local.events.at(-1)?.eventDigest || null, reason: reason.trim(), createdAt,
      expiresAt: new Date(Date.parse(createdAt) + TTL_MS).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, challengeDigest: challenge.digest, expectedCount: challenge.expectedCount, createdAt, expiresAt: challenge.expiresAt,
      confirmation: `ENROLL RETENTION FRESHNESS POLICY ANCHOR ${challenge.digest.slice(0, 12)}`, readOnly: false, mutationAllowed: false };
  }
  async function applyEnrollment(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== ENROLLMENT_KIND || challenge.status !== "prepared"
      || challenge.digest !== digestRecord(challenge) || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(now()) >= Date.parse(challenge.expiresAt)
      || confirmation !== `ENROLL RETENTION FRESHNESS POLICY ANCHOR ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_ENROLLMENT_CHALLENGE_INVALID", "Challenge enrollment tidak valid, kedaluwarsa, atau konfirmasi tidak cocok", 409);
    const [current, local, remote, markerState] = await Promise.all([status(ownerId), ledger(ownerId), readRemote(ownerId), readMarker(ownerId)]);
    if (current.status !== "enrollment_required" || remote.status !== "missing" || markerState.status !== "missing"
      || local.events.length !== challenge.expectedCount || local.events.at(-1)?.eventDigest !== challenge.expectedHeadDigest)
      throw new AgenticError("RETENTION_FRESHNESS_POLICY_ANCHOR_ENROLLMENT_STALE", "Histori berubah sejak enrollment disiapkan atau anchor tidak lagi kosong", 409);
    let previous = null;
    for (const event of local.events) previous = await append(ownerId, event, previous, true);
    const saved = await store.getEvidence(ownerId, id), unsigned = { ...clean(saved), status: "applied", appliedAt: now(), anchoredHeadDigest: previous?.digest || null };
    delete unsigned.digest;
    await store.putEvidence(ownerId, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: saved._storage?.version });
    return { status: "enrolled", anchored: local.events.length, anchorSequence: previous?.anchorSequence || 0,
      anchorDigest: previous?.digest || null, historyNotProven: true, readOnly: false, mutationAllowed: false };
  }
  async function audit(ownerId) {
    assertOwner(ownerId);
    const [approvalAudit, anchor] = await Promise.all([approvalService.auditRecoverySloRetentionFreshnessPolicyApprovals(ownerId), status(ownerId)]);
    const findings = [...(approvalAudit.findings || []), ...(anchor.findings || [])];
    if (approvalAudit.status === "unhealthy" || anchor.status === "unhealthy" || anchor.status === "rollback_suspected")
      return { status: "unhealthy", ownerId, approvalStatus: approvalAudit.status, anchor, findings, readOnly: true, mutationAllowed: false };
    if (anchor.status === "behind_local" || anchor.status === "anchor_pending" || anchor.status === "enrollment_required" || anchor.status === "unavailable")
      return { status: "external_anchor_pending", ownerId, approvalStatus: approvalAudit.status, anchor, findings, readOnly: true, mutationAllowed: false };
    if (approvalAudit.status === "deployment_pending") return { status: "deployment_pending", ownerId, approvalStatus: approvalAudit.status, anchor, findings, readOnly: true, mutationAllowed: false };
    return { status: approvalAudit.status === "not_initialized" ? "not_initialized" : "healthy", ownerId,
      approvalStatus: approvalAudit.status, anchor, findings, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ getRecoverySloRetentionFreshnessPolicyApprovalAnchorStatus: status,
    anchorPendingRecoverySloRetentionFreshnessPolicyApprovals: anchorPending,
    reconcileRecoverySloRetentionFreshnessPolicyApprovalAnchor: anchorPending,
    prepareRecoverySloRetentionFreshnessPolicyApprovalAnchorEnrollment: prepareEnrollment,
    applyRecoverySloRetentionFreshnessPolicyApprovalAnchorEnrollment: applyEnrollment,
    auditRecoverySloRetentionFreshnessPolicyApprovalAnchor: audit, providerConfigured: Boolean(provider), required });
}
