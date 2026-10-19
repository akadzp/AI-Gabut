import { createHash, randomUUID } from "node:crypto";
import { AgenticError } from "./errors.js";

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
  const out = {}; for (const [key, item] of Object.entries(value)) if (key !== "_storage") out[key] = clean(item); return out;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
function assertOwner(ownerId, domain) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_OWNER_REQUIRED", `Owner ${domain} wajib ditentukan`, 400);
}
function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }

export function createRecoverySloExternalSnapshotCheckpointService({ store, provider = null, sourceReader, domain, kind, required = false,
  policyReader = null, clock = () => new Date().toISOString() } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof sourceReader !== "function"
    || typeof domain !== "string" || !/^[a-z0-9_]{3,80}$/.test(domain) || typeof kind !== "string"
    || typeof clock !== "function" || policyReader !== null && typeof policyReader !== "function"
    || provider && (typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") || required && !provider) throw new TypeError("External snapshot checkpoint membutuhkan store, source reader, domain, dan provider CAS jika diwajibkan");
  const markerKind = `${kind}-marker`, challengeKind = `${kind}-enrollment-challenge`;
  const scopeFor = ownerId => `agentic-v4-${domain}-${sha256(ownerId).slice(0, 32)}`;
  const markerId = ownerId => `${kind}-marker-${sha256(ownerId).slice(0, 40)}`;
  const policyChallengeKind = `${kind}-policy-binding-challenge`;
  const policyEventKind = `${kind}-policy-binding-event`;
  const now = () => {
    const ms = Date.parse(String(clock()));
    if (!Number.isFinite(ms)) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_CLOCK_INVALID", `Clock ${domain} tidak valid`, 500);
    return new Date(ms).toISOString();
  };
  async function readPolicy(ownerId) {
    if (!policyReader) return null;
    let policy;
    try { policy = await policyReader(ownerId); }
    catch { throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_UNAVAILABLE", `Kebijakan checkpoint ${domain} tidak dapat dibaca`, 503); }
    if (!policy || typeof policy !== "object" || Array.isArray(policy))
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_INVALID", `Kebijakan checkpoint ${domain} tidak valid`, 500);
    const normalized = clean({ schemaVersion: 1, domain, ...policy });
    return { policy: normalized, digest: sha256(canonical(normalized)) };
  }
  async function readSource(ownerId) {
    const source = await sourceReader(ownerId);
    if (!source || !["healthy", "recoverable", "not_initialized"].includes(source.status))
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_SOURCE_UNHEALTHY", `Sumber ${domain} tidak sehat; checkpoint ditolak`, 409,
        { sourceStatus: source?.status || "unavailable", findings: source?.findings || [] });
    const snapshot = clean(source.snapshot ?? {}), digest = source.digest || sha256(canonical(snapshot)), count = source.count ?? 0;
    if (!DIGEST.test(digest) || digest !== sha256(canonical(snapshot)) || !Number.isSafeInteger(count) || count < 0)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_SOURCE_INVALID", `Snapshot ${domain} tidak valid`, 409);
    return { status: source.status, snapshot, digest, count, historyNotProven: Boolean(source.historyNotProven), findings: source.findings || [] };
  }
  function validateAnchor(anchor, ownerId) {
    if (!anchor || anchor.ownerId !== scopeFor(ownerId) || anchor.sourceOwnerHash !== sha256(ownerId) || anchor.domain !== domain
      || anchor.kind !== `${kind}-external-anchor` || anchor.schemaVersion !== 1 || !Number.isSafeInteger(anchor.anchorSequence)
      || anchor.anchorSequence < 1 || anchor.revision !== anchor.anchorSequence || !DIGEST.test(anchor.snapshotDigest || "")
      || !Number.isSafeInteger(anchor.sourceCount) || anchor.sourceCount < 0 || (anchor.previousAnchorDigest !== null && !DIGEST.test(anchor.previousAnchorDigest || ""))
      || typeof anchor.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(anchor.anchoredAt))
      || anchor.policyDigest !== undefined && anchor.policyDigest !== null && !DIGEST.test(anchor.policyDigest)
      || !DIGEST.test(anchor.digest || "") || anchor.digest !== digestRecord(anchor)) return { valid: false, code: "EXTERNAL_SNAPSHOT_CHECKPOINT_ANCHOR_INVALID" };
    if ((anchor.anchorSequence === 1 && anchor.previousAnchorDigest !== null) || (anchor.anchorSequence > 1 && anchor.previousAnchorDigest === null))
      return { valid: false, code: "EXTERNAL_SNAPSHOT_CHECKPOINT_CHAIN_INVALID" };
    return { valid: true };
  }
  function validateMarker(marker, ownerId) {
    if (!marker || marker.id !== markerId(ownerId) || marker.ownerId !== ownerId || marker.kind !== markerKind || marker.schemaVersion !== 1
      || !Number.isSafeInteger(marker.anchorSequence) || marker.anchorSequence < 1 || !DIGEST.test(marker.anchorDigest || "")
      || !DIGEST.test(marker.snapshotDigest || "") || !Number.isSafeInteger(marker.sourceCount) || marker.sourceCount < 0
      || !Number.isFinite(Date.parse(marker.updatedAt)) || marker.policyDigest !== undefined && marker.policyDigest !== null && !DIGEST.test(marker.policyDigest)
      || !DIGEST.test(marker.digest || "") || marker.digest !== digestRecord(marker))
      return { valid: false, code: "EXTERNAL_SNAPSHOT_CHECKPOINT_MARKER_INVALID" };
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
    const id = markerId(ownerId), previous = await store.getEvidence(ownerId, id);
    const unsigned = { id, ownerId, kind: markerKind, schemaVersion: 1, anchorSequence: anchor.anchorSequence,
      anchorDigest: anchor.digest, snapshotDigest: anchor.snapshotDigest, sourceCount: anchor.sourceCount,
      ...(anchor.policyDigest ? { policyDigest: anchor.policyDigest } : {}), updatedAt: now() };
    const marker = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, marker, previous ? { expectedVersion: previous._storage?.version } : { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!validateMarker(saved, ownerId).valid || saved.anchorDigest !== anchor.digest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_MARKER_WRITE_FAILED", `Marker ${domain} gagal diverifikasi`, 409);
    return saved;
  }
  async function append(ownerId, source, previous, historyNotProven = false) {
    const currentPolicy = await readPolicy(ownerId);
    const unsigned = { ownerId: scopeFor(ownerId), sourceOwnerHash: sha256(ownerId), domain, kind: `${kind}-external-anchor`, schemaVersion: 1,
      ...(currentPolicy ? { policyDigest: currentPolicy.digest } : {}),
      anchorSequence: previous ? previous.anchorSequence + 1 : 1, revision: previous ? previous.revision + 1 : 1,
      snapshotDigest: source.digest, sourceCount: source.count, previousAnchorDigest: previous?.digest || null,
      historyNotProven: Boolean(historyNotProven || source.historyNotProven || previous?.historyNotProven), anchoredAt: now() };
    const candidate = { ...unsigned, digest: digestRecord(unsigned) };
    let result;
    try { result = await provider.compareAndSet(scopeFor(ownerId), previous?.digest ?? null, candidate); }
    catch (error) { throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_WRITE_FAILED", `External checkpoint ${domain} gagal ditulis`, 503, { cause: error?.code || "PROVIDER_WRITE_FAILED" }); }
    if (!result?.applied) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_CAS_CONFLICT", `External checkpoint ${domain} mengalami CAS conflict`, 409);
    const reread = await readRemote(ownerId);
    if (reread.status !== "present" || reread.anchor.digest !== candidate.digest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_VERIFY_FAILED", `External checkpoint ${domain} gagal diverifikasi setelah penulisan`, 409);
    await saveMarker(ownerId, candidate);
    return candidate;
  }
  async function status(ownerId) {
    assertOwner(ownerId, domain);
    let source;
    try { source = await readSource(ownerId); }
    catch (error) { return { status: "unhealthy", ownerId, domain, findings: [{ code: error?.code || "SOURCE_READ_FAILED" }], readOnly: true, mutationAllowed: false }; }
    let markerState, remote, currentPolicy;
    try { [markerState, remote, currentPolicy] = await Promise.all([readMarker(ownerId), readRemote(ownerId), readPolicy(ownerId)]); }
    catch (error) { return { status: "unhealthy", ownerId, domain, sourceCount: source.count,
      findings: [...source.findings, { code: error?.code || "CHECKPOINT_POLICY_READ_FAILED" }], readOnly: true, mutationAllowed: false }; }
    const findings = [...source.findings];
    if (markerState.status === "invalid") return { status: "unhealthy", ownerId, domain, sourceCount: source.count, findings: [...findings, { code: markerState.finding }], readOnly: true, mutationAllowed: false };
    if (remote.status === "local_only") return { status: required ? "unavailable" : "local_only", ownerId, domain, sourceCount: source.count,
      sourceDigest: source.digest, providerConfigured: false, findings, readOnly: true, mutationAllowed: false };
    if (["unavailable", "invalid"].includes(remote.status)) return { status: "unhealthy", ownerId, domain, sourceCount: source.count,
      findings: [...findings, { code: remote.finding || remote.status }], readOnly: true, mutationAllowed: false };
    if (remote.status === "missing") {
      if (markerState.status === "present") return { status: "rollback_suspected", ownerId, domain, sourceCount: source.count,
        sourceDigest: source.digest, markerSequence: markerState.marker.anchorSequence, markerDigest: markerState.marker.anchorDigest,
        markerSnapshotDigest: markerState.marker.snapshotDigest, markerSourceCount: markerState.marker.sourceCount,
        findings: [...findings, { code: "EXTERNAL_SNAPSHOT_CHECKPOINT_MISSING_AFTER_ENROLLMENT" }], readOnly: true, mutationAllowed: false };
      return { status: source.count ? "enrollment_required" : "not_initialized", ownerId, domain, sourceCount: source.count,
        sourceDigest: source.digest, findings, readOnly: true, mutationAllowed: false };
    }
    const anchor = remote.anchor;
    if (markerState.status !== "present") return { status: "unhealthy", ownerId, domain, sourceCount: source.count,
      anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, anchorAnchoredAt: anchor.anchoredAt,
      findings: [...findings, { code: "EXTERNAL_SNAPSHOT_CHECKPOINT_MARKER_MISSING" }], readOnly: true, mutationAllowed: false };
    const marker = markerState.marker;
    if (marker.anchorSequence > anchor.anchorSequence || marker.anchorSequence === anchor.anchorSequence && marker.anchorDigest !== anchor.digest)
      return { status: "rollback_suspected", ownerId, domain, sourceCount: source.count, sourceDigest: source.digest,
        anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, anchorAnchoredAt: anchor.anchoredAt,
        markerSequence: markerState.marker.anchorSequence, markerDigest: markerState.marker.anchorDigest,
        markerSnapshotDigest: markerState.marker.snapshotDigest, markerSourceCount: markerState.marker.sourceCount,
        findings: [...findings, { code: "EXTERNAL_SNAPSHOT_CHECKPOINT_ROLLBACK_OR_MARKER_CONFLICT" }], readOnly: true, mutationAllowed: false };
    if (marker.anchorSequence < anchor.anchorSequence) {
      const recoverable = marker.anchorSequence + 1 === anchor.anchorSequence && anchor.previousAnchorDigest === marker.anchorDigest
        && anchor.snapshotDigest === source.digest && anchor.sourceCount === source.count;
      return { status: recoverable ? "marker_pending" : "unhealthy", ownerId, domain, sourceCount: source.count,
        anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, anchoredSourceCount: anchor.sourceCount, anchorAnchoredAt: anchor.anchoredAt,
        findings: recoverable ? findings : [...findings, { code: "EXTERNAL_SNAPSHOT_CHECKPOINT_MARKER_DISCONTINUITY" }],
        readOnly: true, mutationAllowed: false };
    }
    if (anchor.previousAnchorDigest !== null && marker.anchorSequence > 1 && marker.anchorDigest !== anchor.digest)
      return { status: "unhealthy", ownerId, domain, sourceCount: source.count, anchorSequence: anchor.anchorSequence,
        anchorDigest: anchor.digest, anchorAnchoredAt: anchor.anchoredAt, findings: [...findings, { code: "EXTERNAL_SNAPSHOT_CHECKPOINT_MARKER_MISMATCH" }], readOnly: true, mutationAllowed: false };
    if (source.count < anchor.sourceCount) return { status: "rollback_suspected", ownerId, domain, sourceCount: source.count,
      sourceDigest: source.digest, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, anchorAnchoredAt: anchor.anchoredAt,
      markerSequence: marker.anchorSequence, markerDigest: marker.anchorDigest,
      markerSnapshotDigest: marker.snapshotDigest, markerSourceCount: marker.sourceCount,
      findings: [...findings, { code: "EXTERNAL_SNAPSHOT_CHECKPOINT_SOURCE_ROLLBACK" }], readOnly: true, mutationAllowed: false };
    const aligned = anchor.snapshotDigest === source.digest && anchor.sourceCount === source.count;
    const policyDrift = Boolean(currentPolicy && anchor.policyDigest !== currentPolicy.digest);
    const baseStatus = aligned ? "anchored" : "behind_local";
    return { status: policyDrift && aligned ? "policy_drift" : baseStatus, sourceStatus: baseStatus, policyDrift,
      policyBindingStatus: !currentPolicy ? "not_configured" : policyDrift ? "drift_detected" : "current",
      ...(currentPolicy ? { currentPolicyDigest: currentPolicy.digest } : {}),
      ...(anchor.policyDigest ? { anchoredPolicyDigest: anchor.policyDigest } : { anchoredPolicyDigest: null }),
      ownerId, domain, sourceCount: source.count, sourceDigest: source.digest,
      anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, anchoredSourceCount: anchor.sourceCount,
      anchorAnchoredAt: anchor.anchoredAt, anchoredSourceDigest: anchor.snapshotDigest,
      historyNotProven: anchor.historyNotProven, findings: policyDrift ? [...findings, { code: "EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_DRIFT" }] : findings,
      readOnly: true, mutationAllowed: false };
  }
  async function reconcile(ownerId) {
    assertOwner(ownerId, domain);
    if (!provider) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_PROVIDER_REQUIRED", `Provider external checkpoint ${domain} belum dikonfigurasi`, 503);
    const current = await status(ownerId);
    if (current.status === "marker_pending") {
      const remote = await readRemote(ownerId);
      if (remote.status !== "present") throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_REMOTE_UNAVAILABLE", "Anchor tidak dapat dibaca untuk memperbaiki marker", 503);
      await saveMarker(ownerId, remote.anchor);
      return { status: "marker_repaired", domain, anchorSequence: remote.anchor.anchorSequence, anchorDigest: remote.anchor.digest,
        historyNotProven: remote.anchor.historyNotProven, readOnly: false, mutationAllowed: false };
    }
    if (current.policyDrift) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_DRIFT", `Rekonsiliasi ${domain} ditolak sampai perubahan kebijakan disetujui secara eksplisit`, 409,
      { status: current.status, findings: current.findings || [] });
    if (current.status !== "behind_local") throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_RECONCILIATION_BLOCKED", `Rekonsiliasi ${domain} ditolak karena status bukan behind_local`, 409,
      { status: current.status, findings: current.findings || [] });
    const source = await readSource(ownerId), markerState = await readMarker(ownerId), remote = await readRemote(ownerId);
    if (markerState.status !== "present" || remote.status !== "present" || markerState.marker.anchorDigest !== remote.anchor.digest
      || markerState.marker.anchorSequence !== remote.anchor.anchorSequence || source.count < remote.anchor.sourceCount)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_CONTINUITY_UNPROVEN", `Kontinuitas ${domain} tidak dapat dibuktikan`, 409);
    const anchor = await append(ownerId, source, remote.anchor, false);
    return { status: "anchored", domain, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      sourceDigest: source.digest, historyNotProven: anchor.historyNotProven, readOnly: false, mutationAllowed: false };
  }
  async function reconcileApprovedMultiEventGap(ownerId, expected = {}) {
    assertOwner(ownerId, domain);
    if (!provider) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_PROVIDER_REQUIRED", `Provider external checkpoint ${domain} belum dikonfigurasi`, 503);
    const { expectedAnchorDigest, expectedAnchorSequence, expectedSourceDigest, expectedSourceCount,
      expectedPolicyDigest, candidateEventIds, approvalDigest, approvalVerifier } = expected || {};
    if (!DIGEST.test(expectedAnchorDigest || "") || !Number.isSafeInteger(expectedAnchorSequence) || expectedAnchorSequence < 1
      || !DIGEST.test(expectedSourceDigest || "") || !Number.isSafeInteger(expectedSourceCount) || expectedSourceCount < 2
      || !DIGEST.test(expectedPolicyDigest || "") || !DIGEST.test(approvalDigest || "") || !Array.isArray(candidateEventIds)
      || candidateEventIds.length < 2 || candidateEventIds.some(item => !item || typeof item.id !== "string" || !DIGEST.test(item.digest || ""))
      || new Set(candidateEventIds.map(item => item.id)).size !== candidateEventIds.length || typeof approvalVerifier !== "function")
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_BINDING_INVALID", `Binding finalisasi multi-event ${domain} tidak valid`, 400);
    const current = await status(ownerId);
    if (current.status === "marker_pending") {
      const [source, markerState, remote, policy] = await Promise.all([readSource(ownerId), readMarker(ownerId), readRemote(ownerId), readPolicy(ownerId)]);
      if (source.status === "healthy" && source.digest === expectedSourceDigest && source.count === expectedSourceCount
        && markerState.status === "present" && markerState.marker.anchorDigest === expectedAnchorDigest
        && markerState.marker.anchorSequence === expectedAnchorSequence && remote.status === "present"
        && remote.anchor.anchorSequence === expectedAnchorSequence + 1 && remote.anchor.previousAnchorDigest === expectedAnchorDigest
        && remote.anchor.snapshotDigest === expectedSourceDigest && remote.anchor.sourceCount === expectedSourceCount
        && policy?.digest === expectedPolicyDigest) {
        const approvalCheck = await approvalVerifier({ source, anchor: remote.anchor, policy, candidateEventIds: structuredClone(candidateEventIds), approvalDigest, idempotent: true });
        if (approvalCheck !== true) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_APPROVAL_INVALID", `Approval finalisasi ${domain} tidak valid untuk recovery marker`, 409);
        await saveMarker(ownerId, remote.anchor);
        const recovered = await status(ownerId);
        if (recovered.status !== "anchored") throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_MARKER_RECOVERY_FAILED", `Marker ${domain} tidak dapat difinalisasi`, 409);
        return { status: "anchored", domain, anchorSequence: remote.anchor.anchorSequence, anchorDigest: remote.anchor.digest,
          sourceDigest: remote.anchor.snapshotDigest, sourceCount: remote.anchor.sourceCount, approvalDigest, candidateEventCount: candidateEventIds.length,
          sourceStillCurrent: true, usableForCurrentDecision: !remote.anchor.historyNotProven, historyNotProven: remote.anchor.historyNotProven,
          idempotent: true, markerRecovered: true, readOnly: false, mutationAllowed: false };
      }
    }
    if (current.status === "anchored" && current.sourceDigest === expectedSourceDigest && current.sourceCount === expectedSourceCount
      && current.anchorSequence === expectedAnchorSequence + 1) {
      const [source, remote, policy] = await Promise.all([readSource(ownerId), readRemote(ownerId), readPolicy(ownerId)]);
      if (source.status === "healthy" && source.digest === expectedSourceDigest && source.count === expectedSourceCount
        && remote.status === "present" && remote.anchor.digest === current.anchorDigest && remote.anchor.previousAnchorDigest === expectedAnchorDigest
        && remote.anchor.snapshotDigest === expectedSourceDigest && remote.anchor.sourceCount === expectedSourceCount && policy?.digest === expectedPolicyDigest) {
        const approvalCheck = await approvalVerifier({ source, anchor: remote.anchor, policy, candidateEventIds: structuredClone(candidateEventIds), approvalDigest, idempotent: true });
        if (approvalCheck !== true) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_APPROVAL_INVALID", `Approval finalisasi ${domain} tidak valid untuk pemulihan idempotent`, 409);
        return { status: "anchored", domain, anchorSequence: remote.anchor.anchorSequence, anchorDigest: remote.anchor.digest,
          sourceDigest: remote.anchor.snapshotDigest, sourceCount: remote.anchor.sourceCount, approvalDigest, candidateEventCount: candidateEventIds.length,
          sourceStillCurrent: true, usableForCurrentDecision: !remote.anchor.historyNotProven, historyNotProven: remote.anchor.historyNotProven,
          idempotent: true, readOnly: false, mutationAllowed: false };
      }
    }
    if (current.status !== "behind_local" || current.policyDrift || current.anchorDigest !== expectedAnchorDigest
      || current.anchorSequence !== expectedAnchorSequence || current.sourceDigest !== expectedSourceDigest || current.sourceCount !== expectedSourceCount)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_STALE", `Checkpoint ${domain} berubah sejak approval dibuat`, 409,
        { status: current.status, anchorDigest: current.anchorDigest, anchorSequence: current.anchorSequence, sourceDigest: current.sourceDigest, sourceCount: current.sourceCount });
    const [source, markerState, remote, policy] = await Promise.all([readSource(ownerId), readMarker(ownerId), readRemote(ownerId), readPolicy(ownerId)]);
    if (source.status !== "healthy" || source.digest !== expectedSourceDigest || source.count !== expectedSourceCount
      || markerState.status !== "present" || remote.status !== "present" || markerState.marker.anchorDigest !== expectedAnchorDigest
      || markerState.marker.anchorSequence !== expectedAnchorSequence || remote.anchor.digest !== expectedAnchorDigest
      || remote.anchor.anchorSequence !== expectedAnchorSequence || policy?.digest !== expectedPolicyDigest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_STALE", `Snapshot, marker, anchor, atau policy ${domain} tidak lagi cocok`, 409,
        { sourceStatus: source.status, sourceDigest: source.digest, sourceCount: source.count, markerStatus: markerState.status, remoteStatus: remote.status,
          policyDigest: policy?.digest || null });
    const events = source.snapshot?.events;
    if (!Array.isArray(events) || events.length !== source.count || candidateEventIds.length !== source.count - remote.anchor.sourceCount)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_SHAPE_INVALID", `Snapshot ${domain} tidak mendukung finalisasi gap multi-event`, 409);
    const candidateById = new Map(candidateEventIds.map(item => [item.id, item]));
    const actualCandidates = events.filter(item => candidateById.has(item.id));
    if (actualCandidates.length !== candidateEventIds.length || actualCandidates.some(item => candidateById.get(item.id).digest !== item.digest))
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_CANDIDATES_CHANGED", `Kandidat gap ${domain} berubah`, 409);
    const previousSnapshot = structuredClone(source.snapshot);
    previousSnapshot.events = events.filter(item => !candidateById.has(item.id));
    if (previousSnapshot.events.length !== remote.anchor.sourceCount || sha256(canonical(previousSnapshot)) !== remote.anchor.snapshotDigest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_CONTINUITY_UNPROVEN", `Kandidat gap ${domain} tidak merekonstruksi snapshot yang di-anchor`, 409);
    const approvalCheck = await approvalVerifier({ source, anchor: remote.anchor, policy, candidateEventIds: structuredClone(candidateEventIds), approvalDigest });
    if (approvalCheck !== true) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_APPROVAL_INVALID", `Approval finalisasi ${domain} tidak lagi valid`, 409);
    // Re-read all CAS bindings immediately before the external compare-and-set.
    const [sourceAgain, remoteAgain, markerAgain, policyAgain] = await Promise.all([readSource(ownerId), readRemote(ownerId), readMarker(ownerId), readPolicy(ownerId)]);
    if (sourceAgain.digest !== expectedSourceDigest || sourceAgain.count !== expectedSourceCount || sourceAgain.status !== "healthy"
      || remoteAgain.status !== "present" || remoteAgain.anchor.digest !== expectedAnchorDigest || remoteAgain.anchor.anchorSequence !== expectedAnchorSequence
      || markerAgain.status !== "present" || markerAgain.marker.anchorDigest !== expectedAnchorDigest
      || markerAgain.marker.anchorSequence !== expectedAnchorSequence || policyAgain?.digest !== expectedPolicyDigest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_CAS_PRECONDITION_FAILED", `Precondition CAS ${domain} berubah sebelum finalisasi`, 409);
    const finalApprovalCheck = await approvalVerifier({ source: sourceAgain, anchor: remoteAgain.anchor, policy: policyAgain,
      candidateEventIds: structuredClone(candidateEventIds), approvalDigest });
    if (finalApprovalCheck !== true) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_APPROVED_GAP_APPROVAL_STALE", `Approval finalisasi ${domain} menjadi stale sebelum CAS`, 409);
    const anchor = await append(ownerId, sourceAgain, remoteAgain.anchor, false);
    const sourceAfter = await readSource(ownerId);
    const sourceStillCurrent = sourceAfter.digest === anchor.snapshotDigest && sourceAfter.count === anchor.sourceCount;
    return { status: sourceStillCurrent ? "anchored" : "anchored_but_source_advanced", domain, anchorSequence: anchor.anchorSequence,
      anchorDigest: anchor.digest, sourceDigest: anchor.snapshotDigest, sourceCount: anchor.sourceCount, approvalDigest,
      candidateEventCount: candidateEventIds.length, sourceStillCurrent, usableForCurrentDecision: sourceStillCurrent && !anchor.historyNotProven,
      historyNotProven: anchor.historyNotProven, readOnly: false, mutationAllowed: false };
  }

  async function inspectMarkerRecoveryIntent(ownerId) {
    assertOwner(ownerId, domain);
    if (!provider) return { status: required ? "unavailable" : "local_only", domain, recoverable: false,
      findings: [{ code: "EXTERNAL_SNAPSHOT_CHECKPOINT_PROVIDER_REQUIRED" }], readOnly: true, mutationAllowed: false };
    let source, currentPolicy;
    try { [source, currentPolicy] = await Promise.all([readSource(ownerId), readPolicy(ownerId)]); }
    catch (error) { return { status: "unhealthy", domain, recoverable: false,
      findings: [{ code: error?.code || "EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_INSPECTION_FAILED" }], readOnly: true, mutationAllowed: false }; }
    const [markerState, remote] = await Promise.all([readMarker(ownerId), readRemote(ownerId)]);
    if (source.status === "unhealthy" || markerState.status === "invalid" || remote.status === "invalid")
      return { status: "unhealthy", domain, recoverable: false,
        findings: [{ code: markerState.finding || remote.finding || "EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_SOURCE_UNHEALTHY" }], readOnly: true, mutationAllowed: false };
    if (remote.status !== "present") return { status: remote.status === "unavailable" ? "unavailable" : "anchor_missing", domain,
      recoverable: false, findings: [{ code: remote.finding || "EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_ANCHOR_NOT_PRESENT" }], readOnly: true, mutationAllowed: false };
    const anchor = remote.anchor;
    const currentPolicyDigest = currentPolicy?.digest ?? null;
    if ((anchor.policyDigest ?? null) !== currentPolicyDigest)
      return { status: "policy_drift", domain, recoverable: false, anchorSequence: anchor.anchorSequence,
        anchorDigest: anchor.digest, anchoredPolicyDigest: anchor.policyDigest ?? null, currentPolicyDigest,
        findings: [{ code: "EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_POLICY_DRIFT" }], readOnly: true, mutationAllowed: false };
    if (source.digest !== anchor.snapshotDigest || source.count !== anchor.sourceCount)
      return { status: "source_advanced", domain, recoverable: false, anchorSequence: anchor.anchorSequence,
        anchorDigest: anchor.digest, anchoredSourceDigest: anchor.snapshotDigest, anchoredSourceCount: anchor.sourceCount,
        sourceDigest: source.digest, sourceCount: source.count,
        markerSequence: markerState.status === "present" ? markerState.marker.anchorSequence : null,
        markerDigest: markerState.status === "present" ? markerState.marker.anchorDigest : null,
        markerSnapshotDigest: markerState.status === "present" ? markerState.marker.snapshotDigest : null,
        findings: [{ code: "EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_SOURCE_ADVANCED" }], readOnly: true, mutationAllowed: false };
    if (markerState.status === "present" && markerState.marker.anchorDigest === anchor.digest
      && markerState.marker.anchorSequence === anchor.anchorSequence)
      return { status: "not_required", domain, recoverable: false, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
        sourceDigest: source.digest, sourceCount: source.count, policyDigest: currentPolicyDigest, historyNotProven: anchor.historyNotProven,
        findings: [], readOnly: true, mutationAllowed: false };
    if (markerState.status === "present" && (markerState.marker.anchorSequence + 1 !== anchor.anchorSequence
      || markerState.marker.anchorDigest !== anchor.previousAnchorDigest))
      return { status: "continuity_unproven", domain, recoverable: false, anchorSequence: anchor.anchorSequence,
        anchorDigest: anchor.digest, markerSequence: markerState.marker.anchorSequence, markerDigest: markerState.marker.anchorDigest,
        findings: [{ code: "EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_MARKER_CONTINUITY_UNPROVEN" }], readOnly: true, mutationAllowed: false };
    const expected = { expectedAnchorSequence: anchor.anchorSequence, expectedSourceDigest: anchor.snapshotDigest,
      expectedSourceCount: anchor.sourceCount, previousAnchorDigest: anchor.previousAnchorDigest ?? null };
    const binding = { domain, markerStatus: markerState.status, anchorDigest: anchor.digest, ...expected, policyDigest: currentPolicyDigest };
    return { status: "recoverable", domain, recoverable: true, ...binding,
      recoveryIntentDigest: sha256(canonical(binding)), historyNotProven: anchor.historyNotProven,
      findings: [], readOnly: true, mutationAllowed: false };
  }

  async function recoverMarkerFromExternalAnchor(ownerId, expected = {}) {
    assertOwner(ownerId, domain);
    if (!provider) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_PROVIDER_REQUIRED", `Provider external checkpoint ${domain} belum dikonfigurasi`, 503);
    if (!Number.isSafeInteger(expected.expectedAnchorSequence) || expected.expectedAnchorSequence < 1
      || !DIGEST.test(expected.expectedSourceDigest || "") || !Number.isSafeInteger(expected.expectedSourceCount) || expected.expectedSourceCount < 0
      || (expected.previousAnchorDigest !== null && !DIGEST.test(expected.previousAnchorDigest || "")))
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_INTENT_INVALID", `Recovery intent ${domain} tidak valid`, 409);
    const [source, markerState, remote] = await Promise.all([readSource(ownerId), readMarker(ownerId), readRemote(ownerId)]);
    if (markerState.status === "invalid") throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_MARKER_INVALID", `Marker ${domain} rusak; pemulihan otomatis ditolak`, 409);
    if (remote.status !== "present") throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_ANCHOR_UNAVAILABLE", `External anchor ${domain} tidak dapat diverifikasi`, 503);
    const anchor = remote.anchor;
    if (source.digest !== expected.expectedSourceDigest || source.count !== expected.expectedSourceCount
      || anchor.snapshotDigest !== expected.expectedSourceDigest || anchor.sourceCount !== expected.expectedSourceCount
      || anchor.anchorSequence !== expected.expectedAnchorSequence || anchor.previousAnchorDigest !== expected.previousAnchorDigest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_INTENT_MISMATCH", `External anchor ${domain} tidak cocok dengan recovery intent`, 409,
        { sourceDigestMatches: source.digest === expected.expectedSourceDigest, sourceCountMatches: source.count === expected.expectedSourceCount,
          anchorSequence: anchor.anchorSequence, expectedAnchorSequence: expected.expectedAnchorSequence });
    if (markerState.status === "present") {
      if (markerState.marker.anchorDigest === anchor.digest && markerState.marker.anchorSequence === anchor.anchorSequence)
        return { status: "marker_already_current", domain, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest, idempotent: true,
          readOnly: false, mutationAllowed: false };
      if (markerState.marker.anchorSequence + 1 !== expected.expectedAnchorSequence
        || markerState.marker.anchorDigest !== expected.previousAnchorDigest || markerState.marker.anchorSequence >= anchor.anchorSequence)
        throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_MARKER_CONFLICT", `Marker ${domain} tidak memiliki hubungan previous-anchor yang cocok dengan recovery intent`, 409);
    }
    const saved = await saveMarker(ownerId, anchor);
    const after = await status(ownerId);
    if (after.status !== "anchored") throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_RECOVERY_FINALIZATION_UNVERIFIED",
      `Marker ${domain} tersimpan tetapi checkpoint belum dapat diverifikasi sebagai anchored`, 409, { status: after.status, findings: after.findings || [] });
    return { status: "marker_recovered", domain, anchorSequence: saved.anchorSequence, anchorDigest: saved.anchorDigest,
      historyNotProven: Boolean(anchor.historyNotProven), readOnly: false, mutationAllowed: false };
  }

  async function refresh(ownerId) {
    assertOwner(ownerId, domain);
    if (!provider) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_PROVIDER_REQUIRED", `Provider external checkpoint ${domain} belum dikonfigurasi`, 503);
    const current = await status(ownerId);
    if (current.status !== "anchored") throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_REFRESH_BLOCKED",
      `Refresh ${domain} hanya boleh dilakukan jika source dan marker masih cocok dengan anchor`, 409,
      { status: current.status, findings: current.findings || [] });
    const [source, markerState, remote] = await Promise.all([readSource(ownerId), readMarker(ownerId), readRemote(ownerId)]);
    if (markerState.status !== "present" || remote.status !== "present"
      || markerState.marker.anchorDigest !== remote.anchor.digest || markerState.marker.anchorSequence !== remote.anchor.anchorSequence
      || source.digest !== remote.anchor.snapshotDigest || source.count !== remote.anchor.sourceCount)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_REFRESH_CONTINUITY_UNPROVEN",
        `Refresh ${domain} ditolak karena snapshot atau marker tidak sama dengan external anchor`, 409);
    const anchor = await append(ownerId, source, remote.anchor, false);
    return { status: "anchored", domain, refreshed: true, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      sourceDigest: source.digest, sourceCount: source.count, anchoredAt: anchor.anchoredAt,
      historyNotProven: anchor.historyNotProven, readOnly: false, mutationAllowed: false };
  }

  async function preparePolicyBinding(ownerId, { reason } = {}) {
    assertOwner(ownerId, domain);
    if (!policyReader) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_BINDING_UNAVAILABLE", `Kebijakan checkpoint ${domain} tidak dikonfigurasi`, 409);
    if (!provider) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_PROVIDER_REQUIRED", `Provider ${domain} belum dikonfigurasi`, 503);
    if (!validReason(reason)) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_REASON_INVALID", "Alasan policy binding wajib 12–240 karakter", 400);
    const current = await status(ownerId);
    if (current.status !== "policy_drift" || current.sourceStatus !== "anchored" || !current.anchorDigest || !current.currentPolicyDigest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_BINDING_BLOCKED", "Policy binding hanya boleh disiapkan ketika sumber tetap selaras dan hanya digest kebijakan yang berubah", 409,
        { status: current.status, sourceStatus: current.sourceStatus, findings: current.findings || [] });
    const createdAt = now(), id = `${kind}-policy-binding-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: policyChallengeKind, schemaVersion: 1, status: "prepared", domain,
      expectedAnchorDigest: current.anchorDigest, expectedAnchorSequence: current.anchorSequence,
      expectedSourceDigest: current.sourceDigest, expectedSourceCount: current.sourceCount,
      previousPolicyDigest: current.anchoredPolicyDigest || null, targetPolicyDigest: current.currentPolicyDigest,
      reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + 10 * 60_000).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, domain, challengeDigest: challenge.digest, expectedAnchorDigest: challenge.expectedAnchorDigest,
      previousPolicyDigest: challenge.previousPolicyDigest, targetPolicyDigest: challenge.targetPolicyDigest,
      createdAt, expiresAt: challenge.expiresAt, confirmation: `BIND ${domain.toUpperCase()} FRESHNESS POLICY ${challenge.digest.slice(0, 12)}`,
      readOnly: false, mutationAllowed: false };
  }
  async function auditPolicyBindingApprovalChain(ownerId, { allowPendingChallengeId = null } = {}) {
    assertOwner(ownerId, domain);
    const rows = await store.listEvidence(ownerId);
    const events = rows.filter(row => row?.ownerId === ownerId && row.kind === policyEventKind)
      .sort((a, b) => a.sequence - b.sequence || String(a.id).localeCompare(String(b.id)));
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === policyChallengeKind);
    const findings = [], eventByChallenge = new Map();
    let previous = null, historyNotProven = false;
    for (let index = 0; index < events.length; index++) {
      const event = events[index];
      if (event.digest !== digestRecord(event) || event.schemaVersion !== 1 || event.domain !== domain
        || !Number.isSafeInteger(event.sequence) || event.sequence !== index + 1
        || (event.previousEventDigest ?? null) !== (previous?.digest ?? null)
        || !DIGEST.test(event.challengeDigest || "") || !DIGEST.test(event.resultAnchorDigest || "")
        || !DIGEST.test(event.targetPolicyDigest || "")
        || (event.previousPolicyDigest !== null && !DIGEST.test(event.previousPolicyDigest || ""))
        || !Number.isSafeInteger(event.anchorSequence) || event.anchorSequence < 2
        || typeof event.historyNotProven !== "boolean" || !Number.isFinite(Date.parse(event.appliedAt))) {
        findings.push({ code: "EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_EVENT_INVALID", eventId: event.id });
        continue;
      }
      if (eventByChallenge.has(event.challengeId)) findings.push({ code: "EXTERNAL_SNAPSHOT_POLICY_BINDING_DUPLICATE_EVENT", challengeId: event.challengeId });
      eventByChallenge.set(event.challengeId, event);
      const challenge = challenges.find(item => item.id === event.challengeId);
      if (!challenge || challenge.digest !== digestRecord(challenge) || challenge.status !== "applied"
        || challenge.digest !== event.challengeDigest || challenge.domain !== domain
        || challenge.resultAnchorDigest !== event.resultAnchorDigest || challenge.targetPolicyDigest !== event.targetPolicyDigest
        || challenge.reason !== event.reason || challenge.expectedAnchorDigest !== event.expectedAnchorDigest
        || (challenge.previousPolicyDigest ?? null) !== (event.previousPolicyDigest ?? null)
        || (challenge.preparedChallengeDigest && challenge.preparedChallengeDigest !== event.preparedChallengeDigest))
        findings.push({ code: "EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_EVENT_CHALLENGE_MISMATCH", eventId: event.id });
      if (event.historyNotProven) historyNotProven = true;
      previous = event;
    }
    const missing = challenges.filter(challenge => challenge.status === "applied" && challenge.id !== allowPendingChallengeId && !eventByChallenge.has(challenge.id));
    if (missing.length) {
      historyNotProven = true;
      findings.push({ code: "EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_HISTORY_UNPROVEN", missingChallengeIds: missing.map(item => item.id) });
    }
    const integrityFailure = findings.some(item => item.code !== "EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_HISTORY_UNPROVEN");
    return { status: integrityFailure ? "unhealthy" : historyNotProven ? "history_unproven" : events.length ? "healthy" : challenges.length ? "history_unproven" : "not_initialized",
      ownerId, domain, eventCount: events.length, appliedChallengeCount: challenges.filter(item => item.status === "applied").length,
      eventHead: previous ? { sequence: previous.sequence, digest: previous.digest, anchorSequence: previous.anchorSequence } : null,
      historyNotProven, findings, readOnly: true, mutationAllowed: false };
  }

  async function ensurePolicyBindingAuditEvent(ownerId, challengeId, anchor) {
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== policyChallengeKind || challenge.status !== "applied"
      || challenge.digest !== digestRecord(challenge) || !anchor || anchor.digest !== challenge.resultAnchorDigest
      || anchor.policyDigest !== challenge.targetPolicyDigest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_SOURCE_INVALID", "Policy binding tidak dapat ditautkan ke event audit yang valid", 409);
    const id = `${policyEventKind}-${sha256(challenge.id).slice(0, 32)}`;
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      if (existing.digest !== digestRecord(existing) || existing.challengeId !== challenge.id || existing.challengeDigest !== challenge.digest
        || existing.resultAnchorDigest !== anchor.digest)
        throw new AgenticError("EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_EVENT_CONFLICT", "Event audit policy binding yang sudah ada tidak cocok", 409);
      return existing;
    }
    const chain = await auditPolicyBindingApprovalChain(ownerId, { allowPendingChallengeId: challenge.id });
    if (chain.status === "unhealthy") throw new AgenticError("EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_CHAIN_UNHEALTHY", "Audit chain policy binding tidak sehat", 409,
      { findings: chain.findings });
    const rows = await store.listEvidence(ownerId);
    const priorAppliedWithoutEvents = rows.filter(row => row?.ownerId === ownerId && row.kind === policyChallengeKind
      && row.status === "applied" && row.id !== challenge.id
      && !rows.some(item => item?.ownerId === ownerId && item.kind === policyEventKind && item.challengeId === row.id));
    const unsigned = { id, ownerId, kind: policyEventKind, schemaVersion: 1, domain, sequence: (chain.eventCount || 0) + 1,
      previousEventDigest: chain.eventHead?.digest || null, challengeId: challenge.id, challengeDigest: challenge.digest,
      preparedChallengeDigest: challenge.preparedChallengeDigest || null, expectedAnchorDigest: challenge.expectedAnchorDigest,
      resultAnchorDigest: anchor.digest, anchorSequence: anchor.anchorSequence, previousPolicyDigest: challenge.previousPolicyDigest ?? null,
      targetPolicyDigest: challenge.targetPolicyDigest, reason: challenge.reason, appliedAt: challenge.appliedAt,
      historyNotProven: Boolean(chain.historyNotProven || priorAppliedWithoutEvents.length) };
    const event = { ...unsigned, digest: digestRecord(unsigned) };
    try { await store.putEvidence(ownerId, event, { overwrite: false }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, id);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.challengeDigest !== challenge.digest
        || concurrent.resultAnchorDigest !== anchor.digest)
        throw new AgenticError("EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_EVENT_WRITE_FAILED", "Event audit policy binding gagal disimpan", 409);
      return concurrent;
    }
    const saved = await store.getEvidence(ownerId, id);
    if (!saved || saved.digest !== digestRecord(saved)) throw new AgenticError("EXTERNAL_SNAPSHOT_POLICY_BINDING_AUDIT_EVENT_WRITE_FAILED", "Event audit policy binding gagal diverifikasi setelah penyimpanan", 409);
    return saved;
  }

  async function applyPolicyBinding(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId, domain);
    if (!policyReader || !provider) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_BINDING_UNAVAILABLE", `Policy binding ${domain} tidak tersedia`, 409);
    const challenge = await store.getEvidence(ownerId, id);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== policyChallengeKind || challenge.domain !== domain
      || challenge.digest !== digestRecord(challenge)) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_CHALLENGE_INVALID", "Challenge policy binding tidak valid", 409);
    const current = await status(ownerId);
    const remoteAtApply = await readRemote(ownerId);
    const anchorMatchesChallenge = remoteAtApply.status === "present" && remoteAtApply.anchor.policyDigest === challenge.targetPolicyDigest
      && remoteAtApply.anchor.previousAnchorDigest === challenge.expectedAnchorDigest
      && remoteAtApply.anchor.snapshotDigest === challenge.expectedSourceDigest && remoteAtApply.anchor.sourceCount === challenge.expectedSourceCount
      && current.status === "anchored" && current.anchorDigest === remoteAtApply.anchor.digest && current.sourceDigest === challenge.expectedSourceDigest
      && current.sourceCount === challenge.expectedSourceCount && current.currentPolicyDigest === challenge.targetPolicyDigest;
    if (challenge.status === "applied") {
      if (anchorMatchesChallenge && remoteAtApply.anchor.digest === challenge.resultAnchorDigest) {
        await ensurePolicyBindingAuditEvent(ownerId, id, remoteAtApply.anchor);
        return { status: "anchored", domain, anchorSequence: remoteAtApply.anchor.anchorSequence, anchorDigest: remoteAtApply.anchor.digest,
          policyDigest: remoteAtApply.anchor.policyDigest, idempotent: true, readOnly: false, mutationAllowed: false };
      }
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_REPLAY_CONFLICT", "Policy binding yang selesai tidak cocok dengan anchor terkini", 409);
    }
    if (challenge.status === "prepared" && anchorMatchesChallenge) {
      const recoveredUnsigned = { ...clean(challenge), status: "applied", preparedChallengeDigest: challenge.digest,
        appliedAt: now(), resultAnchorDigest: remoteAtApply.anchor.digest, recoveredAfterExternalCommit: true };
      delete recoveredUnsigned.digest;
      const recovered = { ...recoveredUnsigned, digest: digestRecord(recoveredUnsigned) };
      try { await store.putEvidence(ownerId, recovered, { expectedVersion: challenge._storage?.version }); }
      catch {
        const concurrent = await store.getEvidence(ownerId, id);
        if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.status !== "applied"
          || concurrent.resultAnchorDigest !== remoteAtApply.anchor.digest)
          throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_FINALIZE_CONFLICT", "Policy anchor sudah maju tetapi recovery intent tidak dapat difinalisasi", 409);
      }
      await ensurePolicyBindingAuditEvent(ownerId, id, remoteAtApply.anchor);
      return { status: "anchored", domain, anchorSequence: remoteAtApply.anchor.anchorSequence, anchorDigest: remoteAtApply.anchor.digest,
        policyDigest: remoteAtApply.anchor.policyDigest, idempotent: true, recovered: true, readOnly: false, mutationAllowed: false };
    }
    if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `BIND ${domain.toUpperCase()} FRESHNESS POLICY ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_CHALLENGE_EXPIRED", "Challenge policy binding kedaluwarsa, sudah digunakan, atau konfirmasinya tidak cocok", 409);
    if (current.status !== "policy_drift" || current.sourceStatus !== "anchored" || current.anchorDigest !== challenge.expectedAnchorDigest
      || current.anchorSequence !== challenge.expectedAnchorSequence || current.sourceDigest !== challenge.expectedSourceDigest
      || current.sourceCount !== challenge.expectedSourceCount || current.currentPolicyDigest !== challenge.targetPolicyDigest
      || (current.anchoredPolicyDigest || null) !== challenge.previousPolicyDigest)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_CHALLENGE_STALE", "Sumber, anchor, atau kebijakan berubah sejak challenge dibuat", 409);
    const source = await readSource(ownerId), remote = await readRemote(ownerId), markerState = await readMarker(ownerId);
    if (source.digest !== challenge.expectedSourceDigest || source.count !== challenge.expectedSourceCount || remote.status !== "present"
      || remote.anchor.digest !== challenge.expectedAnchorDigest || markerState.status !== "present"
      || markerState.marker.anchorDigest !== remote.anchor.digest || markerState.marker.anchorSequence !== remote.anchor.anchorSequence)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_CONTINUITY_UNPROVEN", "Policy binding ditolak karena source, marker, atau remote anchor berubah", 409);
    const anchor = await append(ownerId, source, remote.anchor, false);
    const completedUnsigned = { ...clean(challenge), status: "applied", preparedChallengeDigest: challenge.digest,
      appliedAt: now(), resultAnchorDigest: anchor.digest };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, id);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.status !== "applied"
        || concurrent.resultAnchorDigest !== anchor.digest)
        throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_POLICY_FINALIZE_CONFLICT", "Anchor policy berhasil ditulis tetapi challenge belum dapat difinalisasi", 409);
    }
    await ensurePolicyBindingAuditEvent(ownerId, id, anchor);
    return { status: "anchored", domain, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      policyDigest: anchor.policyDigest, refreshed: true, idempotent: false, readOnly: false, mutationAllowed: false };
  }

  async function prepareEnrollment(ownerId, { reason } = {}) {
    assertOwner(ownerId, domain);
    if (!provider) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_PROVIDER_REQUIRED", `Provider ${domain} belum dikonfigurasi`, 503);
    if (!validReason(reason)) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_REASON_INVALID", "Alasan enrollment wajib 12–240 karakter", 400);
    const state = await status(ownerId), source = await readSource(ownerId);
    const emptyGenesis = state.status === "not_initialized" && source.count === 0;
    if (state.status !== "enrollment_required" && !emptyGenesis) throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_ENROLLMENT_BLOCKED", "Enrollment hanya berlaku untuk histori lokal yang belum di-anchor atau baseline genesis kosong", 409,
      { status: state.status, sourceCount: source.count, findings: state.findings || [] });
    const createdAt = now(), id = `${kind}-enrollment-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: challengeKind, schemaVersion: 1, status: "prepared", domain, expectedSourceDigest: source.digest,
      expectedSourceCount: source.count, reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + 10 * 60_000).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { challengeId: id, challengeDigest: challenge.digest, domain, expectedSourceDigest: source.digest, expectedSourceCount: source.count,
      createdAt, expiresAt: challenge.expiresAt, confirmation: `ENROLL ${domain.toUpperCase()} CHECKPOINT ${challenge.digest.slice(0, 12)}`,
      readOnly: false, mutationAllowed: false };
  }
  async function applyEnrollment(ownerId, id, { confirmation } = {}) {
    assertOwner(ownerId, domain);
    const challenge = await store.getEvidence(ownerId, id), unsigned = clean(challenge || {}); delete unsigned.digest;
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== challengeKind || challenge.status !== "prepared"
      || challenge.digest !== sha256(canonical(unsigned)) || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `ENROLL ${domain.toUpperCase()} CHECKPOINT ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_ENROLLMENT_INVALID", "Challenge enrollment tidak valid, kedaluwarsa, atau konfirmasi tidak cocok", 409);
    const state = await status(ownerId), source = await readSource(ownerId);
    const emptyGenesis = state.status === "not_initialized" && source.count === 0;
    if ((state.status !== "enrollment_required" && !emptyGenesis) || source.digest !== challenge.expectedSourceDigest
      || source.count !== challenge.expectedSourceCount)
      throw new AgenticError("EXTERNAL_SNAPSHOT_CHECKPOINT_ENROLLMENT_STALE", "Snapshot sumber berubah sejak enrollment disiapkan", 409);
    const anchor = await append(ownerId, source, null, source.count > 0);
    const completedUnsigned = { ...clean(challenge), status: "applied", appliedAt: now(), anchorDigest: anchor.digest };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version });
    return { status: "anchored", domain, anchorSequence: anchor.anchorSequence, anchorDigest: anchor.digest,
      historyNotProven: Boolean(anchor.historyNotProven), genesisBaseline: source.count === 0, readOnly: false, mutationAllowed: false };
  }
  async function audit(ownerId) {
    const current = await status(ownerId), findings = [...(current.findings || [])];
    if (["unhealthy", "rollback_suspected"].includes(current.status)) return { ...current, status: "unhealthy", findings, readOnly: true, mutationAllowed: false };
    if (["behind_local", "marker_pending", "enrollment_required", "unavailable", "policy_drift"].includes(current.status))
      return { ...current, status: "external_checkpoint_pending", findings, readOnly: true, mutationAllowed: false };
    return { ...current, status: current.status === "local_only" ? "local_only" : current.status === "not_initialized" ? "not_initialized" : "healthy",
      findings, readOnly: true, mutationAllowed: false };
  }
  return Object.freeze({ getExternalSnapshotCheckpointStatus: status, reconcileExternalSnapshotCheckpoint: reconcile,
    reconcileApprovedMultiEventGap, refreshExternalSnapshotCheckpoint: refresh, inspectExternalSnapshotCheckpointMarkerRecoveryIntent: inspectMarkerRecoveryIntent,
    recoverExternalSnapshotCheckpointMarkerFromIntent: recoverMarkerFromExternalAnchor,
    prepareExternalSnapshotCheckpointPolicyBinding: preparePolicyBinding,
    applyExternalSnapshotCheckpointPolicyBinding: applyPolicyBinding,
    auditExternalSnapshotCheckpointPolicyBindingApprovalChain: auditPolicyBindingApprovalChain,
    prepareExternalSnapshotCheckpointEnrollment: prepareEnrollment, applyExternalSnapshotCheckpointEnrollment: applyEnrollment,
    auditExternalSnapshotCheckpoint: audit, domain, providerConfigured: Boolean(provider) });
}
