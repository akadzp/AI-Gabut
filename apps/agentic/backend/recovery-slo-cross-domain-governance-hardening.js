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
  const result = {};
  for (const [key, item] of Object.entries(value)) if (key !== "_storage") result[key] = clean(item);
  return result;
};
const digestRecord = value => { const copy = clean(value); delete copy.digest; return sha256(canonical(copy)); };
const ownerHash = ownerId => sha256(ownerId).slice(0, 32);
const RECEIPT_KIND = "recovery-slo-cross-domain-provider-baseline-transition-receipt";
const MANIFEST_KIND = "recovery-slo-cross-domain-provider-baseline-receipt-compaction-manifest-draft";
const MANIFEST_APPROVAL_CHALLENGE_KIND = "recovery-slo-cross-domain-provider-baseline-receipt-compaction-manifest-approval-challenge";
const MANIFEST_APPROVAL_KIND = "recovery-slo-cross-domain-provider-baseline-receipt-compaction-manifest-approval";
const MANIFEST_APPROVAL_REVOCATION_CHALLENGE_KIND = "recovery-slo-cross-domain-provider-baseline-receipt-compaction-manifest-approval-revocation-challenge";
const MANIFEST_APPROVAL_REVOCATION_KIND = "recovery-slo-cross-domain-provider-baseline-receipt-compaction-manifest-approval-revocation";
const MANIFEST_APPROVAL_SUPERSESSION_KIND = "recovery-slo-cross-domain-provider-baseline-receipt-compaction-manifest-approval-supersession";
const REVALIDATION_LEASE_KIND = "recovery-slo-cross-domain-retention-review-revalidation-lease";

function validReason(value) { return typeof value === "string" && value.trim().length >= 12 && value.trim().length <= 240 && !/[\u0000-\u001f\u007f]/.test(value); }

function assertOwner(ownerId) {
  if (typeof ownerId !== "string" || !ownerId.trim() || ownerId.trim() !== ownerId || ownerId.length > 200)
    throw new AgenticError("CROSS_DOMAIN_GOVERNANCE_OWNER_REQUIRED", "Owner governance lintas-domain wajib ditentukan", 400);
}

export function createRecoverySloCrossDomainGovernanceHardeningService({ store, checkpointServices = new Map(), clock = () => new Date().toISOString(), maxCacheEntries = 512, maxCacheAgeMs = 30000 } = {}) {
  if (!store?.getEvidence || !store?.putEvidence || !store?.listEvidence || typeof clock !== "function" || !Number.isSafeInteger(maxCacheEntries) || maxCacheEntries < 1 || !Number.isSafeInteger(maxCacheAgeMs) || maxCacheAgeMs < 1)
    throw new TypeError("Cross-domain governance hardening membutuhkan store dan clock");
  const revalidationCache = new Map();
  const revalidationGenerations = new Map();
  const observedFingerprints = new Map();
  const inFlightRevalidations = new Map();
  const cacheStats = { hits: 0, misses: 0, invalidations: 0, evictions: 0, generationConflicts: 0, coalescedRevalidations: 0 };
  const leaseTimers = new Map();
  function generationKey(ownerId, approvalId) { return cacheKey(ownerId, approvalId); }
  function getRevalidationGeneration(ownerId, approvalId) { return revalidationGenerations.get(generationKey(ownerId, approvalId)) || 0; }
  function isRevalidationGenerationCurrent(ownerId, approvalId, generation) { return getRevalidationGeneration(ownerId, approvalId) === generation; }
  async function runConsistentRevalidation(ownerId, approvalId, worker) {
    assertOwner(ownerId);
    if (typeof approvalId !== "string" || !approvalId.trim() || typeof worker !== "function")
      throw new AgenticError("CROSS_DOMAIN_RETENTION_REVALIDATION_ID_REQUIRED", "Approval ID dan worker revalidasi wajib ditentukan", 400);
    const key = generationKey(ownerId, approvalId), existing = inFlightRevalidations.get(key);
    if (existing) { cacheStats.coalescedRevalidations++; return existing; }
    const promise = Promise.resolve().then(worker);
    inFlightRevalidations.set(key, promise);
    promise.finally(() => { if (inFlightRevalidations.get(key) === promise) inFlightRevalidations.delete(key); }).catch(() => {});
    return promise;
  }
  function observeRevalidationFingerprint(ownerId, approvalId, fingerprint) {
    const key = generationKey(ownerId, approvalId), previous = observedFingerprints.get(key);
    if (previous !== undefined && previous !== fingerprint) {
      revalidationGenerations.set(key, getRevalidationGeneration(ownerId, approvalId) + 1);
      if (revalidationCache.delete(key)) cacheStats.invalidations++;
    }
    observedFingerprints.set(key, fingerprint);
    return getRevalidationGeneration(ownerId, approvalId);
  }
  function now() {
    const value = Date.parse(String(clock()));
    if (!Number.isFinite(value)) throw new AgenticError("CROSS_DOMAIN_GOVERNANCE_CLOCK_INVALID", "Clock governance lintas-domain tidak valid", 500);
    return new Date(value).toISOString();
  }
  function cacheKey(ownerId, approvalId) { return `${ownerId}\0${approvalId}`; }
  function getCachedRevalidation(ownerId, approvalId, fingerprint, { validUntil = null } = {}) {
    const key = cacheKey(ownerId, approvalId), entry = revalidationCache.get(key);
    if (!entry) { cacheStats.misses++; return null; }
    const nowMs = Date.parse(now()), cachedAtMs = Date.parse(entry.cachedAt), entryDeadline = entry.validUntil ? Date.parse(entry.validUntil) : Infinity;
    const requestedDeadline = validUntil ? Date.parse(validUntil) : Infinity;
    const expired = !Number.isFinite(nowMs) || !Number.isFinite(cachedAtMs) || nowMs - cachedAtMs >= maxCacheAgeMs
      || nowMs >= entryDeadline || nowMs >= requestedDeadline || entry.validUntil !== (validUntil || null);
    if (expired || entry.fingerprint !== fingerprint) {
      revalidationCache.delete(key); cacheStats.invalidations++; cacheStats.misses++;
      return null;
    }
    cacheStats.hits++;
    return { ...structuredClone(entry.result), cacheHit: true, cacheFingerprint: fingerprint };
  }
  function setCachedRevalidation(ownerId, approvalId, fingerprint, result, { validUntil = null, expectedGeneration = null } = {}) {
    const key = cacheKey(ownerId, approvalId);
    if (expectedGeneration !== null && !isRevalidationGenerationCurrent(ownerId, approvalId, expectedGeneration)) {
      cacheStats.generationConflicts++;
      return { ...structuredClone(result), cacheStored: false, generationConflict: true };
    }
    if (validUntil && (!Number.isFinite(Date.parse(validUntil)) || Date.parse(validUntil) <= Date.parse(now())))
      return { ...structuredClone(result), cacheStored: false, freshnessExpired: true };
    if (!revalidationCache.has(key) && revalidationCache.size >= maxCacheEntries) {
      const oldest = revalidationCache.keys().next().value;
      if (oldest !== undefined) { revalidationCache.delete(oldest); cacheStats.evictions++; }
    }
    revalidationCache.set(key, { fingerprint, result: structuredClone(result), cachedAt: now(), validUntil: validUntil || null,
      generation: getRevalidationGeneration(ownerId, approvalId) });
    return { ...structuredClone(result), cacheStored: true };
  }
  function invalidateRevalidation(ownerId, approvalId, reason = "explicit_invalidation") {
    const key = cacheKey(ownerId, approvalId), existed = revalidationCache.delete(key);
    revalidationGenerations.set(key, getRevalidationGeneration(ownerId, approvalId) + 1);
    if (existed) cacheStats.invalidations++;
    return { invalidated: existed, reason, readOnly: false, mutationAllowed: false };
  }
  function auditRevalidationCache(ownerId = null) {
    const entries = [...revalidationCache.entries()].filter(([key]) => ownerId === null || key.startsWith(`${ownerId}\0`))
      .map(([key, entry]) => {
        const [entryOwnerId, approvalId] = key.split("\0");
        return { ownerId: entryOwnerId, approvalId, fingerprint: entry.fingerprint, cachedAt: entry.cachedAt, generation: entry.generation };
      });
    return { status: "healthy", cacheScope: ownerId === null ? "all_in_process_entries" : "owner", ownerId,
      entryCount: entries.length, entries, stats: { ...cacheStats }, invalidationRule: "evidence_checkpoint_or_policy_fingerprint_change_or_explicit_invalidation",
      generationCount: [...revalidationGenerations.keys()].filter(key => ownerId === null || key.startsWith(`${ownerId}\0`)).length,
      inFlightCount: [...inFlightRevalidations.keys()].filter(key => ownerId === null || key.startsWith(`${ownerId}\0`)).length,
      persistent: false, decisionAuthority: false, readOnly: true, mutationAllowed: false };
  }

  function leaseIdFor(ownerId, approvalId) { return `${REVALIDATION_LEASE_KIND}-${sha256(`${ownerId}\0${approvalId}`).slice(0, 36)}`; }
  function leaseEventBody(event) { const copy = clean(event); delete copy.eventDigest; delete copy.digest; return copy; }
  function validateLeaseRecord(record, ownerId = record?.ownerId) {
    const findings = [];
    if (!record || record.kind !== REVALIDATION_LEASE_KIND || record.ownerId !== ownerId || record.digest !== digestRecord(record)
      || !Array.isArray(record.events) || !Number.isSafeInteger(record.fencingToken) || record.fencingToken < 1
      || ![1, 2].includes(record.schemaVersion) || !record.approvalId || !Number.isFinite(Date.parse(record.createdAt))) {
      return { valid: false, historyNotProven: false, findings: [{ code: "CROSS_DOMAIN_REVALIDATION_LEASE_RECORD_INVALID" }] };
    }
    let previousEventDigest = null, previousAt = -Infinity;
    let previousFence = 0, previousAction = null, previousExpiry = null;
    let historyNotProven = record.schemaVersion < 2;
    const recoveryRequestIds = new Set();
    const activeActions = new Set(["acquired", "reclaimed", "renewed"]);
    for (let index = 0; index < record.events.length; index++) {
      const event = record.events[index];
      const at = Date.parse(event.at), expiry = event.leaseExpiresAt == null ? null : Date.parse(event.leaseExpiresAt);
      const actionValid = ["acquired", "reclaimed", "renewed", "released", "recovered"].includes(event.action);
      const baseValid = event.sequence === index + 1 && (event.previousEventDigest ?? null) === previousEventDigest
        && event.eventDigest === sha256(canonical(leaseEventBody(event))) && actionValid
        && Number.isSafeInteger(event.fencingToken) && event.fencingToken >= 1
        && Number.isFinite(at) && at >= previousAt && validReason(event.reason || "Lease event system-generated")
        && DIGEST.test(event.leaseTokenDigest || "");
      if (!baseValid) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EVENT_CHAIN_INVALID", sequence: event.sequence });
      if (event.recoveryRequestId !== undefined) {
        if (event.action !== "recovered" || typeof event.recoveryRequestId !== "string" || !/^[A-Za-z0-9._:-]{1,120}$/.test(event.recoveryRequestId)
          || recoveryRequestIds.has(event.recoveryRequestId))
          findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_RECOVERY_REQUEST_ID_INVALID", sequence: event.sequence });
        else recoveryRequestIds.add(event.recoveryRequestId);
      }
      if (Object.prototype.hasOwnProperty.call(event, "previousRecordDigest")) {
        if (index === 0 ? event.previousRecordDigest !== null : !DIGEST.test(event.previousRecordDigest || ""))
          findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_RECORD_LINK_INVALID", sequence: event.sequence });
      } else historyNotProven = true;
      let transitionValid = true;
      if (event.action === "acquired") {
        transitionValid = event.fencingToken === previousFence + 1
          && (index === 0 || ["released", "recovered"].includes(previousAction))
          && Number.isFinite(expiry) && expiry > at;
      } else if (event.action === "reclaimed") {
        transitionValid = index > 0 && activeActions.has(previousAction) && Number.isFinite(previousExpiry)
          && at >= previousExpiry && event.fencingToken === previousFence + 1 && Number.isFinite(expiry) && expiry > at;
      } else if (event.action === "renewed") {
        transitionValid = index > 0 && activeActions.has(previousAction) && event.fencingToken === previousFence
          && Number.isFinite(previousExpiry) && at < previousExpiry && Number.isFinite(expiry) && expiry > at && expiry >= previousExpiry;
      } else if (event.action === "released") {
        transitionValid = index > 0 && activeActions.has(previousAction) && event.fencingToken === previousFence && expiry === null;
      } else if (event.action === "recovered") {
        transitionValid = index > 0 && activeActions.has(previousAction) && Number.isFinite(previousExpiry)
          && at >= previousExpiry && event.fencingToken === previousFence + 1 && expiry === null;
      }
      if (!transitionValid) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_TRANSITION_INVALID", sequence: event.sequence, action: event.action });
      previousEventDigest = event.eventDigest || null;
      previousAt = Number.isFinite(at) ? at : previousAt;
      previousFence = Number.isSafeInteger(event.fencingToken) ? event.fencingToken : previousFence;
      previousAction = event.action;
      previousExpiry = Number.isFinite(expiry) ? expiry : null;
    }
    if (record.headEventDigest !== previousEventDigest) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_HEAD_INVALID" });
    const lastEvent = record.events.at(-1);
    if (lastEvent && Object.prototype.hasOwnProperty.call(lastEvent, "previousRecordDigest")) {
      if (record.previousRecordDigest !== lastEvent.previousRecordDigest) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_RECORD_LINK_INVALID" });
    } else if (lastEvent) historyNotProven = true;
    if (!Number.isFinite(Date.parse(record.updatedAt)) || !["active", "released", "recovered"].includes(record.status)
      || record.fencingToken !== previousFence) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_STATE_INVALID" });
    const expectedStatus = activeActions.has(previousAction) ? "active" : previousAction === "released" ? "released" : previousAction === "recovered" ? "recovered" : null;
    if (!expectedStatus || record.status !== expectedStatus) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_TERMINAL_STATE_MISMATCH" });
    if (record.status === "active") {
      if (!record.leaseToken || !Number.isFinite(Date.parse(record.leaseExpiresAt)) || record.leaseExpiresAt !== new Date(previousExpiry).toISOString()
        || sha256(record.leaseToken) !== record.events.at(-1)?.leaseTokenDigest)
        findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_ACTIVE_FIELDS_INVALID" });
    } else if (record.leaseToken !== null || record.leaseExpiresAt !== null) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_TERMINAL_FIELDS_INVALID" });
    return { valid: findings.length === 0, historyNotProven, findings };
  }
  async function mutateLease(ownerId, approvalId, operation) {
    if (typeof store.mutateEvidence !== "function") throw new AgenticError("CROSS_DOMAIN_REVALIDATION_LEASE_STORE_UNSUPPORTED",
      "Cross-process revalidation membutuhkan storage dengan atomic mutateEvidence", 503);
    const id = leaseIdFor(ownerId, approvalId);
    return store.mutateEvidence(ownerId, id, async current => {
      if (current) {
        const checked = validateLeaseRecord(current, ownerId);
        if (!checked.valid) throw new AgenticError("CROSS_DOMAIN_REVALIDATION_LEASE_UNHEALTHY", "Lease revalidasi tersimpan tidak sehat", 409, { findings: checked.findings });
      }
      return operation(current, id);
    });
  }
  function appendLeaseEvent(record, action, fields = {}) {
    const previousEventDigest = record?.headEventDigest || null;
    const body = { sequence: (record?.events?.length || 0) + 1, action, previousEventDigest,
      previousRecordDigest: record?.digest || null, at: now(), ...fields };
    const event = { ...body, eventDigest: sha256(canonical(body)) };
    return { ...event, eventDigest: event.eventDigest };
  }
  async function acquireRevalidationLease(ownerId, approvalId, leaseMs) {
    const token = randomUUID();
    const outcome = await mutateLease(ownerId, approvalId, (current, id) => {
      const nowMs = Date.parse(now());
      if (current?.status === "active" && Date.parse(current.leaseExpiresAt) > nowMs)
        return { write: false, result: { acquired: false, leaseId: id, leaseExpiresAt: current.leaseExpiresAt, fencingToken: current.fencingToken } };
      const reclaimed = current?.status === "active";
      const fencingToken = (current?.fencingToken || 0) + 1;
      const event = appendLeaseEvent(current, reclaimed ? "reclaimed" : "acquired", { fencingToken, leaseTokenDigest: sha256(token),
        leaseExpiresAt: new Date(nowMs + leaseMs).toISOString(), reason: reclaimed ? "Expired lease reclaimed with a higher fencing token" : "Lease acquired for bounded revalidation" });
      const events = [...(current?.events || []), event];
      const unsigned = { id, ownerId, kind: REVALIDATION_LEASE_KIND, schemaVersion: 2, approvalId, status: "active", leaseToken: token,
        fencingToken, leaseExpiresAt: event.leaseExpiresAt, createdAt: current?.createdAt || now(), updatedAt: now(),
        previousRecordDigest: current?.digest || null, events, headEventDigest: event.eventDigest };
      const record = { ...unsigned, digest: digestRecord(unsigned) };
      return { value: record, result: { acquired: true, leaseId: id, leaseToken: token, fencingToken, leaseExpiresAt: record.leaseExpiresAt } };
    });
    return outcome;
  }
  async function heartbeatRevalidationLease(ownerId, approvalId, lease, leaseMs) {
    let renewed = false;
    await mutateLease(ownerId, approvalId, (current, id) => {
      if (!current || current.id !== lease.leaseId || current.status !== "active" || current.leaseToken !== lease.leaseToken
        || current.fencingToken !== lease.fencingToken || Date.parse(current.leaseExpiresAt) <= Date.parse(now()))
        return { write: false, result: null };
      const expiry = new Date(Date.parse(now()) + leaseMs).toISOString();
      const event = appendLeaseEvent(current, "renewed", { fencingToken: lease.fencingToken, leaseTokenDigest: sha256(lease.leaseToken),
        leaseExpiresAt: expiry, reason: "Lease heartbeat extended before expiry" });
      const unsigned = { ...clean(current), schemaVersion: 2, status: "active", leaseExpiresAt: expiry, updatedAt: now(),
        previousRecordDigest: current.digest, events: [...current.events, event], headEventDigest: event.eventDigest };
      delete unsigned.digest;
      const next = { ...unsigned, digest: digestRecord(unsigned) };
      renewed = true;
      return { value: next, result: next };
    });
    return renewed;
  }
  async function releaseRevalidationLease(ownerId, approvalId, lease, action = "released") {
    await mutateLease(ownerId, approvalId, current => {
      if (!current || current.status !== "active" || current.leaseToken !== lease.leaseToken || current.fencingToken !== lease.fencingToken)
        return { write: false, result: false };
      const event = appendLeaseEvent(current, action, { fencingToken: lease.fencingToken, leaseTokenDigest: sha256(lease.leaseToken),
        reason: action === "released" ? "Revalidation worker completed" : "Expired lease explicitly recovered" });
      const unsigned = { ...clean(current), schemaVersion: 2, status: action === "released" ? "released" : "recovered", leaseToken: null,
        leaseExpiresAt: null, updatedAt: now(), previousRecordDigest: current.digest, events: [...current.events, event], headEventDigest: event.eventDigest };
      delete unsigned.digest;
      return { value: { ...unsigned, digest: digestRecord(unsigned) }, result: true };
    });
  }
  async function runLeasedRevalidation(ownerId, approvalId, worker, { leaseMs = 30000 } = {}) {
    assertOwner(ownerId);
    if (typeof approvalId !== "string" || !approvalId.trim() || typeof worker !== "function"
      || !Number.isSafeInteger(leaseMs) || leaseMs < 1000 || leaseMs > 300000)
      throw new AgenticError("CROSS_DOMAIN_REVALIDATION_LEASE_ARGUMENT_INVALID", "Approval, worker, atau lease duration tidak valid", 400);
    const lease = await acquireRevalidationLease(ownerId, approvalId, leaseMs);
    if (!lease.acquired) return { status: "revalidation_in_progress", approvalId, current: false, usableForCurrentDecision: false,
      leaseExpiresAt: lease.leaseExpiresAt, fencingToken: lease.fencingToken, cacheStored: false, readOnly: true, mutationAllowed: false };
    let lost = false, heartbeatBusy = false;
    const heartbeat = async () => {
      if (heartbeatBusy || lost) return;
      heartbeatBusy = true;
      try { if (!await heartbeatRevalidationLease(ownerId, approvalId, lease, leaseMs)) lost = true; }
      catch { lost = true; }
      finally { heartbeatBusy = false; }
    };
    const timer = setInterval(heartbeat, Math.max(250, Math.floor(leaseMs / 3)));
    timer.unref?.();
    leaseTimers.set(lease.leaseId, timer);
    try {
      const result = await worker({ leaseId: lease.leaseId, fencingToken: lease.fencingToken, heartbeat,
        isCurrent: async () => {
          const current = await store.getEvidence(ownerId, lease.leaseId);
          return Boolean(current && validateLeaseRecord(current, ownerId).valid && current.status === "active"
            && current.leaseToken === lease.leaseToken && current.fencingToken === lease.fencingToken
            && Date.parse(current.leaseExpiresAt) > Date.parse(now()));
        } });
      await heartbeat();
      const stillCurrent = !lost && await (async () => {
        const current = await store.getEvidence(ownerId, lease.leaseId);
        return Boolean(current && validateLeaseRecord(current, ownerId).valid && current.status === "active"
          && current.leaseToken === lease.leaseToken && current.fencingToken === lease.fencingToken
          && Date.parse(current.leaseExpiresAt) > Date.parse(now()));
      })();
      if (!stillCurrent) throw new AgenticError("CROSS_DOMAIN_REVALIDATION_LEASE_LOST", "Lease revalidasi hilang atau digantikan; hasil worker ditolak", 409);
      return { ...result, lease: { leaseId: lease.leaseId, fencingToken: lease.fencingToken, status: "held_until_release" } };
    } finally {
      clearInterval(timer); leaseTimers.delete(lease.leaseId);
      await releaseRevalidationLease(ownerId, approvalId, lease, "released").catch(() => {});
    }
  }
  async function recoverRevalidationLease(ownerId, approvalId, { recoveryRequestId = null } = {}) {
    assertOwner(ownerId);
    if (typeof approvalId !== "string" || !approvalId.trim()) throw new AgenticError("CROSS_DOMAIN_REVALIDATION_LEASE_APPROVAL_REQUIRED", "Approval ID wajib ditentukan", 400);
    if (recoveryRequestId !== null && (typeof recoveryRequestId !== "string" || !/^[A-Za-z0-9._:-]{1,120}$/.test(recoveryRequestId)))
      throw new AgenticError("CROSS_DOMAIN_REVALIDATION_LEASE_RECOVERY_REQUEST_ID_INVALID", "Recovery request ID tidak valid", 400);
    return mutateLease(ownerId, approvalId, (current, id) => {
      if (!current) return { write: false, result: { status: "not_initialized", leaseId: id, recovered: false, idempotent: true,
        recoveryCount: 0, reason: "lease_not_initialized" } };
      const recoveryEvents = current.events.filter(item => item.action === "recovered");
      if (recoveryRequestId) {
        const priorRequest = recoveryEvents.find(item => item.recoveryRequestId === recoveryRequestId);
        if (priorRequest) return { write: false, result: { status: "recovered", leaseId: id, recovered: false, idempotent: true,
          recoveryRequestId, recoveryEventDigest: priorRequest.eventDigest, recoveryCount: recoveryEvents.length,
          fencingToken: priorRequest.fencingToken, lastRecoveredAt: priorRequest.at } };
      }
      const nowMs = Date.parse(now());
      if (current.status === "active" && Date.parse(current.leaseExpiresAt) > nowMs)
        return { write: false, result: { status: "lease_active", leaseId: id, recovered: false, idempotent: true,
          leaseExpiresAt: current.leaseExpiresAt, fencingToken: current.fencingToken, recoveryCount: recoveryEvents.length,
          reason: "lease_not_expired" } };
      if (current.status !== "active") {
        const lastRecovery = recoveryEvents.at(-1) || null;
        return { write: false, result: { status: current.status, leaseId: id, recovered: false, idempotent: true,
          recoveryRequestId: recoveryRequestId || null, recoveryEventDigest: lastRecovery?.eventDigest || null,
          recoveryCount: recoveryEvents.length, fencingToken: current.fencingToken, lastRecoveredAt: lastRecovery?.at || null,
          reason: "lease_already_terminal" } };
      }
      const event = appendLeaseEvent(current, "recovered", { fencingToken: current.fencingToken + 1, leaseTokenDigest: sha256(current.leaseToken),
        ...(recoveryRequestId ? { recoveryRequestId } : {}), reason: "Expired revalidation lease explicitly recovered" });
      const unsigned = { ...clean(current), schemaVersion: 2, status: "recovered", leaseToken: null, leaseExpiresAt: null, fencingToken: current.fencingToken + 1,
        updatedAt: now(), previousRecordDigest: current.digest, events: [...current.events, event], headEventDigest: event.eventDigest };
      delete unsigned.digest;
      const value = { ...unsigned, digest: digestRecord(unsigned) };
      return { value, result: { status: "recovered", leaseId: id, recovered: true, idempotent: false, recoveryRequestId: recoveryRequestId || null,
        recoveryEventDigest: event.eventDigest, recoveryCount: recoveryEvents.length + 1, fencingToken: value.fencingToken, lastRecoveredAt: event.at } };
    });
  }
  async function auditRevalidationLeases(ownerId = null) {
    const rows = ownerId === null ? await store.listEvidence() : await store.listEvidence(ownerId);
    const leases = rows.filter(row => row?.kind === REVALIDATION_LEASE_KIND && (ownerId === null || row.ownerId === ownerId));
    const findings = [], historyUnprovenLeaseIds = [];
    for (const lease of leases) {
      const checked = validateLeaseRecord(lease, lease.ownerId);
      findings.push(...checked.findings.map(item => ({ ...item, leaseId: lease.id, ownerId: lease.ownerId })));
      if (checked.historyNotProven) historyUnprovenLeaseIds.push(lease.id);
      const recoveryRequestIds = lease.events.filter(item => item.action === "recovered" && item.recoveryRequestId).map(item => item.recoveryRequestId);
      if (new Set(recoveryRequestIds).size !== recoveryRequestIds.length)
        findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_RECOVERY_REQUEST_DUPLICATE", leaseId: lease.id, ownerId: lease.ownerId });
    }
    const expiredCount = leases.filter(item => item.status === "active" && Date.parse(item.leaseExpiresAt) <= Date.parse(now())).length;
    const recoveryEvents = leases.flatMap(item => item.events.filter(event => event.action === "recovered").map(event => ({ ...event, leaseId: item.id, ownerId: item.ownerId })));
    const reclaimEvents = leases.flatMap(item => item.events.filter(event => event.action === "reclaimed"));
    const lastRecovery = recoveryEvents.sort((a, b) => Date.parse(b.at) - Date.parse(a.at))[0] || null;
    return { status: findings.length ? "unhealthy" : expiredCount ? "recovery_required" : historyUnprovenLeaseIds.length ? "history_unproven" : leases.length ? "healthy" : "not_initialized", leaseCount: leases.length,
      activeCount: leases.filter(item => item.status === "active" && Date.parse(item.leaseExpiresAt) > Date.parse(now())).length,
      expiredCount, recoveredLeaseCount: leases.filter(item => item.status === "recovered").length,
      recoveryEventCount: recoveryEvents.length, reclaimedEventCount: reclaimEvents.length,
      recoveryRequestIdCount: new Set(recoveryEvents.map(item => item.recoveryRequestId).filter(Boolean)).size,
      lastRecoveredAt: lastRecovery?.at || null, lastRecoveryEventDigest: lastRecovery?.eventDigest || null,
      historyUnprovenLeaseIds,
      leases: leases.map(item => { const recovery = item.events.filter(event => event.action === "recovered"); return { id: item.id, ownerId: item.ownerId,
        approvalId: item.approvalId, status: item.status, fencingToken: item.fencingToken, leaseExpiresAt: item.leaseExpiresAt || null,
        headEventDigest: item.headEventDigest, recoveryCount: recovery.length, lastRecoveredAt: recovery.at(-1)?.at || null,
        lastRecoveryEventDigest: recovery.at(-1)?.eventDigest || null, recoveryRequestIds: recovery.map(event => event.recoveryRequestId).filter(Boolean) }; }),
      findings, persistent: true, crossProcessSafe: typeof store.mutateEvidence === "function", readOnly: true, mutationAllowed: false };
  }

  async function exportRevalidationLeaseAuditEvents(ownerId) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const leases = rows.filter(row => row?.ownerId === ownerId && row.kind === REVALIDATION_LEASE_KIND)
      .sort((a, b) => String(a.id).localeCompare(String(b.id))).map(record => {
        const projection = { leaseId: record.id, ownerId: record.ownerId, approvalId: record.approvalId, schemaVersion: record.schemaVersion,
          status: record.status, fencingToken: record.fencingToken, leaseExpiresAt: record.leaseExpiresAt || null,
          createdAt: record.createdAt, updatedAt: record.updatedAt, headEventDigest: record.headEventDigest || null,
          sourceRecordDigest: record.digest, events: (record.events || []).map(event => clean(event)), rawLeaseTokenExcluded: true };
        return { ...projection, projectionDigest: sha256(canonical(projection)) };
      });
    const audit = await auditRevalidationLeases(ownerId);
    const body = { schemaVersion: 1, kind: "recovery-slo-cross-domain-revalidation-lease-audit-event-export", ownerId,
      exportedAt: now(), sourceAuditStatus: audit.status, leaseCount: leases.length,
      eventCount: leases.reduce((sum, item) => sum + item.events.length, 0), leases, rawLeaseTokensExcluded: true };
    return { ...body, digest: sha256(canonical(body)), integrityAlgorithm: "sha256", authenticity: "integrity-only-no-signature",
      readOnly: true, mutationAllowed: false };
  }
  async function verifyRevalidationLeaseAuditEventExport(ownerId, bundle) {
    assertOwner(ownerId);
    const findings = [];
    if (!bundle || bundle.ownerId !== ownerId || bundle.kind !== "recovery-slo-cross-domain-revalidation-lease-audit-event-export"
      || bundle.schemaVersion !== 1 || !Array.isArray(bundle.leases) || bundle.rawLeaseTokensExcluded !== true)
      findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_ENVELOPE_INVALID" });
    const body = bundle ? clean(bundle) : {};
    for (const key of ["digest", "integrityAlgorithm", "authenticity", "readOnly", "mutationAllowed"]) delete body[key];
    if (!bundle || bundle.digest !== sha256(canonical(body))) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_DIGEST_INVALID" });
    const seenLeaseIds = new Set(); let eventCount = 0;
    for (const lease of bundle?.leases || []) {
      eventCount += Array.isArray(lease.events) ? lease.events.length : 0;
      const projection = clean(lease); delete projection.projectionDigest;
      if (lease.ownerId !== ownerId || lease.leaseId !== leaseIdFor(ownerId, lease.approvalId)
        || !DIGEST.test(lease.sourceRecordDigest || "") || lease.projectionDigest !== sha256(canonical(projection))
        || seenLeaseIds.has(lease.leaseId) || lease.rawLeaseTokenExcluded !== true || !Array.isArray(lease.events))
        findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_PROJECTION_INVALID", leaseId: lease.leaseId });
      seenLeaseIds.add(lease.leaseId);
      let previousEventDigest = null, previousAt = -Infinity, previousFence = 0, previousAction = null, previousExpiry = null;
      const recoveryRequestIds = new Set();
      for (let index = 0; index < (lease.events || []).length; index++) {
        const event = lease.events[index];
        const at = Date.parse(event.at), expiry = event.leaseExpiresAt == null ? null : Date.parse(event.leaseExpiresAt);
        const eventValid = event.sequence === index + 1 && (event.previousEventDigest ?? null) === previousEventDigest
          && event.eventDigest === sha256(canonical(leaseEventBody(event))) && ["acquired", "reclaimed", "renewed", "released", "recovered"].includes(event.action)
          && Number.isSafeInteger(event.fencingToken) && event.fencingToken >= 1 && Number.isFinite(at) && at >= previousAt
          && validReason(event.reason || "Lease event system-generated") && DIGEST.test(event.leaseTokenDigest || "");
        if (!eventValid) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_EVENT_INVALID", leaseId: lease.leaseId, sequence: event.sequence });
        if (event.recoveryRequestId !== undefined) {
          if (event.action !== "recovered" || typeof event.recoveryRequestId !== "string" || !/^[A-Za-z0-9._:-]{1,120}$/.test(event.recoveryRequestId)
            || recoveryRequestIds.has(event.recoveryRequestId)) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_RECOVERY_REQUEST_INVALID", leaseId: lease.leaseId, sequence: event.sequence });
          else recoveryRequestIds.add(event.recoveryRequestId);
        }
        if (Object.prototype.hasOwnProperty.call(event, "previousRecordDigest")
          && (index === 0 ? event.previousRecordDigest !== null : !DIGEST.test(event.previousRecordDigest || "")))
          findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_RECORD_LINK_INVALID", leaseId: lease.leaseId, sequence: event.sequence });
        let transitionValid = true;
        const activeActions = new Set(["acquired", "reclaimed", "renewed"]);
        if (event.action === "acquired") transitionValid = event.fencingToken === previousFence + 1
          && (index === 0 || ["released", "recovered"].includes(previousAction)) && Number.isFinite(expiry) && expiry > at;
        else if (event.action === "reclaimed") transitionValid = index > 0 && activeActions.has(previousAction) && Number.isFinite(previousExpiry)
          && at >= previousExpiry && event.fencingToken === previousFence + 1 && Number.isFinite(expiry) && expiry > at;
        else if (event.action === "renewed") transitionValid = index > 0 && activeActions.has(previousAction) && event.fencingToken === previousFence
          && Number.isFinite(previousExpiry) && at < previousExpiry && Number.isFinite(expiry) && expiry > at && expiry >= previousExpiry;
        else if (event.action === "released") transitionValid = index > 0 && activeActions.has(previousAction) && event.fencingToken === previousFence && expiry === null;
        else if (event.action === "recovered") transitionValid = index > 0 && activeActions.has(previousAction) && Number.isFinite(previousExpiry)
          && at >= previousExpiry && event.fencingToken === previousFence + 1 && expiry === null;
        if (!transitionValid) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_TRANSITION_INVALID", leaseId: lease.leaseId, sequence: event.sequence });
        previousEventDigest = event.eventDigest || null; previousAt = Number.isFinite(at) ? at : previousAt;
        previousFence = Number.isSafeInteger(event.fencingToken) ? event.fencingToken : previousFence;
        previousAction = event.action; previousExpiry = Number.isFinite(expiry) ? expiry : null;
      }
      if (lease.headEventDigest !== previousEventDigest || lease.fencingToken !== previousFence
        || !Number.isFinite(Date.parse(lease.createdAt)) || !Number.isFinite(Date.parse(lease.updatedAt)))
        findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_HEAD_OR_STATE_INVALID", leaseId: lease.leaseId });
      const last = lease.events.at(-1);
      const expectedStatus = ["acquired", "reclaimed", "renewed"].includes(last?.action) ? "active"
        : last?.action === "released" ? "released" : last?.action === "recovered" ? "recovered" : null;
      if (!expectedStatus || lease.status !== expectedStatus || (lease.status === "active"
        ? !Number.isFinite(Date.parse(lease.leaseExpiresAt)) || lease.leaseExpiresAt !== new Date(previousExpiry).toISOString()
        : lease.leaseExpiresAt !== null)) findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_STATUS_INVALID", leaseId: lease.leaseId });
    }
    if (bundle && (bundle.leaseCount !== bundle.leases.length || bundle.eventCount !== eventCount))
      findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_COUNTS_INVALID" });
    const rows = await store.listEvidence(ownerId);
    for (const lease of bundle?.leases || []) {
      const current = rows.find(row => row?.ownerId === ownerId && row.id === lease.leaseId && row.kind === REVALIDATION_LEASE_KIND);
      if (!current || current.digest !== lease.sourceRecordDigest || current.headEventDigest !== lease.headEventDigest)
        findings.push({ code: "CROSS_DOMAIN_REVALIDATION_LEASE_EXPORT_SOURCE_MISMATCH", leaseId: lease.leaseId });
    }
    return { status: findings.length ? "unhealthy" : "verified", ownerId, leaseCount: bundle?.leases?.length || 0,
      eventCount, digest: bundle?.digest || null, findings, authenticity: "integrity-only-no-signature",
      rawLeaseTokensExcluded: true, readOnly: true, mutationAllowed: false };
  }

  async function auditPolicyBindingApprovalChain(ownerId) {
    assertOwner(ownerId);
    const domains = [];
    for (const [domain, service] of checkpointServices) {
      if (typeof service?.auditExternalSnapshotCheckpointPolicyBindingApprovalChain !== "function") continue;
      const audit = await service.auditExternalSnapshotCheckpointPolicyBindingApprovalChain(ownerId);
      domains.push({ domain, ...audit });
    }
    const statuses = domains.map(item => item.status);
    const status = statuses.includes("unhealthy") ? "unhealthy"
      : statuses.includes("history_unproven") ? "history_unproven"
      : statuses.includes("healthy") ? "healthy" : "not_initialized";
    return { status, ownerId, domainCount: domains.length, eventCount: domains.reduce((sum, item) => sum + (item.eventCount || 0), 0),
      domains, findings: domains.flatMap(item => (item.findings || []).map(finding => ({ domain: item.domain, ...finding }))),
      readOnly: true, mutationAllowed: false };
  }

  async function buildReceiptManifestSource(ownerId, guardrails, checkpointStatus) {
    const rows = await store.listEvidence(ownerId);
    const receipts = rows.filter(row => row?.ownerId === ownerId && row.kind === RECEIPT_KIND)
      .sort((a, b) => String(a.domain).localeCompare(String(b.domain)) || a.revision - b.revision || String(a.id).localeCompare(String(b.id)));
    const invalid = receipts.filter(item => item.digest !== digestRecord(item) || !Number.isSafeInteger(item.revision)
      || !DIGEST.test(item.digest || "") || !DIGEST.test(item.sourceReportDigest || ""));
    const receiptRefs = receipts.map(item => ({ id: item.id, digest: item.digest, domain: item.domain, revision: item.revision,
      previousReceiptDigest: item.previousReceiptDigest ?? null, transitionChallengeId: item.transitionChallengeId,
      sourceReportDigest: item.sourceReportDigest, historyNotProven: Boolean(item.historyNotProven) }));
    const sequenceRanges = {};
    for (const item of receipts) {
      const range = sequenceRanges[item.domain] || { firstRevision: item.revision, lastRevision: item.revision, count: 0 };
      range.firstRevision = Math.min(range.firstRevision, item.revision);
      range.lastRevision = Math.max(range.lastRevision, item.revision);
      range.count++;
      sequenceRanges[item.domain] = range;
    }
    const checkpoint = checkpointStatus ? { status: checkpointStatus.status, anchorSequence: checkpointStatus.anchorSequence ?? null,
      anchorDigest: checkpointStatus.anchorDigest ?? null, policyBindingStatus: checkpointStatus.policyBindingStatus ?? null,
      anchoredPolicyDigest: checkpointStatus.anchoredPolicyDigest ?? null, currentPolicyDigest: checkpointStatus.currentPolicyDigest ?? null,
      sourceDigest: checkpointStatus.sourceDigest ?? null, sourceCount: checkpointStatus.sourceCount ?? null } : null;
    const guardrailSummary = { status: guardrails?.status || "unavailable", compactionEligible: Boolean(guardrails?.compactionEligible),
      receiptAuditStatus: guardrails?.receiptAuditStatus || null, baselineAuditStatus: guardrails?.baselineAuditStatus || null,
      receiptCount: guardrails?.receiptCount ?? receipts.length, receiptHeads: guardrails?.receiptHeads || {},
      blockers: [...(guardrails?.blockers || [])].sort() };
    const sourceFingerprint = sha256(canonical({ ownerId, receiptRefs, sequenceRanges, checkpoint, guardrailSummary }));
    return { rows, receipts, invalid, receiptRefs, sequenceRanges, checkpoint, guardrailSummary, sourceFingerprint };
  }

  async function createProviderBaselineReceiptCompactionManifest(ownerId, { guardrails, checkpointStatus } = {}) {
    assertOwner(ownerId);
    if (!guardrails || typeof guardrails !== "object") throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_GUARDRAILS_REQUIRED", "Audit guardrails receipt wajib disediakan", 400);
    const source = await buildReceiptManifestSource(ownerId, guardrails, checkpointStatus);
    const blockers = [...(guardrails.blockers || [])];
    if (source.invalid.length) blockers.push("receipt_digest_invalid");
    if (checkpointStatus?.status !== "anchored" || checkpointStatus?.policyBindingStatus !== "current") blockers.push("external_checkpoint_not_current");
    if (!guardrails.compactionEligible) blockers.push("compaction_guardrails_not_eligible");
    const uniqueBlockers = [...new Set(blockers)].sort();
    const status = uniqueBlockers.length ? "blocked" : "ready_for_review";
    const id = `cd-receipt-manifest-${ownerHash(ownerId).slice(0, 12)}-${source.sourceFingerprint.slice(0, 16)}`;
    const unsigned = { id, ownerId, kind: MANIFEST_KIND, schemaVersion: 1, status, sourceFingerprint: source.sourceFingerprint,
      receiptCount: source.receipts.length, receiptRefs: source.receiptRefs, sequenceRanges: source.sequenceRanges,
      receiptHeads: guardrails.receiptHeads || {}, checkpoint: source.checkpoint, guardrailSummary: source.guardrailSummary,
      requiredPreservations: ["per-domain receipt head digest", "receipt count and revision ranges", "previous-receipt linkage",
        "historyNotProven flags", "source challenge and conformance report digests"],
      historyNotProvenDomains: [...new Set(source.receipts.filter(item => item.historyNotProven).map(item => item.domain))].sort(),
      blockers: uniqueBlockers, createdAt: now(), manifestOnly: true, compactionPerformed: false,
      automaticCompactionAllowed: false, destructiveActionPerformed: false, readOnly: false, mutationAllowed: false };
    const manifest = { ...unsigned, digest: digestRecord(unsigned) };
    const existing = await store.getEvidence(ownerId, id);
    if (existing) {
      if (existing.digest !== digestRecord(existing) || existing.sourceFingerprint !== source.sourceFingerprint)
        throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_CONFLICT", "Manifest compaction dengan fingerprint sama tidak cocok", 409);
      return { status: existing.status, manifest: existing, idempotent: true, sourceCurrent: true,
        compactionPerformed: false, automaticCompactionAllowed: false, readOnly: true, mutationAllowed: false };
    }
    try { await store.putEvidence(ownerId, manifest, { overwrite: false }); }
    catch (error) {
      const concurrent = await store.getEvidence(ownerId, id);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.sourceFingerprint !== source.sourceFingerprint)
        throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_WRITE_FAILED", `Manifest compaction gagal disimpan secara konsisten: ${error?.code || error?.message || "WRITE_FAILED"}`, 409,
          { cause: error?.code || error?.message || "WRITE_FAILED" });
      return { status: concurrent.status, manifest: concurrent, idempotent: true, sourceCurrent: true,
        compactionPerformed: false, automaticCompactionAllowed: false, readOnly: true, mutationAllowed: false };
    }
    const saved = await store.getEvidence(ownerId, id);
    if (!saved || saved.digest !== digestRecord(saved)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_WRITE_FAILED", "Manifest compaction gagal diverifikasi setelah penyimpanan", 409);
    return { status: saved.status, manifest: saved, idempotent: false, sourceCurrent: true,
      compactionPerformed: false, automaticCompactionAllowed: false, readOnly: true, mutationAllowed: false };
  }

  async function verifyProviderBaselineReceiptCompactionManifest(ownerId, manifestId, { guardrails, checkpointStatus } = {}) {
    assertOwner(ownerId);
    const manifest = await store.getEvidence(ownerId, manifestId);
    if (!manifest || manifest.ownerId !== ownerId || manifest.kind !== MANIFEST_KIND)
      return { status: "not_found", valid: false, current: false, compactionPerformed: false, findings: [{ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_NOT_FOUND" }], readOnly: true, mutationAllowed: false };
    const integrityValid = manifest.digest === digestRecord(manifest) && DIGEST.test(manifest.sourceFingerprint || "")
      && manifest.manifestOnly === true && manifest.compactionPerformed === false && manifest.automaticCompactionAllowed === false;
    const source = await buildReceiptManifestSource(ownerId, guardrails || { blockers: ["guardrails_not_supplied"], compactionEligible: false }, checkpointStatus || null);
    const current = integrityValid && source.sourceFingerprint === manifest.sourceFingerprint;
    const findings = [];
    if (!integrityValid) findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_INTEGRITY_INVALID" });
    if (integrityValid && !current) findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_SOURCE_CHANGED" });
    return { status: !integrityValid ? "unhealthy" : current ? manifest.status : "stale", valid: integrityValid,
      current, manifestId, sourceFingerprint: source.sourceFingerprint, manifestSourceFingerprint: manifest.sourceFingerprint,
      compactionPerformed: false, automaticCompactionAllowed: false, findings, readOnly: true, mutationAllowed: false };
  }

  async function prepareProviderBaselineReceiptCompactionManifestApproval(ownerId, manifestId, { guardrails, checkpointStatus, reason } = {}) {
    assertOwner(ownerId);
    if (typeof manifestId !== "string" || !manifestId.trim()) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_ID_REQUIRED", "Manifest ID wajib ditentukan", 400);
    if (!validReason(reason)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REASON_INVALID", "Alasan persetujuan manifest wajib 12–240 karakter", 400);
    const verification = await verifyProviderBaselineReceiptCompactionManifest(ownerId, manifestId, { guardrails, checkpointStatus });
    if (!verification.valid || !verification.current || verification.status !== "ready_for_review")
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_NOT_APPROVABLE", "Manifest harus valid, terkini, dan siap ditinjau sebelum persetujuan", 409,
        { status: verification.status, findings: verification.findings || [] });
    const manifest = await store.getEvidence(ownerId, manifestId);
    if (!manifest || manifest.status !== "ready_for_review" || manifest.compactionPerformed !== false
      || manifest.automaticCompactionAllowed !== false || manifest.destructiveActionPerformed !== false)
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_NOT_APPROVABLE", "Manifest tidak memenuhi guardrail non-destruktif", 409);
    const createdAt = now(), id = `${MANIFEST_APPROVAL_CHALLENGE_KIND}-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: MANIFEST_APPROVAL_CHALLENGE_KIND, schemaVersion: 1, status: "prepared", manifestId,
      manifestDigest: manifest.digest, sourceFingerprint: manifest.sourceFingerprint,
      expectedCheckpointDigest: manifest.checkpoint?.anchorDigest || null,
      expectedCheckpointSequence: manifest.checkpoint?.anchorSequence ?? null,
      reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + 10 * 60_000).toISOString() };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    return { status: "prepared", challengeId: id, challengeDigest: challenge.digest, manifestId, manifestDigest: manifest.digest,
      sourceFingerprint: manifest.sourceFingerprint, createdAt, expiresAt: challenge.expiresAt,
      confirmation: `APPROVE RECEIPT MANIFEST ${challenge.digest.slice(0, 12)}`,
      compactionPerformed: false, automaticCompactionAllowed: false, destructiveActionPerformed: false };
  }

  async function applyProviderBaselineReceiptCompactionManifestApproval(ownerId, challengeId, { guardrails, checkpointStatus, confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== MANIFEST_APPROVAL_CHALLENGE_KIND
      || challenge.digest !== digestRecord(challenge)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_CHALLENGE_INVALID", "Challenge persetujuan manifest tidak valid", 409);
    const approvalId = `cd-receipt-manifest-approval-${ownerHash(ownerId).slice(0, 12)}-${sha256(challenge.manifestId).slice(0, 24)}`;
    const existing = await store.getEvidence(ownerId, approvalId);
    if (existing) {
      if (existing.digest !== digestRecord(existing) || existing.challengeId !== challenge.id || existing.manifestId !== challenge.manifestId
        || existing.manifestDigest !== challenge.manifestDigest)
        throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_CONFLICT", "Manifest sudah mempunyai approval lain atau record approval tidak konsisten", 409);
      if (challenge.status !== "completed") {
        const completedUnsigned = { ...clean(challenge), status: "completed", preparedChallengeDigest: challenge.preparedChallengeDigest || challenge.digest,
          approvalId, approvalDigest: existing.digest, completedAt: now(), recoveredAfterApprovalWrite: true };
        delete completedUnsigned.digest;
        const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
        try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
        catch { const latest = await store.getEvidence(ownerId, challengeId); if (!latest || latest.status !== "completed" || latest.approvalDigest !== existing.digest) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_FINALIZE_CONFLICT", "Approval tersimpan tetapi challenge tidak dapat difinalisasi", 409); }
      }
      return { status: "approved_for_review", approval: existing, idempotent: true, compactionPerformed: false,
        automaticCompactionAllowed: false, destructiveActionPerformed: false };
    }
    if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `APPROVE RECEIPT MANIFEST ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_EXPIRED", "Challenge persetujuan manifest kedaluwarsa, sudah digunakan, atau konfirmasinya tidak cocok", 409);
    const verification = await verifyProviderBaselineReceiptCompactionManifest(ownerId, challenge.manifestId, { guardrails, checkpointStatus });
    const manifest = await store.getEvidence(ownerId, challenge.manifestId);
    if (!verification.valid || !verification.current || verification.status !== "ready_for_review" || !manifest
      || manifest.digest !== challenge.manifestDigest || manifest.sourceFingerprint !== challenge.sourceFingerprint
      || (manifest.checkpoint?.anchorDigest || null) !== challenge.expectedCheckpointDigest
      || (manifest.checkpoint?.anchorSequence ?? null) !== challenge.expectedCheckpointSequence)
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_STALE", "Manifest, checkpoint, atau guardrails berubah sejak challenge dibuat", 409,
        { status: verification.status, findings: verification.findings || [] });
    const createdAt = now();
    const unsigned = { id: approvalId, ownerId, kind: MANIFEST_APPROVAL_KIND, schemaVersion: 1, status: "approved_for_review",
      decision: "approve_for_review", manifestId: manifest.id, manifestDigest: manifest.digest, sourceFingerprint: manifest.sourceFingerprint,
      challengeId: challenge.id, challengeDigest: challenge.digest, reason: challenge.reason, approvedAt: createdAt,
      checkpointDigest: manifest.checkpoint?.anchorDigest || null, checkpointSequence: manifest.checkpoint?.anchorSequence ?? null,
      compactionPerformed: false, automaticCompactionAllowed: false, destructiveActionPerformed: false };
    const approval = { ...unsigned, digest: digestRecord(unsigned) };
    try { await store.putEvidence(ownerId, approval, { overwrite: false }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, approvalId);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.challengeId !== challenge.id)
        throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_WRITE_FAILED", "Approval manifest gagal disimpan secara konsisten", 409);
    }
    const savedApproval = await store.getEvidence(ownerId, approvalId);
    const completedUnsigned = { ...clean(challenge), status: "completed", preparedChallengeDigest: challenge.preparedChallengeDigest || challenge.digest,
      approvalId, approvalDigest: savedApproval.digest, completedAt: now() };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
    catch { const latest = await store.getEvidence(ownerId, challengeId); if (!latest || latest.status !== "completed" || latest.approvalDigest !== savedApproval.digest) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_FINALIZE_CONFLICT", "Approval tersimpan tetapi challenge tidak dapat difinalisasi", 409); }
    const verifiedApproval = await store.getEvidence(ownerId, approvalId);
    if (!verifiedApproval || verifiedApproval.digest !== digestRecord(verifiedApproval)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_WRITE_FAILED", "Approval manifest gagal diverifikasi setelah penyimpanan", 409);
    return { status: "approved_for_review", approval: verifiedApproval, idempotent: false, compactionPerformed: false,
      automaticCompactionAllowed: false, destructiveActionPerformed: false };
  }

  function manifestVerificationSnapshot(verification) {
    return { status: verification?.status || "unavailable", valid: Boolean(verification?.valid), current: Boolean(verification?.current),
      sourceFingerprint: verification?.sourceFingerprint || null, manifestSourceFingerprint: verification?.manifestSourceFingerprint || null,
      findings: (verification?.findings || []).map(item => item.code || "UNKNOWN").sort() };
  }

  async function prepareProviderBaselineReceiptCompactionManifestApprovalRevocation(ownerId, approvalId,
    { guardrails, checkpointStatus, reason } = {}) {
    assertOwner(ownerId);
    if (typeof approvalId !== "string" || !approvalId.trim()) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_ID_REQUIRED", "Approval ID wajib ditentukan", 400);
    if (!validReason(reason)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_REASON_INVALID", "Alasan pencabutan wajib 12–240 karakter", 400);
    const rows = await store.listEvidence(ownerId);
    const approval = rows.find(row => row?.ownerId === ownerId && row.id === approvalId && row.kind === MANIFEST_APPROVAL_KIND);
    if (!approval || approval.digest !== digestRecord(approval) || approval.status !== "approved_for_review")
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_INVALID", "Approval manifest tidak valid atau tidak ditemukan", 409);
    const prior = rows.find(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_REVOCATION_KIND && row.approvalId === approvalId);
    if (prior) {
      if (prior.digest !== digestRecord(prior)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_INVALID", "Record pencabutan yang sudah ada tidak valid", 409);
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_ALREADY_REVOKED", "Approval manifest sudah dicabut", 409, { revocationId: prior.id });
    }
    const verification = await verifyProviderBaselineReceiptCompactionManifest(ownerId, approval.manifestId, { guardrails, checkpointStatus });
    if (!verification.valid || verification.status === "unhealthy")
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_SOURCE_UNTRUSTED", "Integritas manifest tidak dapat dibuktikan untuk pencabutan", 409,
        { status: verification.status, findings: verification.findings || [] });
    if (verification.current && verification.status === "ready_for_review")
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_STILL_CURRENT", "Approval tidak dapat dicabut melalui jalur supersession karena manifest masih memenuhi syarat", 409);
    const sourceState = manifestVerificationSnapshot(verification), sourceStateDigest = sha256(canonical(sourceState));
    const createdAt = now(), id = `${MANIFEST_APPROVAL_REVOCATION_CHALLENGE_KIND}-${randomUUID()}`;
    const unsigned = { id, ownerId, kind: MANIFEST_APPROVAL_REVOCATION_CHALLENGE_KIND, schemaVersion: 1, status: "prepared",
      approvalId, approvalDigest: approval.digest, manifestId: approval.manifestId, manifestDigest: approval.manifestDigest,
      sourceState, sourceStateDigest, reason: reason.trim(), createdAt, expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString(),
      compactionPerformed: false, automaticCompactionAllowed: false, destructiveActionPerformed: false };
    const challenge = { ...unsigned, digest: digestRecord(unsigned) };
    await store.putEvidence(ownerId, challenge, { overwrite: false });
    const saved = await store.getEvidence(ownerId, id);
    if (!saved || saved.digest !== digestRecord(saved)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_CHALLENGE_WRITE_FAILED", "Challenge pencabutan tidak lolos verifikasi setelah penyimpanan", 409);
    return { status: "prepared", challengeId: saved.id, challengeDigest: saved.digest, approvalId, manifestId: approval.manifestId,
      sourceStatus: verification.status, sourceStateDigest, expiresAt: saved.expiresAt,
      confirmation: `REVOKE RECEIPT MANIFEST APPROVAL ${saved.digest.slice(0, 12)}`,
      compactionPerformed: false, automaticCompactionAllowed: false, destructiveActionPerformed: false };
  }

  async function applyProviderBaselineReceiptCompactionManifestApprovalRevocation(ownerId, challengeId,
    { guardrails, checkpointStatus, confirmation } = {}) {
    assertOwner(ownerId);
    const challenge = await store.getEvidence(ownerId, challengeId);
    if (!challenge || challenge.ownerId !== ownerId || challenge.kind !== MANIFEST_APPROVAL_REVOCATION_CHALLENGE_KIND
      || challenge.digest !== digestRecord(challenge))
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_CHALLENGE_INVALID", "Challenge pencabutan tidak valid", 409);
    const revocationId = `cd-receipt-manifest-approval-revocation-${ownerHash(ownerId).slice(0, 12)}-${sha256(challenge.approvalId).slice(0, 24)}`;
    const existing = await store.getEvidence(ownerId, revocationId);
    if (existing) {
      if (existing.digest !== digestRecord(existing) || existing.challengeId !== challenge.id || existing.approvalId !== challenge.approvalId
        || existing.approvalDigest !== challenge.approvalDigest)
        throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_CONFLICT", "Approval memiliki record pencabutan yang berbeda atau tidak konsisten", 409);
      if (challenge.status !== "completed") {
        const completedUnsigned = { ...clean(challenge), status: "completed", preparedChallengeDigest: challenge.preparedChallengeDigest || challenge.digest,
          revocationId, revocationDigest: existing.digest, completedAt: now(), recoveredAfterRevocationWrite: true };
        delete completedUnsigned.digest;
        const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
        try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
        catch { const latest = await store.getEvidence(ownerId, challengeId); if (!latest || latest.status !== "completed" || latest.revocationDigest !== existing.digest)
          throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_FINALIZE_CONFLICT", "Pencabutan tersimpan tetapi challenge tidak dapat difinalisasi", 409); }
      }
      return { status: "revoked", approvalId: existing.approvalId, revocation: existing, idempotent: true,
        compactionPerformed: false, automaticCompactionAllowed: false, destructiveActionPerformed: false };
    }
    if (challenge.status !== "prepared" || !Number.isFinite(Date.parse(challenge.expiresAt)) || Date.parse(challenge.expiresAt) <= Date.parse(now())
      || confirmation !== `REVOKE RECEIPT MANIFEST APPROVAL ${challenge.digest.slice(0, 12)}`)
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_EXPIRED", "Challenge pencabutan kedaluwarsa, sudah digunakan, atau konfirmasinya tidak cocok", 409);
    const approval = await store.getEvidence(ownerId, challenge.approvalId);
    if (!approval || approval.digest !== digestRecord(approval) || approval.digest !== challenge.approvalDigest
      || approval.manifestId !== challenge.manifestId || approval.manifestDigest !== challenge.manifestDigest)
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_APPROVAL_CHANGED", "Approval berubah sejak challenge pencabutan dibuat", 409);
    const verification = await verifyProviderBaselineReceiptCompactionManifest(ownerId, challenge.manifestId, { guardrails, checkpointStatus });
    if (!verification.valid || verification.status === "unhealthy")
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_SOURCE_UNTRUSTED", "Integritas manifest tidak dapat dibuktikan saat pencabutan", 409);
    const currentState = manifestVerificationSnapshot(verification), currentStateDigest = sha256(canonical(currentState));
    if (currentStateDigest !== challenge.sourceStateDigest || (verification.current && verification.status === "ready_for_review"))
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_STALE", "Kondisi sumber berubah atau manifest kembali memenuhi syarat setelah challenge dibuat", 409,
        { expectedSourceStateDigest: challenge.sourceStateDigest, actualSourceStateDigest: currentStateDigest, status: verification.status });
    const revokedAt = now();
    const unsigned = { id: revocationId, ownerId, kind: MANIFEST_APPROVAL_REVOCATION_KIND, schemaVersion: 1, status: "revoked",
      decision: "revoke_approval", approvalId: approval.id, approvalDigest: approval.digest, manifestId: approval.manifestId,
      manifestDigest: approval.manifestDigest, challengeId: challenge.id, challengeDigest: challenge.digest,
      sourceStateDigest: challenge.sourceStateDigest, sourceStatus: verification.status, reason: challenge.reason, revokedAt,
      compactionPerformed: false, automaticCompactionAllowed: false, destructiveActionPerformed: false };
    const revocation = { ...unsigned, digest: digestRecord(unsigned) };
    try { await store.putEvidence(ownerId, revocation, { overwrite: false }); }
    catch {
      const concurrent = await store.getEvidence(ownerId, revocationId);
      if (!concurrent || concurrent.digest !== digestRecord(concurrent) || concurrent.challengeId !== challenge.id
        || concurrent.approvalDigest !== approval.digest)
        throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_WRITE_FAILED", "Record pencabutan gagal disimpan secara konsisten", 409);
    }
    const saved = await store.getEvidence(ownerId, revocationId);
    if (!saved || saved.digest !== digestRecord(saved)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_WRITE_FAILED", "Record pencabutan gagal diverifikasi setelah penyimpanan", 409);
    const completedUnsigned = { ...clean(challenge), status: "completed", preparedChallengeDigest: challenge.preparedChallengeDigest || challenge.digest,
      revocationId, revocationDigest: saved.digest, completedAt: now() };
    delete completedUnsigned.digest;
    const completed = { ...completedUnsigned, digest: digestRecord(completedUnsigned) };
    try { await store.putEvidence(ownerId, completed, { expectedVersion: challenge._storage?.version }); }
    catch { const latest = await store.getEvidence(ownerId, challengeId); if (!latest || latest.status !== "completed" || latest.revocationDigest !== saved.digest)
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_FINALIZE_CONFLICT", "Pencabutan tersimpan tetapi challenge tidak dapat difinalisasi", 409); }
    return { status: "revoked", approvalId: approval.id, revocation: saved, idempotent: false,
      compactionPerformed: false, automaticCompactionAllowed: false, destructiveActionPerformed: false };
  }

  async function recordProviderBaselineReceiptCompactionManifestApprovalSupersession(ownerId, approvalId, { verifyManifest, reason } = {}) {
    assertOwner(ownerId);
    if (typeof approvalId !== "string" || !approvalId.trim() || typeof verifyManifest !== "function")
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_ARGUMENT_INVALID", "Approval ID dan verifier manifest wajib ditentukan", 400);
    if (!validReason(reason)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_REASON_INVALID", "Alasan supersession wajib 12–240 karakter", 400);
    const rows = await store.listEvidence(ownerId);
    const approval = rows.find(row => row?.ownerId === ownerId && row.id === approvalId && row.kind === MANIFEST_APPROVAL_KIND);
    if (!approval || approval.digest !== digestRecord(approval)) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_INVALID", "Approval manifest tidak valid atau tidak ditemukan", 409);
    if (rows.some(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_REVOCATION_KIND && row.approvalId === approvalId))
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_ALREADY_REVOKED", "Approval sudah dicabut; supersession event tambahan tidak diperlukan", 409);
    const verification = await verifyManifest(ownerId, approval.manifestId);
    if (!verification?.valid || verification.status === "unhealthy") throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_SOURCE_UNTRUSTED", "Manifest tidak dapat diverifikasi untuk pencatatan supersession", 409);
    if (verification.current && verification.status === "ready_for_review") throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_STILL_CURRENT", "Manifest masih memenuhi syarat dan tidak dapat dicatat sebagai superseded", 409);
    const sourceState = manifestVerificationSnapshot(verification), sourceStateDigest = sha256(canonical(sourceState));
    const supersessions = rows.filter(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_SUPERSESSION_KIND).sort((a, b) => a.sequence - b.sequence);
    const chain = auditSupersessionEvents(ownerId, supersessions, rows);
    if (chain.findings.length) throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_LEDGER_UNHEALTHY", "Supersession ledger tidak sehat", 409, { findings: chain.findings });
    const prior = supersessions.find(item => item.approvalId === approvalId && item.sourceStateDigest === sourceStateDigest);
    if (prior) return { status: "superseded_recorded", event: prior, idempotent: true, externalCheckpointPending: true };
    const createdAt = now(), id = `${MANIFEST_APPROVAL_SUPERSESSION_KIND}-${sha256(`${ownerId}\0${approvalId}\0${sourceStateDigest}`).slice(0, 32)}`;
    const body = { id, ownerId, kind: MANIFEST_APPROVAL_SUPERSESSION_KIND, schemaVersion: 1, status: "superseded", sequence: supersessions.length + 1,
      previousEventDigest: supersessions.at(-1)?.eventDigest || null, approvalId, approvalDigest: approval.digest, manifestId: approval.manifestId,
      manifestDigest: approval.manifestDigest, sourceState, sourceStateDigest, sourceStatus: verification.status, reason: reason.trim(), createdAt };
    const event = { ...body, eventDigest: sha256(canonical(body)) };
    event.digest = digestRecord(event);
    try { await store.putEvidence(ownerId, event, { overwrite: false }); }
    catch {
      const existing = await store.getEvidence(ownerId, id);
      if (!existing || existing.digest !== digestRecord(existing) || existing.eventDigest !== event.eventDigest)
        throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_WRITE_FAILED", "Supersession event gagal disimpan secara konsisten", 409);
    }
    const saved = await store.getEvidence(ownerId, id);
    if (!saved || saved.digest !== digestRecord(saved) || saved.eventDigest !== sha256(canonical(Object.fromEntries(Object.entries(saved).filter(([key]) => !["_storage", "digest", "eventDigest"].includes(key))))))
      throw new AgenticError("CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_WRITE_FAILED", "Supersession event gagal diverifikasi setelah penyimpanan", 409);
    return { status: "superseded_recorded", event: saved, idempotent: false, externalCheckpointPending: true };
  }
  function auditSupersessionEvents(ownerId, supersessions, rows) {
    const findings = []; let previous = null, expected = 1;
    for (const event of supersessions) {
      const body = clean(event); delete body.digest; delete body.eventDigest;
      const approval = rows.find(row => row?.ownerId === ownerId && row.id === event.approvalId && row.kind === MANIFEST_APPROVAL_KIND);
      if (event.digest !== digestRecord(event) || event.eventDigest !== sha256(canonical(body)) || event.sequence !== expected
        || (event.previousEventDigest ?? null) !== previous || event.status !== "superseded" || !validReason(event.reason)
        || !approval || approval.digest !== event.approvalDigest || approval.manifestId !== event.manifestId || approval.manifestDigest !== event.manifestDigest
        || !DIGEST.test(event.sourceStateDigest || "") || sha256(canonical(event.sourceState)) !== event.sourceStateDigest)
        findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_SUPERSESSION_CHAIN_INVALID", eventId: event.id });
      previous = event.eventDigest || null; expected++;
    }
    return { findings, headDigest: previous, eventCount: supersessions.length };
  }

  async function auditProviderBaselineReceiptCompactionManifestApprovals(ownerId, { verifyManifest = null } = {}) {
    assertOwner(ownerId);
    const rows = await store.listEvidence(ownerId);
    const challenges = rows.filter(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_CHALLENGE_KIND);
    const approvals = rows.filter(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_KIND);
    const revocationChallenges = rows.filter(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_REVOCATION_CHALLENGE_KIND);
    const revocations = rows.filter(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_REVOCATION_KIND);
    const supersessions = rows.filter(row => row?.ownerId === ownerId && row.kind === MANIFEST_APPROVAL_SUPERSESSION_KIND).sort((a, b) => a.sequence - b.sequence);
    const supersessionAudit = auditSupersessionEvents(ownerId, supersessions, rows);
    const findings = [...supersessionAudit.findings], seenManifests = new Map(), revocationByApproval = new Map();
    for (const approval of approvals) {
      const challenge = challenges.find(item => item.id === approval.challengeId);
      const manifest = rows.find(item => item?.ownerId === ownerId && item.id === approval.manifestId && item.kind === MANIFEST_KIND);
      if (approval.digest !== digestRecord(approval) || approval.status !== "approved_for_review" || approval.decision !== "approve_for_review"
        || approval.compactionPerformed !== false || approval.automaticCompactionAllowed !== false || approval.destructiveActionPerformed !== false
        || !challenge || challenge.digest !== digestRecord(challenge) || challenge.status !== "completed"
        || challenge.approvalId !== approval.id || challenge.approvalDigest !== approval.digest
        || challenge.manifestId !== approval.manifestId || challenge.manifestDigest !== approval.manifestDigest
        || (challenge.preparedChallengeDigest || challenge.digest) !== approval.challengeDigest
        || !manifest || manifest.digest !== digestRecord(manifest) || manifest.digest !== approval.manifestDigest
        || manifest.sourceFingerprint !== approval.sourceFingerprint)
        findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_INVALID", approvalId: approval.id });
      if (seenManifests.has(approval.manifestId)) findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_DUPLICATE", manifestId: approval.manifestId });
      seenManifests.set(approval.manifestId, approval.id);
    }
    for (const challenge of challenges) {
      if (challenge.digest !== digestRecord(challenge)) findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_CHALLENGE_INVALID", challengeId: challenge.id });
      if (challenge.status === "completed" && !approvals.some(item => item.id === challenge.approvalId && item.digest === challenge.approvalDigest))
        findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_MISSING", challengeId: challenge.id });
    }
    for (const revocation of revocations) {
      const approval = approvals.find(item => item.id === revocation.approvalId);
      const challenge = revocationChallenges.find(item => item.id === revocation.challengeId);
      if (revocation.digest !== digestRecord(revocation) || revocation.status !== "revoked" || revocation.decision !== "revoke_approval"
        || revocation.compactionPerformed !== false || revocation.automaticCompactionAllowed !== false || revocation.destructiveActionPerformed !== false
        || !approval || approval.digest !== revocation.approvalDigest || approval.manifestId !== revocation.manifestId
        || approval.manifestDigest !== revocation.manifestDigest || !challenge || challenge.digest !== digestRecord(challenge)
        || challenge.status !== "completed" || challenge.revocationId !== revocation.id || challenge.revocationDigest !== revocation.digest
        || (challenge.preparedChallengeDigest || challenge.digest) !== revocation.challengeDigest
        || challenge.approvalId !== approval.id || challenge.approvalDigest !== approval.digest || challenge.sourceStateDigest !== revocation.sourceStateDigest)
        findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_INVALID", revocationId: revocation.id });
      if (revocationByApproval.has(revocation.approvalId)) findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_MULTIPLE_REVOCATIONS", approvalId: revocation.approvalId });
      revocationByApproval.set(revocation.approvalId, revocation);
    }
    for (const challenge of revocationChallenges) {
      if (challenge.digest !== digestRecord(challenge)) findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_CHALLENGE_INVALID", challengeId: challenge.id });
      if (challenge.status === "completed" && !revocations.some(item => item.id === challenge.revocationId && item.digest === challenge.revocationDigest))
        findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_MISSING", challengeId: challenge.id });
    }
    const approvalStates = [];
    const supersessionByApproval = new Map();
    for (const event of supersessions) if (!supersessionByApproval.has(event.approvalId)) supersessionByApproval.set(event.approvalId, event);
    for (const approval of approvals) {
      const revocation = revocationByApproval.get(approval.id);
      const supersession = supersessionByApproval.get(approval.id);
      let currentStatus = revocation ? "revoked" : supersession ? "superseded" : "approved_for_review", sourceStatus = null;
      if (!revocation && !supersession && typeof verifyManifest === "function") {
        const verification = await verifyManifest(ownerId, approval.manifestId);
        sourceStatus = verification?.status || "unavailable";
        if (!verification?.valid || sourceStatus === "unhealthy") {
          findings.push({ code: "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_SOURCE_UNTRUSTED", approvalId: approval.id, status: sourceStatus });
          currentStatus = "unhealthy";
        } else if (!verification.current || sourceStatus !== "ready_for_review") currentStatus = "superseded";
      }
      approvalStates.push({ id: approval.id, manifestId: approval.manifestId, digest: approval.digest, decision: approval.decision,
        approvedAt: approval.approvedAt, currentStatus, sourceStatus, revokedAt: revocation?.revokedAt || null, revocationId: revocation?.id || null,
        supersededAt: supersession?.createdAt || null, supersessionId: supersession?.id || null,
        compactionPerformed: approval.compactionPerformed, automaticCompactionAllowed: approval.automaticCompactionAllowed });
    }
    const integrityStatus = findings.length ? "unhealthy" : approvals.length || revocations.length || supersessions.length ? "healthy" : challenges.length || revocationChallenges.length ? "pending" : "not_initialized";
    const status = findings.length ? "unhealthy" : approvalStates.some(item => item.currentStatus === "superseded") ? "superseded"
      : approvalStates.length && approvalStates.every(item => item.currentStatus === "revoked") ? "revoked"
        : approvalStates.some(item => item.currentStatus === "revoked") ? "revoked"
          : approvalStates.length ? "healthy" : challenges.length || revocationChallenges.length ? "pending" : "not_initialized";
    return { status, integrityStatus, ownerId, challengeCount: challenges.length, approvalCount: approvals.length,
      revocationChallengeCount: revocationChallenges.length, revocationCount: revocations.length,
      supersessionCount: supersessions.length, supersessionHeadDigest: supersessionAudit.headDigest,
      supersededCount: approvalStates.filter(item => item.currentStatus === "superseded").length,
      currentApprovalCount: approvalStates.filter(item => item.currentStatus === "approved_for_review").length,
      approvals: approvalStates, supersessions: supersessions.map(item => ({ id: item.id, digest: item.digest, eventDigest: item.eventDigest,
        sequence: item.sequence, approvalId: item.approvalId, approvalDigest: item.approvalDigest, manifestId: item.manifestId,
        manifestDigest: item.manifestDigest, sourceStateDigest: item.sourceStateDigest, createdAt: item.createdAt })),
      findings, compactionPerformed: false, automaticCompactionAllowed: false,
      destructiveActionPerformed: false, readOnly: true, mutationAllowed: false };
  }

  return Object.freeze({ getRevalidationGeneration, isRevalidationGenerationCurrent, observeRevalidationFingerprint, runConsistentRevalidation,
    auditPolicyBindingApprovalChain, createProviderBaselineReceiptCompactionManifest, verifyProviderBaselineReceiptCompactionManifest,
    prepareProviderBaselineReceiptCompactionManifestApproval, applyProviderBaselineReceiptCompactionManifestApproval,
    prepareProviderBaselineReceiptCompactionManifestApprovalRevocation, applyProviderBaselineReceiptCompactionManifestApprovalRevocation,
    auditProviderBaselineReceiptCompactionManifestApprovals, recordProviderBaselineReceiptCompactionManifestApprovalSupersession,
    getCachedRevalidation, setCachedRevalidation, invalidateRevalidation, auditRevalidationCache,
    runLeasedRevalidation, recoverRevalidationLease, auditRevalidationLeases,
    exportRevalidationLeaseAuditEvents, verifyRevalidationLeaseAuditEventExport });
}
