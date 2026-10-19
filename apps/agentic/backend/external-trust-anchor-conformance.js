import { createHash, randomUUID } from "node:crypto";

const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function digestAnchor(anchor) {
  const { digest, ...unsigned } = anchor;
  return sha256(canonical(unsigned));
}
function candidate(ownerId, anchorSequence, revision, previousAnchorDigest, reason) {
  const unsigned = {
    schemaVersion: 1, ownerId, anchorSequence, revision,
    trustDigest: sha256(`conformance-trust-${ownerId}-${revision}`),
    headHash: sha256(`conformance-head-${ownerId}-${revision}`),
    bootstrapDigest: sha256(`conformance-bootstrap-${ownerId}`),
    previousAnchorDigest, anchoredAt: new Date(0 + revision * 1000).toISOString(),
    reason, enrollmentChallengeId: null
  };
  return { ...unsigned, digest: digestAnchor(unsigned) };
}
function sameAnchor(a, b) { return canonical(a) === canonical(b); }

/**
 * Destructive contract probe for a disposable external-anchor namespace.
 * It intentionally writes two revisions and verifies compare-and-set behavior.
 * Do not run against a production owner namespace.
 */
export async function runExternalTrustAnchorProviderConformance(provider, {
  ownerId = `__agentic_v4_conformance__${randomUUID()}`,
  allowWrites = false
} = {}) {
  if (!provider || typeof provider.read !== "function" || typeof provider.compareAndSet !== "function") {
    throw new TypeError("Provider harus menyediakan read(ownerId) dan compareAndSet(ownerId, expectedDigest, candidate)");
  }
  if (allowWrites !== true) throw new TypeError("Conformance probe menulis anchor; set allowWrites:true hanya untuk namespace disposable");
  if (typeof ownerId !== "string" || !/^__agentic_v4_conformance__[A-Za-z0-9._:-]{8,180}$/.test(ownerId)) {
    throw new TypeError("Conformance probe hanya diizinkan pada owner namespace disposable berprefix __agentic_v4_conformance__");
  }

  const checks = [];
  const record = (name, passed, details = {}) => checks.push({ name, passed: passed === true, ...details });
  const initial = await provider.read(ownerId);
  record("empty_namespace", initial == null, { observed: initial == null ? "empty" : "occupied" });
  if (initial != null) return { conformant: false, ownerId, checks, findings: ["CONFORMANCE_NAMESPACE_NOT_EMPTY"], writesPerformed: 0 };

  const first = candidate(ownerId, 1, 0, null, "genesis");
  const created = await provider.compareAndSet(ownerId, null, first);
  const firstRead = await provider.read(ownerId);
  const firstApplied = created === true || created?.applied === true;
  record("genesis_compare_and_set", firstApplied && sameAnchor(firstRead, first));
  if (!firstApplied || !sameAnchor(firstRead, first)) {
    return { conformant: false, ownerId, checks, findings: ["CONFORMANCE_GENESIS_CAS_FAILED"], writesPerformed: firstApplied ? 1 : 0 };
  }

  const stale = candidate(ownerId, 1, 0, null, "genesis");
  stale.trustDigest = sha256(`stale-${ownerId}`);
  stale.digest = digestAnchor(stale);
  const staleResult = await provider.compareAndSet(ownerId, null, stale);
  const afterStale = await provider.read(ownerId);
  const staleRejected = staleResult !== true && staleResult?.applied !== true && sameAnchor(afterStale, first);
  record("stale_create_is_rejected_without_overwrite", staleRejected);

  const second = candidate(ownerId, 2, 1, first.digest, "trust_transition");
  const advanced = await provider.compareAndSet(ownerId, first.digest, second);
  const secondRead = await provider.read(ownerId);
  const advancedOk = (advanced === true || advanced?.applied === true) && sameAnchor(secondRead, second);
  record("monotonic_advance", advancedOk);
  if (!advancedOk) return { conformant: false, ownerId, checks, findings: ["CONFORMANCE_MONOTONIC_ADVANCE_FAILED"], writesPerformed: 1 };

  const competingA = candidate(ownerId, 3, 2, second.digest, "trust_transition");
  const competingB = candidate(ownerId, 3, 2, second.digest, "reconciliation");
  const race = await Promise.allSettled([
    provider.compareAndSet(ownerId, second.digest, competingA),
    provider.compareAndSet(ownerId, second.digest, competingB)
  ]);
  const raceApplied = race.filter(item => item.status === "fulfilled"
    && (item.value === true || item.value?.applied === true)).length;
  const afterRace = await provider.read(ownerId);
  const raceWinnerValid = sameAnchor(afterRace, competingA) || sameAnchor(afterRace, competingB);
  const racePassed = raceApplied === 1 && raceWinnerValid;
  record("concurrent_compare_and_set_has_one_winner", racePassed, { appliedCount: raceApplied });
  if (!raceWinnerValid) return { conformant: false, ownerId, checks, findings: ["CONFORMANCE_CONCURRENT_CAS_STATE_INVALID"], writesPerformed: 2 };

  const replay = candidate(ownerId, afterRace.anchorSequence + 1, afterRace.revision + 1, afterRace.digest, "trust_transition");
  const replayResult = await provider.compareAndSet(ownerId, first.digest, replay);
  const afterReplay = await provider.read(ownerId);
  const replayRejected = replayResult !== true && replayResult?.applied !== true && sameAnchor(afterReplay, afterRace);
  record("stale_digest_replay_is_rejected", replayRejected);

  const skippedSequence = candidate(ownerId, afterRace.anchorSequence + 2, afterRace.revision + 1, afterRace.digest, "trust_transition");
  let skippedRejected = false;
  try {
    const result = await provider.compareAndSet(ownerId, afterRace.digest, skippedSequence);
    skippedRejected = result !== true && result?.applied !== true;
  } catch {
    skippedRejected = true;
  }
  const afterSkipped = await provider.read(ownerId);
  skippedRejected = skippedRejected && sameAnchor(afterSkipped, afterRace);
  record("sequence_jump_is_rejected", skippedRejected);

  const otherOwner = `${ownerId}:other`;
  const other = await provider.read(otherOwner);
  record("owner_scope_isolation", other == null);

  const findings = checks.filter(check => !check.passed).map(check => `CONFORMANCE_${check.name.toUpperCase()}`);
  return { conformant: findings.length === 0, ownerId, checks, findings, writesPerformed: 3,
    note: "Behavioral probe only; it cannot prove remote durability, administrator separation, or resistance to whole-service rollback." };
}
