import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const hasCode = code => error => error?.code === code;
function keyPair(keyId) {
  const pair = generateKeyPairSync("ed25519");
  return { keyId, publicKey: pair.publicKey, privateKey: pair.privateKey };
}
function signPayload(key, payload) { return sign(null, Buffer.from(canonical(payload), "utf8"), key.privateKey).toString("base64url"); }
function provider(identity, { failNext = false } = {}) {
  const records = new Map();
  const state = { failNext };
  return { providerIdentity: identity, state, records,
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (state.failNext) { state.failNext = false; throw Object.assign(new Error("injected anchor outage"), { code: "INJECTED_ANCHOR_OUTAGE" }); }
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId) throw Object.assign(new Error("owner scope mismatch"), { code: "OWNER_SCOPE_MISMATCH" });
      if (candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || !Number.isSafeInteger(candidate.revision) || candidate.revision <= (current?.revision ?? 0)
        || candidate.previousAnchorDigest !== (current?.digest ?? null)) throw Object.assign(new Error("non-monotonic anchor"), { code: "NON_MONOTONIC_ANCHOR" });
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = options.root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b141-"));
  if (!options.root) t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloProviderIdentityTrustPolicyAnchor: options.provider || null,
    recoverySloRootRecoveryTrustAnchor: options.rootAnchor || null,
    requireRecoverySloRootRecoveryTrustAnchor: options.requireRootAnchor || false,
    recoverySloProviderIdentityPolicyAuthorityRootRecoveryPublicKeys: options.rootKeys || null,
    recoverySloRetentionReconciliationSigner: options.reconciliationSigner || null,
    recoverySloRetentionReconciliationKeyId: options.reconciliationKeyId || null,
    recoverySloRetentionReconciliationPublicKeys: options.reconciliationPublicKeys || null,
    recoverySloRetentionReconciliationAttestationMaxAgeMs: options.maxAgeMs || 86400000,
    recoverySloRetentionReconciliationAttestationFutureSkewMs: options.futureSkewMs ?? 60000,
    recoverySloProviderConformanceDriftRetentionDays: options.driftRetentionDays || 90
  });
  return { app, root, ownerId: options.ownerId || "owner-b141", now: clock, advance: (ms = 1000) => { nowMs += ms; } };
}
async function runConformance(app, ownerId, reason = "Verify provider behavior and identity before trusting the baseline.") {
  const challenge = await app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, { reason });
  return { challenge, result: await app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation }) };
}

 test("Batch 141: root-trust policy bootstraps and advances an external checkpoint with CAS", async t => {
  const rootA = keyPair("root-141-a"), rootB = keyPair("root-141-b"), anchor = provider("https://root-trust-141.example");
  const f = await fixture(t, { rootAnchor: anchor, requireRootAnchor: true,
    rootKeys: { [rootA.keyId]: rootA.publicKey, [rootB.keyId]: rootB.publicKey } });
  const initial = await f.app.ensureRecoverySloRootRecoveryTrust(f.ownerId);
  assert.equal(initial.status, "healthy");
  assert.equal(initial.anchorStatus, "anchored");
  const remote1 = [...anchor.records.values()][0];
  assert.equal(remote1.revision, 1);
  assert.equal(remote1.anchorType, "genesis");
  f.advance(2000);
  const challenge = await f.app.prepareRecoverySloRootRecoveryTrustTransition(f.ownerId, { action: "rotate", targetKeyId: rootB.keyId,
    reason: "Rotate the root key while proving the external checkpoint advances monotonically." });
  const result = await f.app.applyRecoverySloRootRecoveryTrustTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, authorizationSignature: signPayload(rootA, challenge.authorizationPayload),
    proofOfPossessionSignature: signPayload(rootB, challenge.proofOfPossessionPayload)
  });
  assert.equal(result.status, "rotated");
  const remote2 = [...anchor.records.values()][0];
  assert.equal(remote2.revision, 2);
  assert.equal(remote2.anchorSequence, 2);
  assert.equal(remote2.previousPolicyDigest, remote1.policyDigest);
  assert.equal((await f.app.getRecoverySloRootRecoveryTrustAnchorStatus(f.ownerId)).status, "anchored");
});

test("Batch 141: failed external advance is recoverable only through one-revision continuity reconciliation", async t => {
  const rootA = keyPair("root-141-reconcile-a"), rootB = keyPair("root-141-reconcile-b"), anchor = provider("https://root-trust-reconcile-141.example");
  const f = await fixture(t, { rootAnchor: anchor, requireRootAnchor: true,
    rootKeys: { [rootA.keyId]: rootA.publicKey, [rootB.keyId]: rootB.publicKey } });
  await f.app.ensureRecoverySloRootRecoveryTrust(f.ownerId);
  anchor.state.failNext = true;
  const challenge = await f.app.prepareRecoverySloRootRecoveryTrustTransition(f.ownerId, { action: "rotate", targetKeyId: rootB.keyId,
    reason: "Exercise recoverable external checkpoint failure after a committed local policy transition." });
  await assert.rejects(f.app.applyRecoverySloRootRecoveryTrustTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, authorizationSignature: signPayload(rootA, challenge.authorizationPayload),
    proofOfPossessionSignature: signPayload(rootB, challenge.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_ROOT_TRUST_ANCHOR_WRITE_FAILED"));
  assert.equal((await f.app.auditRecoverySloRootRecoveryTrust(f.ownerId)).status, "behind_local");
  await assert.rejects(f.app.prepareRecoverySloRootRecoveryTrustTransition(f.ownerId, { action: "revoke", targetKeyId: rootA.keyId,
    reason: "Do not allow another root transition until checkpoint trust is restored." }), hasCode("RECOVERY_SLO_ROOT_TRUST_UNHEALTHY"));
  const reconciled = await f.app.reconcileRecoverySloRootRecoveryTrustAnchor(f.ownerId);
  assert.equal(reconciled.status, "anchored");
  assert.equal(reconciled.reconciled, true);
  assert.equal((await f.app.auditRecoverySloRootRecoveryTrust(f.ownerId)).status, "healthy");
});

test("Batch 141: remote root-trust rollback is detected and cannot be reconciled over a newer local marker", async t => {
  const rootA = keyPair("root-141-rollback-a"), rootB = keyPair("root-141-rollback-b"), anchor = provider("https://root-trust-rollback-141.example");
  const f = await fixture(t, { rootAnchor: anchor, requireRootAnchor: true,
    rootKeys: { [rootA.keyId]: rootA.publicKey, [rootB.keyId]: rootB.publicKey } });
  await f.app.ensureRecoverySloRootRecoveryTrust(f.ownerId);
  const scope = [...anchor.records.keys()][0];
  const genesis = structuredClone(anchor.records.get(scope));
  const challenge = await f.app.prepareRecoverySloRootRecoveryTrustTransition(f.ownerId, { action: "rotate", targetKeyId: rootB.keyId,
    reason: "Advance the root trust before simulating restoration of an older remote checkpoint." });
  await f.app.applyRecoverySloRootRecoveryTrustTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, authorizationSignature: signPayload(rootA, challenge.authorizationPayload),
    proofOfPossessionSignature: signPayload(rootB, challenge.proofOfPossessionPayload)
  });
  anchor.records.set(scope, genesis);
  assert.equal((await f.app.getRecoverySloRootRecoveryTrustAnchorStatus(f.ownerId)).status, "rollback_suspected");
  assert.equal((await f.app.auditRecoverySloRootRecoveryTrust(f.ownerId)).status, "rollback_suspected");
  assert.equal((await f.app.ensureRecoverySloRootRecoveryTrust(f.ownerId)).status, "rollback_suspected");
  await assert.rejects(f.app.reconcileRecoverySloRootRecoveryTrustAnchor(f.ownerId), hasCode("RECOVERY_SLO_ROOT_TRUST_ANCHOR_RECONCILIATION_BLOCKED"));
});

test("Batch 141: legacy root-trust anchor enrollment is explicit and preserves unproven history", async t => {
  const rootA = keyPair("root-141-legacy");
  const f1 = await fixture(t, { rootKeys: { [rootA.keyId]: rootA.publicKey } });
  await f1.app.ensureRecoverySloRootRecoveryTrust(f1.ownerId);
  const anchor = provider("https://root-trust-legacy-141.example");
  const f2 = createAgenticApplication({ storage: createStorage({ root: f1.root }), clock: f1.now,
    recoverySloProviderIdentityPolicyAuthorityRootRecoveryPublicKeys: { [rootA.keyId]: rootA.publicKey },
    recoverySloRootRecoveryTrustAnchor: anchor, requireRecoverySloRootRecoveryTrustAnchor: true });
  assert.equal((await f2.auditRecoverySloRootRecoveryTrust(f1.ownerId)).status, "enrollment_required");
  const enrollment = await f2.prepareRecoverySloRootRecoveryTrustAnchorEnrollment(f1.ownerId, {
    reason: "Enroll the existing root-trust ledger without claiming its pre-enrollment history was proven."
  });
  const applied = await f2.applyRecoverySloRootRecoveryTrustAnchorEnrollment(f1.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal(applied.status, "anchored");
  assert.equal(applied.historyNotProven, true);
  assert.equal((await f2.getRecoverySloRootRecoveryTrustAnchorStatus(f1.ownerId)).status, "anchored");
  await assert.rejects(f2.applyRecoverySloRootRecoveryTrustAnchorEnrollment(f1.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation }),
    hasCode("RECOVERY_SLO_ROOT_TRUST_ANCHOR_ENROLLMENT_REPLAY"));
});

test("Batch 141: reconciliation attestation freshness distinguishes stale evidence from historical signature validity", async t => {
  const signing = keyPair("retention-reconcile-141-freshness");
  const f = await fixture(t, { reconciliationSigner: async payload => signPayload(signing, payload),
    reconciliationKeyId: signing.keyId, reconciliationPublicKeys: { [signing.keyId]: signing.publicKey }, maxAgeMs: 60000, futureSkewMs: 1000 });
  const issued = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Capture a signed reconciliation snapshot with a bounded freshness lifetime."
  });
  const fresh = await f.app.verifyRecoverySloRetentionEvidenceReconciliationAttestation(f.ownerId, issued.attestation);
  assert.equal(fresh.valid, true);
  assert.equal(fresh.fresh, true);
  f.advance(-2000);
  const future = await f.app.verifyRecoverySloRetentionEvidenceReconciliationAttestation(f.ownerId, issued.attestation);
  assert.equal(future.signatureValid, true);
  assert.equal(future.historicallyValid, true);
  assert.equal(future.fresh, false);
  assert.ok(future.findings.some(item => item.code === "RETENTION_RECONCILIATION_ATTESTATION_FROM_FUTURE"));
  f.advance(63000);
  const stale = await f.app.verifyRecoverySloRetentionEvidenceReconciliationAttestation(f.ownerId, issued.attestation);
  assert.equal(stale.valid, false);
  assert.equal(stale.historicallyValid, true);
  assert.equal(stale.signatureValid, true);
  assert.equal(stale.fresh, false);
  assert.equal(stale.usableForCurrentDecision, false);
  const audit = await f.app.auditRecoverySloRetentionEvidenceReconciliationAttestations(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.staleCount, 1);
});

test("Batch 141: provider conformance drift events are retained idempotently and pruned to digest-preserving tombstones", async t => {
  const anchor = provider("https://provider-drift-retention-141.example");
  const f = await fixture(t, { provider: anchor, driftRetentionDays: 1 });
  const first = await runConformance(f.app, f.ownerId);
  const baseline = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, {
    challengeId: first.challenge.challengeId, reason: "Enroll a trusted provider identity before the drift retention test."
  });
  await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, baseline.challengeId, { confirmation: baseline.confirmation });
  anchor.providerIdentity = "https://provider-drift-retention-replaced-141.example";
  const captured = await f.app.captureRecoverySloProviderConformanceDriftEvent(f.ownerId, {
    reason: "Retain the observed provider drift snapshot for later forensic review."
  });
  assert.equal(captured.status, "retained");
  assert.equal(captured.event.eventType, "provider_conformance_drift_detected");
  const duplicate = await f.app.captureRecoverySloProviderConformanceDriftEvent(f.ownerId, {
    reason: "Retain the observed provider drift snapshot for later forensic review."
  });
  assert.equal(duplicate.retention.idempotent, true);
  assert.equal((await f.app.auditRecoverySloProviderConformanceDriftEvents(f.ownerId)).status, "healthy");
  f.advance(2 * 86400_000);
  const before = await f.app.auditRecoverySloProviderConformanceDriftEvents(f.ownerId);
  assert.equal(before.expiredRetained, 1);
  const pruned = await f.app.pruneExpiredRecoverySloProviderConformanceDriftEvents(f.ownerId, { limit: 10 });
  assert.equal(pruned.count, 1);
  const listed = await f.app.listRecoverySloProviderConformanceDriftEvents(f.ownerId, { includePayload: true });
  assert.equal(listed.items.length, 1);
  assert.equal(listed.items[0].status, "tombstone");
  assert.equal(listed.items[0].payload, null);
  assert.match(listed.items[0].payloadDigest, /^[a-f0-9]{64}$/);
  assert.equal((await f.app.auditRecoverySloProviderConformanceDriftEvents(f.ownerId)).status, "healthy");
});

test("Batch 141: root trust anchor and drift retention APIs are exposed with independent trust domain configuration", async t => {
  const root = keyPair("root-141-route");
  const rootAnchor = provider("https://root-trust-route-141.example");
  const f = await fixture(t, { rootAnchor, rootKeys: { [root.keyId]: root.publicKey } });
  for (const name of ["getRecoverySloRootRecoveryTrustAnchorStatus", "reconcileRecoverySloRootRecoveryTrustAnchor",
    "prepareRecoverySloRootRecoveryTrustAnchorEnrollment", "applyRecoverySloRootRecoveryTrustAnchorEnrollment",
    "captureRecoverySloProviderConformanceDriftEvent", "listRecoverySloProviderConformanceDriftEvents",
    "auditRecoverySloProviderConformanceDriftEvents", "pruneExpiredRecoverySloProviderConformanceDriftEvents"]) {
    assert.equal(typeof f.app[name], "function", `${name} should be exported`);
  }
  const independence = await f.app.auditRecoverySloAnchorTrustDomainIndependence(f.ownerId);
  assert.ok(independence.domains.some(item => item.domain === "root_recovery_trust"));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: f.root }),
    recoverySloProviderIdentityTrustPolicyAnchor: rootAnchor, recoverySloRootRecoveryTrustAnchor: rootAnchor,
    recoverySloProviderIdentityPolicyAuthorityRootRecoveryPublicKeys: { [root.keyId]: root.publicKey } }), /external anchor provider terpisah/);
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: f.root }),
    requireRecoverySloRootRecoveryTrustAnchor: true,
    recoverySloProviderIdentityPolicyAuthorityRootRecoveryPublicKeys: { [root.keyId]: root.publicKey } }), /External root-recovery trust anchor diwajibkan/);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /root-recovery-trust\/anchor\/enrollments/);
  assert.match(server, /provider-conformance-drift\/events\/prune/);
});
