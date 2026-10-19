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
function provider(identity, { mode = "normal", failReads = false, failWrites = false } = {}) {
  const records = new Map();
  return { providerIdentity: identity, state: { records },
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" }, failReads, failWrites,
    async read(ownerId) {
      if (this.failReads) throw Object.assign(new Error("provider unavailable"), { code: "TEST_PROVIDER_UNAVAILABLE" });
      return structuredClone(records.get(ownerId) ?? null);
    },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (this.failWrites) throw Object.assign(new Error("provider write unavailable"), { code: "TEST_PROVIDER_WRITE_UNAVAILABLE" });
      const current = records.get(ownerId) ?? null;
      if (mode === "accept-stale" && expectedDigest === null && current) {
        records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
      }
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId) throw Object.assign(new Error("owner scope mismatch"), { code: "OWNER_SCOPE_MISMATCH" });
      if (candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || !Number.isSafeInteger(candidate.revision) || candidate.revision <= (current?.revision ?? 0)
        || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        throw Object.assign(new Error("non-monotonic anchor"), { code: "NON_MONOTONIC_ANCHOR" });
      }
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = options.root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b139-"));
  if (!options.root) t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const baselineProvider = options.baselineProvider ?? provider("https://baseline-b139.example");
  const trustPolicyAnchor = options.trustPolicyAnchor ?? null;
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloProviderIdentityBaselineAnchor: baselineProvider, requireRecoverySloProviderIdentityBaselineAnchor: true,
    recoverySloProviderIdentityTrustPolicyAnchor: trustPolicyAnchor,
    requireRecoverySloProviderIdentityTrustPolicyAnchor: options.requireTrustPolicyAnchor ?? false,
    recoverySloRetainedEvidenceAnchor: options.retainedEvidenceAnchor ?? null,
    requireRecoverySloRetainedEvidenceAnchor: options.requireRetainedEvidenceAnchor ?? false,
    recoverySloProviderIdentityPolicyAuthorityPublicKeys: options.authorityPublicKeys ?? null,
    recoverySloProviderIdentityPolicyAuthorityInitialKeyId: options.initialAuthorityKeyId ?? null,
    recoverySloProviderIdentityPolicyAuthorityRootRecoveryPublicKeys: options.rootRecoveryPublicKeys ?? null
  });
  return { app, root, ownerId: options.ownerId || "owner-b139", trustPolicyAnchor, baselineProvider,
    now: clock, advance: (ms = 1000) => { nowMs += ms; } };
}

test("Batch 139: trust-policy anchor conformance validates CAS, monotonicity, isolation, and retains report idempotently", async t => {
  const anchor = provider("https://trust-policy-anchor-b139.example");
  const f = await fixture(t, { trustPolicyAnchor: anchor, requireTrustPolicyAnchor: true });
  const challenge = await f.app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, {
    reason: "Verify the independent provider contract before relying on it for policy lifecycle trust."
  });
  const result = await f.app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result.status, "conformant");
  assert.equal(result.report.checks.every(item => item.passed), true);
  assert.equal(result.report.writesToProductionNamespace, false);
  assert.equal(result.retention.status, "retained");
  const replay = await f.app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
  assert.equal(replay.retention.idempotent, true);
  assert.equal((await f.app.auditRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "healthy");
});

test("Batch 139: stale-CAS provider is reported nonconformant and never touches the production namespace", async t => {
  const anchor = provider("https://trust-policy-anchor-stale-b139.example", { mode: "accept-stale" });
  const f = await fixture(t, { trustPolicyAnchor: anchor });
  const before = await anchor.read(`provider-identity-trust-policy-${sha256(f.ownerId).slice(0, 40)}-drift_event`);
  const challenge = await f.app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, {
    reason: "Exercise stale compare-and-set rejection against a disposable namespace only."
  });
  const result = await f.app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result.status, "nonconformant");
  assert.ok(result.report.findings.some(item => item.code.includes("STALE_CAS_REJECTION")));
  assert.equal(await anchor.read(`provider-identity-trust-policy-${sha256(f.ownerId).slice(0, 40)}-drift_event`), before);
});

test("Batch 139: independent root authority recovers a compromised active policy-authority key", async t => {
  const active = keyPair("authority-139-active"), replacement = keyPair("authority-139-replacement"), root = keyPair("root-139");
  const trustPolicyAnchor = provider("https://trust-policy-anchor-root-recovery-b139.example");
  const f = await fixture(t, { trustPolicyAnchor, requireTrustPolicyAnchor: true,
    authorityPublicKeys: { [active.keyId]: active.publicKey, [replacement.keyId]: replacement.publicKey },
    initialAuthorityKeyId: active.keyId, rootRecoveryPublicKeys: { [root.keyId]: root.publicKey } });
  const initial = await f.app.ensureRecoverySloProviderIdentityPolicyAuthority(f.ownerId);
  assert.equal(initial.status, "healthy");
  const prior = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-provider-identity-policy-authority-policy");
  const activeEntry = prior.keys.find(item => item.keyId === active.keyId);
  f.advance(2000);
  const challenge = await f.app.prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery(f.ownerId, {
    targetKeyId: replacement.keyId, rootKeyId: root.keyId,
    reason: "Recover authority after the active operational signing key is considered compromised."
  });
  const applied = await f.app.applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation,
    rootRecoverySignature: signPayload(root, challenge.rootRecoveryPayload),
    proofOfPossessionSignature: signPayload(replacement, challenge.proofOfPossessionPayload)
  });
  assert.equal(applied.status, "recovered");
  assert.equal(applied.activeKeyId, replacement.keyId);
  assert.equal((await f.app.auditRecoverySloProviderIdentityPolicyAuthority(f.ownerId)).status, "healthy");
  assert.equal((await f.app.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature(f.ownerId, active.keyId, activeEntry.validFrom)).trusted, true);
  assert.equal((await f.app.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature(f.ownerId, active.keyId, f.now())).trusted, false);
  const policy = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-provider-identity-policy-authority-policy");
  assert.equal(policy.events.at(-1).action, "root_recover");
  const historical = await f.app.verifyRecoverySloProviderIdentityPolicyAuthorityHistoricalAuthorization(f.ownerId, { digest: policy.events.at(-1).digest });
  assert.equal(historical.valid, true);
  assert.equal(historical.signerKeyId, root.keyId);
  await assert.rejects(f.app.applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, rootRecoverySignature: signPayload(root, challenge.rootRecoveryPayload),
    proofOfPossessionSignature: signPayload(replacement, challenge.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_RECOVERY_REPLAY"));
});

test("Batch 139: root recovery rejects invalid signatures and cannot reuse operational authority keys", async t => {
  const active = keyPair("authority-139-bad-active"), replacement = keyPair("authority-139-bad-target"), root = keyPair("root-139-bad");
  const f = await fixture(t, { authorityPublicKeys: { [active.keyId]: active.publicKey, [replacement.keyId]: replacement.publicKey },
    initialAuthorityKeyId: active.keyId, rootRecoveryPublicKeys: { [root.keyId]: root.publicKey } });
  await f.app.ensureRecoverySloProviderIdentityPolicyAuthority(f.ownerId);
  const before = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-provider-identity-policy-authority-policy");
  const challenge = await f.app.prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery(f.ownerId, {
    targetKeyId: replacement.keyId, rootKeyId: root.keyId, reason: "Reject a recovery attempt without an authentic independent root signature."
  });
  await assert.rejects(f.app.applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, rootRecoverySignature: signPayload(active, challenge.rootRecoveryPayload),
    proofOfPossessionSignature: signPayload(replacement, challenge.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_POLICY_AUTHORITY_ROOT_SIGNATURE_INVALID"));
  const after = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-provider-identity-policy-authority-policy");
  assert.equal(after.digest, before.digest);
  await assert.rejects(async () => fixture(t, { authorityPublicKeys: { [active.keyId]: active.publicKey }, initialAuthorityKeyId: active.keyId,
    rootRecoveryPublicKeys: { "root-alias": active.publicKey } }), error => error instanceof TypeError && /terpisah/.test(error.message));
});

test("Batch 139: retention reconciliation detects cross-store tampering and blocks automatic repair", async t => {
  const anchor = provider("https://trust-policy-anchor-reconcile-b139.example");
  const f = await fixture(t, { trustPolicyAnchor: anchor });
  const challenge = await f.app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, {
    reason: "Create retained conformance evidence to test reconciliation across the evidence registry and chain."
  });
  await f.app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const healthyOrDegraded = await f.app.auditRecoverySloRetentionEvidenceReconciliation(f.ownerId);
  assert.ok(["healthy", "degraded"].includes(healthyOrDegraded.status));
  const record = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-anchor-evidence-retention-record"
    && item.sourceId === challenge.challengeId && item.payload?.providerDomain === "provider_identity_trust_policy");
  assert.ok(record);
  const tampered = { ...record, payload: { ...record.payload, reportDigest: "0".repeat(64) } };
  await f.app.store.putEvidence(f.ownerId, tampered, { expectedVersion: record._storage.version });
  const audit = await f.app.auditRecoverySloRetentionEvidenceReconciliation(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  const result = await f.app.reconcileRecoverySloRetentionEvidenceAudit(f.ownerId);
  assert.equal(result.status, "blocked");
  assert.equal(result.mutationPerformed, false);
  assert.equal(result.before.status, "unhealthy");
});


test("Batch 139: reconciliation advances only a provably behind external evidence-chain anchor after clean record audits", async t => {
  const trustAnchor = provider("https://trust-policy-anchor-behind-b139.example");
  const retainedAnchor = provider("https://retained-evidence-anchor-behind-b139.example", { failWrites: true });
  const f = await fixture(t, { trustPolicyAnchor: trustAnchor, retainedEvidenceAnchor: retainedAnchor });
  const challenge = await f.app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, {
    reason: "Create a valid retained conformance report while the independent evidence-chain anchor is temporarily unavailable."
  });
  await assert.rejects(f.app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(f.ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation }));
  retainedAnchor.failWrites = false;
  const before = await f.app.auditRecoverySloRetentionEvidenceReconciliation(f.ownerId);
  assert.equal(before.status, "degraded");
  assert.equal(before.reconciliation.safeToAdvanceChainAnchor, true);
  const reconciled = await f.app.reconcileRecoverySloRetentionEvidenceAudit(f.ownerId);
  assert.equal(reconciled.status, "reconciled_with_limitations");
  assert.equal(reconciled.mutationPerformed, true);
  assert.equal(reconciled.localEvidenceRewritten, false);
  assert.equal(reconciled.after.sources.chainAnchor, "anchored");
});

test("Batch 139: application exports and HTTP routes expose root recovery, conformance, and retention reconciliation", async t => {
  const active = keyPair("authority-139-http"), target = keyPair("authority-139-http-target"), root = keyPair("root-139-http");
  const anchor = provider("https://trust-policy-anchor-http-b139.example");
  const f = await fixture(t, { trustPolicyAnchor: anchor, authorityPublicKeys: { [active.keyId]: active.publicKey, [target.keyId]: target.publicKey },
    initialAuthorityKeyId: active.keyId, rootRecoveryPublicKeys: { [root.keyId]: root.publicKey } });
  for (const name of ["prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery", "applyRecoverySloProviderIdentityPolicyAuthorityRootRecovery",
    "prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance", "runRecoverySloProviderIdentityTrustPolicyAnchorConformance",
    "auditRecoverySloRetentionEvidenceReconciliation", "reconcileRecoverySloRetentionEvidenceAudit"]) assert.equal(typeof f.app[name], "function");
  const routes = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(routes, /policy-authority\/root-recovery\/challenges/);
  assert.match(routes, /provider-identity-trust\/conformance\/challenges/);
  assert.match(routes, /retention-reconciliation\/reconcile/);
});
