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
function signPayload(key, payload) {
  return sign(null, Buffer.from(canonical(payload), "utf8"), key.privateKey).toString("base64url");
}
function signerFor(keys) {
  return async payload => {
    const key = keys[payload.signing.keyId];
    if (!key) throw new Error(`No signer for ${payload.signing.keyId}`);
    return { keyId: key.keyId, signature: signPayload(key, payload) };
  };
}
function provider(identity, { mode = "normal", failReads = false } = {}) {
  const records = new Map();
  return {
    providerIdentity: identity,
    state: { records },
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    failReads,
    async read(ownerId) {
      if (this.failReads) throw Object.assign(new Error("provider unavailable"), { code: "TEST_PROVIDER_UNAVAILABLE" });
      return structuredClone(records.get(ownerId) ?? null);
    },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if (mode === "accept-stale" && expectedDigest === null && current) {
        records.set(ownerId, structuredClone(candidate));
        return { applied: true, anchor: structuredClone(candidate) };
      }
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId) throw Object.assign(new Error("owner scope mismatch"), { code: "OWNER_SCOPE_MISMATCH" });
      if (candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || !Number.isSafeInteger(candidate.revision) || candidate.revision <= (current?.revision ?? 0)
        || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        throw Object.assign(new Error("non-monotonic anchor"), { code: "NON_MONOTONIC_ANCHOR" });
      }
      records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = options.root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b138-"));
  if (!options.root) t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const advance = (ms = 1000) => { nowMs += ms; };
  const trustPolicyAnchor = options.trustPolicyAnchor ?? null;
  const baselineProvider = options.baselineProvider ?? provider("https://baseline-b138.example");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloProviderIdentityBaselineAnchor: baselineProvider,
    requireRecoverySloProviderIdentityBaselineAnchor: true,
    recoverySloProviderIdentityTrustPolicyAnchor: trustPolicyAnchor,
    requireRecoverySloProviderIdentityTrustPolicyAnchor: options.requireTrustPolicyAnchor ?? false,
    recoverySloProviderIdentityPolicyAuthorityPublicKeys: options.authorityPublicKeys ?? null,
    recoverySloProviderIdentityPolicyAuthorityInitialKeyId: options.initialAuthorityKeyId ?? null,
    recoverySloProviderIdentityDriftSigner: options.driftSigner ?? null,
    recoverySloProviderIdentityDriftKeyId: options.driftKeyId ?? null,
    recoverySloProviderIdentityDriftPublicKeys: options.driftPublicKeys ?? null,
    requireRecoverySloSignedProviderIdentityDriftEvents: options.requireDriftSigner ?? false
  });
  return { app, root, ownerId: options.ownerId || "owner-b138", trustPolicyAnchor, baselineProvider, advance, now: clock };
}
async function applyPolicyAuthorityTransition(f, challenge, signer, target = null) {
  return f.app.applyRecoverySloProviderIdentityPolicyAuthorityTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation,
    authoritySignature: signPayload(signer, challenge.authorizationPayload),
    proofOfPossessionSignature: target && challenge.proofOfPossessionPayload ? signPayload(target, challenge.proofOfPossessionPayload) : undefined
  });
}
async function applySigningTransition(f, challenge, authority, target) {
  return f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation,
    policyAuthoritySignature: signPayload(authority, challenge.authorizationPayload),
    proofOfPossessionSignature: target && challenge.proofOfPossessionPayload ? signPayload(target, challenge.proofOfPossessionPayload) : undefined
  });
}

test("Batch 138: trust-policy checkpoints are externally anchored and local rollback fails closed", async t => {
  const authority1 = keyPair("authority-138-a"), drift1 = keyPair("drift-138-a"), drift2 = keyPair("drift-138-b");
  const anchor = provider("https://trust-policy-anchor-b138.example");
  const f = await fixture(t, { trustPolicyAnchor: anchor, requireTrustPolicyAnchor: true,
    authorityPublicKeys: { [authority1.keyId]: authority1.publicKey }, initialAuthorityKeyId: authority1.keyId,
    driftKeyId: drift1.keyId, driftPublicKeys: { [drift1.keyId]: drift1.publicKey, [drift2.keyId]: drift2.publicKey },
    driftSigner: signerFor({ [drift1.keyId]: drift1, [drift2.keyId]: drift2 }), requireDriftSigner: true });

  const initial = await f.app.ensureRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  assert.equal(initial.status, "healthy");
  assert.equal((await f.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(f.ownerId, "drift_event")).status, "anchored");
  const scope = `provider-identity-trust-policy-${sha256(f.ownerId).slice(0, 40)}-drift_event`;
  const firstAnchor = await anchor.read(scope);
  const rawPolicy = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-provider-identity-attestation-trust-policy"
    && item.domain === "drift_event");
  assert.ok(rawPolicy);

  const challenge = await f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, { domain: "drift_event", action: "rotate",
    targetKeyId: drift2.keyId, reason: "Rotate the drift-event key under a current, externally anchored policy revision.",
    policyAuthorityKeyId: authority1.keyId });
  await applySigningTransition(f, challenge, authority1, drift2);
  assert.equal((await f.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(f.ownerId, "drift_event")).status, "anchored");

  const currentPolicy = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === rawPolicy.kind && item.domain === "drift_event");
  const rolledBack = { ...rawPolicy }; delete rolledBack._storage;
  await f.app.store.putEvidence(f.ownerId, rolledBack, { expectedVersion: currentPolicy._storage.version });
  const status = await f.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(f.ownerId, "drift_event");
  assert.equal(status.status, "rollback_detected");
  assert.equal((await f.app.getRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event")).status, "unhealthy");
  await assert.rejects(f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, { domain: "drift_event", action: "revoke",
    targetKeyId: drift2.keyId, reason: "Must block a transition while the local policy is behind its external anchor.",
    policyAuthorityKeyId: authority1.keyId }), hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_UNHEALTHY"));
  assert.equal((await anchor.read(scope)).digest !== firstAnchor.digest, true);
});

test("Batch 138: policy-authority rotation and revocation preserve valid history but reject retired-time signatures", async t => {
  const authority1 = keyPair("authority-138-old"), authority2 = keyPair("authority-138-new");
  const f = await fixture(t, { authorityPublicKeys: { [authority1.keyId]: authority1.publicKey, [authority2.keyId]: authority2.publicKey },
    initialAuthorityKeyId: authority1.keyId });
  const bootstrap = await f.app.ensureRecoverySloProviderIdentityPolicyAuthority(f.ownerId);
  assert.equal(bootstrap.status, "healthy");
  const policyBefore = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-provider-identity-policy-authority-policy");
  const oldValidFrom = policyBefore.keys.find(item => item.keyId === authority1.keyId).validFrom;
  f.advance();

  const rotate = await f.app.prepareRecoverySloProviderIdentityPolicyAuthorityTransition(f.ownerId, { action: "rotate",
    targetKeyId: authority2.keyId, reason: "Rotate the policy authority to a preconfigured replacement with proof of possession." });
  await applyPolicyAuthorityTransition(f, rotate, authority1, authority2);
  const rotatedAudit = await f.app.auditRecoverySloProviderIdentityPolicyAuthority(f.ownerId);
  assert.equal(rotatedAudit.status, "healthy");
  assert.equal(rotatedAudit.activeKeyId, authority2.keyId);
  assert.equal((await f.app.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature(f.ownerId, authority1.keyId, oldValidFrom)).trusted, true);
  assert.equal((await f.app.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature(f.ownerId, authority1.keyId, f.now())).trusted, false);

  const revoke = await f.app.prepareRecoverySloProviderIdentityPolicyAuthorityTransition(f.ownerId, { action: "revoke",
    targetKeyId: authority1.keyId, reason: "Revoke the retired authority key after the replacement is active and verified." });
  await applyPolicyAuthorityTransition(f, revoke, authority2);
  const audit = await f.app.auditRecoverySloProviderIdentityPolicyAuthority(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.activeKeyId, authority2.keyId);
  assert.equal((await f.app.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature(f.ownerId, authority1.keyId, oldValidFrom)).trusted, true);
  assert.equal((await f.app.evaluateRecoverySloProviderIdentityPolicyAuthoritySignature(f.ownerId, authority1.keyId, f.now())).trusted, false);
  await assert.rejects(f.app.prepareRecoverySloProviderIdentityPolicyAuthorityTransition(f.ownerId, { action: "rotate",
    targetKeyId: authority1.keyId, reason: "A revoked authority key cannot be restored through ordinary rotation." }),
  hasCode("RECOVERY_SLO_POLICY_AUTHORITY_TARGET_NOT_ROTATABLE"));
});

test("Batch 138: baseline conformance reports are retained with digest binding and audited", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, {
    reason: "Retain the completed baseline-provider conformance report for later operational investigation."
  });
  const result = await f.app.runRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "conformant");
  assert.equal(result.retention.status, "retained");
  const retained = await f.app.listRecoverySloRetainedAnchorEvidence(f.ownerId, { limit: 500, includePayload: true });
  const evidence = retained.items.find(item => item.artifactType === "provider_conformance"
    && item.sourceId === challenge.challengeId && item.payload?.providerDomain === "provider_identity_baseline");
  assert.ok(evidence);
  assert.equal(evidence.payload.reportDigest, result.reportDigest);
  assert.equal((await f.app.auditRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "healthy");
  const replay = await f.app.runRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
  assert.equal(replay.retention.idempotent, true);
  f.advance(91 * 24 * 60 * 60 * 1000);
  const pruned = await f.app.pruneExpiredRecoverySloRetainedAnchorEvidence(f.ownerId, { limit: 20 });
  assert.equal(pruned.status, "completed");
  assert.equal(pruned.count, 1);
  const afterPrune = await f.app.listRecoverySloRetainedAnchorEvidence(f.ownerId, { limit: 200, includePayload: true });
  assert.ok(afterPrune.items.some(item => item.sourceId === challenge.challengeId && item.status === "tombstone"
    && item.tombstone?.payloadDigest === evidence.payloadDigest));
  assert.equal((await f.app.auditRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "healthy");
});

test("Batch 138: pre-existing local trust policies require explicit digest-bound external enrollment", async t => {
  const drift = keyPair("drift-138-legacy");
  const authority = keyPair("authority-138-legacy");
  const f = await fixture(t, { driftSigner: signerFor({ [drift.keyId]: drift }), driftKeyId: drift.keyId,
    driftPublicKeys: { [drift.keyId]: drift.publicKey }, authorityPublicKeys: { [authority.keyId]: authority.publicKey }, initialAuthorityKeyId: authority.keyId });
  await f.app.ensureRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  const legacyPolicy = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-provider-identity-attestation-trust-policy"
    && item.domain === "drift_event");
  const anchor = provider("https://trust-policy-anchor-legacy-b138.example");
  const upgraded = await fixture(t, { root: f.root, ownerId: f.ownerId, trustPolicyAnchor: anchor, requireTrustPolicyAnchor: true,
    driftSigner: signerFor({ [drift.keyId]: drift }), driftKeyId: drift.keyId,
    driftPublicKeys: { [drift.keyId]: drift.publicKey }, authorityPublicKeys: { [authority.keyId]: authority.publicKey }, initialAuthorityKeyId: authority.keyId });
  assert.equal((await upgraded.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(upgraded.ownerId, "drift_event")).status, "enrollment_required");
  await assert.rejects(upgraded.app.prepareRecoverySloProviderIdentityTrustKeyTransition(upgraded.ownerId, { domain: "drift_event", action: "revoke",
    targetKeyId: drift.keyId, reason: "Do not allow a trust-policy mutation before legacy anchor enrollment is approved.",
    policyAuthorityKeyId: authority.keyId }), error => error?.code === "RECOVERY_SLO_PROVIDER_TRUST_POLICY_UNHEALTHY");
  const enrollment = await upgraded.app.enrollRecoverySloProviderIdentityTrustPolicyAnchor(upgraded.ownerId, "drift_event", {
    confirmation: `ENROLL PROVIDER IDENTITY TRUST POLICY ANCHOR ${legacyPolicy.digest.slice(0, 12)}`,
    reason: "Enroll the legacy trust policy after reviewing the current local revision and digest."
  });
  assert.equal(enrollment.status, "anchored");
  assert.equal(enrollment.historyNotProven, true);
  assert.equal((await upgraded.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(upgraded.ownerId, "drift_event")).status, "anchored");
  assert.equal((await upgraded.app.getRecoverySloProviderIdentityTrustPolicy(upgraded.ownerId, "drift_event")).historyNotProven, true);
});

test("Batch 138: external trust-policy provider outage is visible and blocks trust-policy use", async t => {
  const drift = keyPair("drift-138-outage");
  const anchor = provider("https://trust-policy-anchor-outage-b138.example");
  const f = await fixture(t, { trustPolicyAnchor: anchor, requireTrustPolicyAnchor: true,
    driftSigner: signerFor({ [drift.keyId]: drift }), driftKeyId: drift.keyId, driftPublicKeys: { [drift.keyId]: drift.publicKey } });
  await f.app.ensureRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  anchor.failReads = true;
  const status = await f.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(f.ownerId, "drift_event");
  assert.equal(status.status, "unavailable");
  assert.equal((await f.app.getRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event")).status, "unhealthy");
  anchor.failReads = false;
  assert.equal((await f.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(f.ownerId, "drift_event")).status, "anchored");
});

test("Batch 138: provider-identity trust-policy anchor is included in independence checks and HTTP routes expose lifecycle APIs", async t => {
  const authority = keyPair("authority-138-http");
  const anchor = provider("https://trust-policy-anchor-http-b138.example");
  const f = await fixture(t, { trustPolicyAnchor: anchor, requireTrustPolicyAnchor: true,
    authorityPublicKeys: { [authority.keyId]: authority.publicKey }, initialAuthorityKeyId: authority.keyId });
  await f.app.ensureRecoverySloProviderIdentityPolicyAuthority(f.ownerId);
  const routes = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(routes, /provider-identity-trust\/anchors/);
  assert.match(routes, /policy-authority\/transitions\/challenges/);
  assert.match(routes, /policy-authority\/audit/);
  assert.match(routes, /historical-authorization\/verify/);
  const anchorStatus = await f.app.getRecoverySloProviderIdentityTrustPolicyAnchorStatus(f.ownerId, "policy_authority");
  assert.equal(anchorStatus.status, "anchored");
  const independence = await f.app.auditRecoverySloAnchorTrustDomainIndependence(f.ownerId);
  assert.ok(independence.domains.some(item => item.domain === "provider_identity_trust_policy"));
});
