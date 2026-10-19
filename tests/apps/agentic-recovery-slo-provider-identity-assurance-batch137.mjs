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
const hasCode = code => error => error?.code === code;
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
async function fixture(t, options = {}) {
  const root = options.root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b137-"));
  if (!options.root) t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const advance = (ms = 1000) => { nowMs += ms; };
  const journalProvider = options.journalProvider ?? provider("https://journal-b137.example");
  const retentionProvider = options.retentionProvider ?? provider("https://retention-b137.example");
  const baselineProvider = options.baselineProvider ?? provider("https://baseline-b137.example");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRecoveryJournalAnchor: journalProvider,
    recoverySloRetentionCheckpointAnchor: retentionProvider,
    requireRecoverySloRetentionCheckpointAnchor: true,
    recoverySloProviderIdentityBaselineAnchor: baselineProvider,
    requireRecoverySloProviderIdentityBaselineAnchor: true,
    recoverySloProviderIdentityDriftSigner: options.driftSigner ?? null,
    recoverySloProviderIdentityDriftKeyId: options.driftKeyId ?? null,
    recoverySloProviderIdentityDriftPublicKeys: options.driftPublicKeys ?? null,
    requireRecoverySloSignedProviderIdentityDriftEvents: options.requireDriftSigner ?? false,
    recoverySloRetainedEvidenceRecoverySigner: options.recoverySigner ?? null,
    recoverySloRetainedEvidenceRecoveryKeyId: options.recoveryKeyId ?? null,
    recoverySloRetainedEvidenceRecoveryPublicKeys: options.recoveryPublicKeys ?? null,
    requireRecoverySloRetainedEvidenceRecoveryAttestation: options.requireRecoverySigner ?? false,
    recoverySloProviderIdentityPolicyAuthorityPublicKeys: options.policyAuthorityPublicKeys ?? null
  });
  return { app, root, ownerId: options.ownerId || "owner-b137", journalProvider, retentionProvider, baselineProvider, advance };
}
async function enrollBaseline(f) {
  const challenge = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, {
    reason: "Enroll the provider identity baseline after checking each configured trust-domain endpoint."
  });
  return f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function runConformance(f) {
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, {
    reason: "Verify provider semantics and preserve the conformance result for recovery evidence."
  });
  return f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function prepareAndApplyTransition(f, input, authority) {
  const challenge = await f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, input);
  const policyAuthoritySignature = signPayload(authority, challenge.authorizationPayload);
  const proofOfPossessionSignature = challenge.proofOfPossessionPayload && input.action === "rotate"
    ? signPayload(input.targetKey, challenge.proofOfPossessionPayload) : undefined;
  const result = await f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, policyAuthoritySignature, proofOfPossessionSignature
  });
  return { challenge, result };
}

test("Batch 137: provider identity baseline conformance validates CAS, monotonicity, isolation, and replay-safe challenges", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, {
    reason: "Run a disposable conformance probe before trusting the provider for identity baselines."
  });
  assert.equal(challenge.writesToProductionNamespace, false);
  await assert.rejects(f.app.runRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: "wrong" }),
    hasCode("RECOVERY_SLO_PROVIDER_IDENTITY_CONFORMANCE_CONFIRMATION_INVALID"));
  const result = await f.app.runRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "conformant");
  assert.equal(result.report.writesToProductionNamespace, false);
  assert.ok(result.report.checks.every(item => item.passed));
  const replay = await f.app.runRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
  assert.equal((await f.app.auditRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId)).status, "healthy");
});

test("Batch 137: provider identity baseline conformance detects a provider that accepts stale CAS", async t => {
  const bad = provider("https://bad-baseline-b137.example", { mode: "accept-stale" });
  const f = await fixture(t, { baselineProvider: bad });
  const challenge = await f.app.prepareRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, {
    reason: "Test a provider implementation that violates stale compare-and-set rejection."
  });
  const result = await f.app.runRecoverySloProviderIdentityBaselineAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "nonconformant");
  assert.ok(result.report.findings.some(item => item.code.includes("STALE_CAS_REJECTION")));
});

test("Batch 137: signed drift key rotation requires policy-authority approval and target proof of possession", async t => {
  const oldKey = keyPair("drift-k1"), nextKey = keyPair("drift-k2"), authority = keyPair("policy-authority-1");
  const keys = { [oldKey.keyId]: oldKey, [nextKey.keyId]: nextKey };
  const f = await fixture(t, { driftSigner: signerFor(keys), driftKeyId: oldKey.keyId,
    driftPublicKeys: { [oldKey.keyId]: oldKey.publicKey, [nextKey.keyId]: nextKey.publicKey },
    policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireDriftSigner: true });
  await enrollBaseline(f);
  f.journalProvider.providerIdentity = "https://journal-drift-before-rotation-b137.example";
  const first = await f.app.attestRecoverySloAnchorProviderIdentityDrift(f.ownerId);
  assert.equal(first.event.signing.keyId, oldKey.keyId);
  f.advance();
  const input = { domain: "drift_event", action: "rotate", targetKeyId: nextKey.keyId,
    reason: "Rotate the drift-event signing key after reviewing the approved replacement key.", policyAuthorityKeyId: authority.keyId };
  const challenge = await f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, input);
  await assert.rejects(f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, policyAuthoritySignature: signPayload(authority, challenge.authorizationPayload),
    proofOfPossessionSignature: signPayload(oldKey, challenge.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_PROOF_OF_POSSESSION_INVALID"));
  const applied = await f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, policyAuthoritySignature: signPayload(authority, challenge.authorizationPayload),
    proofOfPossessionSignature: signPayload(nextKey, challenge.proofOfPossessionPayload)
  });
  assert.equal(applied.activeKeyId, nextKey.keyId);
  assert.equal((await f.app.verifyRecoverySloAnchorProviderIdentityDriftEvent(f.ownerId, first.event)).valid, true);
  const restarted = await fixture(t, { root: f.root, ownerId: f.ownerId, journalProvider: f.journalProvider,
    retentionProvider: f.retentionProvider, baselineProvider: f.baselineProvider, driftSigner: signerFor(keys),
    driftKeyId: oldKey.keyId, driftPublicKeys: { [oldKey.keyId]: oldKey.publicKey, [nextKey.keyId]: nextKey.publicKey },
    policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireDriftSigner: true });
  assert.equal((await restarted.app.getRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event")).activeKeyId, nextKey.keyId);
  assert.equal((await restarted.app.verifyRecoverySloAnchorProviderIdentityDriftEvent(f.ownerId, first.event)).valid, true);
  f.advance();
  f.journalProvider.providerIdentity = "https://journal-drift-after-rotation-b137.example";
  const second = await f.app.attestRecoverySloAnchorProviderIdentityDrift(f.ownerId);
  assert.equal(second.event.signing.keyId, nextKey.keyId);
  assert.equal((await f.app.verifyRecoverySloAnchorProviderIdentityDriftEvent(f.ownerId, second.event)).valid, true);
});

test("Batch 137: revocation compromise cutoff invalidates signatures at or after cutoff and blocks new signing", async t => {
  const oldKey = keyPair("drift-r1"), nextKey = keyPair("drift-r2"), authority = keyPair("policy-authority-r");
  const keys = { [oldKey.keyId]: oldKey, [nextKey.keyId]: nextKey };
  const f = await fixture(t, { driftSigner: signerFor(keys), driftKeyId: oldKey.keyId,
    driftPublicKeys: { [oldKey.keyId]: oldKey.publicKey, [nextKey.keyId]: nextKey.publicKey },
    policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireDriftSigner: true });
  await enrollBaseline(f);
  f.journalProvider.providerIdentity = "https://journal-drift-revocation-1-b137.example";
  const before = await f.app.attestRecoverySloAnchorProviderIdentityDrift(f.ownerId);
  f.advance();
  await prepareAndApplyTransition(f, { domain: "drift_event", action: "rotate", targetKeyId: nextKey.keyId,
    reason: "Rotate to the replacement key before exercising compromise revocation policy.", policyAuthorityKeyId: authority.keyId, targetKey: nextKey }, authority);
  f.advance();
  f.journalProvider.providerIdentity = "https://journal-drift-revocation-2-b137.example";
  const compromised = await f.app.attestRecoverySloAnchorProviderIdentityDrift(f.ownerId);
  const revoked = await prepareAndApplyTransition(f, { domain: "drift_event", action: "revoke", targetKeyId: nextKey.keyId,
    invalidateBefore: compromised.event.issuedAt, reason: "Revoke the compromised drift key and invalidate all evidence from the cutoff onward.",
    policyAuthorityKeyId: authority.keyId }, authority);
  assert.equal(revoked.result.activeKeyId, null);
  assert.equal((await f.app.verifyRecoverySloAnchorProviderIdentityDriftEvent(f.ownerId, compromised.event)).valid, false);
  assert.equal((await f.app.verifyRecoverySloAnchorProviderIdentityDriftEvent(f.ownerId, before.event)).valid, true);
  await assert.rejects(f.app.attestRecoverySloAnchorProviderIdentityDrift(f.ownerId), hasCode("RECOVERY_SLO_PROVIDER_DRIFT_SIGNER_NOT_CONFIGURED"));
  const initialized = await f.app.ensureRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  assert.equal(initialized.status, "healthy");
  const policy = await f.app.getRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  assert.equal(policy.status, "healthy");
  assert.equal(policy.activeKeyId, null);
});

test("Batch 137: recovery-attestation key rotation preserves pre-retirement receipts and signs with the new active key", async t => {
  const r1 = keyPair("recovery-r1"), r2 = keyPair("recovery-r2"), authority = keyPair("policy-authority-recovery");
  const keys = { [r1.keyId]: r1, [r2.keyId]: r2 };
  const f = await fixture(t, { recoverySigner: signerFor(keys), recoveryKeyId: r1.keyId,
    recoveryPublicKeys: { [r1.keyId]: r1.publicKey, [r2.keyId]: r2.publicKey },
    policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireRecoverySigner: true });
  await runConformance(f);
  const first = await f.app.attestRecoverySloRetainedEvidenceChainRecovery(f.ownerId, {
    reason: "Attest the current retained-evidence chain checkpoint before rotating the recovery signing key."
  });
  f.advance();
  const rotated = await prepareAndApplyTransition(f, { domain: "recovery_attestation", action: "rotate", targetKeyId: r2.keyId,
    reason: "Rotate the recovery attestation key after validating the replacement key possession.", policyAuthorityKeyId: authority.keyId, targetKey: r2 }, authority);
  assert.equal(rotated.result.activeKeyId, r2.keyId);
  assert.equal((await f.app.verifyRecoverySloRetainedEvidenceChainRecoveryAttestation(f.ownerId, first.attestation)).valid, true);
  f.advance();
  await runConformance(f);
  const second = await f.app.attestRecoverySloRetainedEvidenceChainRecovery(f.ownerId, {
    reason: "Attest the updated retained-evidence chain using the newly active recovery signing key."
  });
  assert.equal(second.attestation.signing.keyId, r2.keyId);
  assert.equal((await f.app.verifyRecoverySloRetainedEvidenceChainRecoveryAttestation(f.ownerId, second.attestation)).valid, true);
});

test("Batch 137: trust policy challenge rejects invalid authority, stale revision, replay, and owner substitution", async t => {
  const a = keyPair("drift-a"), b = keyPair("drift-b"), c = keyPair("drift-c"), authority = keyPair("policy-authority-t");
  const keys = { [a.keyId]: a, [b.keyId]: b, [c.keyId]: c };
  const f = await fixture(t, { driftSigner: signerFor(keys), driftKeyId: a.keyId,
    driftPublicKeys: { [a.keyId]: a.publicKey, [b.keyId]: b.publicKey, [c.keyId]: c.publicKey },
    policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireDriftSigner: true });
  await assert.rejects(f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, { domain: "drift_event", action: "revoke",
    targetKeyId: a.keyId, reason: "Reject a future compromise cutoff because it must not be accepted as historical policy.",
    invalidateBefore: "2099-01-01T00:00:00.000Z", policyAuthorityKeyId: authority.keyId }),
  hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CUTOFF_INVALID"));
  const stale = await f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, { domain: "drift_event", action: "rotate",
    targetKeyId: b.keyId, reason: "Prepare a transition that must become stale after another transition wins.", policyAuthorityKeyId: authority.keyId });
  await assert.rejects(f.app.applyRecoverySloProviderIdentityTrustKeyTransition("other-owner", stale.challengeId, {}),
    hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CHALLENGE_INVALID"));
  await assert.rejects(f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, stale.challengeId, {
    confirmation: stale.confirmation, policyAuthoritySignature: "A".repeat(86), proofOfPossessionSignature: signPayload(b, stale.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_AUTHORIZATION_INVALID"));
  const winning = await f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, { domain: "drift_event", action: "rotate",
    targetKeyId: c.keyId, reason: "Apply the competing transition so the first challenge is no longer current.", policyAuthorityKeyId: authority.keyId });
  const winningResult = await f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, winning.challengeId, {
    confirmation: winning.confirmation, policyAuthoritySignature: signPayload(authority, winning.authorizationPayload),
    proofOfPossessionSignature: signPayload(c, winning.proofOfPossessionPayload)
  });
  assert.equal(winningResult.activeKeyId, c.keyId);
  await assert.rejects(f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, stale.challengeId, {
    confirmation: stale.confirmation, policyAuthoritySignature: signPayload(authority, stale.authorizationPayload),
    proofOfPossessionSignature: signPayload(b, stale.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_STALE"));
  await assert.rejects(f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, winning.challengeId, {
    confirmation: winning.confirmation, policyAuthoritySignature: signPayload(authority, winning.authorizationPayload),
    proofOfPossessionSignature: signPayload(c, winning.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CHALLENGE_REPLAY"));
  const expired = await f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, { domain: "drift_event", action: "rotate",
    targetKeyId: b.keyId, reason: "Prepare another transition and verify the bounded challenge expiry.", policyAuthorityKeyId: authority.keyId });
  f.advance(11 * 60 * 1000);
  await assert.rejects(f.app.applyRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, expired.challengeId, {
    confirmation: expired.confirmation, policyAuthoritySignature: signPayload(authority, expired.authorizationPayload),
    proofOfPossessionSignature: signPayload(b, expired.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_CHALLENGE_EXPIRED"));
});


test("Batch 137: recovery-attestation compromise revocation applies cutoff and leaves the trust policy auditable", async t => {
  const r1 = keyPair("recovery-cutoff-1"), r2 = keyPair("recovery-cutoff-2"), authority = keyPair("recovery-cutoff-authority");
  const keys = { [r1.keyId]: r1, [r2.keyId]: r2 };
  const f = await fixture(t, { recoverySigner: signerFor(keys), recoveryKeyId: r1.keyId,
    recoveryPublicKeys: { [r1.keyId]: r1.publicKey, [r2.keyId]: r2.publicKey },
    policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireRecoverySigner: true });
  await runConformance(f);
  f.advance();
  await prepareAndApplyTransition(f, { domain: "recovery_attestation", action: "rotate", targetKeyId: r2.keyId,
    reason: "Rotate the recovery attestation key before simulating a compromise cutoff.", policyAuthorityKeyId: authority.keyId, targetKey: r2 }, authority);
  f.advance();
  await runConformance(f);
  const compromised = await f.app.attestRecoverySloRetainedEvidenceChainRecovery(f.ownerId, {
    reason: "Create a recovery attestation that will be invalidated by the declared compromise cutoff."
  });
  f.advance();
  await prepareAndApplyTransition(f, { domain: "recovery_attestation", action: "revoke", targetKeyId: r2.keyId,
    invalidateBefore: compromised.attestation.issuedAt, reason: "Revoke the compromised recovery key and enforce the evidence cutoff.",
    policyAuthorityKeyId: authority.keyId }, authority);
  const checked = await f.app.verifyRecoverySloRetainedEvidenceChainRecoveryAttestation(f.ownerId, compromised.attestation);
  assert.equal(checked.valid, false);
  assert.equal(checked.keyPolicyTrusted, false);
  const policyAudit = await f.app.auditRecoverySloProviderIdentityTrustPolicy(f.ownerId, "recovery_attestation");
  assert.equal(policyAudit.status, "healthy");
  assert.equal(policyAudit.policies[0].activeKeyId, null);
});


test("Batch 137: trust-policy hash-chain tampering is detected and transition APIs fail closed", async t => {
  const a = keyPair("tamper-drift"), authority = keyPair("tamper-authority");
  const f = await fixture(t, { driftSigner: signerFor({ [a.keyId]: a }), driftKeyId: a.keyId,
    driftPublicKeys: { [a.keyId]: a.publicKey }, policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireDriftSigner: true });
  await f.app.ensureRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  const summary = await f.app.getRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  const stored = await f.app.store.getEvidence(f.ownerId, summary.id);
  const tampered = { ...stored, activeKeyId: "untrusted-key" };
  await f.app.store.putEvidence(f.ownerId, tampered, { expectedVersion: stored._storage?.version });
  const audit = await f.app.auditRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.findings[0].detail, "PROVIDER_IDENTITY_TRUST_POLICY_INVALID");
  await assert.rejects(f.app.prepareRecoverySloProviderIdentityTrustKeyTransition(f.ownerId, { domain: "drift_event", action: "revoke",
    targetKeyId: a.keyId, reason: "Attempt a revocation while the trust policy integrity check is failing.", policyAuthorityKeyId: authority.keyId }),
  hasCode("RECOVERY_SLO_PROVIDER_TRUST_POLICY_UNHEALTHY"));
});


test("Batch 137: policy authority cannot reuse a drift or recovery signing key", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b137-authority-separation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const key = keyPair("shared-operational-authority");
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }),
    recoverySloProviderIdentityDriftSigner: signerFor({ [key.keyId]: key }), recoverySloProviderIdentityDriftKeyId: key.keyId,
    recoverySloProviderIdentityDriftPublicKeys: { [key.keyId]: key.publicKey },
    recoverySloProviderIdentityPolicyAuthorityPublicKeys: { [key.keyId]: key.publicKey }
  }), /Policy-authority public keys harus terpisah/);
});

test("Batch 137: trust-policy audit and HTTP routes expose conformance, rotation, revocation, and historical verification policy", async t => {
  const drift = keyPair("audit-drift");
  const authority = keyPair("audit-authority");
  const f = await fixture(t, { driftSigner: signerFor({ [drift.keyId]: drift }), driftKeyId: drift.keyId,
    driftPublicKeys: { [drift.keyId]: drift.publicKey }, policyAuthorityPublicKeys: { [authority.keyId]: authority.publicKey }, requireDriftSigner: true });
  const initialized = await f.app.ensureRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  assert.equal(initialized.status, "healthy");
  const policy = await f.app.getRecoverySloProviderIdentityTrustPolicy(f.ownerId, "drift_event");
  assert.equal(policy.status, "healthy");
  const audit = await f.app.auditRecoverySloProviderIdentityTrustPolicy(f.ownerId);
  assert.equal(audit.status, "healthy");
  for (const name of ["prepareRecoverySloProviderIdentityBaselineAnchorConformance", "runRecoverySloProviderIdentityBaselineAnchorConformance",
    "auditRecoverySloProviderIdentityBaselineAnchorConformance", "getRecoverySloProviderIdentityTrustPolicy",
    "auditRecoverySloProviderIdentityTrustPolicy", "prepareRecoverySloProviderIdentityTrustKeyTransition",
    "applyRecoverySloProviderIdentityTrustKeyTransition"]) assert.equal(typeof f.app[name], "function");
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["provider-identity-baseline/conformance/challenges", "provider-identity-baseline/conformance/audit",
    "provider-identity-trust/policies/audit", "provider-identity-trust/key-transitions/challenges/:id/apply"]) assert.ok(source.includes(route));
});
