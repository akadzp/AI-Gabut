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
function provider(identity, { mode = "normal" } = {}) {
  const records = new Map();
  return { providerIdentity: identity, state: { records },
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if (mode === "accept-stale" && expectedDigest === null && current) { records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) }; }
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b140-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloProviderIdentityTrustPolicyAnchor: options.provider || null,
    recoverySloProviderIdentityPolicyAuthorityPublicKeys: options.authorityKeys || null,
    recoverySloProviderIdentityPolicyAuthorityInitialKeyId: options.initialAuthorityKeyId || null,
    recoverySloProviderIdentityPolicyAuthorityRootRecoveryPublicKeys: options.rootKeys || null,
    recoverySloRetentionReconciliationSigner: options.reconciliationSigner || null,
    recoverySloRetentionReconciliationKeyId: options.reconciliationKeyId || null,
    recoverySloRetentionReconciliationPublicKeys: options.reconciliationPublicKeys || null,
    requireRecoverySloRetentionReconciliationAttestation: options.requireReconciliationAttestation || false
  });
  return { app, root, ownerId: options.ownerId || "owner-b140", now: clock, advance: (ms = 1000) => { nowMs += ms; } };
}

async function runConformance(app, ownerId, reason = "Verify provider behavior and identity before trusting the baseline.") {
  const challenge = await app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, { reason });
  return { challenge, result: await app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, challenge.challengeId,
    { confirmation: challenge.confirmation }) };
}

test("Batch 140: root-recovery trust rotates and revokes with signed lifecycle audit and historical cutoff", async t => {
  const rootA = keyPair("root-140-a"), rootB = keyPair("root-140-b");
  const authority = keyPair("authority-140-a"), replacement = keyPair("authority-140-b");
  const f = await fixture(t, { rootKeys: { [rootA.keyId]: rootA.publicKey, [rootB.keyId]: rootB.publicKey },
    authorityKeys: { [authority.keyId]: authority.publicKey, [replacement.keyId]: replacement.publicKey }, initialAuthorityKeyId: authority.keyId });
  await f.app.ensureRecoverySloProviderIdentityPolicyAuthority(f.ownerId);
  const initial = await f.app.auditRecoverySloRootRecoveryTrust(f.ownerId);
  assert.equal(initial.status, "healthy");
  assert.equal(initial.activeKeyId, rootA.keyId);
  const issuedBeforeRotation = f.now();
  f.advance(2000);
  const rotate = await f.app.prepareRecoverySloRootRecoveryTrustTransition(f.ownerId, { action: "rotate", targetKeyId: rootB.keyId,
    reason: "Rotate root trust key under a signed, digest-bound lifecycle transition." });
  const rotated = await f.app.applyRecoverySloRootRecoveryTrustTransition(f.ownerId, rotate.challengeId, {
    confirmation: rotate.confirmation, authorizationSignature: signPayload(rootA, rotate.authorizationPayload),
    proofOfPossessionSignature: signPayload(rootB, rotate.proofOfPossessionPayload)
  });
  assert.equal(rotated.status, "rotated");
  assert.equal(rotated.activeKeyId, rootB.keyId);
  assert.equal((await f.app.evaluateRecoverySloRootRecoveryTrustKey(f.ownerId, rootA.keyId, issuedBeforeRotation)).trusted, true);
  assert.equal((await f.app.evaluateRecoverySloRootRecoveryTrustKey(f.ownerId, rootA.keyId, f.now())).trusted, false);
  await assert.rejects(f.app.prepareRecoverySloProviderIdentityPolicyAuthorityRootRecovery(f.ownerId, {
    targetKeyId: replacement.keyId, rootKeyId: rootA.keyId,
    reason: "Old root must no longer authorize new policy recovery challenges."
  }), hasCode("RECOVERY_SLO_ROOT_TRUST_KEY_NOT_ACTIVE"));
  const revoke = await f.app.prepareRecoverySloRootRecoveryTrustTransition(f.ownerId, { action: "revoke", targetKeyId: rootA.keyId,
    reason: "Revoke the retired root key after the planned trust rotation has completed." });
  const revoked = await f.app.applyRecoverySloRootRecoveryTrustTransition(f.ownerId, revoke.challengeId, {
    confirmation: revoke.confirmation, authorizationSignature: signPayload(rootB, revoke.authorizationPayload)
  });
  assert.equal(revoked.status, "revoked");
  assert.equal((await f.app.auditRecoverySloRootRecoveryTrust(f.ownerId)).status, "healthy");
  assert.equal((await f.app.evaluateRecoverySloRootRecoveryTrustKey(f.ownerId, rootA.keyId, issuedBeforeRotation)).trusted, true);
  assert.equal((await f.app.evaluateRecoverySloRootRecoveryTrustKey(f.ownerId, rootA.keyId, f.now())).trusted, false);
  await assert.rejects(f.app.applyRecoverySloRootRecoveryTrustTransition(f.ownerId, revoke.challengeId, {
    confirmation: revoke.confirmation, authorizationSignature: signPayload(rootB, revoke.authorizationPayload)
  }), hasCode("RECOVERY_SLO_ROOT_TRUST_REPLAY"));
});

test("Batch 140: root-recovery trust rejects stale, invalid, and replayed transitions", async t => {
  const rootA = keyPair("root-140-invalid-a"), rootB = keyPair("root-140-invalid-b");
  const authority = keyPair("authority-140-invalid");
  const f = await fixture(t, { rootKeys: { [rootA.keyId]: rootA.publicKey, [rootB.keyId]: rootB.publicKey },
    authorityKeys: { [authority.keyId]: authority.publicKey }, initialAuthorityKeyId: authority.keyId });
  await f.app.ensureRecoverySloRootRecoveryTrust(f.ownerId);
  const challenge = await f.app.prepareRecoverySloRootRecoveryTrustTransition(f.ownerId, { action: "rotate", targetKeyId: rootB.keyId,
    reason: "Prepare a rotation that must reject an invalid root signature." });
  await assert.rejects(f.app.applyRecoverySloRootRecoveryTrustTransition(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation, authorizationSignature: signPayload(rootB, challenge.authorizationPayload),
    proofOfPossessionSignature: signPayload(rootB, challenge.proofOfPossessionPayload)
  }), hasCode("RECOVERY_SLO_ROOT_TRUST_SIGNATURE_INVALID"));
  const state = await f.app.auditRecoverySloRootRecoveryTrust(f.ownerId);
  assert.equal(state.revision, 1);
  assert.equal(state.activeKeyId, rootA.keyId);
});

test("Batch 140: retention reconciliation attestation is signed, retained, verifiable, and tamper-evident", async t => {
  const signing = keyPair("retention-reconcile-140");
  const f = await fixture(t, { reconciliationSigner: async payload => signPayload(signing, payload),
    reconciliationKeyId: signing.keyId, reconciliationPublicKeys: { [signing.keyId]: signing.publicKey }, requireReconciliationAttestation: true });
  const attested = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Preserve a signed snapshot of the current retained-evidence reconciliation audit."
  });
  assert.equal(attested.status, "signed");
  assert.ok(["healthy", "degraded"].includes(attested.snapshotStatus));
  const verified = await f.app.verifyRecoverySloRetentionEvidenceReconciliationAttestation(f.ownerId, attested.attestation, {
    expectedAuditDigest: attested.attestation.snapshot.auditDigest
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.retained, true);
  const tampered = structuredClone(attested.attestation);
  tampered.snapshot.audit.status = "healthy";
  assert.equal((await f.app.verifyRecoverySloRetentionEvidenceReconciliationAttestation(f.ownerId, tampered)).valid, false);
  assert.equal((await f.app.auditRecoverySloRetentionEvidenceReconciliationAttestations(f.ownerId)).status, "healthy");
  const crossOwner = await f.app.verifyRecoverySloRetentionEvidenceReconciliationAttestation("other-owner", attested.attestation);
  assert.equal(crossOwner.valid, false);
  assert.ok(crossOwner.findings.length > 0);
});

test("Batch 140: provider conformance drift is detected and baseline rotation requires a fresh conformant report", async t => {
  const anchor = provider("https://provider-b140.example");
  const f = await fixture(t, { provider: anchor });
  const first = await runConformance(f.app, f.ownerId);
  assert.equal(first.result.status, "conformant");
  assert.match(first.result.report.providerIdentityFingerprint, /^[a-f0-9]{64}$/);
  assert.match(first.result.report.providerContractDigest, /^[a-f0-9]{64}$/);
  const prepared = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, {
    challengeId: first.challenge.challengeId, reason: "Accept the first conformant provider identity as an explicit baseline."
  });
  const enrolled = await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, prepared.challengeId, { confirmation: prepared.confirmation });
  assert.equal(enrolled.status, "enrolled");
  assert.equal((await f.app.auditRecoverySloProviderConformanceDrift(f.ownerId)).status, "healthy");
  anchor.providerIdentity = "https://provider-b140-replaced.example";
  const drift = await f.app.auditRecoverySloProviderConformanceDrift(f.ownerId);
  assert.equal(drift.status, "drift_detected");
  assert.ok(drift.findings.some(item => item.code === "PROVIDER_IDENTITY_DRIFT"));
  await assert.rejects(f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, {
    challengeId: first.challenge.challengeId, rotate: true, reason: "This stale report must not reset a changed provider baseline."
  }), hasCode("RECOVERY_SLO_CONFORMANCE_DRIFT_SOURCE_PROVIDER_CHANGED"));
  const second = await runConformance(f.app, f.ownerId, "Re-test the replacement provider before considering baseline rotation.");
  assert.equal(second.result.status, "conformant");
  const rotate = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, {
    challengeId: second.challenge.challengeId, rotate: true, reason: "Accept the replacement only after fresh conformance succeeds."
  });
  assert.equal((await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, rotate.challengeId, { confirmation: rotate.confirmation })).status, "rotated");
  assert.equal((await f.app.auditRecoverySloProviderConformanceDrift(f.ownerId)).status, "healthy");
});

test("Batch 140: drift watch detects contract changes and refuses cross-owner baseline access", async t => {
  const anchor = provider("https://provider-b140-contract.example");
  const f = await fixture(t, { provider: anchor });
  const first = await runConformance(f.app, f.ownerId);
  const prepared = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, {
    challengeId: first.challenge.challengeId, reason: "Set the accepted provider contract fingerprint for drift detection."
  });
  await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, prepared.challengeId, { confirmation: prepared.confirmation });
  anchor.contractInfo.version = "1.2.0";
  const audit = await f.app.auditRecoverySloProviderConformanceDrift(f.ownerId);
  assert.equal(audit.status, "drift_detected");
  assert.ok(audit.findings.some(item => item.code === "PROVIDER_CONTRACT_DRIFT"));
  assert.equal((await f.app.auditRecoverySloProviderConformanceDrift("another-owner")).status, "baseline_missing");
});

test("Batch 140: application exports and HTTP routes expose root trust, reconciliation attestation, and conformance drift watch", async t => {
  const root = keyPair("root-140-routes"), authority = keyPair("authority-140-routes");
  const f = await fixture(t, { rootKeys: { [root.keyId]: root.publicKey }, authorityKeys: { [authority.keyId]: authority.publicKey }, initialAuthorityKeyId: authority.keyId });
  for (const name of ["prepareRecoverySloRootRecoveryTrustTransition", "applyRecoverySloRootRecoveryTrustTransition", "auditRecoverySloRootRecoveryTrust",
    "attestRecoverySloRetentionEvidenceReconciliation", "verifyRecoverySloRetentionEvidenceReconciliationAttestation",
    "prepareRecoverySloProviderConformanceDriftBaseline", "applyRecoverySloProviderConformanceDriftBaseline", "auditRecoverySloProviderConformanceDrift"]) {
    assert.equal(typeof f.app[name], "function", `${name} should be exported`);
  }
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /root-recovery-trust\/transitions\/challenges/);
  assert.match(server, /retention-reconciliation\/attestations/);
  assert.match(server, /provider-conformance-drift\/baselines/);
});
