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
function keyPair() {
  const pair = generateKeyPairSync("ed25519");
  return { ...pair, publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() };
}
const signPayload = (payload, pair) => sign(null, Buffer.from(canonical(payload), "utf8"), pair.privateKey).toString("base64url");

async function setup(t, { ownerId = "owner-b126", root = null, pair = keyPair(), recoveryRootPair = keyPair() } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b126-key-policy-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  const pairs = new Map([["v4-finalizer-test-key", pair]]);
  const app = createAgenticApplication({
    storage: createStorage({ root: storageRoot }),
    recoverySloFinalizationSigner: async payload => {
      const active = pairs.get(payload.keyId);
      if (!active) throw new Error(`No signer configured for ${payload.keyId}`);
      return signPayload(payload, active);
    },
    recoverySloFinalizationKeyId: "v4-finalizer-test-key",
    recoverySloFinalizationPublicKeys: { "v4-finalizer-test-key": pair.publicKey },
    recoverySloFinalizationRecoveryPublicKeys: { "v4-finalizer-recovery-root": recoveryRootPair.publicKey },
    requireRecoverySloFinalizationAttestation: true
  });
  return { app, ownerId, root: storageRoot, pairs, initialPair: pair, recoveryRootPair };
}
async function createSignedFinalization(t, ownerId = "owner-b126") {
  const sourceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b126-source-"));
  t.after(() => fs.rm(sourceRoot, { recursive: true, force: true }));
  const source = createAgenticApplication({ storage: createStorage({ root: sourceRoot }) });
  await source.evaluateRecoverySLOs(ownerId);
  const bundle = await source.exportRecoverySloEvidenceBundle(ownerId);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(ownerId, bundle);
  const restoreApproval = await target.app.approveRecoverySloEvidenceRestorePlan(ownerId, plan, bundle, {
    reason: "Reviewed source integrity and target restore impact.",
    confirmation: `APPROVE RESTORE ${plan.planDigest.slice(0, 12)}`
  });
  const imported = await target.app.applyRecoverySloEvidenceRestorePlan(ownerId, restoreApproval.approvalId, bundle);
  const review = await target.app.reviewRecoverySloEvidenceRestoreQuarantine(ownerId, imported.journalId, {
    reason: "Reviewed restored evidence and verified the target snapshot."
  });
  const promotionApproval = await target.app.approveRecoverySloEvidencePromotion(ownerId, review.reviewId, {
    reason: "Approved evidence activation after integrity review.",
    confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}`
  });
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(ownerId, promotionApproval.approvalId);
  const finalization = await target.app.finalizeRecoverySloEvidenceRestore(ownerId, promoted.journalId);
  return { ...target, imported, review, promotionApproval, promoted, finalization, bundle };
}
async function rotate(fixture, newKeyId = "v4-finalizer-rotated-key") {
  const nextPair = keyPair();
  const policy = await fixture.app.getRecoverySloFinalizationKeyPolicy(fixture.ownerId);
  const challenge = await fixture.app.createRecoverySloFinalizationKeyTransitionChallenge(fixture.ownerId, {
    action: "rotate", expectedRevision: policy.revision, newKeyId, newPublicKey: nextPair.publicPem,
    reason: "Scheduled signing key rotation after operational review."
  });
  const result = await fixture.app.applyRecoverySloFinalizationKeyTransition(fixture.ownerId, challenge.challengeId, {
    expectedRevision: policy.revision,
    authorizationSignature: signPayload(challenge.payload, fixture.initialPair),
    newKeyProofSignature: signPayload(challenge.payload, nextPair)
  });
  fixture.pairs.set(newKeyId, nextPair);
  fixture.rotatedPair = nextPair;
  fixture.rotatedKeyId = newKeyId;
  return result;
}
async function revoke(fixture, keyId, options = {}) {
  const policy = await fixture.app.getRecoverySloFinalizationKeyPolicy(fixture.ownerId);
  const challenge = await fixture.app.createRecoverySloFinalizationKeyTransitionChallenge(fixture.ownerId, {
    action: "revoke", expectedRevision: policy.revision, targetKeyId: keyId,
    reason: "Revoked retired key following trust review.", ...options
  });
  const signer = fixture.pairs.get(policy.activeKeyId);
  return fixture.app.applyRecoverySloFinalizationKeyTransition(fixture.ownerId, challenge.challengeId, {
    expectedRevision: policy.revision, authorizationSignature: signPayload(challenge.payload, signer)
  });
}

test("Batch 126: rotation requires current-key authorization and proof of possession by the new key", async t => {
  const fixture = await createSignedFinalization(t);
  const policy = await rotate(fixture);
  assert.equal(policy.status, "healthy");
  assert.equal(policy.activeKeyId, fixture.rotatedKeyId);
  assert.equal(policy.revision, 2);
  assert.equal((await fixture.app.auditRecoverySloFinalizationKeyPolicy(fixture.ownerId)).status, "healthy");
  const otherOwnerPolicy = await fixture.app.getRecoverySloFinalizationKeyPolicy("other-owner");
  assert.equal(otherOwnerPolicy.status, "not_initialized");
  assert.equal(otherOwnerPolicy.revision, 0);
});

test("Batch 126: a retired key's pre-rotation receipt remains historically valid but is not the active signing key", async t => {
  const fixture = await createSignedFinalization(t);
  await rotate(fixture);
  const verified = await fixture.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.authorizedForCurrentUse, true);
  assert.equal(verified.signingKeyActive, false);
  assert.equal(verified.status, "valid_historical_retired");
  assert.equal((await fixture.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(fixture.ownerId, fixture.promoted.journalId)).status, "healthy");
});

test("Batch 126: finalization after rotation is signed by the newly active key", async t => {
  const fixture = await createSignedFinalization(t);
  await rotate(fixture);
  const sourceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b126-rotated-source-"));
  t.after(() => fs.rm(sourceRoot, { recursive: true, force: true }));
  const source = createAgenticApplication({ storage: createStorage({ root: sourceRoot }) });
  await source.evaluateRecoverySLOs(fixture.ownerId);
  await source.evaluateRecoverySLOs(fixture.ownerId);
  const exported = await source.exportRecoverySloEvidenceBundle(fixture.ownerId);
  const sections = {
    policyLedger: null,
    evaluationEvidenceArchives: [],
    evaluationEvidence: [exported.sections.evaluationEvidence.at(-1)],
    alertArchives: [],
    alertLedger: null,
    evaluationEvidenceArchiveIndex: null
  };
  const manifestSections = Object.keys(sections).sort().map(name => ({
    name, count: sections[name] == null ? 0 : Array.isArray(sections[name]) ? sections[name].length : 1,
    digest: sha256(canonical(sections[name]))
  }));
  const bundleDigest = sha256(canonical({ domain: "agentic-v4-recovery-slo-evidence-export", schemaVersion: 1,
    ownerId: fixture.ownerId, exportedAt: exported.exportedAt, sections, manifestSections }));
  const bundle = {
    schemaVersion: 1, kind: "recovery-slo-evidence-export-bundle", ownerId: fixture.ownerId,
    exportedAt: exported.exportedAt, sections, manifest: { sections: manifestSections, bundleDigest },
    attestation: { status: "integrity_only", algorithm: "SHA-256", keyId: null,
      payload: { domain: "agentic-v4-recovery-slo-export-attestation", schemaVersion: 1, ownerId: fixture.ownerId,
        exportedAt: exported.exportedAt, bundleDigest, keyId: null }, signature: null, authenticity: "not_asserted" }
  };
  bundle.byteLength = Buffer.byteLength(canonical(bundle), "utf8");
  bundle.readOnly = true; bundle.mutationAllowed = false;
  const plan = await fixture.app.planRecoverySloEvidenceRestore(fixture.ownerId, bundle);
  assert.equal(plan.status, "ready");
  const restoreApproval = await fixture.app.approveRecoverySloEvidenceRestorePlan(fixture.ownerId, plan, bundle, {
    reason: "Reviewed the newly exported evaluation evidence and target impact.",
    confirmation: `APPROVE RESTORE ${plan.planDigest.slice(0, 12)}`
  });
  const imported = await fixture.app.applyRecoverySloEvidenceRestorePlan(fixture.ownerId, restoreApproval.approvalId, bundle);
  const review = await fixture.app.reviewRecoverySloEvidenceRestoreQuarantine(fixture.ownerId, imported.journalId, {
    reason: "Reviewed the isolated evaluation evidence payload and digest."
  });
  const approval = await fixture.app.approveRecoverySloEvidencePromotion(fixture.ownerId, review.reviewId, {
    reason: "Approved isolated evaluation evidence after review.",
    confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}`
  });
  const promotion = await fixture.app.promoteRecoverySloQuarantinedEvidence(fixture.ownerId, approval.approvalId);
  const finalized = await fixture.app.finalizeRecoverySloEvidenceRestore(fixture.ownerId, promotion.journalId);
  assert.equal(finalized.attestationKeyId, fixture.rotatedKeyId);
  const verified = await fixture.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, promotion.journalId);
  assert.equal(verified.valid, true);
  assert.equal(verified.status, "valid_signed");
  assert.equal(verified.signingKeyActive, true);
});

test("Batch 126: key policy and rotated public keys survive application restart under the pinned bootstrap trust root", async t => {
  const fixture = await createSignedFinalization(t);
  await rotate(fixture);
  const restarted = createAgenticApplication({
    storage: createStorage({ root: fixture.root }),
    recoverySloFinalizationSigner: async payload => signPayload(payload, fixture.pairs.get(payload.keyId)),
    recoverySloFinalizationKeyId: "v4-finalizer-test-key",
    recoverySloFinalizationPublicKeys: { "v4-finalizer-test-key": fixture.initialPair.publicKey },
    recoverySloFinalizationRecoveryPublicKeys: { "v4-finalizer-recovery-root": fixture.recoveryRootPair.publicKey },
    requireRecoverySloFinalizationAttestation: true
  });
  const policy = await restarted.getRecoverySloFinalizationKeyPolicy(fixture.ownerId);
  assert.equal(policy.status, "healthy");
  assert.equal(policy.activeKeyId, fixture.rotatedKeyId);
  const verified = await restarted.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, true);
  assert.equal(verified.status, "valid_historical_retired");
});

test("Batch 126: normal revocation preserves pre-revocation historical receipt validity", async t => {
  const fixture = await createSignedFinalization(t);
  await rotate(fixture);
  const result = await revoke(fixture, "v4-finalizer-test-key");
  assert.equal(result.status, "healthy");
  const verified = await fixture.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.status, "valid_historical_revoked");
});

test("Batch 126: compromise cutoff distinguishes a valid cryptographic signature from a receipt no longer authorized for use", async t => {
  const fixture = await createSignedFinalization(t);
  await rotate(fixture);
  const receipt = await fixture.app.store.getEvidence(fixture.ownerId, fixture.finalization.finalizationId);
  await revoke(fixture, "v4-finalizer-test-key", { invalidateBefore: receipt.finalizedAt });
  const verified = await fixture.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, false);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.authorizedForCurrentUse, false);
  assert.ok(verified.findings.includes("ATTESTATION_KEY_COMPROMISE_WINDOW"));
  const reconciliation = await fixture.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(reconciliation.status, "unhealthy");
});


test("Batch 126: recovery authority can revoke a compromised active key and re-establish signing with proof of possession", async t => {
  const fixture = await createSignedFinalization(t);
  const receipt = await fixture.app.store.getEvidence(fixture.ownerId, fixture.finalization.finalizationId);
  let policy = await fixture.app.getRecoverySloFinalizationKeyPolicy(fixture.ownerId);
  const revokeChallenge = await fixture.app.createRecoverySloFinalizationKeyTransitionChallenge(fixture.ownerId, {
    action: "revoke", expectedRevision: policy.revision, targetKeyId: policy.activeKeyId,
    recoveryAuthorityKeyId: "v4-finalizer-recovery-root", invalidateBefore: receipt.finalizedAt,
    reason: "Emergency revocation after active signing key compromise."
  });
  policy = await fixture.app.applyRecoverySloFinalizationKeyTransition(fixture.ownerId, revokeChallenge.challengeId, {
    expectedRevision: policy.revision, authorizationSignature: signPayload(revokeChallenge.payload, fixture.recoveryRootPair)
  });
  assert.equal(policy.activeKeyId, null);
  const oldReceipt = await fixture.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(oldReceipt.valid, false);
  assert.equal(oldReceipt.signatureValid, true);
  assert.equal(oldReceipt.authorizedForCurrentUse, false);

  const replacement = keyPair();
  const rotateChallenge = await fixture.app.createRecoverySloFinalizationKeyTransitionChallenge(fixture.ownerId, {
    action: "rotate", expectedRevision: policy.revision, newKeyId: "v4-finalizer-recovery-replacement",
    newPublicKey: replacement.publicPem, recoveryAuthorityKeyId: "v4-finalizer-recovery-root",
    reason: "Re-establish finalization signing after emergency key revocation."
  });
  policy = await fixture.app.applyRecoverySloFinalizationKeyTransition(fixture.ownerId, rotateChallenge.challengeId, {
    expectedRevision: policy.revision, authorizationSignature: signPayload(rotateChallenge.payload, fixture.recoveryRootPair),
    newKeyProofSignature: signPayload(rotateChallenge.payload, replacement)
  });
  fixture.pairs.set("v4-finalizer-recovery-replacement", replacement);
  assert.equal(policy.activeKeyId, "v4-finalizer-recovery-replacement");
  assert.equal(policy.status, "healthy");
});

test("Batch 126: transition challenge is bound to policy revision and cannot be replayed after another transition", async t => {
  const fixture = await createSignedFinalization(t);
  const policy = await fixture.app.getRecoverySloFinalizationKeyPolicy(fixture.ownerId);
  const nextOne = keyPair(), nextTwo = keyPair();
  const challengeOne = await fixture.app.createRecoverySloFinalizationKeyTransitionChallenge(fixture.ownerId, {
    action: "rotate", expectedRevision: policy.revision, newKeyId: "rotate-one", newPublicKey: nextOne.publicPem,
    reason: "First valid rotation challenge for current policy."
  });
  const challengeTwo = await fixture.app.createRecoverySloFinalizationKeyTransitionChallenge(fixture.ownerId, {
    action: "rotate", expectedRevision: policy.revision, newKeyId: "rotate-two", newPublicKey: nextTwo.publicPem,
    reason: "Second competing rotation challenge for current policy."
  });
  await fixture.app.applyRecoverySloFinalizationKeyTransition(fixture.ownerId, challengeOne.challengeId, {
    expectedRevision: policy.revision, authorizationSignature: signPayload(challengeOne.payload, fixture.initialPair),
    newKeyProofSignature: signPayload(challengeOne.payload, nextOne)
  });
  await assert.rejects(fixture.app.applyRecoverySloFinalizationKeyTransition(fixture.ownerId, challengeTwo.challengeId, {
    expectedRevision: policy.revision, authorizationSignature: signPayload(challengeTwo.payload, fixture.initialPair),
    newKeyProofSignature: signPayload(challengeTwo.payload, nextTwo)
  }), hasCode("RECOVERY_SLO_FINALIZATION_KEY_POLICY_STALE"));
});

test("Batch 126: policy ledger tampering is detected and receipt verification fails closed", async t => {
  const fixture = await createSignedFinalization(t);
  const policy = await fixture.app.store.getEvidence(fixture.ownerId, (await fixture.app.getRecoverySloFinalizationKeyPolicy(fixture.ownerId)).id ||
    `recovery-slo-finalization-key-policy-${sha256(fixture.ownerId).slice(0, 48)}`);
  const tampered = structuredClone(policy);
  tampered.activeKeyId = "attacker-key";
  await fixture.app.store.putEvidence(fixture.ownerId, tampered, { overwrite: true });
  assert.equal((await fixture.app.auditRecoverySloFinalizationKeyPolicy(fixture.ownerId)).status, "unhealthy");
  const verified = await fixture.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, false);
  assert.ok(verified.findings.includes("KEY_POLICY_UNHEALTHY"));
});

test("Batch 126: key policy APIs are owner-scoped, read-only on inspection, and mapped to HTTP routes", async t => {
  const fixture = await createSignedFinalization(t);
  const before = (await fixture.app.store.listEvidence(fixture.ownerId)).length;
  const policy = await fixture.app.getRecoverySloFinalizationKeyPolicy(fixture.ownerId);
  const audit = await fixture.app.auditRecoverySloFinalizationKeyPolicy(fixture.ownerId);
  const after = (await fixture.app.store.listEvidence(fixture.ownerId)).length;
  assert.equal(policy.status, "healthy");
  assert.equal(audit.status, "healthy");
  assert.equal(before, after);
  const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(appSource, /createRecoverySloFinalizationKeyPolicyService/);
  assert.match(appSource, /applyRecoverySloFinalizationKeyTransition/);
  assert.match(serverSource, /finalization-keys\/challenges\/:id\/apply/);
  assert.match(serverSource, /finalization-keys\/audit/);
});
