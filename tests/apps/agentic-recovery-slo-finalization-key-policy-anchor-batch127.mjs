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
function anchorProvider() {
  const records = new Map();
  const state = { failNextRead: false, failNextWrite: false, records };
  return {
    state,
    async read(ownerId) {
      if (state.failNextRead) { state.failNextRead = false; const error = new Error("temporary read outage"); error.code = "TEST_ANCHOR_READ_OUTAGE"; throw error; }
      return structuredClone(records.get(ownerId) ?? null);
    },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (state.failNextWrite) { state.failNextWrite = false; const error = new Error("temporary write outage"); error.code = "TEST_ANCHOR_WRITE_OUTAGE"; throw error; }
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId || candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision <= (current?.revision ?? 0) || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        const error = new Error("non-monotonic candidate rejected"); error.code = "TEST_ANCHOR_NON_MONOTONIC"; throw error;
      }
      records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b127-key-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const pair = keyPair();
  const anchor = options.anchor || anchorProvider();
  const ownerId = options.ownerId || "owner-b127";
  const app = createAgenticApplication({
    storage: createStorage({ root }),
    recoverySloFinalizationSigner: async payload => signPayload(payload, pair),
    recoverySloFinalizationKeyId: "finalizer-root",
    recoverySloFinalizationPublicKeys: { "finalizer-root": pair.publicKey },
    requireRecoverySloFinalizationAttestation: true,
    recoverySloFinalizationRecoveryPublicKeys: { "recovery-root": keyPair().publicKey },
    recoverySloFinalizationKeyPolicyAnchor: anchor,
    requireRecoverySloFinalizationKeyPolicyAnchor: true
  });
  return { app, anchor, pair, ownerId, root };
}
async function createRotationChallenge(f, keyId = "finalizer-next") {
  const next = keyPair();
  const challenge = await f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: keyId, newPublicKey: next.publicPem,
    reason: "Rotate key after the independent anchor has been checked."
  });
  return { challenge, next };
}
async function applyRotation(f, challenge, next) {
  return f.app.applyRecoverySloFinalizationKeyTransition(f.ownerId, challenge.challengeId, {
    expectedRevision: challenge.payload.expectedRevision,
    authorizationSignature: signPayload(challenge.payload, f.pair),
    newKeyProofSignature: signPayload(challenge.payload, next)
  });
}

test("Batch 127: genesis key-policy revision is anchored and each successful rotation advances the independent anchor", async t => {
  const f = await fixture(t);
  const { challenge, next } = await createRotationChallenge(f);
  const genesis = await f.app.getRecoverySloFinalizationKeyPolicyAnchorStatus(f.ownerId);
  assert.equal(genesis.status, "anchored");
  assert.equal(genesis.anchorRevision, 1);
  const rotated = await applyRotation(f, challenge, next);
  assert.equal(rotated.status, "healthy");
  assert.equal(rotated.externalAnchor.status, "anchored");
  assert.equal(rotated.externalAnchor.anchorRevision, 2);
  assert.equal(rotated.externalAnchor.anchorSequence, 2);
  assert.equal((await f.app.auditRecoverySloFinalizationKeyPolicy(f.ownerId)).status, "healthy");
});

test("Batch 127: restoring a valid older local snapshot is detected as rollback and blocks key-policy mutations", async t => {
  const f = await fixture(t);
  const { challenge, next } = await createRotationChallenge(f);
  const policyId = (await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId)).id;
  const genesisSnapshot = await f.app.store.getEvidence(f.ownerId, policyId);
  await applyRotation(f, challenge, next);
  await f.app.store.putEvidence(f.ownerId, genesisSnapshot, { overwrite: true });
  const status = await f.app.getRecoverySloFinalizationKeyPolicyAnchorStatus(f.ownerId);
  assert.equal(status.status, "rollback_detected");
  assert.equal(status.localRevision, 1);
  assert.equal(status.anchorRevision, 2);
  assert.equal((await f.app.auditRecoverySloFinalizationKeyPolicy(f.ownerId)).status, "unhealthy");
  await assert.rejects(f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "blocked-key", newPublicKey: keyPair().publicPem,
    reason: "Must be blocked after a rollback is detected."
  }), hasCode("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ROLLBACK_DETECTED"));
});

test("Batch 127: a transient anchor write failure leaves an explicit pending state and reconciliation safely advances an exact ancestor", async t => {
  const f = await fixture(t);
  const { challenge, next } = await createRotationChallenge(f);
  f.anchor.state.failNextWrite = true;
  const rotated = await applyRotation(f, challenge, next);
  assert.equal(rotated.status, "anchor_pending");
  assert.equal(rotated.mutationAllowed, false);
  assert.equal((await f.app.getRecoverySloFinalizationKeyPolicyAnchorStatus(f.ownerId)).status, "behind_registry");
  await assert.rejects(f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 2, newKeyId: "blocked-during-lag", newPublicKey: keyPair().publicPem,
    reason: "Mutations remain blocked until the anchor catches up."
  }), hasCode("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_BEHIND_REGISTRY"));
  const reconciled = await f.app.reconcileRecoverySloFinalizationKeyPolicyAnchor(f.ownerId);
  assert.equal(reconciled.status, "anchored");
  assert.equal(reconciled.anchorRevision, 2);
  assert.equal(reconciled.anchorSequence, 2);
});

test("Batch 127: external anchor digest or policy-state mismatch is never auto-repaired", async t => {
  const f = await fixture(t);
  await createRotationChallenge(f);
  const anchor = f.anchor.state.records.get(f.ownerId);
  const unsigned = { ...anchor, trustDigest: "0".repeat(64) };
  delete unsigned.digest;
  f.anchor.state.records.set(f.ownerId, { ...unsigned, digest: sha256(canonical(unsigned)) });
  assert.equal((await f.app.getRecoverySloFinalizationKeyPolicyAnchorStatus(f.ownerId)).status, "mismatch");
  assert.equal((await f.app.reconcileRecoverySloFinalizationKeyPolicyAnchor(f.ownerId)).status, "mismatch");
  assert.equal(f.anchor.state.records.get(f.ownerId).trustDigest, "0".repeat(64));
});

test("Batch 127: anchor outages fail closed for key-policy mutations", async t => {
  const f = await fixture(t);
  await createRotationChallenge(f);
  f.anchor.state.failNextRead = true;
  assert.equal((await f.app.getRecoverySloFinalizationKeyPolicyAnchorStatus(f.ownerId)).status, "unavailable");
  f.anchor.state.failNextRead = true;
  await assert.rejects(f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "outage-key", newPublicKey: keyPair().publicPem,
    reason: "A provider outage must stop trust-sensitive mutations."
  }), hasCode("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ANCHOR_UNAVAILABLE"));
});


async function createSignedFinalization(t, f) {
  const sourceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b127-source-"));
  t.after(() => fs.rm(sourceRoot, { recursive: true, force: true }));
  const source = createAgenticApplication({ storage: createStorage({ root: sourceRoot }) });
  await source.evaluateRecoverySLOs(f.ownerId);
  const bundle = await source.exportRecoverySloEvidenceBundle(f.ownerId);
  const plan = await f.app.planRecoverySloEvidenceRestore(f.ownerId, bundle);
  const restoreApproval = await f.app.approveRecoverySloEvidenceRestorePlan(f.ownerId, plan, bundle, {
    reason: "Reviewed source integrity and target restore impact.",
    confirmation: `APPROVE RESTORE ${plan.planDigest.slice(0, 12)}`
  });
  const imported = await f.app.applyRecoverySloEvidenceRestorePlan(f.ownerId, restoreApproval.approvalId, bundle);
  const review = await f.app.reviewRecoverySloEvidenceRestoreQuarantine(f.ownerId, imported.journalId, {
    reason: "Reviewed restored evidence and verified the target snapshot."
  });
  const promotionApproval = await f.app.approveRecoverySloEvidencePromotion(f.ownerId, review.reviewId, {
    reason: "Approved evidence activation after integrity review.",
    confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}`
  });
  const promoted = await f.app.promoteRecoverySloQuarantinedEvidence(f.ownerId, promotionApproval.approvalId);
  const finalization = await f.app.finalizeRecoverySloEvidenceRestore(f.ownerId, promoted.journalId);
  return { promoted, finalization };
}

test("Batch 127: receipt verification rejects an otherwise valid signature when the local key policy has rolled back", async t => {
  const f = await fixture(t);
  const finalized = await createSignedFinalization(t, f);
  const policy = await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId);
  const genesisSnapshot = await f.app.store.getEvidence(f.ownerId, policy.id);
  const { challenge, next } = await createRotationChallenge(f);
  await applyRotation(f, challenge, next);
  await f.app.store.putEvidence(f.ownerId, genesisSnapshot, { overwrite: true });
  const verified = await f.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(f.ownerId, finalized.promoted.journalId);
  assert.equal(verified.valid, false);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.authorizedForCurrentUse, false);
  assert.equal(verified.attestationStatus, "policy_anchor_rollback_detected");
});

test("Batch 127: missing local key policy with an existing external anchor is treated as rollback, not re-bootstrapped", async t => {
  const f = await fixture(t);
  await createRotationChallenge(f);
  const policy = await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId);
  const id = policy.id;
  await f.app.store.removeOwned("evidence", f.ownerId, id);
  const status = await f.app.getRecoverySloFinalizationKeyPolicyAnchorStatus(f.ownerId);
  assert.equal(status.status, "rollback_detected");
  await assert.rejects(f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "no-rebootstrap", newPublicKey: keyPair().publicPem,
    reason: "Do not initialize a new policy over an existing anchor."
  }), hasCode("RECOVERY_SLO_FINALIZATION_KEY_POLICY_ROLLBACK_DETECTED"));
});

test("Batch 127: key-policy anchor state is owner-scoped and audit endpoints are mapped", async t => {
  const f = await fixture(t);
  await createRotationChallenge(f);
  assert.equal((await f.app.getRecoverySloFinalizationKeyPolicyAnchorStatus("other-owner")).status, "missing");
  const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(appSource, /recoverySloFinalizationKeyPolicyAnchor/);
  assert.match(appSource, /reconcileRecoverySloFinalizationKeyPolicyAnchor/);
  assert.match(serverSource, /finalization-keys\/anchor\/reconcile/);
  assert.match(serverSource, /finalization-keys\/anchor/);
});

test("Batch 127: required external anchoring rejects absent configuration and prevents anchor-store reuse", async t => {
  assert.throws(() => createAgenticApplication({ requireRecoverySloFinalizationKeyPolicyAnchor: true }), /External anchor wajib dikonfigurasi/);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b127-shared-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchor = anchorProvider();
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), attestationTrustAnchor: anchor,
    recoverySloFinalizationKeyPolicyAnchor: anchor }), /harus terpisah/);
});
