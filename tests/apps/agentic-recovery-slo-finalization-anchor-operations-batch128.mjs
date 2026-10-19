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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b128-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const pair = keyPair();
  const anchor = options.anchor || anchorProvider();
  let currentTime = options.startAt || "2026-10-12T00:00:00.000Z";
  const clock = options.clock || (() => currentTime);
  const app = createAgenticApplication({
    storage: createStorage({ root }), clock,
    recoverySloFinalizationSigner: async payload => signPayload(payload, pair),
    recoverySloFinalizationKeyId: "finalizer-root",
    recoverySloFinalizationPublicKeys: { "finalizer-root": pair.publicKey },
    requireRecoverySloFinalizationAttestation: true,
    recoverySloFinalizationRecoveryPublicKeys: { "recovery-root": keyPair().publicKey },
    recoverySloFinalizationKeyPolicyAnchor: anchor,
    requireRecoverySloFinalizationKeyPolicyAnchor: true
  });
  return { app, anchor, pair, ownerId: options.ownerId || "owner-b128", root, setTime: value => { currentTime = value; } };
}
async function initializePolicy(f) {
  return f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "finalizer-next", newPublicKey: keyPair().publicPem,
    reason: "Initialize and anchor the policy before the continuity operation."
  });
}

test("Batch 128: provider conformance is two-step, typed-confirmation gated, and writes only to a disposable namespace", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, {
    reason: "Check the anchor provider CAS contract before recovery operations."
  });
  assert.match(challenge.disposableNamespace, /^__agentic_v4_conformance__/);
  assert.equal(challenge.writesToOwnerNamespace, false);
  await assert.rejects(f.app.runRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: "RUN CONFORMANCE wrong-token"
  }), hasCode("RECOVERY_SLO_FINALIZATION_CONFORMANCE_CONFIRMATION_INVALID"));
  assert.equal(f.anchor.state.records.has(f.ownerId), false);
  const result = await f.app.runRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
  assert.equal(result.status, "conformant");
  assert.equal(result.report.conformant, true);
  assert.equal(result.writesToOwnerNamespace, false);
  assert.equal(f.anchor.state.records.has(f.ownerId), false);
  assert.equal((await f.app.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId)).status, "healthy");
  const replay = await f.app.runRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
  assert.equal(replay.idempotent, true);
});

test("Batch 128: provider conformance fails safely and records a bounded failure code", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, {
    reason: "Confirm provider failure handling without touching the production owner namespace."
  });
  f.anchor.state.failNextRead = true;
  await assert.rejects(f.app.runRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  }), hasCode("RECOVERY_SLO_FINALIZATION_CONFORMANCE_FAILED"));
  const events = await f.app.listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId);
  assert.equal(events.status, "healthy");
  assert.ok(events.items.some(item => item.type === "provider_conformance_failed"));
  assert.equal(f.anchor.state.records.has(f.ownerId), false);
});

test("Batch 128: continuity proof binds the local policy chain to the current external anchor and verifies storage-independently", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const before = await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId);
  const proofResult = await f.app.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId);
  assert.equal(proofResult.proof.observedAnchorStatus, "anchored");
  assert.equal(proofResult.proof.claims.anchorCurrent, true);
  assert.equal(proofResult.proof.externalHistoryProof, "latest-only-provider-does-not-expose-prior-anchor-records");
  const verified = await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId, proofResult.proof);
  assert.equal(verified.valid, true);
  assert.equal(verified.continuityEstablished, true);
  assert.equal(verified.current, true);
  assert.equal(verified.remoteObservationAuthenticated, false);
  const after = await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId);
  assert.equal(after.digest, before.digest);
});

test("Batch 128: continuity proof detects payload tampering and owner mismatch", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const { proof } = await f.app.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId);
  const tampered = structuredClone(proof);
  tampered.localPolicySnapshot.revision = 99;
  const invalid = await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId, tampered);
  assert.equal(invalid.valid, false);
  assert.ok(invalid.findings.includes("CONTINUITY_PROOF_DIGEST_MISMATCH"));
  const otherOwner = await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof("other-owner", proof);
  assert.equal(otherOwner.valid, false);
});

test("Batch 128: an exact ancestor anchor proves historical continuity but is not reported as current", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const before = await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId);
  const policyId = before.id;
  const snapshot = await f.app.store.getEvidence(f.ownerId, policyId);
  const next = keyPair();
  const challenge = await f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "finalizer-next-2", newPublicKey: next.publicPem,
    reason: "Rotate the key to test an external anchor that is a valid ancestor."
  });
  f.anchor.state.failNextWrite = true;
  const rotated = await f.app.applyRecoverySloFinalizationKeyTransition(f.ownerId, challenge.challengeId, {
    expectedRevision: challenge.payload.expectedRevision,
    authorizationSignature: signPayload(challenge.payload, f.pair),
    newKeyProofSignature: signPayload(challenge.payload, next)
  });
  assert.equal(rotated.status, "anchor_pending");
  const { proof } = await f.app.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId);
  assert.equal(proof.observedAnchorStatus, "behind_registry");
  const verified = await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId, proof);
  assert.equal(verified.valid, true);
  assert.equal(verified.continuityEstablished, true);
  assert.equal(verified.current, false);
  assert.equal(verified.anchorRevision, 1);
  assert.equal(snapshot.revision, 1);
});

test("Batch 128: a rolled-back local policy produces a valid diagnostic proof but no continuity claim", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const policy = await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId);
  const genesis = await f.app.store.getEvidence(f.ownerId, policy.id);
  const next = keyPair();
  const challenge = await f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "finalizer-next-rollback", newPublicKey: next.publicPem,
    reason: "Create a later anchored revision before simulating local snapshot rollback."
  });
  await f.app.applyRecoverySloFinalizationKeyTransition(f.ownerId, challenge.challengeId, {
    expectedRevision: challenge.payload.expectedRevision,
    authorizationSignature: signPayload(challenge.payload, f.pair),
    newKeyProofSignature: signPayload(challenge.payload, next)
  });
  await f.app.store.putEvidence(f.ownerId, genesis, { overwrite: true });
  const { proof } = await f.app.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId);
  assert.equal(proof.observedAnchorStatus, "rollback_detected");
  const verified = await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorContinuityProof(f.ownerId, proof);
  assert.equal(verified.valid, true);
  assert.equal(verified.continuityEstablished, false);
  assert.equal(verified.status, "rollback_detected");
});

test("Batch 128: reconciliation records request and result as a hash-linked operator evidence pair", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const current = await f.app.getRecoverySloFinalizationKeyPolicy(f.ownerId);
  const next = keyPair();
  const challenge = await f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: current.revision, newKeyId: "finalizer-next-reconcile", newPublicKey: next.publicPem,
    reason: "Create a behind-registry condition to exercise operator reconciliation evidence."
  });
  f.anchor.state.failNextWrite = true;
  await f.app.applyRecoverySloFinalizationKeyTransition(f.ownerId, challenge.challengeId, {
    expectedRevision: challenge.payload.expectedRevision,
    authorizationSignature: signPayload(challenge.payload, f.pair),
    newKeyProofSignature: signPayload(challenge.payload, next)
  });
  const reconciled = await f.app.reconcileRecoverySloFinalizationKeyPolicyAnchor(f.ownerId);
  assert.equal(reconciled.status, "anchored");
  assert.ok(reconciled.operationId);
  const audit = await f.app.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingReconciliations.length, 0);
  const listed = await f.app.listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId, { limit: 100 });
  assert.ok(listed.items.some(item => item.type === "reconciliation_requested" && item.payload.operationId === reconciled.operationId));
  assert.ok(listed.items.some(item => item.type === "reconciliation_completed" && item.payload.operationId === reconciled.operationId));
});

test("Batch 128: operator evidence notes are audit-only and owner scoped", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const note = await f.app.recordRecoverySloFinalizationKeyPolicyAnchorOperatorNote(f.ownerId, {
    reason: "Operator reviewed the current anchor status and documented the next recovery action."
  });
  assert.equal(note.status, "recorded");
  assert.equal(note.noteIsAuthorization, false);
  assert.equal((await f.app.listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence("other-owner")).status, "empty");
  const audit = await f.app.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId);
  assert.equal(audit.status, "healthy");
});

test("Batch 128: operator evidence hash-chain tampering is detected and blocks further appends", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  await f.app.recordRecoverySloFinalizationKeyPolicyAnchorOperatorNote(f.ownerId, {
    reason: "Create an initial operator note before testing evidence ledger integrity."
  });
  const ledger = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-finalization-anchor-operator-evidence");
  assert.ok(ledger);
  const tampered = structuredClone(ledger);
  tampered.events[0].payload.reason = "rewritten evidence";
  await f.app.store.putEvidence(f.ownerId, tampered, { overwrite: true });
  assert.equal((await f.app.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId)).status, "unhealthy");
  await assert.rejects(f.app.recordRecoverySloFinalizationKeyPolicyAnchorOperatorNote(f.ownerId, {
    reason: "Must refuse to append onto an evidence chain that failed integrity verification."
  }), hasCode("RECOVERY_SLO_FINALIZATION_OPERATOR_EVIDENCE_CHAIN_INVALID"));
});

test("Batch 128: HTTP routes and application boundary expose conformance, continuity, and operator evidence", async t => {
  const f = await fixture(t);
  const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(appSource, /createRecoverySloFinalizationAnchorOperations/);
  assert.match(appSource, /createRecoverySloFinalizationKeyPolicyAnchorContinuityProof/);
  assert.match(appSource, /runRecoverySloFinalizationKeyPolicyAnchorProviderConformance/);
  assert.match(serverSource, /finalization-keys\/anchor\/conformance-challenges/);
  assert.match(serverSource, /finalization-keys\/anchor\/continuity-proof\/verify/);
  assert.match(serverSource, /finalization-keys\/anchor\/operator-evidence\/audit/);
  assert.equal(typeof f.app.createRecoverySloFinalizationKeyPolicyAnchorContinuityProof, "function");
});
