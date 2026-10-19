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
const digestRecord = record => { const value = structuredClone(record); delete value.digest; delete value._storage; return sha256(canonical(value)); };
const hasCode = code => error => error?.code === code;
function keyPair() {
  const pair = generateKeyPairSync("ed25519");
  return { ...pair, publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() };
}
const signPayload = (payload, pair) => sign(null, Buffer.from(canonical(payload), "utf8"), pair.privateKey).toString("base64url");
function provider(version = "1.0.0") {
  const records = new Map();
  const v11 = ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"];
  return {
    state: { records },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId || candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision <= (current?.revision ?? 0) || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        const error = new Error("non-monotonic candidate rejected"); error.code = "TEST_ANCHOR_NON_MONOTONIC"; throw error;
      }
      records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    },
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version, schemaVersion: 1,
      capabilities: version === "1.1.0" ? v11 : ["read", "compareAndSet"], ownerScope: "ownerId", casSemantics: "digest-compare-and-set" }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b131-governance-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const finalizer = keyPair();
  const continuity = keyPair();
  const runbook = keyPair();
  const runbookKeys = new Map([["runbook-root", runbook]]);
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const anchor = options.anchor || provider(options.providerVersion || "1.0.0");
  const app = createAgenticApplication({
    storage: createStorage({ root }), clock,
    recoverySloFinalizationSigner: async payload => signPayload(payload, finalizer),
    recoverySloFinalizationKeyId: "finalizer-root",
    recoverySloFinalizationPublicKeys: { "finalizer-root": finalizer.publicKey },
    requireRecoverySloFinalizationAttestation: true,
    recoverySloFinalizationRecoveryPublicKeys: { "recovery-root": keyPair().publicKey },
    recoverySloFinalizationKeyPolicyAnchor: anchor,
    requireRecoverySloFinalizationKeyPolicyAnchor: true,
    recoverySloFinalizationKeyPolicyAnchorContractVersion: options.baseContractVersion || "1.0.0",
    recoverySloAnchorContinuitySigner: async payload => signPayload(payload, continuity),
    recoverySloAnchorContinuityKeyId: "continuity-root",
    recoverySloAnchorContinuityPublicKeys: { "continuity-root": continuity.publicKey },
    recoverySloRunbookSigner: options.disableRunbookSigner ? null : async payload => {
      const selected = runbookKeys.get(payload.keyId);
      if (!selected) throw new Error(`missing test signing key ${payload.keyId}`);
      return { signature: signPayload(payload, selected), keyId: payload.keyId };
    },
    recoverySloRunbookKeyId: options.disableRunbookSigner ? null : "runbook-root",
    recoverySloRunbookPublicKeys: options.disableRunbookSigner ? null : { "runbook-root": runbook.publicKey },
    requireRecoverySloSignedRunbookAttestation: options.requireSignedRunbook ?? true,
    recoverySloEvidenceRetentionDays: options.retentionDays || 90
  });
  return { app, anchor, finalizer, continuity, runbook, runbookKeys, ownerId: options.ownerId || "owner-b131", root,
    clock, advance: ms => { nowMs += ms; }, now: () => nowMs };
}
async function runConformance(f) {
  const challenge = await f.app.prepareRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, {
    reason: "Validate provider semantics before approving the contract migration."
  });
  return f.app.runRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
}
async function planAndApproveMigration(f) {
  await runConformance(f);
  const planned = await f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Prepare a bounded migration for rollback recovery testing."
  });
  const approved = await f.app.approveRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve the migration after checking the plan and conformance proof."
  });
  return { planned, approved };
}

test("Batch 131: migration writes a high-water checkpoint and completed recovery journal", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  const { planned, approved } = await planAndApproveMigration(f);
  const result = await f.app.applyRecoverySloFinalizationAnchorContractMigration(f.ownerId, approved.approval.id, {
    expectedVersion: "1.0.0", targetVersion: "1.1.0"
  });
  assert.equal(result.status, "applied");
  const records = await f.app.store.listEvidence(f.ownerId);
  const checkpoint = records.find(item => item.kind === "recovery-slo-anchor-contract-migration-checkpoint");
  const journal = records.find(item => item.kind === "recovery-slo-anchor-contract-migration-recovery-journal");
  assert.equal(checkpoint.highWaterRevision, result.revision);
  assert.equal(journal.status, "completed");
  const interruptedEvent = { sequence: journal.revision + 1, type: "migration_recovery_interrupted",
    at: f.clock(), previousHash: journal.events.at(-1).eventHash,
    payload: { status: "recovery_required", reason: "Simulated crash after ledger commit and before journal finalization." } };
  interruptedEvent.eventHash = sha256(canonical(interruptedEvent));
  const interrupted = { ...journal, status: "recovery_required", revision: interruptedEvent.sequence,
    events: [...journal.events, interruptedEvent], updatedAt: interruptedEvent.at };
  interrupted.digest = digestRecord(interrupted);
  await f.app.store.putEvidence(f.ownerId, interrupted);
  assert.equal((await f.app.auditRecoverySloAnchorContractMigration(f.ownerId)).status, "recovery_required");
  const recovered = await f.app.recoverRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id);
  assert.equal(recovered.status, "completed");
  assert.equal((await f.app.auditRecoverySloAnchorContractMigration(f.ownerId)).status, "healthy");
});

test("Batch 131: explicit migration recovery can retry an approved but uncommitted migration", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  const { planned } = await planAndApproveMigration(f);
  const waiting = await f.app.recoverRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id);
  assert.equal(waiting.status, "retry_required");
  await assert.rejects(f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId),
    hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_RECOVERY_REQUIRED"));
  const recovered = await f.app.recoverRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    confirmation: waiting.confirmation
  });
  assert.equal(recovered.status, "applied");
  assert.equal(recovered.recovered, true);
  assert.equal((await f.app.auditRecoverySloAnchorContractMigration(f.ownerId)).status, "healthy");
});

test("Batch 131: high-water checkpoint detects rollback to a still-valid older migration ledger", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  const { planned, approved } = await planAndApproveMigration(f);
  await f.app.applyRecoverySloFinalizationAnchorContractMigration(f.ownerId, approved.approval.id, {
    expectedVersion: "1.0.0", targetVersion: "1.1.0"
  });
  const ledger = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-anchor-contract-migration-ledger");
  const rolledBack = { ...ledger, revision: 1, activeVersion: "1.0.0", events: [ledger.events[0]], updatedAt: ledger.events[0].at };
  rolledBack.digest = digestRecord(rolledBack);
  await f.app.store.putEvidence(f.ownerId, rolledBack);
  await assert.rejects(f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId),
    hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_ROLLBACK_DETECTED"));
  const recovery = await f.app.recoverRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id);
  assert.equal(recovery.status, "rollback_detected");
  assert.equal((await f.app.auditRecoverySloAnchorContractMigration(f.ownerId)).status, "unhealthy");
});

test("Batch 131: runbook key rotation requires old-key authorization and new-key proof of possession", async t => {
  const f = await fixture(t);
  const oldRunbook = (await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId)).runbook;
  const next = keyPair();
  f.runbookKeys.set("runbook-next", next);
  const challenge = await f.app.createRecoverySloRunbookTrustKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "runbook-next", newPublicKey: next.publicPem,
    reason: "Rotate the recovery runbook signing key under a digest-bound challenge."
  });
  await assert.rejects(f.app.applyRecoverySloRunbookTrustKeyTransition(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation
  }), hasCode("RECOVERY_SLO_RUNBOOK_KEY_PROOF_INVALID"));
  const rotated = await f.app.applyRecoverySloRunbookTrustKeyTransition(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation,
    authorizationSignature: signPayload(challenge.challenge.authorizationPayload, f.runbook),
    proofOfPossession: signPayload(challenge.challenge.proofOfPossessionPayload, next)
  });
  assert.equal(rotated.activeKeyId, "runbook-next");
  const newRunbook = (await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId)).runbook;
  assert.equal(newRunbook.attestation.signing.keyId, "runbook-next");
  assert.equal((await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, newRunbook)).valid, true);
  const historical = await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, oldRunbook);
  assert.equal(historical.valid, true);
  assert.equal(historical.attestation.currentKeyStatus, "retired");
  assert.equal((await f.app.auditRecoverySloRunbookTrustKeyPolicy(f.ownerId)).status, "healthy");
});

test("Batch 131: runbook key rotation rejects stale challenge and cross-owner replay", async t => {
  const f = await fixture(t);
  const next = keyPair();
  const challenge = await f.app.createRecoverySloRunbookTrustKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "runbook-next", newPublicKey: next.publicPem,
    reason: "Rotate the runbook key after validating both signing proofs."
  });
  await assert.rejects(f.app.applyRecoverySloRunbookTrustKeyTransition("other-owner", challenge.challenge.id, {
    confirmation: challenge.confirmation,
    authorizationSignature: signPayload(challenge.challenge.authorizationPayload, f.runbook),
    proofOfPossession: signPayload(challenge.challenge.proofOfPossessionPayload, next)
  }), hasCode("RECOVERY_SLO_RUNBOOK_KEY_CHALLENGE_INVALID"));
  f.advance(11 * 60 * 1000);
  await assert.rejects(f.app.applyRecoverySloRunbookTrustKeyTransition(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation,
    authorizationSignature: signPayload(challenge.challenge.authorizationPayload, f.runbook),
    proofOfPossession: signPayload(challenge.challenge.proofOfPossessionPayload, next)
  }), hasCode("RECOVERY_SLO_RUNBOOK_KEY_CHALLENGE_EXPIRED"));
});

test("Batch 131: runbook key-policy tampering blocks verification and new signatures", async t => {
  const f = await fixture(t);
  const exported = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  const policy = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-runbook-signing-key-policy");
  policy.activeKeyId = "attacker-key";
  await f.app.store.putEvidence(f.ownerId, policy);
  const audit = await f.app.auditRecoverySloRunbookTrustKeyPolicy(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.equal((await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, exported.runbook)).valid, false);
  await assert.rejects(f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId),
    hasCode("RECOVERY_SLO_RUNBOOK_KEY_POLICY_UNHEALTHY"));
});

test("Batch 131: runbook key-policy checkpoint detects rollback to the pre-rotation key set", async t => {
  const f = await fixture(t);
  await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  const before = structuredClone((await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-runbook-signing-key-policy"));
  const next = keyPair();
  f.runbookKeys.set("runbook-next", next);
  const challenge = await f.app.createRecoverySloRunbookTrustKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "runbook-next", newPublicKey: next.publicPem,
    reason: "Rotate the runbook signing key before testing rollback resistance."
  });
  await f.app.applyRecoverySloRunbookTrustKeyTransition(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation,
    authorizationSignature: signPayload(challenge.challenge.authorizationPayload, f.runbook),
    proofOfPossession: signPayload(challenge.challenge.proofOfPossessionPayload, next)
  });
  await f.app.store.putEvidence(f.ownerId, before);
  assert.equal((await f.app.auditRecoverySloRunbookTrustKeyPolicy(f.ownerId)).status, "unhealthy");
});

test("Batch 131: stale retention plans are rejected after another approved change", async t => {
  const f = await fixture(t);
  const first = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 60, reason: "Prepare the first prospective retention policy update for approval."
  });
  const second = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 45, reason: "Prepare a competing retention policy update from the same revision."
  });
  const approvedFirst = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, first.plan.id, {
    planDigest: first.planDigest, confirmation: first.confirmation,
    reason: "Approve the first retention change after reviewing its scope."
  });
  const approvedSecond = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, second.plan.id, {
    planDigest: second.planDigest, confirmation: second.confirmation,
    reason: "Approve the competing change before either plan is applied."
  });
  await f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approvedFirst.approval.id, {
    expectedRevision: 1, targetRetentionDays: 60
  });
  await assert.rejects(f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approvedSecond.approval.id, {
    expectedRevision: 1, targetRetentionDays: 45
  }), hasCode("RECOVERY_SLO_RETENTION_POLICY_STALE"));
});

test("Batch 131: retention policy changes are approved, versioned, and prospective-only", async t => {
  const f = await fixture(t, { retentionDays: 90 });
  const first = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  const before = await f.app.store.getEvidence(f.ownerId, first.retention.id);
  const plan = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 30, reason: "Reduce retention prospectively after a documented compliance review."
  });
  assert.equal(plan.existingArtifactsAffected, false);
  const approved = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, plan.plan.id, {
    planDigest: plan.planDigest, confirmation: plan.confirmation,
    reason: "Approve a prospective-only retention period change after reviewing impact."
  });
  const applied = await f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approved.approval.id, {
    expectedRevision: 1, targetRetentionDays: 30
  });
  assert.equal(applied.retentionDays, 30);
  assert.equal(applied.revision, 2);
  const oldAfter = await f.app.store.getEvidence(f.ownerId, first.retention.id);
  assert.equal(oldAfter.expiresAt, before.expiresAt);
  assert.equal(oldAfter.retentionDays, 90);
  const second = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  const newStored = await f.app.store.getEvidence(f.ownerId, second.retention.id);
  assert.equal(newStored.retentionDays, 30);
  assert.equal(newStored.retentionPolicyRevision, 2);
  assert.equal((await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloRecoveryEvidenceRetention(f.ownerId)).status, "healthy");
});

test("Batch 131: stale retention plans and tampered policy ledgers fail closed", async t => {
  const f = await fixture(t);
  const plan = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 60, reason: "Prepare a retention change that must not survive a policy conflict."
  });
  const approved = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, plan.plan.id, {
    planDigest: plan.planDigest, confirmation: plan.confirmation,
    reason: "Approve this retention plan while its source revision is still current."
  });
  const policy = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-evidence-retention-policy");
  policy.retentionDays = 120;
  await f.app.store.putEvidence(f.ownerId, policy);
  assert.equal((await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId)).status, "unhealthy");
  await assert.rejects(f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approved.approval.id, {
    expectedRevision: 1, targetRetentionDays: 60
  }), hasCode("RECOVERY_SLO_RETENTION_POLICY_UNHEALTHY"));
});

test("Batch 131: application APIs and authenticated HTTP route mappings expose recovery, key rotation, and retention policy audit", async t => {
  const f = await fixture(t);
  for (const name of ["recoverRecoverySloFinalizationAnchorContractMigration", "createRecoverySloRunbookTrustKeyTransitionChallenge",
    "applyRecoverySloRunbookTrustKeyTransition", "auditRecoverySloRunbookTrustKeyPolicy", "auditRecoverySloEvidenceRetentionPolicy",
    "planRecoverySloEvidenceRetentionPolicyChange", "approveRecoverySloEvidenceRetentionPolicyChange",
    "applyRecoverySloEvidenceRetentionPolicyChange"]) assert.equal(typeof f.app[name], "function", name);
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /contract-migrations\/:id\/recover/);
  assert.match(serverSource, /recovery-runbook\/key-rotation\/challenges/);
  assert.match(serverSource, /recovery-evidence-retention\/policy\/plan/);
  assert.match(serverSource, /recovery-evidence-retention\/policy\/audit/);
});
