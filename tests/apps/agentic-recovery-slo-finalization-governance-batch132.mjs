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
const digestRecord = value => { const copy = structuredClone(value); delete copy.digest; delete copy._storage; return sha256(canonical(copy)); };
const hasCode = code => error => error?.code === code;
function keyPair() {
  const pair = generateKeyPairSync("ed25519");
  return { ...pair, publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() };
}
const signPayload = (payload, pair) => sign(null, Buffer.from(canonical(payload), "utf8"), pair.privateKey).toString("base64url");
function provider(version = "1.1.0") {
  const records = new Map();
  const v11 = ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"];
  return {
    state: { records },
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version, schemaVersion: 1,
      capabilities: version === "1.1.0" ? v11 : ["read", "compareAndSet"], ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId || candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision <= (current?.revision ?? 0) || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        const error = new Error("non-monotonic anchor candidate"); error.code = "TEST_ANCHOR_NON_MONOTONIC"; throw error;
      }
      records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b132-governance-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const finalizer = keyPair();
  const continuity = keyPair();
  const runbookRoot = keyPair();
  const recoveryAuthority = keyPair();
  const runbookKeys = new Map([["runbook-root", runbookRoot]]);
  const keyPolicyAnchor = options.keyPolicyAnchor || provider("1.1.0");
  const journalAnchor = options.journalAnchor || provider("1.0.0");
  const app = createAgenticApplication({
    storage: createStorage({ root }), clock,
    recoverySloFinalizationSigner: async payload => signPayload(payload, finalizer),
    recoverySloFinalizationKeyId: "finalizer-root",
    recoverySloFinalizationPublicKeys: { "finalizer-root": finalizer.publicKey },
    requireRecoverySloFinalizationAttestation: true,
    recoverySloFinalizationRecoveryPublicKeys: { "recovery-root": keyPair().publicKey },
    recoverySloFinalizationKeyPolicyAnchor: keyPolicyAnchor,
    requireRecoverySloFinalizationKeyPolicyAnchor: true,
    recoverySloFinalizationKeyPolicyAnchorContractVersion: options.contractVersion || "1.0.0",
    recoverySloAnchorContinuitySigner: async payload => signPayload(payload, continuity),
    recoverySloAnchorContinuityKeyId: "continuity-root",
    recoverySloAnchorContinuityPublicKeys: { "continuity-root": continuity.publicKey },
    recoverySloRunbookSigner: options.disableRunbookSigner ? null : async payload => {
      const key = runbookKeys.get(payload.keyId);
      if (!key) throw new Error("unknown runbook key");
      return signPayload(payload, key);
    },
    recoverySloRunbookKeyId: options.disableRunbookSigner ? null : "runbook-root",
    recoverySloRunbookPublicKeys: options.disableRunbookSigner ? null : { "runbook-root": runbookRoot.publicKey },
    recoverySloRunbookRecoveryPublicKeys: options.disableRecoveryAuthority ? null : { "emergency-root": recoveryAuthority.publicKey },
    requireRecoverySloSignedRunbookAttestation: options.requireSignedRunbook ?? true,
    recoverySloRecoveryJournalAnchor: options.disableJournalAnchor ? null : journalAnchor,
    requireRecoverySloRecoveryJournalAnchor: options.requireJournalAnchor ?? true,
    recoverySloEvidenceRetentionDays: 90
  });
  return { app, root, clock, now: () => nowMs, advance: ms => { nowMs += ms; }, ownerId: options.ownerId || "owner-b132",
    keyPolicyAnchor, journalAnchor, finalizer, continuity, runbookRoot, recoveryAuthority, runbookKeys };
}
async function runConformance(f) {
  const challenge = await f.app.prepareRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, {
    reason: "Validate provider behavior before approving the contract migration."
  });
  return f.app.runRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
}
async function createMigrationJournal(f) {
  await runConformance(f);
  const planned = await f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Upgrade provider contract after successful conformance validation."
  });
  const approved = await f.app.approveRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve the validated contract migration with an explicit reason."
  });
  await f.app.applyRecoverySloFinalizationAnchorContractMigration(f.ownerId, approved.approval.id, {
    expectedVersion: "1.0.0", targetVersion: "1.1.0"
  });
  const journal = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-anchor-contract-migration-recovery-journal");
  assert.ok(journal);
  return journal;
}

// Batch 132: recovery journal external anchoring.
test("Batch 132: migration recovery journal is externally anchored on each journal transition", async t => {
  const f = await fixture(t);
  const journal = await createMigrationJournal(f);
  const status = await f.app.getRecoverySloRecoveryJournalAnchorStatus(f.ownerId, journal.id);
  assert.equal(status.status, "anchored");
  assert.equal(status.revision, journal.revision);
  const anchors = [...f.journalAnchor.state.records.entries()];
  assert.equal(anchors.length, 1);
  assert.ok(anchors[0][0].startsWith("recovery-journal-"));
  assert.notEqual(anchors[0][0], f.ownerId);
  const audit = await f.app.auditRecoverySloRecoveryJournalAnchors(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.anchoredCount, 1);
});

test("Batch 132: a valid older local recovery journal is detected as rollback against the external anchor", async t => {
  const f = await fixture(t);
  const journal = await createMigrationJournal(f);
  assert.ok(journal.revision >= 2);
  const old = structuredClone(journal);
  delete old._storage;
  old.revision = 1;
  old.events = [old.events[0]];
  old.status = old.events[0].payload.status;
  old.updatedAt = old.events[0].at;
  old.digest = digestRecord(old);
  await f.app.store.putEvidence(f.ownerId, old, { expectedVersion: journal._storage.version });
  const status = await f.app.getRecoverySloRecoveryJournalAnchorStatus(f.ownerId, journal.id);
  assert.equal(status.status, "rollback_detected");
  assert.equal((await f.app.auditRecoverySloRecoveryJournalAnchors(f.ownerId)).status, "unhealthy");
  const reconciled = await f.app.reconcileRecoverySloRecoveryJournalAnchor(f.ownerId, journal.id);
  assert.equal(reconciled.reconciled, false);
  assert.equal(reconciled.reason, "TRUST_CONFLICT_REQUIRES_OPERATOR_REVIEW");
});

test("Batch 132: missing external anchor is never silently re-enrolled for a journal with history", async t => {
  const f = await fixture(t);
  const journal = await createMigrationJournal(f);
  const key = [...f.journalAnchor.state.records.keys()][0];
  f.journalAnchor.state.records.delete(key);
  const status = await f.app.getRecoverySloRecoveryJournalAnchorStatus(f.ownerId, journal.id);
  assert.equal(status.status, "rollback_suspected");
  await assert.rejects(f.app.anchorRecoverySloRecoveryJournal(f.ownerId, journal.id), hasCode("RECOVERY_SLO_JOURNAL_ANCHOR_MISSING"));
});

test("Batch 132: strict journal-anchor configuration fails closed when no provider is configured", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b132-strict-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloRecoveryJournalAnchor: true }),
    /Recovery journal anchor membutuhkan store/);
});

test("Batch 132: key revocation requires a trusted recovery-authority signature and preserves pre-cutoff receipts", async t => {
  const f = await fixture(t);
  const beforeCutoff = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  f.advance(2 * 60 * 60 * 1000);
  const afterCutoff = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  const cutoff = new Date(f.now() - 60 * 60 * 1000).toISOString();
  const challenge = await f.app.createRecoverySloRunbookTrustKeyRevocationChallenge(f.ownerId, {
    targetKeyId: "runbook-root", expectedRevision: 1, invalidateBefore: cutoff,
    recoveryAuthorityKeyId: "emergency-root", reason: "Revoke the compromised runbook key and invalidate post-cutoff signatures."
  });
  await assert.rejects(f.app.applyRecoverySloRunbookTrustKeyRevocation(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation, recoveryAuthoritySignature: "invalid-signature"
  }), hasCode("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_INVALID"));
  const revoked = await f.app.applyRecoverySloRunbookTrustKeyRevocation(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation,
    recoveryAuthoritySignature: signPayload(challenge.challenge.authorizationPayload, f.recoveryAuthority)
  });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.activeKeyId, null);
  assert.equal((await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, beforeCutoff.runbook)).valid, true);
  assert.equal((await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, afterCutoff.runbook)).valid, false);
  const audit = await f.app.auditRecoverySloRunbookTrustKeyPolicy(f.ownerId);
  assert.ok(audit.revokedKeyIds.includes("runbook-root"));
  assert.equal(audit.compromiseCutoffs[0].invalidateBefore, cutoff);
});

test("Batch 132: revoking the active runbook key can be recovered only with recovery authority and new-key proof of possession", async t => {
  const f = await fixture(t);
  const challenge = await f.app.createRecoverySloRunbookTrustKeyRevocationChallenge(f.ownerId, {
    targetKeyId: "runbook-root", expectedRevision: 1, recoveryAuthorityKeyId: "emergency-root",
    reason: "Emergency revoke the compromised key before installing a replacement."
  });
  await f.app.applyRecoverySloRunbookTrustKeyRevocation(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation,
    recoveryAuthoritySignature: signPayload(challenge.challenge.authorizationPayload, f.recoveryAuthority)
  });
  const replacement = keyPair();
  f.runbookKeys.set("runbook-replacement", replacement);
  const prepared = await f.app.createRecoverySloRunbookTrustKeyTransitionChallenge(f.ownerId, {
    action: "recover", expectedRevision: 2, newKeyId: "runbook-replacement", newPublicKey: replacement.publicPem,
    recoveryAuthorityKeyId: "emergency-root", reason: "Install a replacement after recovery-authority validation."
  });
  const applied = await f.app.applyRecoverySloRunbookTrustKeyTransition(f.ownerId, prepared.challenge.id, {
    confirmation: prepared.confirmation,
    recoveryAuthoritySignature: signPayload(prepared.challenge.authorizationPayload, f.recoveryAuthority),
    proofOfPossession: signPayload(prepared.challenge.proofOfPossessionPayload, replacement)
  });
  assert.equal(applied.status, "applied");
  assert.equal(applied.activeKeyId, "runbook-replacement");
  const exported = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  assert.equal(exported.runbook.attestation.signing.keyId, "runbook-replacement");
  assert.equal((await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, exported.runbook)).valid, true);
});

test("Batch 132: compromise cutoff cannot be placed in the future and revoked keys cannot be revoked twice", async t => {
  const f = await fixture(t);
  await assert.rejects(f.app.createRecoverySloRunbookTrustKeyRevocationChallenge(f.ownerId, {
    targetKeyId: "runbook-root", expectedRevision: 1, recoveryAuthorityKeyId: "emergency-root",
    invalidateBefore: new Date(f.now() + 60_000).toISOString(),
    reason: "Attempt to set a compromise cutoff in the future."
  }), hasCode("RECOVERY_SLO_RUNBOOK_COMPROMISE_CUTOFF_INVALID"));
  const challenge = await f.app.createRecoverySloRunbookTrustKeyRevocationChallenge(f.ownerId, {
    targetKeyId: "runbook-root", expectedRevision: 1, recoveryAuthorityKeyId: "emergency-root",
    reason: "Revoke this runbook key as part of an incident response."
  });
  await f.app.applyRecoverySloRunbookTrustKeyRevocation(f.ownerId, challenge.challenge.id, {
    confirmation: challenge.confirmation,
    recoveryAuthoritySignature: signPayload(challenge.challenge.authorizationPayload, f.recoveryAuthority)
  });
  await assert.rejects(f.app.createRecoverySloRunbookTrustKeyRevocationChallenge(f.ownerId, {
    targetKeyId: "runbook-root", expectedRevision: 2, recoveryAuthorityKeyId: "emergency-root",
    reason: "Attempt a duplicate revocation after the key was revoked."
  }), hasCode("RECOVERY_SLO_RUNBOOK_REVOCATION_TARGET_INVALID"));
});

async function applyRetentionChange(f, targetDays) {
  const planned = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: targetDays, reason: "Adjust future recovery evidence retention after policy review."
  });
  const approved = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve the prospective retention change after reviewing its impact."
  });
  return f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approved.approval.id, {
    expectedRevision: 1, targetRetentionDays: targetDays
  });
}

test("Batch 132: retention policy checkpoint advances and detects a valid historical snapshot rollback", async t => {
  const f = await fixture(t);
  const planned = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 120, reason: "Increase retention for newly created recovery evidence records."
  });
  const policyId = `recovery-slo-evidence-retention-policy-${sha256(f.ownerId).slice(0, 48)}`;
  const oldPolicy = await f.app.store.getEvidence(f.ownerId, policyId);
  assert.equal(oldPolicy.revision, 1);
  const approved = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve the prospective retention change after reviewing its impact."
  });
  await f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approved.approval.id, {
    expectedRevision: 1, targetRetentionDays: 120
  });
  const current = await f.app.store.getEvidence(f.ownerId, policyId);
  assert.equal(current.revision, 2);
  const healthy = await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId);
  assert.equal(healthy.status, "healthy");
  const restored = structuredClone(oldPolicy);
  delete restored._storage;
  await f.app.store.putEvidence(f.ownerId, restored, { expectedVersion: current._storage.version });
  const audit = await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.checkpointStatus, "rollback_detected");
  await assert.rejects(f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 180, reason: "Attempt another policy change after a rollback was detected."
  }), hasCode("RECOVERY_SLO_RETENTION_POLICY_ROLLBACK_DETECTED"));
});

test("Batch 132: retention checkpoint detects same-revision policy substitution and keeps audit read-only", async t => {
  const f = await fixture(t);
  await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 120, reason: "Initialize retention policy and checkpoint for substitution testing."
  });
  const policyId = `recovery-slo-evidence-retention-policy-${sha256(f.ownerId).slice(0, 48)}`;
  const current = await f.app.store.getEvidence(f.ownerId, policyId);
  const changed = structuredClone(current);
  delete changed._storage;
  changed.retentionDays = 365;
  changed.events[0].payload.retentionDays = 365;
  changed.events[0].eventHash = sha256(canonical({ sequence: changed.events[0].sequence, type: changed.events[0].type,
    at: changed.events[0].at, previousHash: changed.events[0].previousHash, payload: changed.events[0].payload }));
  changed.digest = digestRecord(changed);
  await f.app.store.putEvidence(f.ownerId, changed, { expectedVersion: current._storage.version });
  const audit = await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.checkpointStatus, "mismatch");
  assert.equal(audit.mutationAllowed, false);
});

test("Batch 132: API and HTTP routes expose journal anchoring, key revocation, and retention rollback audit", async t => {
  const f = await fixture(t);
  for (const name of ["getRecoverySloRecoveryJournalAnchorStatus", "anchorRecoverySloRecoveryJournal",
    "reconcileRecoverySloRecoveryJournalAnchor", "auditRecoverySloRecoveryJournalAnchors",
    "createRecoverySloRunbookTrustKeyRevocationChallenge", "applyRecoverySloRunbookTrustKeyRevocation",
    "auditRecoverySloEvidenceRetentionPolicy"]) assert.equal(typeof f.app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-journals\/audit/);
  assert.match(server, /recovery-journals\/:id\/reconcile/);
  assert.match(server, /recovery-runbook\/key-revocations\/challenges/);
  assert.match(server, /recovery-evidence-retention\/policy\/audit/);
});

test("Batch 132: recovery authority cannot reuse an operational runbook signing public key", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b132-key-separation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const runbook = keyPair();
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }),
    recoverySloRunbookSigner: async payload => signPayload(payload, runbook),
    recoverySloRunbookKeyId: "runbook-root", recoverySloRunbookPublicKeys: { "runbook-root": runbook.publicKey },
    recoverySloRunbookRecoveryPublicKeys: { "emergency-root": runbook.publicKey }
  }), /recovery authority harus memakai kunci Ed25519 yang terpisah/);
});

test("Batch 132: recovery transition rejects missing recovery authorization and invalid new-key proof", async t => {
  const f = await fixture(t);
  const revoke = await f.app.createRecoverySloRunbookTrustKeyRevocationChallenge(f.ownerId, {
    targetKeyId: "runbook-root", expectedRevision: 1, recoveryAuthorityKeyId: "emergency-root",
    reason: "Revoke the compromised operational key before testing recovery proof checks."
  });
  await f.app.applyRecoverySloRunbookTrustKeyRevocation(f.ownerId, revoke.challenge.id, {
    confirmation: revoke.confirmation,
    recoveryAuthoritySignature: signPayload(revoke.challenge.authorizationPayload, f.recoveryAuthority)
  });
  const replacement = keyPair();
  f.runbookKeys.set("runbook-replacement", replacement);
  const prepared = await f.app.createRecoverySloRunbookTrustKeyTransitionChallenge(f.ownerId, {
    action: "recover", expectedRevision: 2, newKeyId: "runbook-replacement", newPublicKey: replacement.publicPem,
    recoveryAuthorityKeyId: "emergency-root", reason: "Recover runbook signing using independent recovery authority."
  });
  await assert.rejects(f.app.applyRecoverySloRunbookTrustKeyTransition(f.ownerId, prepared.challenge.id, {
    confirmation: prepared.confirmation,
    recoveryAuthoritySignature: "invalid-signature",
    proofOfPossession: signPayload(prepared.challenge.proofOfPossessionPayload, replacement)
  }), hasCode("RECOVERY_SLO_RUNBOOK_RECOVERY_AUTHORITY_INVALID"));
  await assert.rejects(f.app.applyRecoverySloRunbookTrustKeyTransition(f.ownerId, prepared.challenge.id, {
    confirmation: prepared.confirmation,
    recoveryAuthoritySignature: signPayload(prepared.challenge.authorizationPayload, f.recoveryAuthority),
    proofOfPossession: signPayload(prepared.challenge.proofOfPossessionPayload, f.runbookRoot)
  }), hasCode("RECOVERY_SLO_RUNBOOK_KEY_PROOF_INVALID"));
});

test("Batch 132: key-policy and recovery-journal trust domains cannot share one provider instance", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b132-anchor-separation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const shared = provider("1.1.0");
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }),
    recoverySloFinalizationKeyPolicyAnchor: shared, recoverySloRecoveryJournalAnchor: shared
  }), /provider terpisah/);
});
