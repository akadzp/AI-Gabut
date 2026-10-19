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
function provider(identity, { failReads = false } = {}) {
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
  const root = options.root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b136-"));
  if (!options.root) t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const journalProvider = options.journalProvider === undefined ? provider("https://journal-b136.example") : options.journalProvider;
  const retentionProvider = options.retentionProvider === undefined ? provider("https://retention-b136.example") : options.retentionProvider;
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRecoveryJournalAnchor: journalProvider,
    recoverySloRetentionCheckpointAnchor: retentionProvider,
    requireRecoverySloRetentionCheckpointAnchor: true,
    recoverySloRetainedEvidenceAnchor: options.chainProvider ?? null,
    requireRecoverySloRetainedEvidenceAnchor: options.requireChainAnchor ?? false,
    recoverySloProviderIdentityBaselineAnchor: options.baselineProvider ?? null,
    requireRecoverySloProviderIdentityBaselineAnchor: options.requireBaselineAnchor ?? false,
    recoverySloAnchorEvidenceRetentionDays: options.retentionDays ?? 90,
    recoverySloProviderIdentityDriftSigner: options.driftSigner ?? null,
    recoverySloProviderIdentityDriftKeyId: options.driftKeyId ?? null,
    recoverySloProviderIdentityDriftPublicKeys: options.driftPublicKeys ?? null,
    requireRecoverySloSignedProviderIdentityDriftEvents: options.requireDriftSigner ?? false,
    recoverySloRetainedEvidenceRecoverySigner: options.recoverySigner ?? null,
    recoverySloRetainedEvidenceRecoveryKeyId: options.recoveryKeyId ?? null,
    recoverySloRetainedEvidenceRecoveryPublicKeys: options.recoveryPublicKeys ?? null,
    requireRecoverySloRetainedEvidenceRecoveryAttestation: options.requireRecoverySigner ?? false
  });
  return { app, root, ownerId: options.ownerId || "owner-b136", journalProvider, retentionProvider, baselineProvider: options.baselineProvider ?? null };
}
function signedSetup(keyId) {
  const pair = generateKeyPairSync("ed25519");
  return { publicKey: pair.publicKey, signer: async payload => ({ keyId,
    signature: sign(null, Buffer.from(canonical(payload), "utf8"), pair.privateKey).toString("base64url") }) };
}
async function enrollBaseline(f, reason = "Enroll provider identity baseline after an explicit review of the configured trust-domain identities.") {
  const challenge = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, { reason });
  return f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function runConformance(f) {
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, {
    reason: "Verify provider semantics and preserve the completed report for operator recovery evidence."
  });
  return f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}

test("Batch 136: provider identity baseline is externally anchored and advances only through a proven single revision", async t => {
  const baselineProvider = provider("https://baseline-anchor-b136.example");
  const f = await fixture(t, { baselineProvider, requireBaselineAnchor: true });
  const enrolled = await enrollBaseline(f);
  assert.equal(enrolled.baselineAnchor.status, "anchored");
  let status = await f.app.getRecoverySloProviderIdentityBaselineAnchorStatus(f.ownerId);
  assert.equal(status.status, "anchored");
  const baseline = await f.app.getRecoverySloAnchorProviderIdentityBaseline(f.ownerId);
  f.journalProvider.providerIdentity = "https://journal-replacement-b136.example";
  const challenge = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, {
    rotate: true, expectedBaselineDigest: baseline.baseline.digest,
    reason: "Approve baseline rotation after reviewing the intentional journal provider replacement."
  });
  const rotated = await f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(rotated.baseline.revision, 2);
  assert.equal(rotated.baselineAnchor.status, "anchored");
  status = await f.app.getRecoverySloProviderIdentityBaselineAnchorStatus(f.ownerId);
  assert.equal(status.baselineRevision, 2);
  assert.equal(status.historyNotProven, false);
});

test("Batch 136: external baseline anchor detects local rollback and blocks baseline audit trust", async t => {
  const baselineProvider = provider("https://baseline-anchor-rollback-b136.example");
  const f = await fixture(t, { baselineProvider, requireBaselineAnchor: true });
  await enrollBaseline(f);
  const oldBaseline = await f.app.store.getEvidence(f.ownerId, (await f.app.getRecoverySloAnchorProviderIdentityBaseline(f.ownerId)).baseline.id);
  const baseline = await f.app.getRecoverySloAnchorProviderIdentityBaseline(f.ownerId);
  const rotate = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, {
    rotate: true, expectedBaselineDigest: baseline.baseline.digest,
    reason: "Rotate the identity baseline before simulating restoration of an older local snapshot."
  });
  await f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, rotate.challengeId, { confirmation: rotate.confirmation });
  const current = await f.app.store.getEvidence(f.ownerId, baseline.baseline.id);
  await f.app.store.putEvidence(f.ownerId, oldBaseline, { expectedVersion: current._storage?.version });
  const status = await f.app.getRecoverySloProviderIdentityBaselineAnchorStatus(f.ownerId);
  assert.equal(status.status, "rollback_detected");
  const audit = await f.app.auditRecoverySloAnchorProviderIdentityDrift(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.baselineAnchor.status, "rollback_detected");
});

test("Batch 136: signed provider identity drift events are retained, verifiable, and tamper evident", async t => {
  const setup = signedSetup("drift-k1");
  const f = await fixture(t, { driftSigner: setup.signer, driftKeyId: "drift-k1", driftPublicKeys: { "drift-k1": setup.publicKey }, requireDriftSigner: true });
  await enrollBaseline(f);
  f.journalProvider.providerIdentity = "https://unexpected-journal-b136.example";
  const result = await f.app.attestRecoverySloAnchorProviderIdentityDrift(f.ownerId);
  assert.equal(result.status, "signed");
  assert.equal(result.event.eventType, "provider_identity_drift_detected");
  assert.equal((await f.app.verifyRecoverySloAnchorProviderIdentityDriftEvent(f.ownerId, result.event)).valid, true);
  const modified = structuredClone(result.event);
  modified.report.status = "healthy";
  assert.equal((await f.app.verifyRecoverySloAnchorProviderIdentityDriftEvent(f.ownerId, modified)).valid, false);
  const audit = await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.ok(audit.total >= 1);
  assert.equal((await f.app.auditRecoverySloProviderIdentityAssuranceEvidence(f.ownerId)).status, "healthy");
});

test("Batch 136: retained-evidence chain recovery attestation binds a verified checkpoint and is retained", async t => {
  const setup = signedSetup("chain-recovery-k1");
  const f = await fixture(t, { recoverySigner: setup.signer, recoveryKeyId: "chain-recovery-k1",
    recoveryPublicKeys: { "chain-recovery-k1": setup.publicKey }, requireRecoverySigner: true });
  await runConformance(f);
  const result = await f.app.attestRecoverySloRetainedEvidenceChainRecovery(f.ownerId, {
    reason: "Attest the recovered retained-evidence chain after verifying its local hash history and current anchor status."
  });
  assert.equal(result.status, "signed");
  assert.equal(result.attestation.snapshot.sequence, 1);
  const verified = await f.app.verifyRecoverySloRetainedEvidenceChainRecoveryAttestation(f.ownerId, result.attestation);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.checkpointValid, true);
  assert.equal(verified.retained, true);
  assert.equal((await f.app.auditRecoverySloProviderIdentityAssuranceEvidence(f.ownerId)).status, "healthy");
  const modified = structuredClone(result.attestation);
  modified.snapshot.headDigest = "a".repeat(64);
  assert.equal((await f.app.verifyRecoverySloRetainedEvidenceChainRecoveryAttestation(f.ownerId, modified)).valid, false);
});

test("Batch 136: baseline anchor outage fails closed, while explicit legacy enrollment preserves history limitation", async t => {
  const failedProvider = provider("https://baseline-unavailable-b136.example", { failReads: true });
  const f = await fixture(t, { baselineProvider: failedProvider, requireBaselineAnchor: true });
  const challenge = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, {
    reason: "Enroll the first baseline while testing fail-closed behavior for an unavailable external anchor."
  });
  await assert.rejects(f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("RECOVERY_SLO_PROVIDER_IDENTITY_BASELINE_ANCHOR_BLOCKED"));
  failedProvider.failReads = false;
  assert.equal((await f.app.reconcileRecoverySloProviderIdentityBaselineAnchor(f.ownerId)).status, "anchored");

  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b136-legacy-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const legacy = await fixture(t, { root, ownerId: "owner-b136-legacy" });
  await enrollBaseline(legacy);
  const first = await legacy.app.getRecoverySloAnchorProviderIdentityBaseline(legacy.ownerId);
  const rotate = await legacy.app.prepareRecoverySloAnchorProviderIdentityBaseline(legacy.ownerId, {
    rotate: true, expectedBaselineDigest: first.baseline.digest,
    reason: "Create a second baseline revision before explicitly enrolling the legacy state externally."
  });
  await legacy.app.applyRecoverySloAnchorProviderIdentityBaseline(legacy.ownerId, rotate.challengeId, { confirmation: rotate.confirmation });
  const baselineProvider = provider("https://baseline-legacy-enrollment-b136.example");
  const upgraded = await fixture(t, { root, ownerId: legacy.ownerId, baselineProvider, requireBaselineAnchor: true });
  assert.equal((await upgraded.app.getRecoverySloProviderIdentityBaselineAnchorStatus(upgraded.ownerId)).status, "enrollment_required");
  const enrollment = await upgraded.app.prepareRecoverySloProviderIdentityBaselineAnchorEnrollment(upgraded.ownerId, {
    reason: "Approve a one-time external enrollment for the pre-existing baseline whose earlier history is not externally proven."
  });
  const anchored = await upgraded.app.applyRecoverySloProviderIdentityBaselineAnchorEnrollment(upgraded.ownerId, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(anchored.status, "anchored");
  assert.equal(anchored.historyNotProven, true);
});

test("Batch 136: application APIs and HTTP routes expose baseline anchoring, drift events, and chain recovery attestations", async t => {
  const f = await fixture(t);
  for (const name of ["getRecoverySloProviderIdentityBaselineAnchorStatus", "anchorRecoverySloProviderIdentityBaseline",
    "reconcileRecoverySloProviderIdentityBaselineAnchor", "prepareRecoverySloProviderIdentityBaselineAnchorEnrollment",
    "applyRecoverySloProviderIdentityBaselineAnchorEnrollment", "attestRecoverySloAnchorProviderIdentityDrift",
    "verifyRecoverySloAnchorProviderIdentityDriftEvent", "attestRecoverySloRetainedEvidenceChainRecovery",
    "verifyRecoverySloRetainedEvidenceChainRecoveryAttestation", "auditRecoverySloProviderIdentityAssuranceEvidence"]) {
    assert.equal(typeof f.app[name], "function", `${name} must be exposed`);
  }
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["provider-identity-baseline/anchor/reconcile", "provider-identity-baseline/anchor/enrollment/challenges",
    "provider-identity-drift/attest", "provider-identity-drift/events/verify", "retained-evidence-chain/recovery-attestations/verify",
    "provider-identity-assurance/evidence/audit"]) {
    assert.ok(source.includes(route), `missing route ${route}`);
  }
});

test("Batch 136: strict provider identity assurance requires a distinct baseline anchor and complete signing configuration", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b136-strict-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloProviderIdentityBaselineAnchor: true }),
    /provider CAS jika diwajibkan/);
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: `${root}-drift` }), requireRecoverySloSignedProviderIdentityDriftEvents: true }),
    /Signed provider identity drift events diwajibkan/);
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: `${root}-recovery` }), requireRecoverySloRetainedEvidenceRecoveryAttestation: true }),
    /Signed retained-evidence chain recovery attestation diwajibkan/);
  const shared = provider("https://shared-b136.example");
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: `${root}-shared` }),
    recoverySloRecoveryJournalAnchor: shared, recoverySloProviderIdentityBaselineAnchor: shared }), /provider terpisah/);
});
