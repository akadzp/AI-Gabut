import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const hasCode = code => error => error?.code === code;
function provider(identity, { enforceSequence = true } = {}) {
  const records = new Map();
  return {
    providerIdentity: identity,
    state: { records },
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId) throw Object.assign(new Error("owner scope mismatch"), { code: "OWNER_SCOPE_MISMATCH" });
      if (enforceSequence && (candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision <= (current?.revision ?? 0) || candidate.previousAnchorDigest !== (current?.digest ?? null))) {
        throw Object.assign(new Error("non-monotonic anchor"), { code: "NON_MONOTONIC_ANCHOR" });
      }
      records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b135-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const journalProvider = options.journalProvider === undefined ? provider("https://journal-b135.example") : options.journalProvider;
  const retentionProvider = options.retentionProvider === undefined ? provider("https://retention-b135.example") : options.retentionProvider;
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRecoveryJournalAnchor: journalProvider,
    recoverySloRetentionCheckpointAnchor: retentionProvider,
    requireRecoverySloRetentionCheckpointAnchor: true,
    recoverySloRetainedEvidenceAnchor: options.chainProvider ?? null,
    requireRecoverySloRetainedEvidenceAnchor: options.requireChainAnchor ?? false,
    recoverySloAnchorEvidenceRetentionDays: options.retentionDays ?? 90,
    recoverySloIndependenceAttestationSigner: options.independenceSigner ?? null,
    recoverySloIndependenceAttestationKeyId: options.independenceKeyId ?? null,
    recoverySloIndependenceAttestationPublicKeys: options.independencePublicKeys ?? null,
    requireRecoverySloSignedIndependenceAttestation: options.requireIndependenceAttestation ?? false,
    attestationTrustAnchor: options.attestationProvider ?? null,
    recoverySloFinalizationKeyPolicyAnchor: options.finalizationProvider ?? null
  });
  return { app, root, clock, now: () => nowMs, advance: ms => { nowMs += ms; }, ownerId: options.ownerId || "owner-b135",
    journalProvider, retentionProvider, chainProvider: options.chainProvider ?? null };
}
async function runConformance(f) {
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, {
    reason: "Verify provider semantics and preserve the completed report for future operator audits."
  });
  return f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
function signedSetup(keyId = "independence-k1") {
  const pair = generateKeyPairSync("ed25519");
  return { publicKey: pair.publicKey, signer: async payload => ({ keyId,
    signature: sign(null, Buffer.from(canonical(payload), "utf8"), pair.privateKey).toString("base64url") }) };
}

test("Batch 135: cross-domain independence report is signed, persisted, and independently verifiable", async t => {
  const setup = signedSetup();
  const f = await fixture(t, { independenceSigner: setup.signer, independenceKeyId: "independence-k1",
    independencePublicKeys: { "independence-k1": setup.publicKey }, requireIndependenceAttestation: true });
  const created = await f.app.attestRecoverySloAnchorTrustDomainIndependence(f.ownerId);
  assert.equal(created.status, "signed");
  assert.equal(created.attestation.report.claims.independentBackingStoresCryptographicallyProven, false);
  const verified = await f.app.verifyRecoverySloAnchorTrustDomainIndependenceAttestation(f.ownerId, created.attestation);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.signedReportIsApproval, false);
  const audit = await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.total, 1);
});

test("Batch 135: modified independence report and untrusted key are rejected", async t => {
  const setup = signedSetup();
  const f = await fixture(t, { independenceSigner: setup.signer, independenceKeyId: "independence-k1",
    independencePublicKeys: { "independence-k1": setup.publicKey } });
  const { attestation } = await f.app.attestRecoverySloAnchorTrustDomainIndependence(f.ownerId);
  const modified = structuredClone(attestation);
  modified.report.status = "healthy-even-if-not";
  assert.equal((await f.app.verifyRecoverySloAnchorTrustDomainIndependenceAttestation(f.ownerId, modified)).valid, false);
  const untrusted = structuredClone(attestation);
  untrusted.signing.keyId = "other-key";
  assert.equal((await f.app.verifyRecoverySloAnchorTrustDomainIndependenceAttestation(f.ownerId, untrusted)).valid, false);
});

test("Batch 135: strict independence attestation mode requires signer and trusted public key", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b135-strict-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloSignedIndependenceAttestation: true }),
    /Signed trust-domain independence attestation diwajibkan/);
});

test("Batch 135: retained evidence is appended to a persistent hash chain and pruning appends a tombstone event", async t => {
  const chainProvider = provider("https://retained-chain-b135.example");
  const f = await fixture(t, { chainProvider, requireChainAnchor: true, retentionDays: 1 });
  const first = await runConformance(f);
  assert.ok(first.retainedEvidence?.id);
  let chain = await f.app.auditRecoverySloRetainedEvidenceChain(f.ownerId);
  assert.equal(chain.status, "healthy");
  assert.equal(chain.sequence, 1);
  assert.equal(chain.anchor.status, "anchored");
  f.advance(86_400_001);
  const pruned = await f.app.pruneExpiredRecoverySloRetainedAnchorEvidence(f.ownerId, { limit: 10 });
  assert.equal(pruned.count, 1);
  chain = await f.app.auditRecoverySloRetainedEvidenceChain(f.ownerId);
  assert.equal(chain.status, "healthy");
  assert.equal(chain.sequence, 2);
  assert.equal(chain.anchor.status, "anchored");
  const stored = await f.app.listRecoverySloRetainedAnchorEvidence(f.ownerId, { includePayload: true });
  assert.equal(stored.items[0].status, "tombstone");
});

test("Batch 135: missing external chain anchor after enrollment is detected and blocks pruning", async t => {
  const chainProvider = provider("https://retained-chain-rollback-b135.example");
  const f = await fixture(t, { chainProvider, requireChainAnchor: true, retentionDays: 1 });
  await runConformance(f);
  const scope = `retained-evidence-chain-${(await import("node:crypto")).createHash("sha256").update(f.ownerId).digest("hex").slice(0, 40)}`;
  chainProvider.state.records.delete(scope);
  const chain = await f.app.auditRecoverySloRetainedEvidenceChain(f.ownerId);
  assert.equal(chain.status, "unhealthy");
  assert.ok(chain.findings.some(item => item.code.includes("ROLLBACK_SUSPECTED")));
  f.advance(86_400_001);
  await assert.rejects(f.app.pruneExpiredRecoverySloRetainedAnchorEvidence(f.ownerId), hasCode("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_UNHEALTHY"));
});

test("Batch 135: provider identity baseline enrollment is explicit and drift requires a new approved baseline", async t => {
  const f = await fixture(t);
  assert.equal((await f.app.auditRecoverySloAnchorProviderIdentityDrift(f.ownerId)).status, "baseline_missing");
  const challenge = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, {
    reason: "Enroll the current trust anchor provider identity snapshot after a controlled deployment review."
  });
  const enrolled = await f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(enrolled.status, "enrolled");
  assert.equal((await f.app.auditRecoverySloAnchorProviderIdentityDrift(f.ownerId)).status, "healthy");
  f.journalProvider.providerIdentity = "https://journal-provider-replaced-b135.example";
  const drift = await f.app.auditRecoverySloAnchorProviderIdentityDrift(f.ownerId);
  assert.equal(drift.status, "drift_detected");
  assert.ok(drift.changedDomains.some(item => item.domain === "recovery_journal"));
  const baseline = await f.app.getRecoverySloAnchorProviderIdentityBaseline(f.ownerId);
  const rotate = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, {
    rotate: true, expectedBaselineDigest: baseline.baseline.digest,
    reason: "Approve a provider identity baseline rotation after validating the replacement anchor service."
  });
  await f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, rotate.challengeId, { confirmation: rotate.confirmation });
  assert.equal((await f.app.auditRecoverySloAnchorProviderIdentityDrift(f.ownerId)).status, "healthy");
});

test("Batch 135: provider identity changes between baseline challenge and apply are rejected", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloAnchorProviderIdentityBaseline(f.ownerId, {
    reason: "Prepare the initial provider identity baseline after reviewing the configured trust domains."
  });
  f.journalProvider.providerIdentity = "https://unexpected-drift-b135.example";
  await assert.rejects(f.app.applyRecoverySloAnchorProviderIdentityBaseline(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("RECOVERY_SLO_PROVIDER_DRIFT_SNAPSHOT_CHANGED"));
});

test("Batch 135: retained evidence chain anchor is a distinct trust domain and strict configuration fails closed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b135-anchor-required-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloRetainedEvidenceAnchor: true }),
    /provider CAS jika diwajibkan/);
  const shared = provider("https://shared-b135.example");
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: `${root}-shared` }),
    recoverySloRecoveryJournalAnchor: shared, recoverySloRetainedEvidenceAnchor: shared }), /provider terpisah/);
});

test("Batch 135: application APIs and HTTP routes expose attestation, evidence chain, and drift operations", async t => {
  const f = await fixture(t);
  for (const name of ["attestRecoverySloAnchorTrustDomainIndependence", "verifyRecoverySloAnchorTrustDomainIndependenceAttestation",
    "auditRecoverySloRetainedEvidenceChain", "getRecoverySloRetainedEvidenceChainStatus", "reconcileRecoverySloRetainedEvidenceChainAnchor",
    "auditRecoverySloAnchorProviderIdentityDrift", "prepareRecoverySloAnchorProviderIdentityBaseline",
    "applyRecoverySloAnchorProviderIdentityBaseline", "getRecoverySloAnchorProviderIdentityBaseline"]) {
    assert.equal(typeof f.app[name], "function", `${name} must be exposed`);
  }
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["trust-domain-independence/attest", "trust-domain-independence/attestations/verify",
    "retained-evidence-chain/audit", "retained-evidence-chain/reconcile", "provider-identity-drift",
    "provider-identity-baseline/challenges", "provider-identity-baseline/challenges/:id/apply"]) {
    assert.ok(source.includes(route), `missing route ${route}`);
  }
});
