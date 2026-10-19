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
  const result = {
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
  return result;
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b134-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const journalProvider = options.journalProvider === undefined ? provider("https://journal-anchor.example") : options.journalProvider;
  const retentionProvider = options.retentionProvider === undefined ? provider("https://retention-anchor.example") : options.retentionProvider;
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRecoveryJournalAnchor: journalProvider,
    requireRecoverySloRecoveryJournalAnchor: false,
    recoverySloRetentionCheckpointAnchor: retentionProvider,
    requireRecoverySloRetentionCheckpointAnchor: options.requireRetentionAnchor ?? true,
    recoverySloRetentionContinuitySigner: options.signer ?? null,
    recoverySloRetentionContinuityKeyId: options.keyId ?? null,
    recoverySloRetentionContinuityPublicKeys: options.publicKeys ?? null,
    requireRecoverySloRetentionSignedContinuityReceipt: options.requireSignedReceipt ?? false,
    recoverySloAnchorEvidenceRetentionDays: options.retentionDays ?? 90,
    attestationTrustAnchor: options.attestationProvider ?? null,
    recoverySloFinalizationKeyPolicyAnchor: options.finalizationProvider ?? null
  });
  return { app, root, clock, now: () => nowMs, advance: ms => { nowMs += ms; }, ownerId: options.ownerId || "owner-b134",
    journalProvider, retentionProvider };
}
async function runConformance(f) {
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, {
    reason: "Verify the recovery journal anchor provider and retain the result for later audit."
  });
  return f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
}
function signedSetup() {
  const pair = generateKeyPairSync("ed25519");
  return {
    publicKey: pair.publicKey,
    signer: async payload => ({ keyId: "retention-k1", signature: sign(null, Buffer.from(canonical(payload), "utf8"), pair.privateKey).toString("base64url") })
  };
}

test("Batch 134: retention checkpoint continuity receipt is Ed25519-signed, persisted, and verifies current anchor binding", async t => {
  const setup = signedSetup();
  const f = await fixture(t, { signer: setup.signer, keyId: "retention-k1", publicKeys: { "retention-k1": setup.publicKey }, requireSignedReceipt: true });
  const created = await f.app.createRecoverySloRetentionCheckpointContinuityReceipt(f.ownerId);
  assert.equal(created.status, "signed");
  assert.equal(created.signed, true);
  const verified = await f.app.verifyRecoverySloRetentionCheckpointContinuityReceipt(f.ownerId, created.receipt);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.current, true);
  assert.equal(verified.historicalCompletenessProven, true);
  const retained = await f.app.listRecoverySloRetainedAnchorEvidence(f.ownerId, { includePayload: true });
  assert.equal(retained.items.filter(item => item.artifactType === "retention_continuity_receipt").length, 1);
  assert.equal((await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "healthy");
});

test("Batch 134: a signed receipt remains historically valid after checkpoint advances but is no longer current", async t => {
  const setup = signedSetup();
  const f = await fixture(t, { signer: setup.signer, keyId: "retention-k1", publicKeys: { "retention-k1": setup.publicKey } });
  const { receipt } = await f.app.createRecoverySloRetentionCheckpointContinuityReceipt(f.ownerId);
  const plan = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 120, reason: "Extend prospective evidence retention after reviewing the signed checkpoint receipt."
  });
  const approval = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, plan.plan.id, {
    planDigest: plan.planDigest, confirmation: plan.confirmation,
    reason: "Approve the prospective retention extension after reviewing its impact."
  });
  await f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approval.approval.id, {
    expectedRevision: 1, targetRetentionDays: 120
  });
  const verified = await f.app.verifyRecoverySloRetentionCheckpointContinuityReceipt(f.ownerId, receipt);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.current, false);
  assert.equal(verified.status, "historical_or_stale");
});

test("Batch 134: receipt modification and owner substitution fail verification", async t => {
  const setup = signedSetup();
  const f = await fixture(t, { signer: setup.signer, keyId: "retention-k1", publicKeys: { "retention-k1": setup.publicKey } });
  const { receipt } = await f.app.createRecoverySloRetentionCheckpointContinuityReceipt(f.ownerId);
  const modified = structuredClone(receipt);
  modified.checkpoint.retentionDays = 7;
  assert.equal((await f.app.verifyRecoverySloRetentionCheckpointContinuityReceipt(f.ownerId, modified)).valid, false);
  assert.equal((await f.app.verifyRecoverySloRetentionCheckpointContinuityReceipt("another-owner", receipt)).valid, false);
});

test("Batch 134: receipt creation fails closed without a trusted signer or an anchored checkpoint", async t => {
  const f = await fixture(t);
  await assert.rejects(f.app.createRecoverySloRetentionCheckpointContinuityReceipt(f.ownerId), hasCode("RECOVERY_SLO_RETENTION_CONTINUITY_SIGNER_NOT_CONFIGURED"));
  const noAnchor = await fixture(t, { retentionProvider: null, requireRetentionAnchor: false });
  const setup = signedSetup();
  const app = createAgenticApplication({ storage: createStorage({ root: noAnchor.root }), clock: noAnchor.clock,
    recoverySloRetentionContinuitySigner: setup.signer, recoverySloRetentionContinuityKeyId: "retention-k1",
    recoverySloRetentionContinuityPublicKeys: { "retention-k1": setup.publicKey } });
  await assert.rejects(app.createRecoverySloRetentionCheckpointContinuityReceipt(noAnchor.ownerId), hasCode("RECOVERY_SLO_RETENTION_CONTINUITY_NOT_ESTABLISHED"));
});

test("Batch 134: completed recovery-journal conformance report is retained automatically and idempotently", async t => {
  const f = await fixture(t, { retentionDays: 1 });
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, {
    reason: "Verify the recovery journal anchor provider and retain the result for later audit."
  });
  const first = await f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(first.status, "conformant");
  assert.ok(first.retainedEvidence?.id);
  assert.equal(first.retainedEvidence.idempotent, false);
  const second = await f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(second.idempotent, true);
  assert.equal(second.retainedEvidence.id, first.retainedEvidence.id);
  assert.equal(second.retainedEvidence.idempotent, true);
  const listed = await f.app.listRecoverySloRetainedAnchorEvidence(f.ownerId, { includePayload: true });
  const conformance = listed.items.filter(item => item.artifactType === "provider_conformance");
  assert.equal(conformance.length, 1);
  assert.equal(conformance[0].payload.reportDigest, first.reportDigest);
  assert.equal((await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "healthy");
});

test("Batch 134: expired conformance evidence is pruned to a digest-preserving tombstone", async t => {
  const f = await fixture(t, { retentionDays: 1 });
  await runConformance(f);
  f.advance(86400_001);
  const before = await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId);
  assert.equal(before.expiredRetained, 1);
  const result = await f.app.pruneExpiredRecoverySloRetainedAnchorEvidence(f.ownerId, { limit: 10 });
  assert.equal(result.count, 1);
  const after = await f.app.listRecoverySloRetainedAnchorEvidence(f.ownerId, { includePayload: true });
  assert.equal(after.items[0].status, "tombstone");
  assert.equal(after.items[0].payload, null);
  assert.equal(after.items[0].tombstone.payloadDigest, after.items[0].payloadDigest);
  assert.equal((await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "healthy");
});

test("Batch 134: tampered retained conformance evidence fails audit and blocks pruning", async t => {
  const f = await fixture(t, { retentionDays: 1 });
  await runConformance(f);
  const listed = await f.app.listRecoverySloRetainedAnchorEvidence(f.ownerId, { includePayload: true });
  const record = listed.items[0];
  const full = await f.app.store.getEvidence(f.ownerId, record.id);
  await f.app.store.putEvidence(f.ownerId, { ...full, payload: { ...full.payload, conformanceStatus: "conformant-but-forged" } }, { expectedVersion: full._storage.version });
  assert.equal((await f.app.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "unhealthy");
  f.advance(86400_001);
  await assert.rejects(f.app.pruneExpiredRecoverySloRetainedAnchorEvidence(f.ownerId), hasCode("RECOVERY_SLO_ANCHOR_EVIDENCE_RETENTION_UNHEALTHY"));
});

test("Batch 134: cross-domain audit reports independent stable identities as healthy without exposing endpoint values", async t => {
  const f = await fixture(t, {
    attestationProvider: provider("https://attestation-anchor.example"),
    finalizationProvider: provider("https://finalization-anchor.example")
  });
  const report = await f.app.auditRecoverySloAnchorTrustDomainIndependence(f.ownerId);
  assert.equal(report.status, "healthy");
  assert.equal(report.domains.length, 4);
  assert.equal(report.collisions.length, 0);
  assert.equal(report.claims.independentBackingStoresCryptographicallyProven, false);
  assert.ok(report.domains.every(domain => domain.identityFingerprints.length > 0));
  assert.equal(JSON.stringify(report).includes("https://attestation-anchor.example"), false);
});

test("Batch 134: cross-domain audit detects a shared backend identity even across distinct provider objects", async t => {
  const f = await fixture(t, {
    attestationProvider: provider("https://shared-anchor.example"),
    finalizationProvider: provider("https://shared-anchor.example")
  });
  const report = await f.app.auditRecoverySloAnchorTrustDomainIndependence(f.ownerId);
  assert.equal(report.status, "unhealthy");
  assert.ok(report.findings.some(item => item.code === "CROSS_DOMAIN_ANCHOR_INDEPENDENCE_VIOLATION"
    && item.domains.includes("attestation") && item.domains.includes("finalization_key_policy")));
});

test("Batch 134: cross-domain audit degrades when a configured provider exposes no stable identity", async t => {
  const opaque = { async read() { return null; }, async compareAndSet() { return { applied: true, anchor: null }; } };
  const f = await fixture(t, { attestationProvider: opaque, finalizationProvider: provider("https://finalization-anchor.example") });
  const report = await f.app.auditRecoverySloAnchorTrustDomainIndependence(f.ownerId);
  assert.equal(report.status, "degraded");
  assert.ok(report.unverifiableDomains.includes("attestation"));
});

test("Batch 134: strict signed receipt configuration requires signer and trusted key registry", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b134-strict-config-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloRetentionSignedContinuityReceipt: true }),
    /Signed retention continuity receipt diwajibkan/);
});

test("Batch 134: application APIs and HTTP routes expose receipts, retained evidence, pruning, and independence audit", async t => {
  const f = await fixture(t);
  for (const name of ["createRecoverySloRetentionCheckpointContinuityReceipt", "verifyRecoverySloRetentionCheckpointContinuityReceipt",
    "listRecoverySloRetainedAnchorEvidence", "auditRecoverySloRetainedAnchorEvidence", "pruneExpiredRecoverySloRetainedAnchorEvidence",
    "auditRecoverySloAnchorTrustDomainIndependence"]) assert.equal(typeof f.app[name], "function", `${name} must be exposed`);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["recovery-evidence-retention/continuity-receipts", "recovery-evidence-retention/continuity-receipts/verify",
    "recovery-evidence-retention/retained-anchor-evidence", "recovery-evidence-retention/retained-anchor-evidence/audit",
    "recovery-evidence-retention/retained-anchor-evidence/prune", "anchor/trust-domain-independence"]) {
    assert.ok(source.includes(route), `missing route ${route}`);
  }
});
