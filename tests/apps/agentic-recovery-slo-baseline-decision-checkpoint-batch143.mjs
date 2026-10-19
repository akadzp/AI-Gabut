import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const hasCode = code => error => error?.code === code;
function keyPair(keyId) { const pair = generateKeyPairSync("ed25519"); return { keyId, publicKey: pair.publicKey, privateKey: pair.privateKey }; }
function signPayload(key, payload) { return sign(null, Buffer.from(canonical(payload), "utf8"), key.privateKey).toString("base64url"); }
function provider(identity) {
  const records = new Map();
  return { providerIdentity: identity, records,
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId) throw Object.assign(new Error("owner mismatch"), { code: "OWNER_SCOPE_MISMATCH" });
      if (candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || !Number.isSafeInteger(candidate.revision) || candidate.revision <= (current?.revision ?? 0)
        || candidate.previousAnchorDigest !== (current?.digest ?? null)) throw Object.assign(new Error("sequence mismatch"), { code: "NON_MONOTONIC_ANCHOR" });
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b143-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRootRecoveryTrustAnchor: options.rootAnchor || null,
    recoverySloProviderIdentityTrustPolicyAnchor: options.trustPolicyAnchor || null,
    recoverySloRetainedEvidenceAnchor: options.retainedEvidenceAnchor || null,
    recoverySloRetentionReconciliationSigner: options.reconciliationSigner || null,
    recoverySloRetentionReconciliationKeyId: options.reconciliationKeyId || null,
    recoverySloRetentionReconciliationPublicKeys: options.reconciliationPublicKeys || null,
    recoverySloRootTrustConformanceBaselineSigner: options.baselineSigner || null,
    recoverySloRootTrustConformanceBaselineKeyId: options.baselineKeyId || null,
    recoverySloRootTrustConformanceBaselinePublicKeys: options.baselinePublicKeys || null,
    recoverySloDriftChainCheckpointSigner: options.checkpointSigner || null,
    recoverySloDriftChainCheckpointKeyId: options.checkpointKeyId || null,
    recoverySloDriftChainCheckpointPublicKeys: options.checkpointPublicKeys || null,
    recoverySloRetentionReconciliationAttestationMaxAgeMs: options.maxAgeMs || 86400000,
    recoverySloRetentionReconciliationAttestationFutureSkewMs: options.futureSkewMs ?? 60000 });
  return { app, root, ownerId: options.ownerId || "owner-b143", now: clock, advance: (ms = 1000) => { nowMs += ms; } };
}
async function runRootConformance(app, ownerId) {
  const challenge = await app.prepareRecoverySloRootRecoveryTrustAnchorConformance(ownerId, {
    reason: "Validate root-trust provider contract before accepting its identity as a baseline."
  });
  const result = await app.runRecoverySloRootRecoveryTrustAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  return { challenge, result };
}
async function runTrustPolicyConformance(app, ownerId) {
  const challenge = await app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, {
    reason: "Validate trust-policy provider contract before establishing the drift watch baseline."
  });
  const result = await app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  return { challenge, result };
}

 test("Batch 143: root-trust conformance baseline attestation is signed, retained, and current-provider bound", async t => {
  const anchor = provider("https://root-baseline-143.example"), signing = keyPair("root-baseline-143");
  const f = await fixture(t, { rootAnchor: anchor, baselineSigner: async payload => signPayload(signing, payload),
    baselineKeyId: signing.keyId, baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  const { challenge, result } = await runRootConformance(f.app, f.ownerId);
  assert.equal(result.status, "conformant");
  const issued = await f.app.attestRecoverySloRootTrustConformanceBaseline(f.ownerId, { challengeId: challenge.challengeId,
    reason: "Accept this verified provider conformance report as the current root-trust baseline." });
  assert.equal(issued.status, "signed");
  const verified = await f.app.verifyRecoverySloRootTrustConformanceBaselineAttestation(f.ownerId, issued.attestation);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.usableAsCurrentBaseline, true);
  anchor.providerIdentity = "https://root-baseline-143-rotated.example";
  const drifted = await f.app.verifyRecoverySloRootTrustConformanceBaselineAttestation(f.ownerId, issued.attestation);
  assert.equal(drifted.historicallyValid, true);
  assert.equal(drifted.usableAsCurrentBaseline, false);
  assert.equal((await f.app.recoverySloAnchorIndependenceEvidenceService.auditRecoverySloRetainedAnchorEvidence(f.ownerId)).status, "healthy");
  assert.equal((await f.app.auditRecoverySloRootTrustConformanceBaselineAttestations(f.ownerId)).status, "healthy");
});

test("Batch 143: baseline attestation refuses a provider changed after conformance", async t => {
  const anchor = provider("https://root-baseline-stale-143.example"), signing = keyPair("root-baseline-stale-143");
  const f = await fixture(t, { rootAnchor: anchor, baselineSigner: async payload => signPayload(signing, payload),
    baselineKeyId: signing.keyId, baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  const { challenge } = await runRootConformance(f.app, f.ownerId);
  anchor.providerIdentity = "https://root-baseline-changed-143.example";
  await assert.rejects(f.app.attestRecoverySloRootTrustConformanceBaseline(f.ownerId, { challengeId: challenge.challengeId,
    reason: "Reject stale conformance after the provider identity changes before baseline signing." }), hasCode("RECOVERY_SLO_ROOT_TRUST_BASELINE_PROVIDER_CHANGED"));
});

test("Batch 143: decision gate records both allow and deny outcomes without storing the attestation payload", async t => {
  const signing = keyPair("decision-gate-143");
  const f = await fixture(t, { reconciliationSigner: async payload => signPayload(signing, payload), reconciliationKeyId: signing.keyId,
    reconciliationPublicKeys: { [signing.keyId]: signing.publicKey }, maxAgeMs: 60000, futureSkewMs: 1000 });
  const issued = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Create a short-lived audit snapshot for the decision-gate audit trail test."
  });
  const allowed = await f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, {
    decision: "apply-retention-change", expectedAuditDigest: issued.attestation.snapshot.auditDigest
  });
  assert.equal(allowed.allowed, true);
  assert.ok(allowed.auditEvidence.decisionId);
  const tampered = { ...issued.attestation, attestationDigest: "f".repeat(64) };
  await assert.rejects(f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, tampered, { decision: "apply-retention-change" }),
    hasCode("RETENTION_RECONCILIATION_ATTESTATION_NOT_USABLE_FOR_DECISION"));
  const listed = await f.app.listRecoverySloRetentionReconciliationDecisionGateEvidence(f.ownerId, { limit: 20 });
  assert.equal(listed.count, 2);
  assert.ok(listed.items.every(item => !Object.hasOwn(item.payload, "signature")));
  const audit = await f.app.auditRecoverySloRetentionReconciliationDecisionGateEvidence(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.allowed, 1);
  assert.equal(audit.denied, 1);
});

test("Batch 143: decision-gate evidence tampering is detected by retained-evidence audit", async t => {
  const signing = keyPair("decision-gate-tamper-143");
  const f = await fixture(t, { reconciliationSigner: async payload => signPayload(signing, payload), reconciliationKeyId: signing.keyId,
    reconciliationPublicKeys: { [signing.keyId]: signing.publicKey } });
  const issued = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Create evidence before modifying a decision-gate audit record in storage."
  });
  await f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, { decision: "verify-retention" });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const records = await store.listEvidence(f.ownerId);
  const record = records.find(item => item.artifactType === "retention_reconciliation_decision_gate_audit" && item.status === "retained");
  assert.ok(record);
  await store.putEvidence(f.ownerId, { ...record, payload: { ...record.payload, decision: "tampered-decision" } }, { expectedVersion: record._storage?.version });
  assert.equal((await f.app.auditRecoverySloRetentionReconciliationDecisionGateEvidence(f.ownerId)).status, "unhealthy");
});

test("Batch 143: drift-chain checkpoint receipts link checkpoints by digest and verify their signatures", async t => {
  const trustProvider = provider("https://trust-policy-checkpoint-143.example"), evidenceProvider = provider("https://retained-chain-checkpoint-143.example");
  const signing = keyPair("drift-checkpoint-143");
  const f = await fixture(t, { trustPolicyAnchor: trustProvider, retainedEvidenceAnchor: evidenceProvider,
    checkpointSigner: async payload => signPayload(signing, payload), checkpointKeyId: signing.keyId,
    checkpointPublicKeys: { [signing.keyId]: signing.publicKey } });
  const conformance = await runTrustPolicyConformance(f.app, f.ownerId);
  assert.equal(conformance.result.status, "conformant");
  const baseline = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, { challengeId: conformance.challenge.challengeId,
    reason: "Enroll the provider baseline so checkpoint continuity is tied to a healthy drift audit." });
  await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, baseline.challengeId, { confirmation: baseline.confirmation });
  const first = await f.app.createRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, {
    reason: "Record the current retained-evidence chain head as a signed continuity checkpoint."
  });
  assert.equal(first.status, "issued");
  const firstVerified = await f.app.verifyRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, first.receipt);
  assert.equal(firstVerified.valid, true);
  const second = await f.app.createRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, {
    reason: "Record the next chain head and link it to the previous signed checkpoint receipt."
  });
  assert.equal(second.receipt.previousReceiptDigest, first.receipt.receiptDigest);
  assert.ok(second.receipt.checkpoint.sequence > first.receipt.checkpoint.sequence);
  assert.equal((await f.app.auditRecoverySloProviderConformanceDriftChainCheckpointContinuity(f.ownerId)).status, "healthy");
});

test("Batch 143: checkpoint continuity refuses a receipt whose prior receipt was tampered", async t => {
  const trustProvider = provider("https://trust-policy-checkpoint-tamper-143.example"), evidenceProvider = provider("https://retained-chain-checkpoint-tamper-143.example");
  const signing = keyPair("drift-checkpoint-tamper-143");
  const f = await fixture(t, { trustPolicyAnchor: trustProvider, retainedEvidenceAnchor: evidenceProvider,
    checkpointSigner: async payload => signPayload(signing, payload), checkpointKeyId: signing.keyId,
    checkpointPublicKeys: { [signing.keyId]: signing.publicKey } });
  const conformance = await runTrustPolicyConformance(f.app, f.ownerId);
  const baseline = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, { challengeId: conformance.challenge.challengeId,
    reason: "Enroll the provider baseline before exercising checkpoint tamper detection." });
  await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, baseline.challengeId, { confirmation: baseline.confirmation });
  const receipt = await f.app.createRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, {
    reason: "Create a signed chain checkpoint before testing retained receipt tampering."
  });
  const store = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const records = await store.listEvidence(f.ownerId);
  const record = records.find(item => item.artifactType === "provider_conformance_drift_chain_checkpoint_receipt" && item.status === "retained");
  assert.ok(record);
  await store.putEvidence(f.ownerId, { ...record, payload: { ...record.payload, reason: "tampered checkpoint reason" } }, { expectedVersion: record._storage?.version });
  assert.equal((await f.app.auditRecoverySloProviderConformanceDriftChainCheckpointContinuity(f.ownerId)).status, "unhealthy");
  const verification = await f.app.verifyRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, receipt.receipt);
  assert.equal(verification.valid, false);
});

test("Batch 143: new application APIs and HTTP routes expose baseline, decision audit, and checkpoint continuity", async t => {
  const f = await fixture(t);
  for (const name of ["attestRecoverySloRootTrustConformanceBaseline", "verifyRecoverySloRootTrustConformanceBaselineAttestation",
    "auditRecoverySloRootTrustConformanceBaselineAttestations", "evaluateRecoverySloRetentionReconciliationDecisionWithAudit",
    "listRecoverySloRetentionReconciliationDecisionGateEvidence", "auditRecoverySloRetentionReconciliationDecisionGateEvidence",
    "createRecoverySloProviderConformanceDriftChainCheckpointReceipt", "verifyRecoverySloProviderConformanceDriftChainCheckpointReceipt",
    "auditRecoverySloProviderConformanceDriftChainCheckpointContinuity"]) assert.equal(typeof f.app[name], "function", `${name} should exist`);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /root-recovery-trust\/anchor\/conformance\/baseline-attestations/);
  assert.match(server, /retention-reconciliation\/attestations\/decision-check\/audited/);
  assert.match(server, /provider-conformance-drift\/retention-chain\/checkpoint-receipts/);
});
