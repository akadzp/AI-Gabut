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
function keyPair(keyId) { const pair = generateKeyPairSync("ed25519"); return { keyId, publicKey: pair.publicKey, privateKey: pair.privateKey }; }
function signPayload(key, payload) { return sign(null, Buffer.from(canonical(payload), "utf8"), key.privateKey).toString("base64url"); }
function provider(identity, { rejectCas = false } = {}) {
  const records = new Map();
  return { providerIdentity: identity, records,
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if (rejectCas) return { applied: false, anchor: structuredClone(current) };
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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b144-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRootRecoveryTrustAnchor: options.rootAnchor || null,
    recoverySloProviderIdentityTrustPolicyAnchor: options.trustPolicyAnchor || null,
    recoverySloRetainedEvidenceAnchor: options.retainedEvidenceAnchor || null,
    recoverySloRetentionDecisionGateAnchor: options.decisionGateAnchor || null,
    recoverySloRetentionReconciliationSigner: options.reconciliationSigner || null,
    recoverySloRetentionReconciliationKeyId: options.reconciliationKeyId || null,
    recoverySloRetentionReconciliationPublicKeys: options.reconciliationPublicKeys || null,
    recoverySloRootTrustConformanceBaselineSigner: options.baselineSigner || null,
    recoverySloRootTrustConformanceBaselineKeyId: options.baselineKeyId || null,
    recoverySloRootTrustConformanceBaselinePublicKeys: options.baselinePublicKeys || null,
    recoverySloDriftChainCheckpointSigner: options.checkpointSigner || null,
    recoverySloDriftChainCheckpointKeyId: options.checkpointKeyId || null,
    recoverySloDriftChainCheckpointPublicKeys: options.checkpointPublicKeys || null,
    recoverySloRetentionReconciliationAttestationMaxAgeMs: options.reconciliationMaxAgeMs || 86400000,
    recoverySloRetentionReconciliationAttestationFutureSkewMs: options.reconciliationFutureSkewMs ?? 60000,
    recoverySloDriftChainCheckpointMaxAgeMs: options.checkpointMaxAgeMs ?? 86400000,
    recoverySloDriftChainCheckpointFutureSkewMs: options.checkpointFutureSkewMs ?? 60000 });
  return { app, root, ownerId: options.ownerId || "owner-b144", now: clock, advance: (ms = 1000) => { nowMs += ms; } };
}
async function runRootConformance(app, ownerId) {
  const challenge = await app.prepareRecoverySloRootRecoveryTrustAnchorConformance(ownerId, {
    reason: "Validate root-trust provider contract before accepting a baseline rotation." });
  const result = await app.runRecoverySloRootRecoveryTrustAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  return { challenge, result };
}
async function runTrustPolicyConformance(app, ownerId) {
  const challenge = await app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, {
    reason: "Validate trust-policy provider contract before checkpoint freshness monitoring." });
  const result = await app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  return { challenge, result };
}
async function createReconciliationAttestation(f, signing) {
  return f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Create a signed reconciliation snapshot for decision-gate external anchoring tests." });
}

test("Batch 144: decision-gate allow and deny evidence are appended to an independent external anchor", async t => {
  const decisionAnchor = provider("https://decision-gate-anchor-144.example");
  const signing = keyPair("decision-gate-144");
  const f = await fixture(t, { decisionGateAnchor: decisionAnchor, reconciliationSigner: async payload => signPayload(signing, payload),
    reconciliationKeyId: signing.keyId, reconciliationPublicKeys: { [signing.keyId]: signing.publicKey } });
  const issued = await createReconciliationAttestation(f, signing);
  const allowed = await f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, {
    decision: "apply-retention-change", expectedAuditDigest: issued.attestation.snapshot.auditDigest });
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.externalAnchor.status, "anchored");
  assert.equal(allowed.externalAnchor.anchorSequence, 1);
  const tampered = { ...issued.attestation, attestationDigest: "f".repeat(64) };
  await assert.rejects(f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, tampered, { decision: "deny-tampered-snapshot" }),
    hasCode("RETENTION_RECONCILIATION_ATTESTATION_NOT_USABLE_FOR_DECISION"));
  const state = await f.app.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId);
  assert.equal(state.status, "anchored");
  assert.equal(state.anchorSequence, 2);
  assert.equal(state.historyNotProven, false);
  assert.equal((await f.app.auditRecoverySloRetentionReconciliationDecisionGateEvidence(f.ownerId)).status, "healthy");
});

test("Batch 144: a configured decision-gate anchor CAS failure prevents an allow result", async t => {
  const decisionAnchor = provider("https://decision-gate-anchor-cas-fail-144.example", { rejectCas: true });
  const signing = keyPair("decision-gate-cas-fail-144");
  const f = await fixture(t, { decisionGateAnchor: decisionAnchor, reconciliationSigner: async payload => signPayload(signing, payload),
    reconciliationKeyId: signing.keyId, reconciliationPublicKeys: { [signing.keyId]: signing.publicKey } });
  const issued = await createReconciliationAttestation(f, signing);
  await assert.rejects(f.app.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, {
    decision: "must-not-allow-without-external-anchor", expectedAuditDigest: issued.attestation.snapshot.auditDigest
  }), hasCode("RETENTION_DECISION_GATE_EXTERNAL_ANCHOR_FAILED"));
  assert.equal((await f.app.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId)).status, "enrollment_required");
  const decisionAudit = await f.app.auditRecoverySloRetentionReconciliationDecisionGateEvidence(f.ownerId);
  assert.equal(decisionAudit.allowed, 0);
  assert.equal(decisionAudit.denied, 1);
  assert.equal(decisionAudit.superseded, 1);
  assert.equal((await f.app.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId)).findings.length, 0);
});

test("Batch 144: legacy decision-gate history requires explicit enrollment and remains marked unproven", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b144-enroll-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString(), storage = createStorage({ root });
  const signing = keyPair("decision-gate-enroll-144");
  const first = createAgenticApplication({ storage, clock, recoverySloRetentionReconciliationSigner: async payload => signPayload(signing, payload),
    recoverySloRetentionReconciliationKeyId: signing.keyId, recoverySloRetentionReconciliationPublicKeys: { [signing.keyId]: signing.publicKey } });
  const f = { app: first, ownerId: "owner-b144-legacy" };
  const issued = await first.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, { reason: "Create a retained audit snapshot before external anchoring is enabled." });
  await first.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId, issued.attestation, { decision: "legacy-allow" });
  await assert.rejects(first.evaluateRecoverySloRetentionReconciliationDecisionWithAudit(f.ownerId,
    { ...issued.attestation, attestationDigest: "e".repeat(64) }, { decision: "legacy-deny" }), hasCode("RETENTION_RECONCILIATION_ATTESTATION_NOT_USABLE_FOR_DECISION"));
  const decisionAnchor = provider("https://decision-gate-anchor-legacy-144.example");
  const second = createAgenticApplication({ storage, clock, recoverySloRetentionDecisionGateAnchor: decisionAnchor,
    recoverySloRetentionReconciliationSigner: async payload => signPayload(signing, payload),
    recoverySloRetentionReconciliationKeyId: signing.keyId, recoverySloRetentionReconciliationPublicKeys: { [signing.keyId]: signing.publicKey } });
  assert.equal((await second.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId)).status, "enrollment_required");
  const challenge = await second.prepareRecoverySloRetentionDecisionGateAnchorEnrollment(f.ownerId, {
    reason: "Explicitly enroll existing decision-gate audit records without claiming pre-enrollment proof." });
  const enrolled = await second.applyRecoverySloRetentionDecisionGateAnchorEnrollment(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(enrolled.status, "enrolled");
  assert.equal(enrolled.historyNotProven, true);
  const status = await second.getRecoverySloRetentionDecisionGateAnchorStatus(f.ownerId);
  assert.equal(status.status, "anchored");
  assert.equal(status.historyNotProven, true);
});

test("Batch 144: root-trust baseline enrollment, rotation, and revalidation preserve a digest-linked lifecycle", async t => {
  const rootAnchor = provider("https://root-baseline-lifecycle-144.example"), signing = keyPair("root-baseline-lifecycle-144");
  const f = await fixture(t, { rootAnchor, baselineSigner: async payload => signPayload(signing, payload), baselineKeyId: signing.keyId,
    baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  const firstSource = await runRootConformance(f.app, f.ownerId);
  const enrollment = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, {
    challengeId: firstSource.challenge.challengeId, reason: "Enroll the first signed root-trust conformance baseline through the explicit lifecycle." });
  const first = await f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal(first.status, "enrolled");
  assert.equal(first.revision, 1);
  assert.equal((await f.app.getRecoverySloRootTrustConformanceCurrentBaseline(f.ownerId)).status, "current");
  assert.equal((await f.app.revalidateRecoverySloRootTrustConformanceCurrentBaseline(f.ownerId)).revalidated, true);
  const secondSource = await runRootConformance(f.app, f.ownerId);
  const rotation = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, {
    challengeId: secondSource.challenge.challengeId, reason: "Rotate the baseline after a fresh successful provider conformance report." });
  const second = await f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, rotation.challengeId, { confirmation: rotation.confirmation });
  assert.equal(second.status, "rotated");
  assert.equal(second.revision, 2);
  assert.equal(second.previousBaselineDigest, first.currentBaselineDigest);
  const superseded = await f.app.verifyRecoverySloRootTrustConformanceBaselineAttestation(f.ownerId, first.attestation);
  assert.equal(superseded.historicallyValid, true);
  assert.equal(superseded.usableAsCurrentBaseline, false);
  assert.equal(superseded.selectedAsCurrentBaseline, false);
  assert.equal((await f.app.auditRecoverySloRootTrustConformanceBaselineLifecycle(f.ownerId)).status, "healthy");
  assert.equal((await f.app.revalidateRecoverySloRootTrustConformanceCurrentBaseline(f.ownerId)).status, "current");
});

test("Batch 144: baseline rotation rejects provider drift and stale competing challenges", async t => {
  const rootAnchor = provider("https://root-baseline-drift-144.example"), signing = keyPair("root-baseline-drift-144");
  const f = await fixture(t, { rootAnchor, baselineSigner: async payload => signPayload(signing, payload), baselineKeyId: signing.keyId,
    baselinePublicKeys: { [signing.keyId]: signing.publicKey } });
  const firstSource = await runRootConformance(f.app, f.ownerId);
  const enroll = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: firstSource.challenge.challengeId,
    reason: "Enroll the first baseline before testing stale baseline rotation challenges." });
  await f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, enroll.challengeId, { confirmation: enroll.confirmation });
  const source = await runRootConformance(f.app, f.ownerId);
  const challengeA = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: source.challenge.challengeId,
    reason: "Prepare the first competing baseline rotation challenge for optimistic concurrency." });
  const challengeB = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: source.challenge.challengeId,
    reason: "Prepare the second competing baseline rotation challenge for optimistic concurrency." });
  await f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, challengeA.challengeId, { confirmation: challengeA.confirmation });
  await assert.rejects(f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, challengeB.challengeId, { confirmation: challengeB.confirmation }),
    hasCode("ROOT_TRUST_BASELINE_ROTATION_STALE"));
  const thirdSource = await runRootConformance(f.app, f.ownerId);
  const challenge = await f.app.prepareRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, { challengeId: thirdSource.challenge.challengeId,
    reason: "Prepare a rotation whose provider identity must remain unchanged until application." });
  rootAnchor.providerIdentity = "https://root-baseline-drift-rotated-144.example";
  await assert.rejects(f.app.applyRecoverySloRootTrustConformanceBaselineRotation(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation }),
    hasCode("RECOVERY_SLO_ROOT_TRUST_BASELINE_PROVIDER_CHANGED"));
  assert.equal((await f.app.auditRecoverySloRootTrustConformanceBaselineLifecycle(f.ownerId)).status, "healthy");
  assert.equal((await f.app.getRecoverySloRootTrustConformanceCurrentBaseline(f.ownerId)).status, "revalidation_required");
});

test("Batch 144: drift checkpoint freshness separates historical validity from current-decision usability", async t => {
  const trustPolicyAnchor = provider("https://trust-policy-freshness-144.example"), retainedEvidenceAnchor = provider("https://retained-chain-freshness-144.example");
  const signing = keyPair("drift-checkpoint-freshness-144");
  const f = await fixture(t, { trustPolicyAnchor, retainedEvidenceAnchor, checkpointSigner: async payload => signPayload(signing, payload),
    checkpointKeyId: signing.keyId, checkpointPublicKeys: { [signing.keyId]: signing.publicKey }, checkpointMaxAgeMs: 60000, checkpointFutureSkewMs: 1000 });
  const conformance = await runTrustPolicyConformance(f.app, f.ownerId);
  assert.equal(conformance.result.status, "conformant");
  const baseline = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, { challengeId: conformance.challenge.challengeId,
    reason: "Enroll a conformant provider baseline before issuing a fresh checkpoint receipt." });
  await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, baseline.challengeId, { confirmation: baseline.confirmation });
  const issued = await f.app.createRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, {
    reason: "Create a short-lived signed checkpoint to test freshness enforcement at decision boundaries." });
  const fresh = await f.app.requireFreshRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, issued.receipt);
  assert.equal(fresh.allowed, true);
  f.advance(61000);
  const historical = await f.app.verifyRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, issued.receipt);
  assert.equal(historical.historicallyValid, true);
  assert.equal(historical.fresh, false);
  assert.equal(historical.freshnessStatus, "stale");
  await assert.rejects(f.app.requireFreshRecoverySloProviderConformanceDriftChainCheckpointReceipt(f.ownerId, issued.receipt),
    hasCode("DRIFT_CHECKPOINT_RECEIPT_NOT_USABLE_FOR_CURRENT_DECISION"));
  const audit = await f.app.auditRecoverySloProviderConformanceDriftChainCheckpointContinuity(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.freshness.status, "stale");
  assert.equal(audit.freshness.usableForCurrentDecision, false);
});

test("Batch 144: application exports and HTTP routes expose anchor, lifecycle, and freshness APIs", async t => {
  const f = await fixture(t);
  for (const name of ["getRecoverySloRetentionDecisionGateAnchorStatus", "anchorPendingRecoverySloRetentionDecisionGateEvidence",
    "prepareRecoverySloRetentionDecisionGateAnchorEnrollment", "applyRecoverySloRetentionDecisionGateAnchorEnrollment",
    "reconcileRecoverySloRetentionDecisionGateAnchor", "prepareRecoverySloRootTrustConformanceBaselineRotation",
    "applyRecoverySloRootTrustConformanceBaselineRotation", "getRecoverySloRootTrustConformanceCurrentBaseline",
    "revalidateRecoverySloRootTrustConformanceCurrentBaseline", "auditRecoverySloRootTrustConformanceBaselineLifecycle",
    "requireFreshRecoverySloProviderConformanceDriftChainCheckpointReceipt"]) assert.equal(typeof f.app[name], "function", `${name} should exist`);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /retention-reconciliation\/decision-gate\/anchor\/status/);
  assert.match(server, /root-trust\/conformance\/baseline-rotation\/challenges/);
  assert.match(server, /checkpoint-receipts\/require-fresh/);
});
