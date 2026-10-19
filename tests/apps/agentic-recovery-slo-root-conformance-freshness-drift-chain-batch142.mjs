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
function keyPair(keyId) {
  const pair = generateKeyPairSync("ed25519");
  return { keyId, publicKey: pair.publicKey, privateKey: pair.privateKey };
}
function signPayload(key, payload) { return sign(null, Buffer.from(canonical(payload), "utf8"), key.privateKey).toString("base64url"); }
function provider(identity, { failNext = false } = {}) {
  const records = new Map(), state = { failNext };
  return { providerIdentity: identity, state, records,
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
      ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (state.failNext) { state.failNext = false; throw Object.assign(new Error("injected anchor outage"), { code: "INJECTED_ANCHOR_OUTAGE" }); }
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId) throw Object.assign(new Error("owner scope mismatch"), { code: "OWNER_SCOPE_MISMATCH" });
      if (candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || !Number.isSafeInteger(candidate.revision) || candidate.revision <= (current?.revision ?? 0)
        || candidate.previousAnchorDigest !== (current?.digest ?? null)) throw Object.assign(new Error("non-monotonic anchor"), { code: "NON_MONOTONIC_ANCHOR" });
      records.set(ownerId, structuredClone(candidate)); return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b142-"));
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
    recoverySloRetentionReconciliationAttestationMaxAgeMs: options.maxAgeMs || 86400000,
    recoverySloRetentionReconciliationAttestationFutureSkewMs: options.futureSkewMs ?? 60000,
    recoverySloProviderConformanceDriftRetentionDays: options.driftRetentionDays || 90 });
  return { app, root, ownerId: options.ownerId || "owner-b142", now: clock, advance: (ms = 1000) => { nowMs += ms; } };
}
async function runTrustPolicyConformance(app, ownerId, reason = "Validate provider contract behavior before establishing a baseline.") {
  const challenge = await app.prepareRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, { reason });
  const result = await app.runRecoverySloProviderIdentityTrustPolicyAnchorConformance(ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  return { challenge, result };
}

 test("Batch 142: root-recovery trust anchor conformance validates CAS semantics and retains a digest-bound report", async t => {
  const anchor = provider("https://root-conformance-142.example");
  const f = await fixture(t, { rootAnchor: anchor });
  const challenge = await f.app.prepareRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, {
    reason: "Validate the root-trust anchor CAS contract before relying on its checkpoint semantics."
  });
  assert.equal(challenge.writesToProductionNamespace, false);
  await assert.rejects(f.app.runRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: "wrong" }),
    hasCode("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_CONFIRMATION_INVALID"));
  const result = await f.app.runRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "conformant");
  assert.equal(result.report.providerDomain, "root_recovery_trust");
  assert.equal(result.report.writesToProductionNamespace, false);
  assert.ok(result.report.checks.some(item => item.name === "stale_cas_no_mutation" && item.passed));
  assert.ok([...anchor.records.keys()].every(scope => scope.startsWith("__agentic_v4_root_recovery_trust_anchor_conformance__")));
  assert.equal((await f.app.auditRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId)).status, "healthy");
  assert.equal((await f.app.runRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation })).idempotent, true);
});

test("Batch 142: a provider that mutates on stale CAS is reported nonconformant", async t => {
  const anchor = provider("https://root-conformance-stale-142.example");
  const compare = anchor.compareAndSet.bind(anchor);
  anchor.compareAndSet = async (ownerId, expectedDigest, candidate) => {
    const current = anchor.records.get(ownerId) ?? null;
    if (expectedDigest === null && current) {
      anchor.records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
    return compare(ownerId, expectedDigest, candidate);
  };
  const f = await fixture(t, { rootAnchor: anchor });
  const challenge = await f.app.prepareRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, {
    reason: "Exercise a deliberately broken stale compare-and-set implementation in isolation."
  });
  const result = await f.app.runRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(result.status, "nonconformant");
  assert.ok(result.report.findings.some(item => item.code.includes("STALE_CAS_NO_MUTATION")));
  assert.equal(result.report.writesToProductionNamespace, false);
});

test("Batch 142: freshness decision gate allows fresh attestations and blocks stale or mismatched snapshots", async t => {
  const signing = keyPair("retention-reconcile-142-decision");
  const f = await fixture(t, { reconciliationSigner: async payload => signPayload(signing, payload),
    reconciliationKeyId: signing.keyId, reconciliationPublicKeys: { [signing.keyId]: signing.publicKey }, maxAgeMs: 60000, futureSkewMs: 1000 });
  const issued = await f.app.attestRecoverySloRetentionEvidenceReconciliation(f.ownerId, {
    reason: "Create a short-lived reconciliation attestation for a decision-boundary freshness test."
  });
  const allowed = await f.app.requireRecoverySloRetentionReconciliationAttestationForDecision(f.ownerId, issued.attestation, {
    decision: "apply-retention-change", expectedAuditDigest: issued.attestation.snapshot.auditDigest
  });
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.verification.usableForCurrentDecision, true);
  await assert.rejects(f.app.requireRecoverySloRetentionReconciliationAttestationForDecision(f.ownerId, issued.attestation, {
    decision: "apply-retention-change", expectedAuditDigest: "a".repeat(64)
  }), hasCode("RETENTION_RECONCILIATION_ATTESTATION_NOT_USABLE_FOR_DECISION"));
  f.advance(61000);
  await assert.rejects(f.app.requireRecoverySloRetentionReconciliationAttestationForDecision(f.ownerId, issued.attestation, {
    decision: "apply-retention-change"
  }), hasCode("RETENTION_RECONCILIATION_ATTESTATION_NOT_USABLE_FOR_DECISION"));
});

test("Batch 142: drift-retention chain reconciliation safely advances a provably behind external anchor", async t => {
  const trustProvider = provider("https://trust-policy-drift-142.example");
  const evidenceProvider = provider("https://retained-evidence-chain-142.example");
  const f = await fixture(t, { trustPolicyAnchor: trustProvider, retainedEvidenceAnchor: evidenceProvider, driftRetentionDays: 90 });
  const conformance = await runTrustPolicyConformance(f.app, f.ownerId);
  assert.equal(conformance.result.status, "conformant");
  const baseline = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, {
    challengeId: conformance.challenge.challengeId, reason: "Enroll a conformant provider baseline before exercising chain recovery."
  });
  await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, baseline.challengeId, { confirmation: baseline.confirmation });
  trustProvider.providerIdentity = "https://trust-policy-drift-changed-142.example";
  evidenceProvider.state.failNext = true;
  await assert.rejects(f.app.captureRecoverySloProviderConformanceDriftEvent(f.ownerId, {
    reason: "Preserve the drift observation even if external chain anchoring fails once."
  }));
  const before = await f.app.auditRecoverySloRetainedEvidenceChain(f.ownerId);
  assert.equal(before.status, "degraded");
  const reconciled = await f.app.reconcileRecoverySloProviderConformanceDriftRetentionChain(f.ownerId);
  assert.equal(reconciled.status, "reconciled");
  assert.equal(reconciled.chainAfter.status, "healthy");
  assert.equal(reconciled.driftAuditAfter.status, "healthy");
  assert.equal((await f.app.auditRecoverySloProviderConformanceDriftRetentionChain(f.ownerId)).status, "healthy");
});

test("Batch 142: drift-retention reconciliation refuses tampered retained records", async t => {
  const trustProvider = provider("https://trust-policy-drift-tamper-142.example");
  const evidenceProvider = provider("https://retained-evidence-chain-tamper-142.example");
  const f = await fixture(t, { trustPolicyAnchor: trustProvider, retainedEvidenceAnchor: evidenceProvider });
  const conformance = await runTrustPolicyConformance(f.app, f.ownerId);
  const baseline = await f.app.prepareRecoverySloProviderConformanceDriftBaseline(f.ownerId, {
    challengeId: conformance.challenge.challengeId, reason: "Enroll a conformant provider baseline before tamper testing."
  });
  await f.app.applyRecoverySloProviderConformanceDriftBaseline(f.ownerId, baseline.challengeId, { confirmation: baseline.confirmation });
  trustProvider.providerIdentity = "https://trust-policy-drift-tampered-142.example";
  await f.app.captureRecoverySloProviderConformanceDriftEvent(f.ownerId, { reason: "Retain the provider drift for tamper-rejection validation." });
  const evidenceStore = createAgenticStore({ storage: createStorage({ root: f.root }) });
  const records = await evidenceStore.listEvidence(f.ownerId);
  const eventRecord = records.find(item => item.artifactType === "provider_conformance_drift_event" && item.status === "retained");
  assert.ok(eventRecord);
  const mutated = { ...eventRecord, payload: { ...eventRecord.payload, reason: "tampered reason value" } };
  await evidenceStore.putEvidence(f.ownerId, mutated, { expectedVersion: eventRecord._storage?.version });
  await assert.rejects(f.app.reconcileRecoverySloProviderConformanceDriftRetentionChain(f.ownerId),
    hasCode("RECOVERY_SLO_DRIFT_CHAIN_RECORDS_UNHEALTHY"));
});

test("Batch 142: missing root anchor provider blocks conformance and the new application APIs/routes exist", async t => {
  const f = await fixture(t);
  await assert.rejects(f.app.prepareRecoverySloRootRecoveryTrustAnchorConformance(f.ownerId, {
    reason: "Attempt conformance without an external root-trust anchor provider."
  }), hasCode("RECOVERY_SLO_ROOT_TRUST_CONFORMANCE_PROVIDER_UNAVAILABLE"));
  for (const name of ["prepareRecoverySloRootRecoveryTrustAnchorConformance", "runRecoverySloRootRecoveryTrustAnchorConformance",
    "auditRecoverySloRootRecoveryTrustAnchorConformance", "requireRecoverySloRetentionReconciliationAttestationForDecision",
    "reconcileRecoverySloProviderConformanceDriftRetentionChain", "auditRecoverySloProviderConformanceDriftRetentionChain"]) {
    assert.equal(typeof f.app[name], "function", `${name} should be exposed by the application`);
  }
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /root-recovery-trust\/anchor\/conformance\/challenges/);
  assert.match(server, /retention-reconciliation\/attestations\/decision-check/);
  assert.match(server, /provider-conformance-drift\/retention-chain\/reconcile/);
});
