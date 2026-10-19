import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createRecoverySloPolicyBindingAuditCheckpointAttestationService } from "../../apps/agentic/backend/recovery-slo-policy-binding-audit-checkpoint-attestation.js";
import { createRecoverySloCrossDomainGovernanceHardeningService } from "../../apps/agentic/backend/recovery-slo-cross-domain-governance-hardening.js";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };

function memoryStore() {
  const rows = new Map();
  const key = (ownerId, id) => `${ownerId}\0${id}`;
  return {
    async getEvidence(ownerId, id) {
      const entry = rows.get(key(ownerId, id));
      return entry ? { ...structuredClone(entry.record), _storage: { version: entry.version } } : null;
    },
    async listEvidence(ownerId) {
      return [...rows.entries()].filter(([itemKey]) => itemKey.startsWith(`${ownerId}\0`))
        .map(([, entry]) => ({ ...structuredClone(entry.record), _storage: { version: entry.version } }));
    },
    async putEvidence(ownerId, record, options = {}) {
      const recordKey = key(ownerId, record.id), existing = rows.get(recordKey);
      if (options.overwrite === false && existing) throw Object.assign(new Error("already exists"), { code: "ALREADY_EXISTS" });
      if (options.expectedVersion !== undefined && (!existing || existing.version !== options.expectedVersion))
        throw Object.assign(new Error("version conflict"), { code: "VERSION_CONFLICT" });
      const version = (existing?.version || 0) + 1;
      rows.set(recordKey, { record: structuredClone(record), version });
      return { ...structuredClone(record), _storage: { version } };
    }
  };
}

function makeReceipt(ownerId, domain, suffix) {
  const unsigned = { id: `receipt-${suffix}`, ownerId,
    kind: "recovery-slo-cross-domain-provider-baseline-transition-receipt", schemaVersion: 1,
    domain, revision: 1, previousReceiptDigest: null, transitionChallengeId: `transition-${suffix}`,
    sourceReportDigest: suffix.padEnd(64, suffix).slice(0, 64), historyNotProven: false, createdAt: "2026-10-13T00:00:00.000Z" };
  return { ...unsigned, digest: digestRecord(unsigned) };
}

function manifestContext() {
  const guardrails = { status: "healthy", compactionEligible: true, blockers: [], receiptAuditStatus: "healthy",
    baselineAuditStatus: "healthy", receiptCount: 2,
    receiptHeads: { alpha: { id: "receipt-a", digest: "a".repeat(64), revision: 1 }, beta: { id: "receipt-b", digest: "b".repeat(64), revision: 1 } } };
  const checkpointStatus = { status: "anchored", anchorSequence: 2, anchorDigest: "c".repeat(64),
    policyBindingStatus: "current", anchoredPolicyDigest: "d".repeat(64), currentPolicyDigest: "d".repeat(64),
    sourceDigest: "e".repeat(64), sourceCount: 2 };
  return { guardrails, checkpointStatus };
}

test("Batch 156: policy-binding checkpoint freshness attestation is signed, verifiable, and fails closed for unproven history", async () => {
  const pair = generateKeyPairSync("ed25519");
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  let historyNotProven = true;
  const clock = () => new Date(nowMs).toISOString();
  const anchorTime = clock();
  const store = memoryStore();
  const service = createRecoverySloPolicyBindingAuditCheckpointAttestationService({
    store, signer: payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url"), keyId: "policy-chain-key",
    publicKeys: { "policy-chain-key": pair.publicKey }, clock, maxAgeMs: 60000, futureSkewMs: 1000,
    readCheckpoint: async () => ({ status: "anchored", freshnessStatus: Date.parse(clock()) - Date.parse(anchorTime) <= 60000 ? "fresh" : "stale",
      anchorSequence: 4, anchorDigest: "a".repeat(64), anchoredAt: anchorTime, historyNotProven, policyBindingStatus: "current",
      currentPolicyDigest: "b".repeat(64), anchoredPolicyDigest: "b".repeat(64), ownerId: "owner-attest" }),
    auditCheckpoint: async () => ({ status: historyNotProven ? "history_unproven" : "healthy", findings: [] }),
    auditPolicyBindingChain: async () => ({ status: historyNotProven ? "history_unproven" : "healthy", findings: [], eventCount: 4 })
  });
  const unproven = await service.create("owner-attest", { reason: "Attest the current checkpoint while preserving the legacy-history warning." });
  assert.equal(unproven.status, "signed_history_unproven");
  assert.equal(unproven.historicallyValid, true);
  assert.equal(unproven.current, false);
  assert.equal(unproven.usableForCurrentDecision, false);
  const unprovenCheck = await service.verify("owner-attest", unproven.attestation.attestationId);
  assert.equal(unprovenCheck.signatureValid, true);
  assert.equal(unprovenCheck.historicallyValid, true);
  assert.equal(unprovenCheck.status, "history_unproven");
  assert.equal(unprovenCheck.usableForCurrentDecision, false);

  historyNotProven = false;
  const current = await service.create("owner-attest", { reason: "Attest the current checkpoint after trusted history is independently proven." });
  assert.equal(current.status, "signed");
  const currentCheck = await service.verify("owner-attest", current.attestation.attestationId);
  assert.equal(currentCheck.status, "current");
  assert.equal(currentCheck.usableForCurrentDecision, true);
  const changedPolicyService = createRecoverySloPolicyBindingAuditCheckpointAttestationService({
    store, signer: payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url"), keyId: "policy-chain-key",
    publicKeys: { "policy-chain-key": pair.publicKey }, clock, maxAgeMs: 120000, futureSkewMs: 1000,
    readCheckpoint: async () => ({ status: "anchored", freshnessStatus: "fresh", anchorSequence: 4, anchorDigest: "a".repeat(64),
      anchoredAt: anchorTime, historyNotProven: false, policyBindingStatus: "current", currentPolicyDigest: "b".repeat(64), anchoredPolicyDigest: "b".repeat(64) }),
    auditCheckpoint: async () => ({ status: "healthy", findings: [] }),
    auditPolicyBindingChain: async () => ({ status: "healthy", findings: [], eventCount: 4 })
  });
  const policyDrift = await changedPolicyService.verify("owner-attest", current.attestation.attestationId);
  assert.equal(policyDrift.current, false);
  assert.equal(policyDrift.status, "stale");
  nowMs += 61000;
  const staleCheck = await service.verify("owner-attest", current.attestation.attestationId);
  assert.equal(staleCheck.current, false);
  assert.equal(staleCheck.usableForCurrentDecision, false);
  assert.equal(staleCheck.status, "stale");
});

test("Batch 156: manifest approval becomes superseded and can be explicitly revoked after source no longer qualifies", async () => {
  const store = memoryStore();
  const ownerId = "owner-manifest";
  await store.putEvidence(ownerId, makeReceipt(ownerId, "alpha", "a"), { overwrite: false });
  await store.putEvidence(ownerId, makeReceipt(ownerId, "beta", "b"), { overwrite: false });
  const service = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => "2026-10-13T00:00:00.000Z" });
  const context = manifestContext();
  const created = await service.createProviderBaselineReceiptCompactionManifest(ownerId, context);
  assert.equal(created.status, "ready_for_review");
  const approvalChallenge = await service.prepareProviderBaselineReceiptCompactionManifestApproval(ownerId, created.manifest.id,
    { ...context, reason: "Approve this manifest for controlled review only." });
  const approval = await service.applyProviderBaselineReceiptCompactionManifestApproval(ownerId, approvalChallenge.challengeId,
    { ...context, confirmation: approvalChallenge.confirmation });
  assert.equal(approval.status, "approved_for_review");

  const auditCurrent = await service.auditProviderBaselineReceiptCompactionManifestApprovals(ownerId, {
    verifyManifest: (targetOwnerId, manifestId) => service.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context)
  });
  assert.equal(auditCurrent.status, "healthy");
  await assert.rejects(() => service.prepareProviderBaselineReceiptCompactionManifestApprovalRevocation(ownerId, approval.approval.id,
    { ...context, reason: "Try to revoke a still-current manifest approval." }), error => error.code === "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_STILL_CURRENT");

  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3, anchorDigest: "f".repeat(64) };
  const auditSuperseded = await service.auditProviderBaselineReceiptCompactionManifestApprovals(ownerId, {
    verifyManifest: (targetOwnerId, manifestId) => service.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context)
  });
  assert.equal(auditSuperseded.status, "superseded");
  assert.equal(auditSuperseded.approvals[0].currentStatus, "superseded");

  const revokeChallenge = await service.prepareProviderBaselineReceiptCompactionManifestApprovalRevocation(ownerId, approval.approval.id,
    { ...context, reason: "Revoke approval because the source checkpoint no longer qualifies." });
  context.checkpointStatus = { ...context.checkpointStatus, anchorSequence: 4, anchorDigest: "9".repeat(64) };
  await assert.rejects(() => service.applyProviderBaselineReceiptCompactionManifestApprovalRevocation(ownerId, revokeChallenge.challengeId,
    { ...context, confirmation: revokeChallenge.confirmation }), error => error.code === "CROSS_DOMAIN_RECEIPT_MANIFEST_APPROVAL_REVOCATION_STALE");

  const refreshedChallenge = await service.prepareProviderBaselineReceiptCompactionManifestApprovalRevocation(ownerId, approval.approval.id,
    { ...context, reason: "Revoke approval against the newly observed stale checkpoint state." });
  const revoked = await service.applyProviderBaselineReceiptCompactionManifestApprovalRevocation(ownerId, refreshedChallenge.challengeId,
    { ...context, confirmation: refreshedChallenge.confirmation });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.compactionPerformed, false);
  const auditRevoked = await service.auditProviderBaselineReceiptCompactionManifestApprovals(ownerId, {
    verifyManifest: (targetOwnerId, manifestId) => service.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context)
  });
  assert.equal(auditRevoked.integrityStatus, "healthy");
  assert.equal(auditRevoked.status, "revoked");
  assert.equal(auditRevoked.approvals[0].currentStatus, "revoked");
  assert.equal(auditRevoked.revocationCount, 1);
});

test("Batch 156: concurrent revalidation calls for one approval share a single consistent execution", async () => {
  const service = createRecoverySloCrossDomainGovernanceHardeningService({ store: memoryStore(), clock: () => "2026-10-13T00:00:00.000Z" });
  let runs = 0, release;
  const gate = new Promise(resolve => { release = resolve; });
  const worker = async () => { runs++; await gate; return { status: "current", current: true, usableForCurrentDecision: true }; };
  const first = service.runConsistentRevalidation("owner-concurrent", "approval-1", worker);
  const second = service.runConsistentRevalidation("owner-concurrent", "approval-1", worker);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(runs, 1);
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.deepEqual(a, b);
  assert.equal(runs, 1);
  const audit = service.auditRevalidationCache("owner-concurrent");
  assert.equal(audit.stats.coalescedRevalidations, 1);
  assert.equal(audit.inFlightCount, 0);
});


test("Batch 156: application exposes attestation/revocation APIs and refuses required attestation without trusted signer configuration", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b156-app-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloPolicyBindingAuditCheckpointAttestation: true }),
    /signer dan trusted public key Ed25519 belum lengkap/);
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  assert.equal(typeof app.createRecoverySloPolicyBindingAuditCheckpointFreshnessAttestation, "function");
  assert.equal(typeof app.verifyRecoverySloPolicyBindingAuditCheckpointFreshnessAttestation, "function");
  assert.equal(typeof app.prepareRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApprovalRevocation, "function");
  assert.equal(typeof app.applyRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApprovalRevocation, "function");
  assert.equal(typeof app.auditRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApprovals, "function");
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /policy-binding-audit-checkpoint\/freshness-attestations/);
  assert.match(serverSource, /compaction-manifests\/approvals\/:approvalId\/revocation-challenges/);
  assert.match(serverSource, /approval-revocation-challenges\/:id\/apply/);
});
