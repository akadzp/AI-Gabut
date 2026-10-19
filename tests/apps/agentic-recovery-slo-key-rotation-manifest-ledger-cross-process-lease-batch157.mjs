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
  const rows = new Map(), locks = new Map();
  const key = (ownerId, id) => `${ownerId}\0${id}`;
  const read = (ownerId, id) => rows.get(key(ownerId, id)) || null;
  const clone = value => value ? { ...structuredClone(value.record), _storage: { version: value.version } } : null;
  async function mutateEvidence(ownerId, id, mutator) {
    const k = key(ownerId, id), prior = locks.get(k) || Promise.resolve();
    let release;
    const hold = new Promise(resolve => { release = resolve; });
    locks.set(k, hold);
    await prior;
    try {
      const current = clone(read(ownerId, id));
      const decision = await mutator(current);
      if (decision?.write === false || decision?.delete === true) return decision.result;
      const value = decision?.value;
      assert.ok(value && typeof value === "object");
      const version = (read(ownerId, id)?.version || 0) + 1;
      rows.set(k, { record: structuredClone({ ...value, ownerId, id }), version });
      return decision.result === undefined ? clone(read(ownerId, id)) : decision.result;
    } finally {
      release();
      if (locks.get(k) === hold) locks.delete(k);
    }
  }
  return {
    async getEvidence(ownerId, id) { return clone(read(ownerId, id)); },
    async listEvidence(ownerId) { return [...rows.entries()].filter(([k]) => k.startsWith(`${ownerId}\0`)).map(([, value]) => clone(value)); },
    async putEvidence(ownerId, record, options = {}) {
      const k = key(ownerId, record.id), existing = read(ownerId, record.id);
      if (options.overwrite === false && existing) throw Object.assign(new Error("already exists"), { code: "ALREADY_EXISTS" });
      if (options.expectedVersion !== undefined && (!existing || existing.version !== options.expectedVersion))
        throw Object.assign(new Error("version conflict"), { code: "VERSION_CONFLICT" });
      const version = (existing?.version || 0) + 1;
      rows.set(k, { record: structuredClone(record), version });
      return clone(read(ownerId, record.id));
    },
    mutateEvidence
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
  return { guardrails: { status: "healthy", compactionEligible: true, blockers: [], receiptAuditStatus: "healthy", baselineAuditStatus: "healthy",
    receiptCount: 2, receiptHeads: { alpha: { id: "receipt-a", digest: "a".repeat(64), revision: 1 }, beta: { id: "receipt-b", digest: "b".repeat(64), revision: 1 } } },
    checkpointStatus: { status: "anchored", anchorSequence: 2, anchorDigest: "c".repeat(64), policyBindingStatus: "current",
      anchoredPolicyDigest: "d".repeat(64), currentPolicyDigest: "d".repeat(64), sourceDigest: "e".repeat(64), sourceCount: 2 } };
}

test("Batch 157: attestation key rotation preserves history, while revocation applies a historical cutoff", async () => {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString(), anchorTime = clock(), store = memoryStore();
  const makeSigner = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const signers = { key_old: makeSigner(oldPair), key_next: makeSigner(nextPair) };
  const service = createRecoverySloPolicyBindingAuditCheckpointAttestationService({ store, signer: signers.key_old, keyId: "key_old", signers,
    publicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey }, clock, maxAgeMs: 86400000, futureSkewMs: 1000,
    readCheckpoint: async () => ({ status: "anchored", freshnessStatus: "fresh", anchorSequence: 3, anchorDigest: "a".repeat(64),
      anchoredAt: anchorTime, historyNotProven: false, policyBindingStatus: "current", currentPolicyDigest: "b".repeat(64), anchoredPolicyDigest: "b".repeat(64) }),
    auditCheckpoint: async () => ({ status: "healthy", findings: [] }), auditPolicyBindingChain: async () => ({ status: "healthy", eventCount: 3, findings: [] }) });
  const oldAttestation = await service.create("owner-keys", { reason: "Create historical attestation before rotating the signing key." });
  const rotation = await service.prepareKeyRotation("owner-keys", "key_next", { reason: "Rotate the active checkpoint attestation signing key." });
  const rotated = await service.applyKeyRotation("owner-keys", rotation.challengeId, { confirmation: rotation.confirmation });
  assert.equal(rotated.status, "rotated");
  assert.equal(rotated.activeKeyId, "key_next");
  const oldAfterRotation = await service.verify("owner-keys", oldAttestation.attestation.attestationId);
  assert.equal(oldAfterRotation.historicallyValid, true);
  assert.equal(oldAfterRotation.current, false);
  assert.equal(oldAfterRotation.status, "key_rotated");
  const nextAttestation = await service.create("owner-keys", { reason: "Create a new attestation under the rotated active signing key." });
  assert.equal(nextAttestation.attestation.signing.keyId, "key_next");
  const revoke = await service.prepareKeyRevocation("owner-keys", "key_old", { reason: "Revoke the retired key after its replacement is active." });
  const revoked = await service.applyKeyRevocation("owner-keys", revoke.challengeId, { confirmation: revoke.confirmation });
  assert.equal(revoked.status, "revoked");
  const oldAfterRevocation = await service.verify("owner-keys", oldAttestation.attestation.attestationId);
  assert.equal(oldAfterRevocation.historicallyValid, true);
  assert.equal(oldAfterRevocation.status, "key_revoked");
  assert.equal(oldAfterRevocation.usableForCurrentDecision, false);
  const nextStillCurrent = await service.verify("owner-keys", nextAttestation.attestation.attestationId);
  assert.equal(nextStillCurrent.status, "current");
  await assert.rejects(() => service.prepareKeyRevocation("owner-keys", "key_next", { reason: "Attempt to revoke the currently active key." }),
    error => error.code === "POLICY_BINDING_ATTESTATION_ACTIVE_KEY_REVOCATION_FORBIDDEN");
  const audit = await service.auditKeyLifecycle("owner-keys");
  assert.equal(audit.status, "healthy");
  assert.equal(audit.activeKeyId, "key_next");
  assert.equal(audit.keys.find(item => item.keyId === "key_old").status, "revoked");
  const oldKeyEvent = (await store.listEvidence("owner-keys")).find(row => row.kind === "recovery-slo-policy-binding-audit-checkpoint-freshness-attestation-key-lifecycle-event");
  const tampered = { ...oldKeyEvent, reason: "Tampered lifecycle reason after key rotation." };
  await store.putEvidence("owner-keys", tampered, { expectedVersion: oldKeyEvent._storage.version });
  assert.equal((await service.auditKeyLifecycle("owner-keys")).status, "unhealthy");
});

test("Batch 157: manifest approval supersession is append-only, idempotent, and auditable for external anchoring", async () => {
  const store = memoryStore(), ownerId = "owner-supersession";
  await store.putEvidence(ownerId, makeReceipt(ownerId, "alpha", "a"), { overwrite: false });
  await store.putEvidence(ownerId, makeReceipt(ownerId, "beta", "b"), { overwrite: false });
  const service = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => "2026-10-13T00:00:00.000Z" });
  const context = manifestContext();
  const created = await service.createProviderBaselineReceiptCompactionManifest(ownerId, context);
  const prepared = await service.prepareProviderBaselineReceiptCompactionManifestApproval(ownerId, created.manifest.id,
    { ...context, reason: "Approve the receipt manifest for controlled review only." });
  const approval = await service.applyProviderBaselineReceiptCompactionManifestApproval(ownerId, prepared.challengeId,
    { ...context, confirmation: prepared.confirmation });
  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3, anchorDigest: "f".repeat(64) };
  const verifyManifest = (targetOwnerId, manifestId) => service.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context);
  const first = await service.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(ownerId, approval.approval.id,
    { verifyManifest, reason: "Record the approval as superseded after checkpoint drift." });
  assert.equal(first.status, "superseded_recorded");
  const repeated = await service.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(ownerId, approval.approval.id,
    { verifyManifest, reason: "Record the approval as superseded after checkpoint drift." });
  assert.equal(repeated.idempotent, true);
  assert.equal(repeated.event.id, first.event.id);
  const audit = await service.auditProviderBaselineReceiptCompactionManifestApprovals(ownerId);
  assert.equal(audit.integrityStatus, "healthy");
  assert.equal(audit.supersessionCount, 1);
  assert.equal(audit.approvals[0].currentStatus, "superseded");
  assert.equal(audit.compactionPerformed, false);
});

test("Batch 157: durable revalidation leases serialize separate service instances and fence stale workers", async () => {
  const store = memoryStore();
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const a = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock });
  const b = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock });
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const running = a.runLeasedRevalidation("owner-lease", "approval-lease", async lease => {
    assert.equal(typeof lease.fencingToken, "number");
    await gate;
    return { status: "current", usableForCurrentDecision: true };
  }, { leaseMs: 1000 });
  await new Promise(resolve => setImmediate(resolve));
  const busy = await b.runLeasedRevalidation("owner-lease", "approval-lease", async () => ({ status: "wrong" }), { leaseMs: 1000 });
  assert.equal(busy.status, "revalidation_in_progress");
  nowMs += 2000;
  const recovered = await b.recoverRevalidationLease("owner-lease", "approval-lease");
  assert.equal(recovered.status, "recovered");
  release();
  await assert.rejects(() => running, error => error.code === "CROSS_DOMAIN_REVALIDATION_LEASE_LOST");
  const audit = await b.auditRevalidationLeases("owner-lease");
  assert.equal(audit.status, "healthy");
  assert.equal(audit.activeCount, 0);
  assert.equal(audit.leases[0].status, "recovered");
  const leaseRecord = (await store.listEvidence("owner-lease")).find(row => row.kind === "recovery-slo-cross-domain-retention-review-revalidation-lease");
  const altered = { ...leaseRecord, events: leaseRecord.events.map((event, index) => index === 0 ? { ...event, reason: "tampered lease event" } : event) };
  await store.putEvidence("owner-lease", altered, { expectedVersion: leaseRecord._storage.version });
  assert.equal((await b.auditRevalidationLeases("owner-lease")).status, "unhealthy");
});

test("Batch 157: application exposes key lifecycle, manifest ledger checkpoint, and durable lease recovery APIs/routes", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b157-app-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  assert.equal((await app.getRecoverySloCrossDomainManifestApprovalLedgerCheckpointStatus("owner-api")).status, "local_only");
  for (const name of [
    "prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation", "applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation",
    "prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation", "applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation",
    "auditRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycle", "recordRecoverySloCrossDomainProviderBaselineReceiptCompactionManifestApprovalSupersession",
    "getRecoverySloCrossDomainManifestApprovalLedgerCheckpointStatus", "reconcileRecoverySloCrossDomainManifestApprovalLedgerCheckpoint",
    "auditRecoverySloCrossDomainManifestApprovalLedgerCheckpoint", "auditRecoverySloCrossDomainRetentionReviewRevalidationLeases",
    "recoverRecoverySloCrossDomainRetentionReviewRevalidationLease"
  ]) assert.equal(typeof app[name], "function", name);
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /key-rotation-challenges/);
  assert.match(serverSource, /manifest-approval-ledger\/checkpoint\/status/);
  assert.match(serverSource, /revalidation-leases\/audit/);
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloCrossDomainManifestApprovalLedgerAnchor: true }),
    /diwajibkan tetapi belum dikonfigurasi/);
  const shared = { async read() { return null; }, async compareAndSet() { return { applied: false }; } };
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }),
    recoverySloCrossDomainSnapshotAuditAnchor: shared, recoverySloCrossDomainManifestApprovalLedgerAnchor: shared }),
    /external anchor provider terpisah/);
  const sameEndpointA = { baseUrl: "https://same-anchor.example", async read() { return null; }, async compareAndSet() { return { applied: false }; } };
  const sameEndpointB = { baseUrl: "https://same-anchor.example/", async read() { return null; }, async compareAndSet() { return { applied: false }; } };
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }),
    recoverySloCrossDomainSnapshotAuditAnchor: sameEndpointA, recoverySloCrossDomainManifestApprovalLedgerAnchor: sameEndpointB }),
    /endpoint external anchor yang berbeda/);
});
