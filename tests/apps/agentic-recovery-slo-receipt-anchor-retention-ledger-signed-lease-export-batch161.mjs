import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";
import { createRecoverySloCrossDomainGovernanceHardeningService } from "../../apps/agentic/backend/recovery-slo-cross-domain-governance-hardening.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
function anchorProvider(baseUrl) {
  const records = new Map();
  return { baseUrl, async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) { const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true }; } };
}
function makeReceipt(ownerId, domain, suffix, createdAt = "2026-10-08T00:00:00.000Z") {
  const unsigned = { id: `receipt-${suffix}`, ownerId, kind: "recovery-slo-cross-domain-provider-baseline-transition-receipt", schemaVersion: 1,
    domain, revision: 1, previousReceiptDigest: null, transitionChallengeId: `transition-${suffix}`,
    sourceReportDigest: suffix.padEnd(64, suffix).slice(0, 64), historyNotProven: false, createdAt };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function manifestContext() {
  return { guardrails: { status: "healthy", compactionEligible: true, blockers: [], receiptAuditStatus: "healthy", baselineAuditStatus: "healthy",
    receiptCount: 2, receiptHeads: { alpha: { id: "receipt-a", digest: "a".repeat(64), revision: 1 }, beta: { id: "receipt-b", digest: "b".repeat(64), revision: 1 } } },
    checkpointStatus: { status: "anchored", anchorSequence: 2, anchorDigest: "c".repeat(64), policyBindingStatus: "current",
      anchoredPolicyDigest: "d".repeat(64), currentPolicyDigest: "d".repeat(64), sourceDigest: "e".repeat(64), sourceCount: 2 } };
}
async function seedOverdueManifestLedger(root) {
  const storage = createStorage({ root }), store = createAgenticStore({ storage }), owner = "b161-ledger";
  const createdAt = "2026-10-08T00:00:00.000Z";
  await store.putEvidence(owner, makeReceipt(owner, "alpha", "a", createdAt), { overwrite: false });
  await store.putEvidence(owner, makeReceipt(owner, "beta", "b", createdAt), { overwrite: false });
  const governance = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => createdAt });
  const context = manifestContext();
  const manifest = await governance.createProviderBaselineReceiptCompactionManifest(owner, context);
  const challenge = await governance.prepareProviderBaselineReceiptCompactionManifestApproval(owner, manifest.manifest.id,
    { ...context, reason: "Approve the receipt manifest for review without compacting retained evidence." });
  const approval = await governance.applyProviderBaselineReceiptCompactionManifestApproval(owner, challenge.challengeId,
    { ...context, confirmation: challenge.confirmation });
  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3, anchorDigest: "f".repeat(64) };
  await governance.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(owner, approval.approval.id,
    { verifyManifest: (targetOwnerId, manifestId) => governance.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context),
      reason: "Record supersession after the external provider baseline checkpoint moved behind local state." });
  return { storage, store, owner };
}

test("Batch 161: transition receipt checkpoint enrolls explicitly and advances one receipt with unique continuity proof", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b161-receipt-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const provider = anchorProvider("https://b161-key-transition-receipts.example");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: provider, requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true });
  const owner = "b161-receipt";
  const firstChallenge = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate the active key before anchoring its registry transition receipt." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, firstChallenge.challengeId, { confirmation: firstChallenge.confirmation });
  const initial = await app.getRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointStatus(owner);
  assert.equal(initial.status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Explicitly enroll the retained key transition receipt chain in its own trust domain." });
  const enrolled = await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const secondChallenge = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_old",
    { reason: "Rotate back to the trusted original key to create one additional transition receipt." });
  const second = await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, secondChallenge.challengeId,
    { confirmation: secondChallenge.confirmation });
  assert.ok(second.transitionReceipt);
  const behind = await app.getRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointStatus(owner);
  assert.equal(behind.status, "behind_local");
  const reconciled = await app.reconcileRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);
  assert.equal(reconciled.status, "anchored");
  assert.equal(reconciled.anchorSequence, 2);
  const audit = await app.auditRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 161: lease export is Ed25519 signed and bound to current receipt checkpoint", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b161-signed-lease-export-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldPair = generateKeyPairSync("ed25519"), pair = generateKeyPairSync("ed25519");
  const oldSigner = payload => sign(null, Buffer.from(canonical(payload)), oldPair.privateKey).toString("base64url");
  const signer = payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const provider = anchorProvider("https://b161-signed-lease-receipts.example");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: oldSigner, recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, export_key: pair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: oldSigner, export_key: signer },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: provider, requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true });
  const owner = "b161-sign";
  const challenge = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "export_key",
    { reason: "Create an explicit key lifecycle event before signing the lease audit export." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, challenge.challengeId, { confirmation: challenge.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the receipt checkpoint before binding signed lease audit exports." });
  await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const signed = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  assert.equal(signed.kind, "recovery-slo-cross-domain-revalidation-lease-audit-event-signed-export");
  assert.equal(signed.signing.algorithm, "Ed25519");
  assert.ok(signed.checkpointBinding.anchorDigest);
  assert.equal(signed.leaseExport.rawLeaseTokensExcluded, true);
  const verified = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, signed);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.status, "history_unproven");
  assert.equal(verified.usableForCurrentDecision, false);
  const tampered = structuredClone(signed); tampered.checkpointBinding.anchorDigest = "f".repeat(64);
  const rejected = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, tampered);
  assert.equal(rejected.status, "unhealthy");
  assert.ok(rejected.findings.some(item => item.code === "CROSS_DOMAIN_REVALIDATION_LEASE_SIGNED_EXPORT_SIGNATURE_INVALID"));
});

test("Batch 161: retention approval revocation linkage is validated before ledger checkpoint reconciliation", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b161-retention-ledger-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const seeded = await seedOverdueManifestLedger(root), provider = anchorProvider("https://b161-manifest-ledger.example");
  const app = createAgenticApplication({ storage: seeded.storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainManifestApprovalLedgerAnchor: provider, recoverySloCrossDomainSnapshotAnchorRetentionDays: 1 });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner,
    { reason: "Enroll the manifest approval ledger before testing revocation chain validation." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const reviewChallenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner,
    { decision: "retain", reason: "Retain the overdue supersession evidence after digest and owner review." });
  const approval = await app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReview(seeded.owner, reviewChallenge.challengeId,
    { confirmation: reviewChallenge.confirmation });
  const revokeChallenge = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerRetentionReviewRevocation(seeded.owner, approval.approval.id,
    { reason: "Revoke the retention approval so its ledger linkage can be independently audited." });
  const revoked = await app.applyRecoverySloCrossDomainManifestApprovalLedgerRetentionReviewRevocation(seeded.owner, revokeChallenge.challengeId,
    { confirmation: revokeChallenge.confirmation });
  assert.equal(revoked.status, "revoked");
  const savedChallenge = await seeded.store.getEvidence(seeded.owner, revoked.revocation.challengeId);
  const tamperedChallenge = { ...savedChallenge, revocationDigest: "a".repeat(64) };
  await seeded.store.putEvidence(seeded.owner, tamperedChallenge, { expectedVersion: savedChallenge._storage?.version });
  const checkpointAudit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerCheckpoint(seeded.owner);
  assert.equal(checkpointAudit.status, "unhealthy");
  assert.match(JSON.stringify(checkpointAudit.findings), /EXTERNAL_SNAPSHOT_CHECKPOINT_SOURCE_UNHEALTHY|MANIFEST_APPROVAL_LEDGER_RETENTION_REVOCATION/);
  await assert.rejects(() => app.reconcileRecoverySloCrossDomainManifestApprovalLedgerCheckpoint(seeded.owner));
});

test("Batch 161: new checkpoint and signed-export APIs/routes are exposed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b161-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of [
    "getRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointStatus",
    "reconcileRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint",
    "prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment",
    "auditRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint",
    "exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents",
    "verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport"
  ]) assert.equal(typeof app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /attestation-key-transition-receipts\/checkpoint\/enrollment-challenges/);
  assert.match(server, /revalidation-leases\/events\/export\/signed/);
  assert.match(server, /revalidation-leases\/events\/verify-signed-export/);
});
