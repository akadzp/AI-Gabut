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
function anchorProvider(baseUrl, { failReadAfterNextCas = false } = {}) {
  const records = new Map(); let failNextRead = false;
  return { baseUrl,
    async read(scope) {
      if (failNextRead) { failNextRead = false; throw new Error("simulated process interruption after external CAS"); }
      const value = records.get(scope); return value ? structuredClone(value) : null;
    },
    async compareAndSet(scope, expectedDigest, candidate) {
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate));
      if (failReadAfterNextCas) failNextRead = true;
      return { applied: true };
    } };
}
function signer(pair) { return payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url"); }
function makeReceipt(ownerId, domain, suffix, createdAt = "2026-10-08T00:00:00.000Z") {
  const unsigned = { id: `receipt-${suffix}`, ownerId, kind: "recovery-slo-cross-domain-provider-baseline-transition-receipt", schemaVersion: 1,
    domain, revision: 1, previousReceiptDigest: null, transitionChallengeId: `transition-${suffix}`,
    sourceReportDigest: suffix.padEnd(64, suffix).slice(0, 64), historyNotProven: false, createdAt };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function manifestContext(suffix = "a") {
  const hex = char => char.repeat(64);
  return { guardrails: { status: "healthy", compactionEligible: true, blockers: [], receiptAuditStatus: "healthy", baselineAuditStatus: "healthy",
    receiptCount: 2, receiptHeads: { alpha: { id: `receipt-alpha-${suffix}`, digest: hex(suffix), revision: suffix.charCodeAt(0) },
      beta: { id: `receipt-beta-${suffix}`, digest: hex(String.fromCharCode(suffix.charCodeAt(0) + 1)), revision: suffix.charCodeAt(0) } } },
    checkpointStatus: { status: "anchored", anchorSequence: 2, anchorDigest: hex("c"), policyBindingStatus: "current",
      anchoredPolicyDigest: hex("d"), currentPolicyDigest: hex("d"), sourceDigest: hex("e"), sourceCount: 2 } };
}
async function seedOverdueManifestLedger(root, owner = "b162-ledger", clock = () => "2026-10-08T00:00:00.000Z") {
  const storage = createStorage({ root }), store = createAgenticStore({ storage });
  await store.putEvidence(owner, makeReceipt(owner, "alpha", "a"), { overwrite: false });
  await store.putEvidence(owner, makeReceipt(owner, "beta", "b"), { overwrite: false });
  const governance = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock });
  const context = manifestContext();
  const manifest = await governance.createProviderBaselineReceiptCompactionManifest(owner, context);
  const challenge = await governance.prepareProviderBaselineReceiptCompactionManifestApproval(owner, manifest.manifest.id,
    { ...context, reason: "Approve the baseline receipt manifest for review only, preserving all evidence." });
  const approval = await governance.applyProviderBaselineReceiptCompactionManifestApproval(owner, challenge.challengeId,
    { ...context, confirmation: challenge.confirmation });
  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3, anchorDigest: "f".repeat(64) };
  await governance.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(owner, approval.approval.id,
    { verifyManifest: (targetOwnerId, manifestId) => governance.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context),
      reason: "Record the supersession after the external provider baseline checkpoint moved behind local state." });
  return { storage, store, owner, governance };
}

function resignBundle(bundle, changes, pair) {
  const unsigned = structuredClone(bundle);
  for (const key of ["payloadDigest", "signature", "digest", "integrityAlgorithm", "readOnly", "mutationAllowed"]) delete unsigned[key];
  Object.assign(unsigned, changes);
  const payloadDigest = sha256(canonical(unsigned));
  const signature = sign(null, Buffer.from(canonical({ ...unsigned, payloadDigest })), pair.privateKey).toString("base64url");
  const signedBody = { ...unsigned, payloadDigest, signature };
  return { ...signedBody, digest: sha256(canonical(signedBody)), integrityAlgorithm: "sha256", readOnly: true, mutationAllowed: false };
}

test("Batch 162: receipt checkpoint recovery intent finalizes an external commit after marker-write interruption", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b162-receipt-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const provider = anchorProvider("https://b162-receipt-recovery.example", { failReadAfterNextCas: true });
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: provider, requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true });
  const owner = "b162-recovery-owner";
  const rotation = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate the initial key to seed a retained transition receipt before checkpoint enrollment." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotation.challengeId, { confirmation: rotation.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the receipt checkpoint and preserve a recoverable intent for crash finalization." });
  await assert.rejects(() => app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation }), error => error.code === "EXTERNAL_SNAPSHOT_CHECKPOINT_VERIFY_FAILED");
  const pending = await app.auditRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointRecoveryIntents(owner);
  assert.equal(pending.status, "recovery_required");
  assert.equal(pending.pendingCount, 1);
  const recovered = await app.recoverRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.finalized.length, 1);
  assert.equal((await app.getRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointStatus(owner)).status, "anchored");
  const audit = await app.auditRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointRecoveryIntents(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.finalizedCount, 1);
  const store = createAgenticStore({ storage });
  const savedChallenge = await store.getEvidence(owner, enrollment.challengeId);
  assert.equal(savedChallenge.status, "applied");
  assert.equal(savedChallenge.recoveredAfterExternalCommit, true);
  const retry = await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(retry.idempotent, true);
  assert.equal(retry.anchorDigest, savedChallenge.anchorDigest);
});

test("Batch 162: manifest ledger diagnostics uniquely identify a multi-event gap but never advance it automatically", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b162-ledger-gap-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const seeded = await seedOverdueManifestLedger(root, "b162-gap-owner");
  const provider = anchorProvider("https://b162-manifest-gap.example");
  const app = createAgenticApplication({ storage: seeded.storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainManifestApprovalLedgerAnchor: provider });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner,
    { reason: "Enroll the initial manifest ledger state before deliberately creating a multi-event gap." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(seeded.owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });

  const governance = createRecoverySloCrossDomainGovernanceHardeningService({ store: seeded.store, clock: () => "2026-10-13T00:00:00.000Z" });
  for (const suffix of ["x", "y"]) {
    const context = manifestContext(suffix);
    const manifest = await governance.createProviderBaselineReceiptCompactionManifest(seeded.owner, context);
    const challenge = await governance.prepareProviderBaselineReceiptCompactionManifestApproval(seeded.owner, manifest.manifest.id,
      { ...context, reason: `Approve manifest ${suffix} for review while preserving the retained receipt history.` });
    const approval = await governance.applyProviderBaselineReceiptCompactionManifestApproval(seeded.owner, challenge.challengeId,
      { ...context, confirmation: challenge.confirmation });
    context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3,
      anchorDigest: "f".repeat(64), sourceDigest: "a".repeat(64) };
    await governance.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(seeded.owner, approval.approval.id,
      { verifyManifest: (targetOwnerId, manifestId) => governance.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context),
        reason: `Record manifest ${suffix} supersession after its checkpoint became stale and preserve all evidence.` });
  }
  const diagnostics = await app.diagnoseRecoverySloCrossDomainManifestApprovalLedgerCheckpointGaps(seeded.owner);
  assert.equal(diagnostics.checkpointStatus, "behind_local");
  assert.equal(diagnostics.status, "multi_event_gap_proven");
  assert.ok(diagnostics.gapCount > 1);
  assert.equal(diagnostics.uniqueContinuityProof, true);
  assert.equal(diagnostics.automaticMultiEventReconciliationAllowed, false);
  assert.equal(diagnostics.candidateEventIds.length, diagnostics.gapCount);
  await assert.rejects(() => app.reconcileRecoverySloCrossDomainManifestApprovalLedgerCheckpoint(seeded.owner),
    error => error.code === "CROSS_DOMAIN_MANIFEST_APPROVAL_LEDGER_CONTINUITY_UNPROVEN");
  const after = await app.getRecoverySloCrossDomainManifestApprovalLedgerCheckpointStatus(seeded.owner);
  assert.equal(after.status, "behind_local");
});

test("Batch 162: signed lease export verifies signing-key cutoff and rejects post-revocation signatures", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b162-key-cutoff-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const provider = anchorProvider("https://b162-key-cutoff.example");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: provider, requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true });
  const owner = "b162-cutoff-owner";
  const rotateToNext = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate to the next signing key before creating the signed lease audit export." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotateToNext.challengeId, { confirmation: rotateToNext.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the transition receipt checkpoint before signing the lease export." });
  await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const signedExport = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  assert.equal(signedExport.signing.keyId, "key_next");
  const rotateBack = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_old",
    { reason: "Rotate away from the export signing key before revoking that retired key." });
  nowMs += 1000;
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotateBack.challengeId, { confirmation: rotateBack.confirmation });
  await app.reconcileRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);
  const revokeNext = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation(owner, "key_next",
    { reason: "Revoke the retired export signing key after its historical export was issued." });
  nowMs += 1000;
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation(owner, revokeNext.challengeId, { confirmation: revokeNext.confirmation });
  await app.reconcileRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint(owner);

  const historical = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, signedExport);
  assert.equal(historical.signatureValid, true);
  assert.equal(historical.keyCutoffValid, true);
  assert.equal(historical.keyCutoffStatus, "valid_before_revocation_cutoff");
  assert.equal(historical.historicallyValid, true);
  assert.equal(historical.usableForCurrentDecision, false);

  nowMs += 1000;
  const signedAfterCutoff = resignBundle(signedExport, { exportedAt: clock(), signing: { ...signedExport.signing, lifecycleSequence: 1 } }, nextPair);
  const afterCutoff = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, signedAfterCutoff);
  assert.equal(afterCutoff.signatureValid, true);
  assert.equal(afterCutoff.keyCutoffValid, false);
  assert.equal(afterCutoff.keyCutoffStatus, "signed_after_revocation");
  assert.equal(afterCutoff.historicallyValid, false);
  assert.ok(afterCutoff.findings.some(item => item.code === "CROSS_DOMAIN_REVALIDATION_LEASE_SIGNED_EXPORT_KEY_SIGNED_AFTER_REVOCATION"));

  const revokedAtSigning = resignBundle(signedExport, { exportedAt: clock(), signing: { ...signedExport.signing, lifecycleSequence: 3 } }, nextPair);
  const revoked = await app.verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, revokedAtSigning);
  assert.equal(revoked.signatureValid, true);
  assert.equal(revoked.keyCutoffValid, false);
  assert.equal(revoked.keyCutoffStatus, "revoked_before_signing");
  assert.equal(revoked.historicallyValid, false);
});

test("Batch 162: recovery-intent, gap-diagnostic, and key-cutoff APIs/routes are exposed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b162-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of ["auditRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointRecoveryIntents",
    "recoverRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpoint", "diagnoseRecoverySloCrossDomainManifestApprovalLedgerCheckpointGaps",
    "verifyRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport"]) assert.equal(typeof app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /attestation-key-transition-receipts\/checkpoint\/recovery-intents\/audit/);
  assert.match(server, /attestation-key-transition-receipts\/checkpoint\/recovery-intents\/recover/);
  assert.match(server, /manifest-approval-ledger\/checkpoint\/gap-diagnostics/);
});
