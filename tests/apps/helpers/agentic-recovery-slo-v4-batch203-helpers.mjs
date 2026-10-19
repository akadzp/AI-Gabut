import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../../apps/agentic/backend/application.js";
import { createStorage } from "../../../core/storage/index.js";

export const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
export const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
export const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
export function anchorProvider(baseUrl) {
  const records = new Map();
  return { baseUrl, records, failWrites: false, throwAfterCommitOnce: false,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      if (this.failWrites) return { applied: false };
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); if (this.throwAfterCommitOnce) { this.throwAfterCommitOnce = false; throw new Error("simulated response loss after external commit"); } return { applied: true };
    } };
}
export function keyMaterial() {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  return { options: {
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)]))
  } };
}
export function makeApp(storage, keyOptions, anchors, clock = () => "2026-10-14T00:00:00.000Z") {
  return createAgenticApplication({ storage, clock, ...keyOptions,
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: anchors.receipt,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: anchors.finalization,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: anchors.reconciliation,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationAttestation: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: anchors.lifecycleRecovery,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: true,
    recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: anchors.lifecycleIntent,
    requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: true,
    recoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: anchors.transition,
    requireRecoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: true,
    recoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: anchors.disposition,
    requireRecoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: true,
    recoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptAnchor: anchors.closureRecoveryReceipts,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptAnchor: true,
    recoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAnchor: anchors.markerRecoveryJournal || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAnchor: Boolean(anchors.requireMarkerRecoveryJournal),
    recoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionAnchor: anchors.lifecycleDisposition || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionAnchor: Boolean(anchors.requireLifecycleDispositionCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleAnchor: anchors.revalidationLifecycle || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleAnchor: Boolean(anchors.requireRevalidationLifecycleCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofAnchor: anchors.recoveryGateProof || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofAnchor: Boolean(anchors.requireRecoveryGateProofCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAnchor: anchors.recoveryGateProofContinuity || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityAnchor: Boolean(anchors.requireRecoveryGateProofContinuityCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleAnchor: anchors.recoveryGateProofContinuityLifecycle || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleAnchor: Boolean(anchors.requireRecoveryGateProofContinuityLifecycleCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidenceAnchor: anchors.recoveryGateProofContinuityLifecycleDriftEvidence || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleDriftEvidenceAnchor: Boolean(anchors.requireRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityReceiptLifecycleAnchor: anchors.recoveryGateProofContinuityReceiptLifecycle || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityReceiptLifecycleAnchor: Boolean(anchors.requireRecoveryGateProofContinuityReceiptLifecycleCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleAnchor: anchors.recoveryGateProofContinuityFinalizationAttestationLifecycle || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAnchor: anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationAnchor: anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestation || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleAnchor: anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint),
    recoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptAnchor: anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt || null,
    requireRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint),
    recoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAnchor: anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt || null,
    requireRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint),
    recoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationAnchor: anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestation || null,
    requireRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint),
    recoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptAnchor: anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceipt || null,
    requireRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint),
    recoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptAnchor: anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt || null,
    requireRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint),
    recoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationAnchor: anchors.recoveryGateProofContinuityFinalizationReceiptExternalAttestation || null,
    requireRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationAnchor: Boolean(anchors.requireRecoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint),
    requireRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointBindingAttestation: Boolean(anchors.requireReceiptLifecycleCheckpointBindingAttestation),
    requireRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation: Boolean(anchors.requireFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation),
    requireRecoverySloCrossDomainRecoveryIntentClosureFreshnessAttestation: Boolean(anchors.requireFreshness),
    requireRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestation: Boolean(anchors.requireMarkerRecoveryJournalAttestation),
    recoverySloCrossDomainRecoveryIntentClosureFreshnessAttestationMaxAgeMs: 300000,
    requireRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshnessAttestation: Boolean(anchors.requireRevalidationLifecycleFreshnessAttestation),
    recoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleFreshnessAttestationMaxAgeMs: anchors.revalidationLifecycleFreshnessAttestationMaxAgeMs || 300000
  });
}
export async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
export async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the signing key for Batch 199 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
export async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate signing key to validate Batch 199 cutoff enforcement." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
export async function rotateKeyToOld(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_old", reason: "Rotate back to the prior key to validate stale challenge rejection." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
export async function enrollClosureCheckpoints(app, owner) {
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition closure checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment", "Enroll closure recovery receipt checkpoint for Batch 199.");
}
export async function setupOwner(t, owner, { requireFreshness = false, requireMarkerRecoveryJournalAttestation = false, clock = () => "2026-10-14T00:00:00.000Z", markerRecoveryJournal = false, enrollMarkerRecoveryJournal = true, reuseMarkerRecoveryJournalProvider = false, lifecycleDispositionCheckpoint = false, enrollLifecycleDispositionCheckpoint = true, reuseLifecycleDispositionProvider = false, revalidationLifecycleCheckpoint = false, enrollRevalidationLifecycleCheckpoint = true, reuseRevalidationLifecycleProvider = false, requireRevalidationLifecycleFreshnessAttestation = false, revalidationLifecycleFreshnessAttestationMaxAgeMs = 300000, recoveryGateProofCheckpoint = false, enrollRecoveryGateProofCheckpoint = true, reuseRecoveryGateProofProvider = false,
  recoveryGateProofContinuityCheckpoint = false, enrollRecoveryGateProofContinuityCheckpoint = true, reuseRecoveryGateProofContinuityProvider = false,
  recoveryGateProofContinuityLifecycleCheckpoint = false, enrollRecoveryGateProofContinuityLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityLifecycleProvider = false,
  recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint = false, enrollRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint = true,
  reuseRecoveryGateProofContinuityLifecycleDriftEvidenceProvider = false,
  recoveryGateProofContinuityReceiptLifecycleCheckpoint = false, enrollRecoveryGateProofContinuityReceiptLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityReceiptLifecycleProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint = false, enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptProvider = false,
  recoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptExternalAttestationProvider = false,
  requireReceiptLifecycleCheckpointBindingAttestation = false,
  requireFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b203-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`),
    lifecycleIntent: anchorProvider(`https://${owner}-lifecycle-intent.example`),
    transition: anchorProvider(`https://${owner}-transition.example`),
    disposition: anchorProvider(`https://${owner}-disposition.example`),
    closureRecoveryReceipts: anchorProvider(`https://${owner}-closure-recovery-receipts.example`),
    ...(markerRecoveryJournal ? { markerRecoveryJournal: anchorProvider(`https://${owner}-marker-recovery-journal.example`), requireMarkerRecoveryJournal: true } : {}),
    ...(lifecycleDispositionCheckpoint ? { lifecycleDisposition: anchorProvider(`https://${owner}-lifecycle-disposition.example`), requireLifecycleDispositionCheckpoint: true } : {}),
    ...(revalidationLifecycleCheckpoint ? { revalidationLifecycle: anchorProvider(`https://${owner}-revalidation-lifecycle.example`), requireRevalidationLifecycleCheckpoint: true } : {}),
    ...(recoveryGateProofCheckpoint ? { recoveryGateProof: anchorProvider(`https://${owner}-recovery-gate-proof.example`), requireRecoveryGateProofCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityCheckpoint ? { recoveryGateProofContinuity: anchorProvider(`https://${owner}-recovery-gate-proof-continuity.example`), requireRecoveryGateProofContinuityCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityLifecycleCheckpoint ? { recoveryGateProofContinuityLifecycle: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-lifecycle.example`), requireRecoveryGateProofContinuityLifecycleCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint ? { recoveryGateProofContinuityLifecycleDriftEvidence: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-lifecycle-drift-evidence.example`), requireRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityReceiptLifecycleCheckpoint ? { recoveryGateProofContinuityReceiptLifecycle: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-receipt-lifecycle.example`), requireRecoveryGateProofContinuityReceiptLifecycleCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint ? { recoveryGateProofContinuityFinalizationAttestationLifecycle: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-finalization-attestation-lifecycle.example`), requireRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint ? { recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-finalization-attestation-lifecycle-receipt.example`), requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint ? { recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestation: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-finalization-attestation-lifecycle-receipt-attestation.example`), requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint ? { recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-finalization-attestation-lifecycle-receipt-attestation-lifecycle.example`), requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint ? { recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt: anchorProvider(`https://${owner}-recovery-gate-proof-continuity-finalization-attestation-lifecycle-receipt-attestation-lifecycle-receipt.example`), requireRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint ? { recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt: anchorProvider(`https://${owner}-finalization-receipt-binding-attestation-lifecycle-receipt.example`), requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint ? { recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestation: anchorProvider(`https://${owner}-finalization-receipt-binding-attestation-lifecycle-receipt-lifecycle-attestation.example`), requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint ? { recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceipt: anchorProvider(`https://${owner}-finalization-receipt-binding-attestation-lifecycle-attestation-receipt.example`), requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint ? { recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt: anchorProvider(`https://${owner}-finalization-receipt-binding-attestation-lifecycle-attestation-receipt-attestation.example`), requireRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint: true } : {}),
    ...(recoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint ? { recoveryGateProofContinuityFinalizationReceiptExternalAttestation: anchorProvider(`https://${owner}-finalization-receipt-external-attestation.example`), requireRecoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint: true } : {}),
    requireReceiptLifecycleCheckpointBindingAttestation,
    requireFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation,
    requireFreshness, requireMarkerRecoveryJournalAttestation, requireRevalidationLifecycleFreshnessAttestation, revalidationLifecycleFreshnessAttestationMaxAgeMs };
  if (reuseMarkerRecoveryJournalProvider && anchors.markerRecoveryJournal)
    anchors.markerRecoveryJournal = anchors.closureRecoveryReceipts;
  if (reuseLifecycleDispositionProvider && anchors.lifecycleDisposition)
    anchors.lifecycleDisposition = anchors.closureRecoveryReceipts;
  if (reuseRevalidationLifecycleProvider && anchors.revalidationLifecycle)
    anchors.revalidationLifecycle = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofProvider && anchors.recoveryGateProof)
    anchors.recoveryGateProof = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityProvider && anchors.recoveryGateProofContinuity)
    anchors.recoveryGateProofContinuity = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityLifecycleProvider && anchors.recoveryGateProofContinuityLifecycle)
    anchors.recoveryGateProofContinuityLifecycle = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityLifecycleDriftEvidenceProvider && anchors.recoveryGateProofContinuityLifecycleDriftEvidence)
    anchors.recoveryGateProofContinuityLifecycleDriftEvidence = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityReceiptLifecycleProvider && anchors.recoveryGateProofContinuityReceiptLifecycle)
    anchors.recoveryGateProofContinuityReceiptLifecycle = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleProvider && anchors.recoveryGateProofContinuityFinalizationAttestationLifecycle)
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycle = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptProvider && anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt)
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceipt = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationProvider && anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestation)
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestation = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleProvider && anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle)
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycle = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptProvider && anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt)
    anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt = anchors.closureRecoveryReceipts;
  if (reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptProvider && anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt)
    anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt = anchors.recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceipt;
  if (reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationProvider && anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestation)
    anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestation = anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt;
  if (reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptProvider && anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceipt)
    anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceipt = anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceipt;
  if (reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptProvider && anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt)
    anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt = anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceipt;
  if (reuseRecoveryGateProofContinuityFinalizationReceiptExternalAttestationProvider && anchors.recoveryGateProofContinuityFinalizationReceiptExternalAttestation)
    anchors.recoveryGateProofContinuityFinalizationReceiptExternalAttestation = anchors.recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceipt;
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors, clock);
  await activateKey(app, owner);
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll base receipt checkpoint for Batch 199.");
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery checkpoint for Batch 199.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle intent checkpoint for Batch 199.");
  await enrollClosureCheckpoints(app, owner);
  if (markerRecoveryJournal && enrollMarkerRecoveryJournal)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpointEnrollment", "Enroll marker-recovery journal checkpoint for Batch 196.");
  if (lifecycleDispositionCheckpoint && enrollLifecycleDispositionCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointEnrollment", "Enroll independent lifecycle-disposition checkpoint for Batch 196.");
  if (revalidationLifecycleCheckpoint && enrollRevalidationLifecycleCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureRevalidationLifecycleCheckpointEnrollment", "Enroll independent revalidation lifecycle checkpoint for Batch 200.");
  if (recoveryGateProofCheckpoint && enrollRecoveryGateProofCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofCheckpointEnrollment", "Enroll independent recovery-gate proof checkpoint for Batch 203.");
  if (recoveryGateProofContinuityCheckpoint && enrollRecoveryGateProofContinuityCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityCheckpointEnrollment", "Enroll independent proof-continuity checkpoint for Batch 204.");
  if (recoveryGateProofContinuityLifecycleCheckpoint && enrollRecoveryGateProofContinuityLifecycleCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryGateProofContinuityLifecycleCheckpointEnrollment", "Enroll independent proof-continuity lifecycle checkpoint for Batch 206.");
  if (recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint && enrollRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpointEnrollment", "Enroll independent proof-continuity lifecycle drift-evidence checkpoint for Batch 208.");
  if (recoveryGateProofContinuityReceiptLifecycleCheckpoint && enrollRecoveryGateProofContinuityReceiptLifecycleCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityReceiptLifecycleCheckpointEnrollment", "Enroll independent revocation-receipt lifecycle checkpoint for Batch 209.");
  if (recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint && enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpointEnrollment", "Enroll independent finalization-attestation lifecycle checkpoint for Batch 212.");
  if (recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint && enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpointEnrollment", "Enroll independent finalization-attestation lifecycle receipt checkpoint for Batch 213.");
  if (recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint && enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestationCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptLifecycleAttestationCheckpointEnrollment", "Enroll independent lifecycle receipt attestation checkpoint for Batch 215.");
  if (recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint && enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpointEnrollment", "Enroll independent attestation lifecycle checkpoint for Batch 216.");
  if (recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint && enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpointEnrollment", "Enroll independent finalization receipt checkpoint for Batch 218.");
  if (recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint && enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint)
    await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpointEnrollment",
      "applyRecoverySloCrossDomainRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpointEnrollment", "Enroll independent binding-attestation lifecycle receipt checkpoint for Batch 221.");
  if (recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint && enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint)
    await enroll(app, owner, "prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpointEnrollment",
      "applyRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpointEnrollment", "Enroll independent lifecycle receipt attestation checkpoint for Batch 223.");
  if (recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint && enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint)
    await enroll(app, owner, "prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpointEnrollment",
      "applyRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpointEnrollment", "Enroll independent lifecycle attestation receipt checkpoint for Batch 224.");
  if (recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint && enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint)
    await enroll(app, owner, "prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpointEnrollment",
      "applyRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpointEnrollment", "Enroll independent lifecycle finalization-attestation receipt checkpoint for Batch 226.");
  if (recoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint && enrollRecoveryGateProofContinuityFinalizationReceiptExternalAttestationCheckpoint)
    await enroll(app, owner, "prepareRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointEnrollment",
      "applyRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleExternalAttestationFinalizationReceiptAttestationCheckpointEnrollment", "Enroll independent finalization-receipt external-attestation checkpoint for Batch 229.");
  return { app, owner, storage, anchors };
}

export async function prepareUnrecoverableLifecycle(app, owner, anchors) {
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalCheckpoint(owner);
  const lifecycle = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew only while lifecycle and checkpoint bindings remain current." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    lifecycle.challengeId, { confirmation: lifecycle.confirmation }));
  anchors.closureRecoveryReceipts.failWrites = false;
  await rotateKey(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycle(owner,
    lifecycle.challengeId, { confirmation: lifecycle.confirmation }),
  error => error.code === "RECOVERY_INTENT_CLOSURE_MARKER_JOURNAL_LIFECYCLE_INTENT_KEY_CUTOFF");
  return lifecycle;
}


export async function createCurrentRevalidation(t, owner, { revalidationLifecycleCheckpoint = false, requireRevalidationLifecycleFreshnessAttestation = false, revalidationLifecycleFreshnessAttestationMaxAgeMs = 300000,
  recoveryGateProofCheckpoint = false, enrollRecoveryGateProofCheckpoint = true, reuseRecoveryGateProofProvider = false,
  recoveryGateProofContinuityCheckpoint = false, enrollRecoveryGateProofContinuityCheckpoint = true, reuseRecoveryGateProofContinuityProvider = false,
  recoveryGateProofContinuityLifecycleCheckpoint = false, enrollRecoveryGateProofContinuityLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityLifecycleProvider = false,
  recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint = false, enrollRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint = true,
  reuseRecoveryGateProofContinuityLifecycleDriftEvidenceProvider = false,
  recoveryGateProofContinuityReceiptLifecycleCheckpoint = false, enrollRecoveryGateProofContinuityReceiptLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityReceiptLifecycleProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint = false, enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleProvider = false,
  recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptProvider = false,
  recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint = false,
  enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint = true,
  reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptProvider = false,
  requireReceiptLifecycleCheckpointBindingAttestation = false,
  requireFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation = false } = {}) {
  const { app, anchors } = await setupOwner(t, owner, { markerRecoveryJournal: true, lifecycleDispositionCheckpoint: true,
    revalidationLifecycleCheckpoint, requireRevalidationLifecycleFreshnessAttestation, revalidationLifecycleFreshnessAttestationMaxAgeMs,
    recoveryGateProofCheckpoint, enrollRecoveryGateProofCheckpoint, reuseRecoveryGateProofProvider,
    recoveryGateProofContinuityCheckpoint, enrollRecoveryGateProofContinuityCheckpoint, reuseRecoveryGateProofContinuityProvider,
    recoveryGateProofContinuityLifecycleCheckpoint, enrollRecoveryGateProofContinuityLifecycleCheckpoint,
    reuseRecoveryGateProofContinuityLifecycleProvider, recoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint,
    enrollRecoveryGateProofContinuityLifecycleDriftEvidenceCheckpoint, reuseRecoveryGateProofContinuityLifecycleDriftEvidenceProvider,
    recoveryGateProofContinuityReceiptLifecycleCheckpoint, enrollRecoveryGateProofContinuityReceiptLifecycleCheckpoint,
    reuseRecoveryGateProofContinuityReceiptLifecycleProvider, recoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleCheckpoint, reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleProvider,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptProvider,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationProvider,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleProvider,
    recoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationAttestationLifecycleReceiptAttestationLifecycleReceiptProvider,
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptProvider,
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptLifecycleAttestationProvider,
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleReceiptAttestationReceiptProvider,
    recoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint,
    enrollRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptCheckpoint,
    reuseRecoveryGateProofContinuityFinalizationReceiptBindingAttestationLifecycleAttestationReceiptProvider,
    requireReceiptLifecycleCheckpointBindingAttestation,
    requireFinalizationReceiptCheckpointBindingAttestationKeyCutoffRevalidation });
  const enrolledAnchor = structuredClone([...anchors.lifecycleDisposition.records.values()][0]);
  const lifecycle = await prepareUnrecoverableLifecycle(app, owner, anchors);
  const disposition = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    lifecycle.challengeId, { disposition: "quarantine", reason: "Prepare current rollback revalidation lifecycle evidence." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureMarkerRecoveryJournalAttestationLifecycleRecoveryIntentDisposition(owner,
    disposition.challengeId, { confirmation: disposition.confirmation });
  const [scope, latestAnchor] = [...anchors.lifecycleDisposition.records.entries()][0];
  anchors.lifecycleDisposition.records.set(scope, enrolledAnchor);
  const rollback = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    { disposition: "quarantine", reason: "Prepare rollback lifecycle for revalidation lifecycle tests." });
  await app.applyRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecoveryIntent(owner,
    rollback.challengeId, { confirmation: rollback.confirmation });
  anchors.lifecycleDisposition.records.set(scope, latestAnchor);
  const revalidated = await app.revalidateRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner, rollback.challengeId);
  assert.equal(revalidated.status, "revalidated_current");
  assert.equal(revalidated.results[0].usableForCurrentDecision, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureLifecycleDispositionCheckpointRollbackRecovery(owner);
  const latest = audit.latestRevalidations.find(item => item.challengeId === rollback.challengeId);
  assert.ok(latest?.attestationId);
  assert.equal(latest.current, true);
  return { app, owner, anchors, rollback, attestation: revalidated.results[0].attestation, audit };
}

