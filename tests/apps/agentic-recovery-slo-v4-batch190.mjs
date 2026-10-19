import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
function anchorProvider(baseUrl) {
  const records = new Map();
  return { baseUrl, records, failWrites: false,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      if (this.failWrites) return { applied: false };
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
function keyMaterial() {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  return { options: {
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)]))
  } };
}
function makeApp(storage, keyOptions, anchors, clock = () => "2026-10-14T00:00:00.000Z") {
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
    requireRecoverySloCrossDomainRecoveryIntentClosureFreshnessAttestation: Boolean(anchors.requireFreshness),
    recoverySloCrossDomainRecoveryIntentClosureFreshnessAttestationMaxAgeMs: 300000
  });
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the signing key for Batch 190 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate signing key to validate Batch 190 cutoff enforcement." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollClosureCheckpoints(app, owner) {
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 190.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition closure checkpoint for Batch 190.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointEnrollment", "Enroll closure recovery receipt checkpoint for Batch 190.");
}
async function setupOwner(t, owner, { requireFreshness = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b190-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`),
    lifecycleIntent: anchorProvider(`https://${owner}-lifecycle-intent.example`),
    transition: anchorProvider(`https://${owner}-transition.example`),
    disposition: anchorProvider(`https://${owner}-disposition.example`),
    closureRecoveryReceipts: anchorProvider(`https://${owner}-closure-recovery-receipts.example`), requireFreshness };
  const { options: keyOptions } = keyMaterial();
  const storage = createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors);
  await activateKey(app, owner);
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll base receipt checkpoint for Batch 190.");
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 190.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 190.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery checkpoint for Batch 190.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle intent checkpoint for Batch 190.");
  await enrollClosureCheckpoints(app, owner);
  return { app, owner, storage, anchors };
}
async function removeTransitionMarker(storage, owner) {
  const store = createAgenticStore({ storage });
  const markerId = `recovery-intent-status-transition-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
}

test("Batch 190: recovery-receipt ledger is independently anchored and closure continuity is current", async t => {
  const { app, owner, storage } = await setupOwner(t, "b190-receipt-anchor");
  const initial = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(initial.status, "healthy");
  assert.equal(initial.usableForCurrentDecision, true);
  await removeTransitionMarker(storage, owner);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  const continuity = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptContinuity(owner);
  assert.equal(continuity.status, "verified_current");
  assert.equal(continuity.usableForCurrentDecision, true);
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointStatus(owner);
  assert.equal(checkpoint.status, "anchored");
  assert.equal(checkpoint.sourceCount, continuity.recoveryReceiptAudit.eventCount);
  assert.notEqual(checkpoint.domain, "cross_domain_recovery_intent_status_transitions");
  assert.equal(checkpoint.anchorSequence, checkpoint.sourceCount + 1);
});

test("Batch 190: external commit interruption resumes the same recovery intent without duplicate receipts", async t => {
  const { app, owner, storage, anchors } = await setupOwner(t, "b190-receipt-crash");
  await removeTransitionMarker(storage, owner);
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.recoverRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner),
    error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  const pending = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptContinuity(owner);
  assert.equal(pending.status, "single_event_pending");
  assert.equal(pending.usableForCurrentDecision, false);
  anchors.closureRecoveryReceipts.failWrites = false;
  const reconciled = await app.reconcileRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpoint(owner);
  assert.equal(reconciled.status, "anchored");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  const finalAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(finalAudit.status, "healthy");
  assert.equal(finalAudit.pendingCount, 0);
  assert.equal(finalAudit.continuityAudit.status, "verified_current");
  assert.equal(finalAudit.events.filter(event => event.eventType === "checkpoint_recovery_intent").length, 1);
  assert.equal(finalAudit.events.filter(event => event.eventType === "checkpoint_recovery_finalized").length, 1);
});

test("Batch 190: freshness attestation renewal and revocation are signed, anchored, and enforced", async t => {
  const { app, owner } = await setupOwner(t, "b190-freshness-lifecycle", { requireFreshness: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(issued.status, "attested");
  let audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(audit.status, "verified_current");
  const renewal = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew current closure freshness evidence for the active decision." });
  const renewed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    renewal.challengeId, { confirmation: renewal.confirmation });
  assert.equal(renewed.status, "completed");
  assert.equal(renewed.event.lifecycleAction, "renew");
  audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(audit.status, "verified_current");
  const revocation = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "revoke", eventId: renewed.event.id, reason: "Revoke closure freshness evidence after explicit policy review." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    revocation.challengeId, { confirmation: revocation.confirmation });
  assert.equal(revoked.status, "completed");
  assert.equal(revoked.event.eventType, "checkpoint_freshness_attestation_revoked");
  audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(audit.status, "revoked");
  assert.equal(audit.usableForCurrentDecision, false);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(closure.status, "healthy");
  assert.equal(closure.usableForCurrentDecision, false);
});

test("Batch 190: freshness lifecycle challenge is invalidated by signing-key cutoff", async t => {
  const { app, owner } = await setupOwner(t, "b190-key-cutoff", { requireFreshness: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew closure freshness evidence before testing key cutoff." });
  await rotateKey(app, owner);
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_INTENT_CLOSURE_FRESHNESS_LIFECYCLE_STALE");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(audit.status, "stale");
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 190: receipt checkpoint endpoint independence is enforced and HTTP routes are present", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b190-independent-provider");
  assert.notEqual(anchors.closureRecoveryReceipts.baseUrl, anchors.transition.baseUrl);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-intent-closure\/recovery-receipt-checkpoint\/enrollment\/prepare/);
  assert.match(server, /recovery-intent-closure\/checkpoint-freshness\/lifecycle\/apply/);
  assert.match(server, /recovery-intent-closure\/recovery-receipts\/continuity/);
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptCheckpointStatus(owner)).usableForCurrentDecision, true);
});
test("Batch 190: interrupted freshness renewal resumes the same signed event after receipt-anchor CAS recovery", async t => {
  const { app, owner, anchors } = await setupOwner(t, "b190-renewal-crash", { requireFreshness: true });
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    { action: "renew", eventId: issued.attestation.id, reason: "Renew freshness evidence and exercise receipt-anchor crash recovery." });
  anchors.closureRecoveryReceipts.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }),
    error => error.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_RECEIPT_CHECKPOINT_ADVANCE_PENDING");
  const pending = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceiptContinuity(owner);
  assert.equal(pending.status, "single_event_pending");
  anchors.closureRecoveryReceipts.failWrites = false;
  const resumed = await app.applyRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshnessAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
  assert.equal(resumed.status, "completed");
  assert.equal(resumed.idempotent, true);
  assert.equal(resumed.event.lifecycleChallengeId, challenge.challengeId);
  const ledger = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(ledger.events.filter(event => event.operationId === `checkpoint-freshness-lifecycle:${challenge.challengeId}`).length, 1);
  assert.equal(ledger.continuityAudit.status, "verified_current");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner)).status, "verified_current");
});

test("Batch 190: reused external provider is detected as a trust-domain independence violation", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b190-provider-reuse-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider("https://b190-reuse-receipt.example"),
    finalization: anchorProvider("https://b190-reuse-finalization.example"),
    reconciliation: anchorProvider("https://b190-reuse-reconciliation.example"),
    lifecycleRecovery: anchorProvider("https://b190-reuse-lifecycle-recovery.example"),
    lifecycleIntent: anchorProvider("https://b190-reuse-lifecycle-intent.example"),
    transition: anchorProvider("https://b190-reuse-transition.example"),
    disposition: anchorProvider("https://b190-reuse-disposition.example"), requireFreshness: false };
  anchors.closureRecoveryReceipts = anchors.transition;
  const { options } = keyMaterial();
  const app = makeApp(createStorage({ root }), options, anchors);
  const report = await app.auditRecoverySloAnchorTrustDomainIndependence("b190-provider-reuse");
  assert.equal(report.status, "unhealthy");
  assert.ok(report.collisions.some(item => item.domains.includes("cross_domain_recovery_intent_closure_recovery_receipts")
    && item.domains.includes("cross_domain_recovery_intent_status_transitions")));
});

