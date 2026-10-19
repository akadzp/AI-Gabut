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
function faultInjectingStorage(root, fault) {
  const base = createStorage({ root });
  return {
    read: key => base.read(key),
    write: async (key, value) => {
      if (fault.enabled && value?.kind === "recovery-slo-cross-domain-recovery-intent-closure-checkpoint-recovery-ledger"
        && value.events?.at(-1)?.eventType === "checkpoint_recovery_finalized")
        throw Object.assign(new Error("simulated crash before recovery receipt finalization"), { code: "SIMULATED_CRASH" });
      return base.write(key, value);
    },
    remove: key => base.remove(key),
    list: prefix => base.list(prefix)
  };
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
    ...(anchors.lifecycleRecovery ? { recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: anchors.lifecycleRecovery,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryAnchor: true } : {}),
    ...(anchors.lifecycleIntent ? { recoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: anchors.lifecycleIntent,
      requireRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentAnchor: true } : {}),
    ...(anchors.transition ? { recoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: anchors.transition,
      requireRecoverySloCrossDomainRecoveryIntentStatusTransitionAnchor: true } : {}),
    ...(anchors.disposition ? { recoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: anchors.disposition,
      requireRecoverySloCrossDomainRecoveryIntentOrphanDispositionAnchor: true } : {}),
    ...(anchors.requireFreshness ? { requireRecoverySloCrossDomainRecoveryIntentClosureFreshnessAttestation: true,
      recoverySloCrossDomainRecoveryIntentClosureFreshnessAttestationMaxAgeMs: 300000 } : {})
  });
}
async function enroll(app, owner, prepare, apply, reason) {
  const challenge = await app[prepare](owner, { reason });
  return app[apply](owner, challenge.challengeId, { confirmation: challenge.confirmation });
}
async function activateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Activate the key for Batch 188 regression coverage." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function enrollReceiptCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment", "Enroll receipt checkpoint for Batch 189.");
}
async function enrollFinalizationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizationCheckpointEnrollment", "Enroll finalization checkpoint for Batch 189.");
}
async function enrollReconciliationCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryReconciliationCheckpointEnrollment", "Enroll reconciliation checkpoint for Batch 189.");
}
async function enrollLifecycleRecoveryCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleRecoveryCheckpointEnrollment", "Enroll lifecycle recovery-receipt checkpoint for Batch 189.");
}
async function enrollLifecycleIntentCheckpoint(app, owner) {
  return enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpointEnrollment", "Enroll lifecycle recovery-intent checkpoint for Batch 189.");
}
async function enrollClosureCheckpoints(app, owner) {
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointEnrollment", "Enroll transition closure checkpoint for Batch 189.");
  await enroll(app, owner, "prepareRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointEnrollment", "Enroll disposition receipt checkpoint for Batch 189.");
}
async function createFinalization(app, storage, owner) {
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  return app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
}
async function rotateKey(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Rotate the key to validate Batch 189 cutoff enforcement." });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function setupOwner(t, owner, { requireFreshness = false, injectFinalizationCrash = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `agentic-b189-${owner}-`));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const anchors = { receipt: anchorProvider(`https://${owner}-receipt.example`),
    finalization: anchorProvider(`https://${owner}-finalization.example`),
    reconciliation: anchorProvider(`https://${owner}-reconciliation.example`),
    lifecycleRecovery: anchorProvider(`https://${owner}-lifecycle-recovery.example`),
    lifecycleIntent: anchorProvider(`https://${owner}-lifecycle-intent.example`),
    transition: anchorProvider(`https://${owner}-transition.example`),
    disposition: anchorProvider(`https://${owner}-disposition.example`), requireFreshness };
  const { options: keyOptions } = keyMaterial();
  const fault = { enabled: false };
  const storage = injectFinalizationCrash ? faultInjectingStorage(root, fault) : createStorage({ root });
  const app = makeApp(storage, keyOptions, anchors);
  await activateKey(app, owner);
  await enrollReceiptCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-bootstrap` });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: `${owner}-source-receipt` });
  await enrollFinalizationCheckpoint(app, owner);
  await enrollReconciliationCheckpoint(app, owner);
  await enrollLifecycleRecoveryCheckpoint(app, owner);
  await enrollLifecycleIntentCheckpoint(app, owner);
  await enrollClosureCheckpoints(app, owner);
  const recovered = await createFinalization(app, storage, owner);
  return { app, storage, anchors, keyOptions, recovered, owner, fault };
}
async function applyLifecycle(app, owner, targetId, action = "renew") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, targetId,
    { action, reason: `Batch 189 ${action} operation for closure checkpoint regression coverage.` });
  const result = await app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  return { challenge, result };
}
async function orphanIntent(context) {
  const { app, owner, recovered, anchors, storage } = context;
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    recovered.finalizationReceipt.receipt.id, { action: "renew", reason: "Create a pending intent for closure checkpoint coverage." });
  anchors.lifecycleIntent.failWrites = true;
  await assert.rejects(() => app.applyRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycle(owner,
    challenge.challengeId, { confirmation: challenge.confirmation }), error => error.code === "RECOVERY_FINALIZATION_ATTESTATION_LIFECYCLE_INTENT_CHECKPOINT_ADVANCE_PENDING");
  anchors.lifecycleIntent.failWrites = false;
  await app.reconcileRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryAttestationLifecycleIntentCheckpoint(owner);
  const store = createAgenticStore({ storage });
  const intent = (await store.listEvidence(owner)).find(row => row?.ownerId === owner
    && row.kind === "recovery-slo-cross-domain-recovery-decision-gate-receipt-recovery-attestation-lifecycle-intent");
  const savedChallenge = await store.getEvidence(owner, challenge.challengeId);
  await store.state.delete("evidence", `${owner}--${challenge.challengeId}`, { expectedVersion: savedChallenge._storage?.version });
  return { intent, challenge };
}


test("Batch 189: missing closure checkpoint marker recovery writes a signed, anchor-bound finalization receipt", async t => {
  const context = await setupOwner(t, "b189-recovery-receipt");
  const { app, owner, storage } = context;
  const store = createAgenticStore({ storage });
  const markerId = `recovery-intent-status-transition-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const result = await app.recoverRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(result.status, "marker_recovered");
  assert.equal(result.finalizationReceipt.status, "finalized");
  assert.ok(result.finalizationReceipt.receipt.attestation?.signature);
  assert.equal(result.finalizationReceipt.receipt.resultAnchorDigest, inspection.anchorDigest);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingCount, 0);
  assert.equal(audit.events.filter(event => event.eventType === "checkpoint_recovery_intent").length, 1);
  assert.equal(audit.events.filter(event => event.eventType === "checkpoint_recovery_finalized").length, 1);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(server, /recovery-intent-closure\/recovery-receipts\/audit/);
  assert.match(server, /recovery-intent-closure\/checkpoint-freshness\/attest/);
});

test("Batch 189: interrupted local receipt finalization resumes from the same intent after marker commit", async t => {
  const context = await setupOwner(t, "b189-crash-recovery", { injectFinalizationCrash: true });
  const { app, owner, storage, fault } = context;
  const store = createAgenticStore({ storage });
  const markerId = `recovery-intent-status-transition-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  fault.enabled = true;
  await assert.rejects(() => app.recoverRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner),
    error => error.code === "RECOVERY_INTENT_CLOSURE_CAS_RETRY_EXHAUSTED");
  fault.enabled = false;
  const pending = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(pending.status, "recovery_required");
  assert.equal(pending.pendingCount, 1);
  const resumed = await app.recoverRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(resumed.status, "marker_already_current");
  assert.equal(resumed.finalizationReceipt.status, "finalized");
  assert.equal(resumed.recoveryIntent.id, pending.pendingIntents[0].id);
  const finalAudit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(finalAudit.status, "healthy");
  assert.equal(finalAudit.pendingCount, 0);
  assert.equal(finalAudit.events.filter(event => event.eventType === "checkpoint_recovery_intent").length, 1);
  assert.equal(finalAudit.events.filter(event => event.eventType === "checkpoint_recovery_finalized").length, 1);
});

test("Batch 189: checkpoint freshness attestation is bound to both anchors and becomes stale after key rotation", async t => {
  const context = await setupOwner(t, "b189-freshness", { requireFreshness: true });
  const { app, owner, recovered } = context;
  await applyLifecycle(app, owner, recovered.finalizationReceipt.receipt.id);
  const issued = await app.attestRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(issued.status, "attested");
  assert.equal(issued.attestation.attestation?.signature !== undefined, true);
  const current = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(current.status, "verified_current");
  assert.equal(current.usableForCurrentDecision, true);
  const closure = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.equal(closure.freshnessAttestation.usableForCurrentDecision, true);
  await rotateKey(app, owner);
  const stale = await app.auditRecoverySloCrossDomainRecoveryIntentClosureCheckpointFreshness(owner);
  assert.equal(stale.status, "stale");
  assert.equal(stale.usableForCurrentDecision, false);
  const after = await app.auditRecoverySloCrossDomainRecoveryIntentClosure(owner);
  assert.notEqual(after.status, "healthy");
  assert.equal(after.usableForCurrentDecision, false);
});

test("Batch 189: recovery finalization records a signing-key cutoff and signs the closure receipt with the current key", async t => {
  const context = await setupOwner(t, "b189-key-cutoff");
  const { app, owner, storage } = context;
  const store = createAgenticStore({ storage });
  const markerId = `recovery-intent-status-transition-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const prepared = await app.prepareRecoverySloCrossDomainRecoveryIntentClosureCheckpointRecoveryIntent(owner, "status_transition");
  assert.equal(prepared.status, "prepared");
  await rotateKey(app, owner);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentStatusTransitionCheckpoint(owner);
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  assert.equal(recovered.finalizationReceipt.keyCutoffDetected, true);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_INTENT_CLOSURE_RECOVERY_KEY_CUTOFF_REVALIDATED"));
  assert.equal(audit.pendingCount, 0);
});

test("Batch 189: orphan-disposition checkpoint marker recovery is bound to its own external anchor and receipt", async t => {
  const context = await setupOwner(t, "b189-disposition-marker");
  const { app, owner, storage } = context;
  const store = createAgenticStore({ storage });
  const markerId = `recovery-intent-orphan-disposition-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentOrphanDispositionCheckpoint(owner);
  assert.equal(recovered.status, "marker_recovered");
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  assert.equal(recovered.finalizationReceipt.receipt.checkpointName, "orphan_disposition");
  assert.equal(recovered.finalizationReceipt.receipt.resultAnchorDigest, inspection.anchorDigest);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentClosureRecoveryReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingCount, 0);
  assert.ok(audit.events.some(event => event.eventType === "checkpoint_recovery_finalized" && event.checkpointName === "orphan_disposition"));
});
