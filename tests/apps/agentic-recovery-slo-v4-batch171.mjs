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
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
function anchorProvider(baseUrl) {
  const records = new Map(); let forceConflict = false;
  return { baseUrl, setForceConflict(value) { forceConflict = Boolean(value); },
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      if (forceConflict) return { applied: false };
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
function signer(pair) { return payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url"); }
async function setupFinalization(root, owner, { finalizationAnchor = null, clock = () => "2026-10-13T00:00:00.000Z", extra = {} } = {}) {
  const pair = generateKeyPairSync("ed25519");
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock,
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(pair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_1",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: { finalization_key_1: pair.publicKey },
    requireRecoverySloDriftRemediationFinalizationAttestation: true,
    ...(finalizationAnchor ? { recoverySloCrossDomainDriftRemediationFinalizationAnchor: finalizationAnchor,
      requireRecoverySloCrossDomainDriftRemediationFinalizationAnchor: true } : {}), ...extra });
  return { app, storage, pair };
}
async function setupAnchoredReceiptCheckpoint(root, owner, extra = {}) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const keyTransitionProvider = anchorProvider(`https://${owner}.key-transition-anchor.example`);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock,
    recoverySloPolicyBindingAuditCheckpointAttestationSigner: signer(oldPair), recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old",
    recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: { key_old: oldPair.publicKey, key_next: nextPair.publicKey },
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: { key_old: signer(oldPair), key_next: signer(nextPair) },
    recoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: keyTransitionProvider,
    requireRecoverySloCrossDomainAttestationKeyTransitionReceiptAnchor: true, ...extra });
  const rotation = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate the signing key before exercising integrated remediation finalization attestation." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotation.challengeId,
    { confirmation: rotation.confirmation });
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the key-transition receipt checkpoint before integrated remediation testing." });
  await app.applyRecoverySloCrossDomainAttestationKeyTransitionReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  return { app, storage, clock, advance: milliseconds => { nowMs += milliseconds; } };
}
async function createReceiptForRetentionReview(app, owner) {
  const bundle = await app.exportRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEvents(owner);
  return app.verifyAndRecordRecoverySloCrossDomainRetentionReviewRevalidationLeaseAuditEventExport(owner, bundle);
}
async function prepareAgedReceiptLedger(root, owner, lifecycleProvider, executionProvider, finalizationProvider, finalizationPair) {
  const receiptAnchor = anchorProvider(`https://${owner}.verification-receipt-anchor.example`);
  const setup = await setupAnchoredReceiptCheckpoint(root, owner, {
    recoverySloCrossDomainLeaseExportVerificationReceiptAnchor: receiptAnchor,
    requireRecoverySloCrossDomainLeaseExportVerificationReceiptAnchor: true,
    recoverySloCrossDomainRetentionApprovalLifecycleAnchor: lifecycleProvider,
    requireRecoverySloCrossDomainRetentionApprovalLifecycleAnchor: true,
    recoverySloCrossDomainDriftRemediationExecutionAnchor: executionProvider,
    requireRecoverySloCrossDomainDriftRemediationExecutionAnchor: true,
    recoverySloCrossDomainDriftRemediationFinalizationAnchor: finalizationProvider,
    requireRecoverySloCrossDomainDriftRemediationFinalizationAnchor: true,
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(finalizationPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_1",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: { finalization_key_1: finalizationPair.publicKey },
    requireRecoverySloDriftRemediationFinalizationAttestation: true
  });
  await createReceiptForRetentionReview(setup.app, owner);
  const enrollment = await setup.app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll verification receipts before the integrated remediation finalization test." });
  await setup.app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await createReceiptForRetentionReview(setup.app, owner);
  setup.advance(91 * 86400000);
  await setup.app.reconcileRecoverySloCrossDomainLeaseExportVerificationReceiptCheckpoint(owner);
  return setup;
}
async function prepareRetentionApproval(app, owner) {
  const challenge = await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner,
    { decision: "retain", reason: "Retain aged verification receipts after source-bound review for integrated remediation." });
  const applied = await app.applyRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReview(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  return applied.approval;
}

async function seedFinalization(storage, owner, suffix = "one", createdAt = "2026-10-13T00:00:00.000Z") {
  const store = createAgenticStore({ storage });
  const action = "reconcile_policy_binding_audit_checkpoint";
  const planUnsigned = { id: `b171-plan-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-plan",
    schemaVersion: 1, status: "prepared", reason: "Create a valid remediation plan fixture for finalization attestation tests.",
    createdAt, expiresAt: new Date(Date.parse(createdAt) + 10 * 60_000).toISOString(), stateFingerprint: "d".repeat(64),
    allowedActions: [action], blockedActions: [], auditStatus: "blocked", auditFindingsDigest: "e".repeat(64),
    deletionPerformed: false, compactionPerformed: false };
  const plan = { ...planUnsigned, digest: digestRecord(planUnsigned) };
  await store.putEvidence(owner, plan, { overwrite: false });
  const intentUnsigned = { id: `b171-intent-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-recovery-intent",
    schemaVersion: 1, status: "completed", planId: plan.id, planDigest: plan.digest, stateFingerprint: plan.stateFingerprint,
    action, confirmationDigest: sha256(`EXECUTE CROSS-DOMAIN DRIFT REMEDIATION ${plan.digest.slice(0, 12)}`),
    createdAt, finalizedAt: createdAt, resultAnchorDigest: null };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  const executionUnsigned = { id: `b171-execution-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-execution",
    schemaVersion: 1, planId: plan.id, planDigest: plan.digest, recoveryIntentId: intent.id,
    recoveryIntentDigest: intent.digest, action, status: "completed", createdAt, completedAt: createdAt,
    deletionPerformed: false, compactionPerformed: false };
  const execution = { ...executionUnsigned, digest: digestRecord(executionUnsigned) };
  await store.putEvidence(owner, execution, { overwrite: false });
  const finalizationUnsigned = { id: `b171-finalization-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-finalization",
    schemaVersion: 1, intentId: intent.id, intentDigest: intent.digest, executionId: execution.id, executionDigest: execution.digest,
    checkpointDomain: "cross_domain_drift_remediation_executions", checkpointStatus: "anchored",
    checkpointAnchorDigest: "c".repeat(64), checkpointAnchorSequence: 1, checkpointHistoryNotProven: false,
    usableForCurrentDecision: true, finalizedAt: createdAt, deletionPerformed: false, compactionPerformed: false };
  const finalization = { ...finalizationUnsigned, digest: digestRecord(finalizationUnsigned) };
  await store.putEvidence(owner, finalization, { overwrite: false });
  return { plan, intent, execution, finalization, store };
}

 test("Batch 171: remediation finalization attestation is Ed25519-signed, finalization-bound, and tamper-evident", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b171-attestation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b171-attestation";
  const { app, storage } = await setupFinalization(root, owner);
  const { finalization } = await seedFinalization(storage, owner);
  const created = await app.createRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, finalization.id);
  assert.equal(created.status, "created");
  assert.equal(created.verification.historicallyValid, true);
  const verified = await app.verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, created.attestation.id, { checkCurrent: false });
  assert.equal(verified.status, "verified_historical_only");
  assert.equal(verified.usableForCurrentDecision, false);
  const audit = await app.auditRecoverySloCrossDomainDriftRemediationFinalizationAttestations(owner);
  assert.equal(audit.status, "healthy");
  const store = createAgenticStore({ storage });
  await store.mutateEvidence(owner, created.attestation.id, current => ({ value: { ...current, signature: `${current.signature.slice(0, -1)}${current.signature.endsWith("A") ? "B" : "A"}` } }));
  const tampered = await app.verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, created.attestation.id, { checkCurrent: false });
  assert.equal(tampered.status, "unhealthy");
  assert.equal(tampered.usableForCurrentDecision, false);
});

test("Batch 171: finalization attestation checkpoint enrolls and recovers a missing marker from the exact external anchor", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b171-finalization-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b171-finalization-recovery";
  const provider = anchorProvider(`https://${owner}.finalization-anchor.example`);
  const { app, storage } = await setupFinalization(root, owner, { finalizationAnchor: provider });
  const { finalization } = await seedFinalization(storage, owner);
  const attestation = await app.createRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, finalization.id);
  assert.equal(attestation.verification.historicallyValid, true);
  const enrollment = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationCheckpointEnrollment(owner,
    { reason: "Enroll signed remediation finalization evidence before testing marker crash recovery." });
  const enrolled = await app.applyRecoverySloCrossDomainDriftRemediationFinalizationCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const store = createAgenticStore({ storage });
  const marker = (await store.listEvidence(owner)).find(row => row.kind === "cross-domain-drift-remediation-finalization-checkpoint-marker");
  assert.ok(marker);
  await store.mutateEvidence(owner, marker.id, () => ({ delete: true }));
  const inspection = await app.inspectRecoverySloCrossDomainDriftRemediationFinalizationCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainDriftRemediationFinalizationCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.checkpoint.status, "anchored");
  assert.equal((await app.getRecoverySloCrossDomainDriftRemediationFinalizationCheckpointStatus(owner)).anchorDigest, enrolled.anchorDigest);
});

test("Batch 171: policy-binding lifecycle checkpoint recovers a missing marker with a persisted recovery intent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b171-policy-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b171-policy-recovery";
  const provider = anchorProvider(`https://${owner}.policy-lifecycle-anchor.example`);
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloCrossDomainPolicyBindingReceiptLifecycleAnchor: provider,
    requireRecoverySloCrossDomainPolicyBindingReceiptLifecycleAnchor: true });
  const receipt = await app.createRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceipt(owner,
    "cross_domain_lease_export_verification_receipts");
  const challenge = await app.prepareRecoverySloCrossDomainCheckpointPolicyBindingVerificationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Prepare a lifecycle event before checkpoint marker recovery validation." });
  assert.ok(challenge.challengeId);
  const enrollment = await app.prepareRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll policy-binding lifecycle history before simulating a lost local marker." });
  await app.applyRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const store = createAgenticStore({ storage });
  const marker = (await store.listEvidence(owner)).find(row => row.kind === "cross-domain-policy-binding-receipt-lifecycle-checkpoint-marker");
  assert.ok(marker);
  await store.mutateEvidence(owner, marker.id, () => ({ delete: true }));
  const inspection = await app.inspectRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.checkpoint.status, "anchored");
  const intents = await app.auditRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointRecoveryIntents(owner);
  assert.equal(intents.status, "healthy");
  assert.equal(intents.pendingCount, 0);
});

test("Batch 171: cross-domain freshness/replay audit blocks stale anchors and preserves rollback findings", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b171-freshness-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b171-freshness";
  const provider = anchorProvider(`https://${owner}.finalization-anchor.example`);
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const { app, storage } = await setupFinalization(root, owner, { finalizationAnchor: provider, clock });
  const { finalization } = await seedFinalization(storage, owner, "freshness", clock());
  await app.createRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, finalization.id);
  const enrollment = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationCheckpointEnrollment(owner,
    { reason: "Enroll signed finalization evidence before validating cross-domain freshness." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  nowMs += 3 * 86400000;
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.equal(audit.status, "blocked");
  assert.ok(audit.findings.some(item => item.code === "CROSS_DOMAIN_CHECKPOINT_FRESHNESS_NOT_CURRENT"));
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 171: real remediation finalization automatically creates a signed receipt and binds it to the finalization checkpoint", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b171-integrated-finalization-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b171-int";
  const lifecycleProvider = anchorProvider(`https://${owner}.retention-lifecycle-anchor.example`);
  const executionProvider = anchorProvider(`https://${owner}.execution-anchor.example`);
  const finalizationProvider = anchorProvider(`https://${owner}.finalization-anchor.example`);
  const finalizationPair = generateKeyPairSync("ed25519");
  const { app, storage } = await prepareAgedReceiptLedger(root, owner, lifecycleProvider, executionProvider, finalizationProvider, finalizationPair);
  const approval = await prepareRetentionApproval(app, owner);
  const lifecycleEnrollment = await app.prepareRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the retention approval lifecycle before creating an integrated remediation plan." });
  await app.applyRecoverySloCrossDomainRetentionApprovalLifecycleCheckpointEnrollment(owner, lifecycleEnrollment.challengeId,
    { confirmation: lifecycleEnrollment.confirmation });
  lifecycleProvider.setForceConflict(true);
  await app.prepareRecoverySloCrossDomainLeaseExportVerificationReceiptLedgerRetentionReviewRevocation(owner, approval.id,
    { reason: "Create a single lifecycle event gap for integrated remediation finalization." });
  const plan = await app.prepareRecoverySloCrossDomainDriftRemediationPlan(owner,
    { reason: "Execute a proven single-event reconciliation and verify signed finalization evidence." });
  assert.ok(plan.allowedActions.includes("reconcile_retention_approval_lifecycle_checkpoint"));
  await assert.rejects(() => app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation }),
    error => error?.code === "CROSS_DOMAIN_DRIFT_REMEDIATION_EXECUTION_CHECKPOINT_REQUIRED");
  const executionEnrollment = await app.prepareRecoverySloCrossDomainDriftRemediationExecutionCheckpointEnrollment(owner,
    { reason: "Enroll the durable remediation intent before executing its approved action." });
  await app.applyRecoverySloCrossDomainDriftRemediationExecutionCheckpointEnrollment(owner, executionEnrollment.challengeId,
    { confirmation: executionEnrollment.confirmation });
  lifecycleProvider.setForceConflict(false);
  const result = await app.executeRecoverySloCrossDomainDriftRemediationPlan(owner, plan.planId,
    { action: "reconcile_retention_approval_lifecycle_checkpoint", confirmation: plan.confirmation });
  assert.ok(result.finalization.id);
  assert.ok(result.finalizationAttestation.id);
  assert.equal(result.finalizationAttestationStatus, "verified_historical_only");
  assert.equal(result.finalizationCheckpoint.status, "enrollment_required");
  assert.equal(result.usableForCurrentDecision, false);
  const audit = await app.auditRecoverySloCrossDomainDriftRemediationFinalizationAttestations(owner);
  assert.equal(audit.status, "healthy");
  const enrollment = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationCheckpointEnrollment(owner,
    { reason: "Enroll the signed finalization ledger after its first attested event." });
  const enrolled = await app.applyRecoverySloCrossDomainDriftRemediationFinalizationCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const verified = await app.verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, result.finalizationAttestation.id);
  assert.equal(verified.historicallyValid, true);
  assert.equal(verified.usableForCurrentDecision, false);
  assert.equal((await createAgenticStore({ storage }).listEvidence(owner)).some(row => row.kind === "recovery-slo-cross-domain-drift-remediation-finalization-attestation"), true);
});

test("Batch 171: required attestation configuration fails closed and all new APIs are wired to HTTP routes", async () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b171-invalid-config" }),
    requireRecoverySloDriftRemediationFinalizationAttestation: true }), /signer dan trusted public key Ed25519/);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["createRecoverySloCrossDomainDriftRemediationFinalizationAttestation",
    "verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation", "auditRecoverySloCrossDomainDriftRemediationFinalizationAttestations",
    "getRecoverySloCrossDomainDriftRemediationFinalizationCheckpointStatus", "recoverRecoverySloCrossDomainDriftRemediationFinalizationCheckpoint",
    "inspectRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpointRecovery",
    "recoverRecoverySloCrossDomainPolicyBindingReceiptLifecycleCheckpoint", "auditRecoverySloCrossDomainCheckpointFreshnessReplay"])
    assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /drift-remediation\/finalization-attestations/);
  assert.match(server, /drift-remediation\/finalization-checkpoint\/recovery/);
  assert.match(server, /policy-binding-receipt-lifecycle\/checkpoint\/recovery/);
  assert.match(server, /checkpoints\/freshness-replay\/audit/);
});
