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
const signer = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
function anchorProvider(baseUrl) {
  const records = new Map();
  return { baseUrl,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
async function setup(root, extra = {}) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    ...extra });
  return { app, storage, pairs };
}
async function seedFinalization(storage, owner, suffix = "one", createdAt = "2026-10-13T00:00:00.000Z") {
  const store = createAgenticStore({ storage });
  const action = "reconcile_policy_binding_audit_checkpoint";
  const planUnsigned = { id: `b176-plan-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-plan", schemaVersion: 1,
    status: "prepared", reason: "Seed a source-bound remediation plan for Batch 176 attestation checkpoint tests.", createdAt,
    expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString(), stateFingerprint: "d".repeat(64),
    allowedActions: [action], blockedActions: [], auditStatus: "blocked", auditFindingsDigest: "e".repeat(64),
    deletionPerformed: false, compactionPerformed: false };
  const plan = { ...planUnsigned, digest: digestRecord(planUnsigned) };
  await store.putEvidence(owner, plan, { overwrite: false });
  const intentUnsigned = { id: `b176-intent-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-recovery-intent",
    schemaVersion: 1, status: "completed", planId: plan.id, planDigest: plan.digest, stateFingerprint: plan.stateFingerprint,
    action, confirmationDigest: sha256(`EXECUTE CROSS-DOMAIN DRIFT REMEDIATION ${plan.digest.slice(0, 12)}`),
    createdAt, finalizedAt: createdAt, resultAnchorDigest: null };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  const executionUnsigned = { id: `b176-execution-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-execution",
    schemaVersion: 1, planId: plan.id, planDigest: plan.digest, recoveryIntentId: intent.id,
    recoveryIntentDigest: intent.digest, action, status: "completed", resultDigest: "a".repeat(64), createdAt, completedAt: createdAt,
    deletionPerformed: false, compactionPerformed: false };
  const execution = { ...executionUnsigned, digest: digestRecord(executionUnsigned) };
  await store.putEvidence(owner, execution, { overwrite: false });
  const finalizationUnsigned = { id: `b176-finalization-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-finalization",
    schemaVersion: 1, intentId: intent.id, intentDigest: intent.digest, executionId: execution.id, executionDigest: execution.digest,
    checkpointDomain: "cross_domain_drift_remediation_executions", checkpointStatus: "anchored",
    checkpointAnchorDigest: "c".repeat(64), checkpointAnchorSequence: 1, checkpointHistoryNotProven: false,
    usableForCurrentDecision: true, finalizedAt: createdAt, deletionPerformed: false, compactionPerformed: false };
  const finalization = { ...finalizationUnsigned, digest: digestRecord(finalizationUnsigned) };
  await store.putEvidence(owner, finalization, { overwrite: false });
  return { store, plan, intent, execution, finalization };
}
async function enrollAttestationCheckpoint(app, owner, reason = "Enroll an empty attestation history before new lifecycle events.") {
  const challenge = await app.prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointEnrollment(owner, { reason });
  return app.applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointEnrollment(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function revokeReceipt(app, storage, owner, suffix) {
  const seeded = await seedFinalization(storage, owner, suffix);
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Revoke a test receipt to verify external attestation history anchoring." });
  return app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}

test("Batch 176: required attestation-history anchor fails closed without a provider", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b176-required-anchor" }),
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: true }),
  /External CAS finalization receipt lifecycle attestation checkpoint diwajibkan/);
});

test("Batch 176: lifecycle attestation history is externally anchored independently from the lifecycle-event checkpoint", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b176-attestation-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b176-attestation-anchor", provider = anchorProvider("https://b176-attestation-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: provider,
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: true });
  const first = await revokeReceipt(app, storage, owner, "pre-enrollment");
  assert.equal(first.recoveryStatus, "awaiting_enrollment");
  const enrollment = await enrollAttestationCheckpoint(app, owner);
  assert.equal(enrollment.status, "anchored");
  const second = await revokeReceipt(app, storage, owner, "post-enrollment");
  assert.equal(second.recoveryStatus, "completed_history_unproven");
  const status = await app.getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointStatus(owner);
  assert.equal(status.status, "anchored");
  assert.equal(status.freshnessStatus, "fresh");
  assert.equal(status.historyNotProven, true);
  const audit = await app.auditRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.sourceCount, 2);
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 176: attestation checkpoint marker recovery is intent-bound and idempotent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b176-marker-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b176-marker-recovery", provider = anchorProvider("https://b176-recovery-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: provider,
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: true });
  await revokeReceipt(app, storage, owner, "marker");
  await enrollAttestationCheckpoint(app, owner);
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-cas-finalization-receipt-lifecycle-attestation-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal((await app.getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointStatus(owner)).status, "anchored");
  const ledgerAudit = await app.auditRecoverySloCrossDomainRecoveryIntentLedgerIntegrity(owner);
  assert.notEqual(ledgerAudit.status, "unhealthy");
});

test("Batch 176: recovery decision gate blocks an un-enrolled required attestation checkpoint", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b176-gate-block-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const provider = anchorProvider("https://b176-gate-anchor.example");
  const { app } = await setup(root, { recoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: provider,
    requireRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationAnchor: true });
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay("b176-gate-owner");
  assert.notEqual(audit.status, "healthy");
  assert.ok(audit.findings.some(item => item.code === "CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_CHECKPOINT_NOT_CURRENT"));
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.lifecycleAttestationCheckpointAudit);
  assert.ok(audit.recoveryIntentIntegrityAudit);
});

test("Batch 176: recovery decision gate rejects a tampered recovery-intent binding", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b176-gate-integrity-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b176-gate-integrity", { app, storage } = await setup(root);
  const revoked = await revokeReceipt(app, storage, owner, "tamper");
  const store = createAgenticStore({ storage });
  const intent = await store.getEvidence(owner, revoked.event.recoveryIntentId);
  const unsigned = { ...intent, bindingDigest: "0".repeat(64) };
  delete unsigned.digest;
  await store.putEvidence(owner, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: intent._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.usableForCurrentDecision, false);
  assert.ok(audit.findings.some(item => item.code === "CROSS_DOMAIN_RECOVERY_INTENT_LEDGER_INTEGRITY_UNHEALTHY"));
});

test("Batch 176: attestation checkpoint APIs are exported and routed through authenticated server handlers", async () => {
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["getRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointStatus",
    "reconcileRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpoint",
    "prepareRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointEnrollment",
    "applyRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointEnrollment",
    "auditRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpoint",
    "inspectRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpointRecovery",
    "recoverRecoverySloCrossDomainCASFinalizationReceiptLifecycleAttestationCheckpoint"])
    assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /receipt-lifecycle\/attestation-checkpoint\/enrollment-challenges/);
  assert.match(server, /receipt-lifecycle\/attestation-checkpoint\/recovery\/inspect/);
});
