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
async function setup(root, owner, extra = {}) {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage,
    clock: () => "2026-10-13T00:00:00.000Z",
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    ...extra });
  return { app, storage, pairs };
}
async function transition(app, owner, action, keyId, reason) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, { action, keyId, reason });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function seedFinalization(storage, owner, suffix = "one", createdAt = "2026-10-13T00:00:00.000Z") {
  const store = createAgenticStore({ storage });
  const action = "reconcile_policy_binding_audit_checkpoint";
  const planUnsigned = { id: `b173-plan-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-plan", schemaVersion: 1,
    status: "prepared", reason: "Seed a source-bound remediation plan for CAS receipt binding tests.", createdAt,
    expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString(), stateFingerprint: "d".repeat(64),
    allowedActions: [action], blockedActions: [], auditStatus: "blocked", auditFindingsDigest: "e".repeat(64),
    deletionPerformed: false, compactionPerformed: false };
  const plan = { ...planUnsigned, digest: digestRecord(planUnsigned) };
  await store.putEvidence(owner, plan, { overwrite: false });
  const intentUnsigned = { id: `b173-intent-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-recovery-intent",
    schemaVersion: 1, status: "completed", planId: plan.id, planDigest: plan.digest, stateFingerprint: plan.stateFingerprint,
    action, confirmationDigest: sha256(`EXECUTE CROSS-DOMAIN DRIFT REMEDIATION ${plan.digest.slice(0, 12)}`),
    createdAt, finalizedAt: createdAt, resultAnchorDigest: null };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  const executionUnsigned = { id: `b173-execution-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-execution",
    schemaVersion: 1, planId: plan.id, planDigest: plan.digest, recoveryIntentId: intent.id,
    recoveryIntentDigest: intent.digest, action, status: "completed", resultDigest: "a".repeat(64), createdAt, completedAt: createdAt,
    deletionPerformed: false, compactionPerformed: false };
  const execution = { ...executionUnsigned, digest: digestRecord(executionUnsigned) };
  await store.putEvidence(owner, execution, { overwrite: false });
  const finalizationUnsigned = { id: `b173-finalization-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-finalization",
    schemaVersion: 1, intentId: intent.id, intentDigest: intent.digest, executionId: execution.id, executionDigest: execution.digest,
    checkpointDomain: "cross_domain_drift_remediation_executions", checkpointStatus: "anchored",
    checkpointAnchorDigest: "c".repeat(64), checkpointAnchorSequence: 1, checkpointHistoryNotProven: false,
    usableForCurrentDecision: true, finalizedAt: createdAt, deletionPerformed: false, compactionPerformed: false };
  const finalization = { ...finalizationUnsigned, digest: digestRecord(finalizationUnsigned) };
  await store.putEvidence(owner, finalization, { overwrite: false });
  return { store, plan, intent, execution, finalization };
}
function seededIncidentLedger(owner, detectedAt = "2026-10-13T00:00:00.000Z") {
  const finding = { code: "CROSS_DOMAIN_CHECKPOINT_REPLAY_DETECTED", domain: "fixture_domain" };
  const incidentKey = sha256(canonical({ ownerId: owner, finding }));
  const eventUnsigned = { id: `cross-domain-replay-incident-${incidentKey.slice(0, 32)}`, ownerId: owner, sequence: 1,
    previousEventDigest: null, incidentKey, finding, detectedAt };
  const event = { ...eventUnsigned, digest: digestRecord(eventUnsigned) };
  const id = `cross-domain-replay-incident-ledger-${sha256(owner).slice(0, 32)}`;
  const ledgerUnsigned = { id, ownerId: owner, kind: "recovery-slo-cross-domain-checkpoint-replay-incident-ledger", schemaVersion: 1,
    events: [event], eventCount: 1, headDigest: event.digest, updatedAt: detectedAt, deletionPerformed: false, compactionPerformed: false };
  return { id, ledger: { ...ledgerUnsigned, digest: digestRecord(ledgerUnsigned) }, event };
}

 test("Batch 173: finalization key lifecycle is externally anchored and advances only on a proven single-event continuation", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b173-key-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b173-key-anchor", provider = anchorProvider("https://b173-key-lifecycle-anchor.example");
  const { app, storage } = await setup(root, owner, { recoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleAnchor: provider,
    requireRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleAnchor: true,
    requireRecoverySloDriftRemediationFinalizationKeyLifecycleBinding: true });
  const activation = await transition(app, owner, "activate", "finalization_key_old", "Activate the first finalization key before enrolling its lifecycle checkpoint.");
  assert.equal(activation.status, "applied");
  assert.equal(activation.externalCheckpoint.status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the finalization key lifecycle after the first immutable activation event." });
  const enrolled = await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, true);
  const rotated = await transition(app, owner, "rotate", "finalization_key_next", "Rotate to the next trusted key and anchor the lifecycle continuation.");
  assert.equal(rotated.externalCheckpoint.status, "anchored");
  assert.equal(rotated.externalCheckpoint.anchorSequence, 2);
  const status = await app.getRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointStatus(owner);
  assert.equal(status.status, "anchored");
  assert.equal(status.anchorSequence, 2);
  assert.equal(status.historyNotProven, true);
  const audit = await app.auditRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.usableForCurrentDecision, false);
  const { finalization } = await seedFinalization(storage, owner, "key-lifecycle-attestation");
  const attestation = await app.createRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, finalization.id);
  const verification = await app.verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, attestation.attestation.id);
  assert.equal(verification.historicallyValid, true);
  assert.equal(verification.current, false);
  assert.equal(verification.keyLifecycleStatus, "history_unproven");
  assert.equal(verification.keyLifecycleCheckpointStatus, "anchored");
});

test("Batch 173: replay incident ledger checkpoint enrolls explicitly and reconciles one unique new incident", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b173-replay-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b173-replay-anchor", provider = anchorProvider("https://b173-replay-ledger-anchor.example");
  const { app, storage } = await setup(root, owner, { recoverySloCrossDomainReplayIncidentLedgerAnchor: provider,
    requireRecoverySloCrossDomainReplayIncidentLedgerAnchor: true });
  const store = createAgenticStore({ storage });
  const seeded = seededIncidentLedger(owner);
  await store.putEvidence(owner, seeded.ledger, { overwrite: false });
  assert.equal((await app.getRecoverySloCrossDomainReplayIncidentLedgerCheckpointStatus(owner)).status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainReplayIncidentLedgerCheckpointEnrollment(owner,
    { reason: "Enroll the existing replay incident ledger before accepting future checkpoint changes." });
  await app.applyRecoverySloCrossDomainReplayIncidentLedgerCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const secondFinding = { code: "CROSS_DOMAIN_CHECKPOINT_ROLLBACK_SUSPECTED", domain: "fixture_domain_2" };
  const secondKey = sha256(canonical({ ownerId: owner, finding: secondFinding }));
  const secondUnsigned = { id: `cross-domain-replay-incident-${secondKey.slice(0, 32)}`, ownerId: owner, sequence: 2,
    previousEventDigest: seeded.event.digest, incidentKey: secondKey, finding: secondFinding, detectedAt: "2026-10-13T00:00:01.000Z" };
  const second = { ...secondUnsigned, digest: digestRecord(secondUnsigned) };
  const current = await store.getEvidence(owner, seeded.id);
  const ledgerUnsigned = { ...current, events: [...current.events, second], eventCount: 2, headDigest: second.digest,
    updatedAt: "2026-10-13T00:00:01.000Z" };
  delete ledgerUnsigned._storage; delete ledgerUnsigned.digest;
  const ledger = { ...ledgerUnsigned, digest: digestRecord(ledgerUnsigned) };
  await store.putEvidence(owner, ledger, { expectedVersion: current._storage?.version });
  const reconciled = await app.reconcileRecoverySloCrossDomainReplayIncidentLedgerCheckpoint(owner);
  assert.equal(reconciled.status, "anchored");
  assert.equal(reconciled.anchorSequence, 2);
  const audit = await app.auditRecoverySloCrossDomainReplayIncidentLedgerCheckpoint(owner);
  assert.equal(audit.status, "history_unproven");
  assert.equal(audit.incidentCount, 2);
  assert.equal(audit.usableForCurrentDecision, false);
});

test("Batch 173: CAS finalization receipt binds intent, execution, finalization, and checkpoint postcondition idempotently", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b173-cas-receipt-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b173-cas-receipt", provider = anchorProvider("https://b173-cas-receipt-anchor.example");
  const { app, storage } = await setup(root, owner, { recoverySloCrossDomainRecoveryIntentCASFinalizationReceiptAnchor: provider,
    requireRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptAnchor: true });
  const seeded = await seedFinalization(storage, owner);
  const first = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  assert.equal(first.status, "created");
  assert.equal(first.receipt.casOutcome, "committed");
  assert.equal(first.receipt.intentDigest, seeded.intent.digest);
  assert.equal(first.receipt.executionDigest, seeded.execution.digest);
  assert.equal(first.receipt.finalizationDigest, seeded.finalization.digest);
  assert.equal(first.receipt.usableForCurrentDecision, false);
  assert.equal(first.checkpoint.status, "enrollment_required");
  const second = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  assert.equal(second.idempotent, true);
  assert.equal(second.receipt.id, first.receipt.id);
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the CAS finalization receipt ledger after validating its source-bound receipt chain." });
  await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const checkpointAudit = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpoint(owner);
  assert.equal(checkpointAudit.status, "history_unproven");
  assert.equal(checkpointAudit.receiptCount, 1);
  const receiptAudit = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipts(owner);
  assert.equal(receiptAudit.status, "healthy");
  const store = createAgenticStore({ storage });
  const ledger = await store.getEvidence(owner, receiptAudit.ledgerId);
  await store.mutateEvidence(owner, ledger.id, current => ({ value: { ...current, events: current.events.map(event => ({ ...event, postconditionDigest: "0".repeat(64) })) } }));
  const tampered = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipts(owner);
  assert.equal(tampered.status, "unhealthy");
  assert.ok(tampered.findings.some(item => /RECEIPT.*(CHAIN|POSTCONDITION|DIGEST)/.test(item.code)));
});

test("Batch 173: required external checkpoint configuration fails closed and all new APIs have authenticated HTTP routes", async () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b173-required-anchor" }),
    requireRecoverySloCrossDomainReplayIncidentLedgerAnchor: true }), /replay-incident ledger checkpoint diwajibkan/);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["getRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointStatus",
    "prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointEnrollment",
    "auditRecoverySloCrossDomainReplayIncidentLedgerCheckpoint", "createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt",
    "auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpoint"])
    assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /finalization-key-lifecycle\/checkpoint\/enrollment-challenges/);
  assert.match(server, /checkpoints\/replay-incidents\/checkpoint\/reconcile/);
  assert.match(server, /recovery-intents\/cas-finalization\/receipts\/checkpoint\/enrollment-challenges/);
});
