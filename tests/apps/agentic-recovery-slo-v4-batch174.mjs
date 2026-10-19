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
async function transition(app, owner, action, keyId, reason) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, { action, keyId, reason });
  return app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
}
async function seedFinalization(storage, owner, suffix = "one", createdAt = "2026-10-13T00:00:00.000Z") {
  const store = createAgenticStore({ storage });
  const action = "reconcile_policy_binding_audit_checkpoint";
  const planUnsigned = { id: `b174-plan-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-plan", schemaVersion: 1,
    status: "prepared", reason: "Seed a source-bound remediation plan for Batch 174 receipt lifecycle tests.", createdAt,
    expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString(), stateFingerprint: "d".repeat(64),
    allowedActions: [action], blockedActions: [], auditStatus: "blocked", auditFindingsDigest: "e".repeat(64),
    deletionPerformed: false, compactionPerformed: false };
  const plan = { ...planUnsigned, digest: digestRecord(planUnsigned) };
  await store.putEvidence(owner, plan, { overwrite: false });
  const intentUnsigned = { id: `b174-intent-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-recovery-intent",
    schemaVersion: 1, status: "completed", planId: plan.id, planDigest: plan.digest, stateFingerprint: plan.stateFingerprint,
    action, confirmationDigest: sha256(`EXECUTE CROSS-DOMAIN DRIFT REMEDIATION ${plan.digest.slice(0, 12)}`),
    createdAt, finalizedAt: createdAt, resultAnchorDigest: null };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  const executionUnsigned = { id: `b174-execution-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-execution",
    schemaVersion: 1, planId: plan.id, planDigest: plan.digest, recoveryIntentId: intent.id,
    recoveryIntentDigest: intent.digest, action, status: "completed", resultDigest: "a".repeat(64), createdAt, completedAt: createdAt,
    deletionPerformed: false, compactionPerformed: false };
  const execution = { ...executionUnsigned, digest: digestRecord(executionUnsigned) };
  await store.putEvidence(owner, execution, { overwrite: false });
  const finalizationUnsigned = { id: `b174-finalization-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-finalization",
    schemaVersion: 1, intentId: intent.id, intentDigest: intent.digest, executionId: execution.id, executionDigest: execution.digest,
    checkpointDomain: "cross_domain_drift_remediation_executions", checkpointStatus: "anchored",
    checkpointAnchorDigest: "c".repeat(64), checkpointAnchorSequence: 1, checkpointHistoryNotProven: false,
    usableForCurrentDecision: true, finalizedAt: createdAt, deletionPerformed: false, compactionPerformed: false };
  const finalization = { ...finalizationUnsigned, digest: digestRecord(finalizationUnsigned) };
  await store.putEvidence(owner, finalization, { overwrite: false });
  return { store, plan, intent, execution, finalization };
}
async function removeCheckpointMarker(storage, owner, markerId) {
  const store = createAgenticStore({ storage });
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker, `expected marker ${markerId}`);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  assert.equal(await store.getEvidence(owner, markerId), null);
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
  return { id, ledger: { ...ledgerUnsigned, digest: digestRecord(ledgerUnsigned) }, event, finding, incidentKey };
}

test("Batch 174: CAS finalization receipt revocation is source-bound, idempotent, and removes current-decision usability", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b174-revoke-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b174-revoke", { app, storage } = await setup(root);
  const seeded = await seedFinalization(storage, owner);
  const created = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, created.receipt.id,
    { reason: "Revoke receipt after independent lifecycle review." });
  const result = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(result.status, "revoked");
  assert.equal(result.usableForCurrentDecision, false);
  const state = await app.getRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleState(owner, created.receipt.id);
  assert.equal(state.status, "revoked");
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipts(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.receipts[0].lifecycleStatus, "revoked");
  assert.equal(audit.receipts[0].usableForCurrentDecision, false);
  const replay = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(replay.idempotent, true);
});

test("Batch 174: revoked CAS finalization receipt can be replaced only through a bound challenge and preserves the old evidence", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b174-replace-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b174-replace", { app, storage } = await setup(root);
  const seeded = await seedFinalization(storage, owner);
  const created = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, created.receipt.id,
    { reason: "Revoke old receipt before a replacement is issued." });
  await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, revoke.challengeId, { confirmation: revoke.confirmation });
  const replacementChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptReplacement(owner, created.receipt.id,
    { reason: "Replace the revoked receipt with a fresh source-bound lifecycle receipt." });
  const replaced = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptReplacement(owner,
    replacementChallenge.challengeId, { confirmation: replacementChallenge.confirmation });
  assert.equal(replaced.status, "replaced");
  assert.equal(replaced.replacementReceipt.replacesReceiptId, created.receipt.id);
  assert.equal(replaced.replacementReceipt.replacesReceiptDigest, created.receipt.digest);
  assert.equal(replaced.replacementReceipt.usableForCurrentDecision, false);
  const oldState = await app.getRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleState(owner, created.receipt.id);
  assert.equal(oldState.status, "superseded");
  assert.equal(oldState.replacementReceipt.id, replaced.replacementReceipt.id);
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycle(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.eventCount, 2);
  const replay = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptReplacement(owner,
    replacementChallenge.challengeId, { confirmation: replacementChallenge.confirmation });
  assert.equal(replay.idempotent, true);
  assert.equal(replay.replacementReceipt.id, replaced.replacementReceipt.id);
});

test("Batch 174: replay-incident CAS recovery completes a prepared intent after the ledger write already committed", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b174-replay-cas-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b174-replay-cas", { app, storage } = await setup(root);
  const store = createAgenticStore({ storage }), seeded = seededIncidentLedger(owner);
  await store.putEvidence(owner, seeded.ledger, { overwrite: false });
  const intentId = `cross-domain-replay-incident-cas-recovery-${sha256(`${owner}\0${seeded.incidentKey}`).slice(0, 32)}`;
  const unsigned = { id: intentId, ownerId: owner, kind: "recovery-slo-cross-domain-replay-incident-ledger-cas-recovery-intent", schemaVersion: 1,
    status: "prepared", incidentKeys: [seeded.incidentKey], findings: [seeded.finding], createdAt: "2026-10-13T00:00:00.000Z",
    resultHeadDigest: null, deletionPerformed: false, compactionPerformed: false };
  unsigned.bindingDigest = sha256(canonical({ id: unsigned.id, ownerId: unsigned.ownerId, kind: unsigned.kind, schemaVersion: unsigned.schemaVersion,
    incidentKeys: unsigned.incidentKeys, findings: unsigned.findings, createdAt: unsigned.createdAt }));
  await store.putEvidence(owner, { ...unsigned, digest: digestRecord(unsigned) }, { overwrite: false });
  const before = await app.auditRecoverySloCrossDomainReplayIncidentLedgerCASRecoveryIntents(owner);
  assert.equal(before.status, "recovery_required");
  assert.equal(before.pendingCount, 1);
  const recovered = await app.recoverRecoverySloCrossDomainReplayIncidentLedgerCAS(owner);
  assert.equal(recovered.status, "healthy");
  assert.equal(recovered.audit.pendingCount, 0);
  assert.equal((await app.auditRecoverySloCrossDomainReplayIncidentLedger(owner)).incidentCount, 1);
});

test("Batch 174: CAS receipt checkpoint marker recovery restores a marker from a matching external anchor", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b174-receipt-marker-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b174-receipt-marker", provider = anchorProvider("https://b174-cas-receipt-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainRecoveryIntentCASFinalizationReceiptAnchor: provider });
  const seeded = await seedFinalization(storage, owner);
  await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpointEnrollment(owner,
    { reason: "Enroll receipt checkpoint before simulating a local marker crash." });
  await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const markerId = `cross-domain-recovery-intent-cas-finalization-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  await removeCheckpointMarker(storage, owner, markerId);
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpointStatus(owner)).status, "anchored");
});

test("Batch 174: replay incident checkpoint marker recovery restores a marker without changing the incident chain", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b174-replay-marker-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b174-replay-marker", provider = anchorProvider("https://b174-replay-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainReplayIncidentLedgerAnchor: provider });
  const store = createAgenticStore({ storage }), seeded = seededIncidentLedger(owner);
  await store.putEvidence(owner, seeded.ledger, { overwrite: false });
  const enrollment = await app.prepareRecoverySloCrossDomainReplayIncidentLedgerCheckpointEnrollment(owner,
    { reason: "Enroll replay incident checkpoint before simulating marker loss." });
  await app.applyRecoverySloCrossDomainReplayIncidentLedgerCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const markerId = `cross-domain-replay-incident-ledger-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  await removeCheckpointMarker(storage, owner, markerId);
  const inspection = await app.inspectRecoverySloCrossDomainReplayIncidentLedgerCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainReplayIncidentLedgerCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal((await app.auditRecoverySloCrossDomainReplayIncidentLedger(owner)).incidentCount, 1);
  assert.equal((await app.getRecoverySloCrossDomainReplayIncidentLedgerCheckpointStatus(owner)).status, "anchored");
});

test("Batch 174: finalization-key lifecycle checkpoint marker recovery is intent-bound and preserves the external anchor", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b174-key-marker-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b174-key-marker", provider = anchorProvider("https://b174-key-lifecycle-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleAnchor: provider,
    requireRecoverySloDriftRemediationFinalizationKeyLifecycleBinding: true });
  await transition(app, owner, "activate", "finalization_key_old", "Activate the initial signing key before checkpoint enrollment.");
  const enrollment = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll finalization key lifecycle before simulating a local marker crash." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const markerId = `cross-domain-drift-remediation-finalization-key-lifecycle-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  await removeCheckpointMarker(storage, owner, markerId);
  const inspection = await app.inspectRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal((await app.getRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleCheckpointStatus(owner)).status, "anchored");
});

test("Batch 174: required receipt lifecycle supports a safe bootstrap revocation, explicit enrollment, and marker recovery", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b174-lifecycle-bootstrap-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b174-lifecycle-bootstrap", provider = anchorProvider("https://b174-lifecycle-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAnchor: provider,
    requireRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAnchor: true });
  const seeded = await seedFinalization(storage, owner);
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Bootstrap revocation creates the first lifecycle event safely." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.checkpoint.status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the first persisted CAS receipt lifecycle event." });
  const enrolled = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpointEnrollment(owner,
    enrollment.challengeId, { confirmation: enrollment.confirmation });
  assert.equal(enrolled.status, "anchored");
  const markerId = `cross-domain-cas-finalization-receipt-lifecycle-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  await removeCheckpointMarker(storage, owner, markerId);
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpointRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpoint(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpointStatus(owner)).status, "anchored");
  const lifecycleAudit = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpoint(owner);
  assert.equal(lifecycleAudit.status, "history_unproven");
  assert.equal(lifecycleAudit.usableForCurrentDecision, false);
});

test("Batch 174: required lifecycle anchor fails closed and new recovery/lifecycle APIs have authenticated HTTP routes", async () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b174-required-lifecycle-anchor" }),
    requireRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAnchor: true }), /CAS finalization receipt lifecycle checkpoint diwajibkan/);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["recoverRecoverySloCrossDomainReplayIncidentLedgerCAS", "recoverRecoverySloCrossDomainReplayIncidentLedgerCheckpoint",
    "recoverRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptCheckpoint", "prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation",
    "applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation", "prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptReplacement",
    "applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptReplacement", "auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycle"])
    assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /recovery-intents\/cas-finalization\/receipts\/revocation-challenges/);
  assert.match(server, /recovery-intents\/cas-finalization\/receipt-lifecycle\/checkpoint\/recovery/);
  assert.match(server, /checkpoints\/replay-incidents\/cas-recovery/);
});
