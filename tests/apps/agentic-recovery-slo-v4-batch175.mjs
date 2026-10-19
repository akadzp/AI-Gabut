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
    status: "prepared", reason: "Seed a source-bound remediation plan for Batch 175 receipt lifecycle tests.", createdAt,
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

test("Batch 175: revocation and replacement lifecycle events carry Ed25519 attestations bound to event and recovery intent", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b175-attestation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b175-attestation", { app, storage } = await setup(root);
  const seeded = await seedFinalization(storage, owner, "attested");
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const revoke = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Create an independently verifiable receipt lifecycle event." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, revoke.challengeId,
    { confirmation: revoke.confirmation });
  assert.equal(revoked.event.eventType, "revoked");
  assert.ok(revoked.event.attestation.signature);
  assert.ok(revoked.event.recoveryIntentId);
  assert.equal((await app.verifyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestation(owner, revoked.event.id)).status,
    "verified_current");
  const replacementChallenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptReplacement(owner, receipt.receipt.id,
    { reason: "Create a replacement whose lifecycle event is independently attested." });
  const replaced = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptReplacement(owner, replacementChallenge.challengeId,
    { confirmation: replacementChallenge.confirmation });
  assert.ok(replaced.event.attestation.signature);
  assert.equal((await app.verifyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestation(owner, replaced.event.id)).historicallyValid, true);
  const attestationAudit = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestations(owner);
  assert.equal(attestationAudit.status, "healthy");
  assert.equal(attestationAudit.attestationCount, 2);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleRecoveryIntents(owner)).status, "healthy");
});

test("Batch 175: lifecycle attestation remains historically valid but loses current usability after signing-key rotation", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b175-cutoff-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b175-key-cutoff", { app, storage } = await setup(root);
  await transition(app, owner, "activate", "finalization_key_old", "Activate the first lifecycle signing key for receipt-event attestations.");
  const seeded = await seedFinalization(storage, owner, "cutoff");
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Bind receipt revocation to the currently active signing key." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const before = await app.verifyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestation(owner, revoked.event.id);
  assert.equal(before.status, "verified_current");
  await transition(app, owner, "rotate", "finalization_key_next", "Rotate the signing key to test historical versus current lifecycle evidence.");
  const after = await app.verifyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestation(owner, revoked.event.id);
  assert.equal(after.historicallyValid, true);
  assert.equal(after.current, false);
  assert.equal(after.status, "historically_valid_stale");
});

test("Batch 175: recovery resumes a lifecycle operation after event persistence but before intent finalization", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b175-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b175-recovery", { app, storage } = await setup(root);
  const seeded = await seedFinalization(storage, owner, "recover");
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Persist a lifecycle recovery intent before finalizing the revocation event." });
  const result = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage });
  const intent = await store.getEvidence(owner, result.event.recoveryIntentId);
  const unsigned = { ...intent, status: "prepared", eventDigest: null, checkpointStatus: null, checkpointAnchorDigest: null,
    checkpointAnchorSequence: null, recoveredAt: null, lastErrorCode: null, updatedAt: "2026-10-13T00:00:00.000Z" };
  delete unsigned.digest;
  await store.putEvidence(owner, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: intent._storage?.version });
  const before = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleRecoveryIntents(owner);
  assert.equal(before.status, "recovery_required");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleOperations(owner);
  assert.equal(recovered.audit.status, "healthy");
  assert.equal(recovered.results[0].status, "completed_local");
  const integrity = await app.auditRecoverySloCrossDomainRecoveryIntentLedgerIntegrity(owner);
  assert.notEqual(integrity.status, "unhealthy");
  assert.deepEqual(integrity.findings, []);
});

test("Batch 175: cross-domain recovery-intent integrity audit detects binding-digest tampering", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b175-integrity-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b175-integrity", { app, storage } = await setup(root);
  const seeded = await seedFinalization(storage, owner, "integrity");
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Create an intent record for cross-domain integrity audit." });
  const result = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage });
  const intent = await store.getEvidence(owner, result.event.recoveryIntentId);
  const unsigned = { ...intent, bindingDigest: "0".repeat(64) };
  delete unsigned.digest;
  await store.putEvidence(owner, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: intent._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentLedgerIntegrity(owner);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => /RECOVERY_INTENT.*INVALID/.test(item.code)));
});

test("Batch 175: required lifecycle attestation fails closed without a trusted signer and new APIs have authenticated routes", async () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b175-required-attestation" }),
    requireRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestation: true }), /CAS finalization receipt lifecycle attestation diwajibkan/);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["verifyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestation",
    "auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestations",
    "auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleRecoveryIntents",
    "recoverRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleOperations",
    "auditRecoverySloCrossDomainRecoveryIntentLedgerIntegrity"])
    assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /recovery-intents\/ledger-integrity\/audit/);
  assert.match(server, /receipt-lifecycle\/attestations\/audit/);
  assert.match(server, /receipt-lifecycle\/recovery-intents\/recover/);
});

test("Batch 175: lifecycle recovery intent restores a missing external marker after enrollment without claiming pre-enrollment history", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b175-external-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b175-external-recovery", provider = anchorProvider("https://b175-lifecycle-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAnchor: provider });
  const seeded = await seedFinalization(storage, owner, "external-recovery");
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Prepare lifecycle event before enrolling the independent checkpoint." });
  const revoked = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  assert.equal(revoked.recoveryStatus, "awaiting_enrollment");
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpointEnrollment(owner,
    { reason: "Anchor the persisted lifecycle event before simulating local marker loss." });
  await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const markerId = `cross-domain-cas-finalization-receipt-lifecycle-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  await removeCheckpointMarker(storage, owner, markerId);
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleOperations(owner);
  assert.equal(recovered.results[0].status, "completed_history_unproven");
  assert.equal((await app.getRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpointStatus(owner)).status, "anchored");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleRecoveryIntents(owner)).status, "healthy");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleCheckpoint(owner)).status, "history_unproven");
});

test("Batch 175: lifecycle attestation tampering is detected even when an attacker recomputes the local event and ledger digests", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b175-attestation-tamper-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b175-attestation-tamper", { app, storage } = await setup(root);
  const seeded = await seedFinalization(storage, owner, "tamper");
  const receipt = await app.createRecoverySloCrossDomainRecoveryIntentCASFinalizationReceipt(owner, seeded.intent.id);
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, receipt.receipt.id,
    { reason: "Create an attested event before testing signature integrity." });
  const result = await app.applyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptRevocation(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const store = createAgenticStore({ storage });
  const ledgerId = `cross-domain-cas-finalization-receipt-lifecycle-ledger-${sha256(owner).slice(0, 32)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const events = structuredClone(ledger.events);
  const index = events.findIndex(event => event.id === result.event.id);
  events[index].attestation.signature = "A".repeat(events[index].attestation.signature.length);
  delete events[index].digest;
  events[index].digest = digestRecord(events[index]);
  const unsigned = { ...ledger, events, headDigest: events.at(-1).digest };
  delete unsigned.digest;
  await store.putEvidence(owner, { ...unsigned, digest: digestRecord(unsigned) }, { expectedVersion: ledger._storage?.version });
  const verification = await app.verifyRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycleAttestation(owner, result.event.id,
    { checkCurrent: false });
  assert.equal(verification.status, "unhealthy");
  assert.equal(verification.reasonCode, "CAS_FINALIZATION_RECEIPT_LIFECYCLE_ATTESTATION_SIGNATURE_INVALID");
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalizationReceiptLifecycle(owner)).status, "unhealthy");
});
