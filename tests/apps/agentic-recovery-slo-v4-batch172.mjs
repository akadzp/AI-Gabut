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

async function seedFinalization(storage, owner, createdAt, suffix = owner) {
  const store = createAgenticStore({ storage });
  const action = "reconcile_policy_binding_audit_checkpoint";
  const planUnsigned = { id: `b172-plan-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-plan", schemaVersion: 1,
    status: "prepared", reason: "Seed a source-bound plan for finalization key lifecycle tests.", createdAt,
    expiresAt: new Date(Date.parse(createdAt) + 600000).toISOString(), stateFingerprint: "d".repeat(64),
    allowedActions: [action], blockedActions: [], auditStatus: "blocked", auditFindingsDigest: "e".repeat(64),
    deletionPerformed: false, compactionPerformed: false };
  const plan = { ...planUnsigned, digest: digestRecord(planUnsigned) };
  await store.putEvidence(owner, plan, { overwrite: false });
  const intentUnsigned = { id: `b172-intent-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-recovery-intent",
    schemaVersion: 1, status: "completed", planId: plan.id, planDigest: plan.digest, stateFingerprint: plan.stateFingerprint,
    action, confirmationDigest: sha256(`EXECUTE CROSS-DOMAIN DRIFT REMEDIATION ${plan.digest.slice(0, 12)}`),
    createdAt, finalizedAt: createdAt, resultAnchorDigest: null };
  const intent = { ...intentUnsigned, digest: digestRecord(intentUnsigned) };
  await store.putEvidence(owner, intent, { overwrite: false });
  const executionUnsigned = { id: `b172-execution-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-execution",
    schemaVersion: 1, planId: plan.id, planDigest: plan.digest, recoveryIntentId: intent.id,
    recoveryIntentDigest: intent.digest, action, status: "completed", createdAt, completedAt: createdAt,
    deletionPerformed: false, compactionPerformed: false };
  const execution = { ...executionUnsigned, digest: digestRecord(executionUnsigned) };
  await store.putEvidence(owner, execution, { overwrite: false });
  const finalizationUnsigned = { id: `b172-finalization-${suffix}`, ownerId: owner, kind: "recovery-slo-cross-domain-drift-remediation-finalization",
    schemaVersion: 1, intentId: intent.id, intentDigest: intent.digest, executionId: execution.id, executionDigest: execution.digest,
    checkpointDomain: "cross_domain_drift_remediation_executions", checkpointStatus: "anchored",
    checkpointAnchorDigest: "c".repeat(64), checkpointAnchorSequence: 1, checkpointHistoryNotProven: false,
    usableForCurrentDecision: true, finalizedAt: createdAt, deletionPerformed: false, compactionPerformed: false };
  const finalization = { ...finalizationUnsigned, digest: digestRecord(finalizationUnsigned) };
  await store.putEvidence(owner, finalization, { overwrite: false });
  return { store, plan, intent, execution, finalization };
}

async function setup(root, owner, { clock, requireLifecycle = true } = {}) {
  const pairOld = generateKeyPairSync("ed25519"), pairNext = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: pairOld, finalization_key_next: pairNext };
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(pairOld),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    requireRecoverySloDriftRemediationFinalizationAttestation: true,
    requireRecoverySloDriftRemediationFinalizationKeyLifecycleBinding: requireLifecycle });
  return { app, storage: createStorage({ root }), pairs };
}

async function transition(app, owner, action, keyId, reason) {
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, { action, keyId, reason });
  const applied = await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  return { challenge, applied };
}

test("Batch 172: finalization attestation binds active key lifecycle and retains validity before a later cutoff", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b172-key-cutoff-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString(), owner = "b172-key-cutoff";
  const { app, storage } = await setup(root, owner, { clock });
  await transition(app, owner, "activate", "finalization_key_old", "Activate the initial finalization signing key for cutoff validation.");
  nowMs += 1000;
  const { finalization } = await seedFinalization(storage, owner, clock());
  const created = await app.createRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, finalization.id);
  assert.equal(created.attestation.signingKeyLifecycleSequence, 1);
  assert.ok(created.attestation.signingKeyLifecycleDigest);
  nowMs += 1000;
  await transition(app, owner, "rotate", "finalization_key_next", "Rotate to the next trusted finalization signing key.");
  const historical = await app.verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, created.attestation.id, { checkCurrent: false });
  assert.equal(historical.historicallyValid, true);
  assert.equal(historical.keyCutoffValid, true);
  assert.equal(historical.keyLifecycleStatus, "historically_valid_stale");
  const current = await app.verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, created.attestation.id);
  assert.equal(current.current, false);
  assert.equal(current.usableForCurrentDecision, false);
  let lifecycle = await app.auditRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycle(owner);
  assert.equal(lifecycle.status, "healthy");
  assert.equal(lifecycle.activeKeyId, "finalization_key_next");
  nowMs += 1000;
  const secondFinalization = await seedFinalization(storage, owner, clock(), "rotated-key");
  const secondAttestation = await app.createRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, secondFinalization.finalization.id);
  assert.equal(secondAttestation.attestation.signingKeyId, "finalization_key_next");
  assert.equal(secondAttestation.attestation.signingKeyLifecycleSequence, 2);
  nowMs += 1000;
  await transition(app, owner, "revoke", "finalization_key_next", "Revoke the active finalization key after the second attestation was issued.");
  const revokedKeyHistorical = await app.verifyRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, secondAttestation.attestation.id, { checkCurrent: false });
  assert.equal(revokedKeyHistorical.historicallyValid, true);
  assert.equal(revokedKeyHistorical.keyCutoffValid, true);
  assert.equal(revokedKeyHistorical.keyLifecycleStatus, "historically_valid_stale");
  lifecycle = await app.auditRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycle(owner);
  assert.equal(lifecycle.status, "healthy");
  assert.equal(lifecycle.activeKeyId, null);
});

test("Batch 172: key lifecycle challenge rejects stale sequence and replay conflict", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b172-key-stale-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b172-key-stale", clock = () => "2026-10-13T00:00:00.000Z";
  const { app } = await setup(root, owner, { clock });
  await transition(app, owner, "activate", "finalization_key_old", "Activate the initial finalization signing key for challenge binding.");
  const stale = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "revoke", keyId: "finalization_key_old", reason: "Prepare a revocation challenge that will become stale." });
  await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "rotate", keyId: "finalization_key_next", reason: "Prepare a competing key rotation against the same ledger head." }).then(async challenge => {
      await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
        { confirmation: challenge.confirmation });
    });
  await assert.rejects(() => app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, stale.challengeId,
    { confirmation: stale.confirmation }), error => error?.code === "FINALIZATION_KEY_LIFECYCLE_CHALLENGE_STALE");
  const lifecycle = await app.auditRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycle(owner);
  assert.equal(lifecycle.status, "healthy");
  assert.equal(lifecycle.eventCount, 2);
});

test("Batch 172: freshness/replay audit writes an append-only incident ledger and deduplicates repeat findings", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b172-replay-ledger-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b172-replay-ledger", clock = () => "2026-10-13T00:00:00.000Z";
  const { app, storage } = await setup(root, owner, { clock, requireLifecycle: false });
  const { finalization } = await seedFinalization(storage, owner, clock());
  const created = await app.createRecoverySloCrossDomainDriftRemediationFinalizationAttestation(owner, finalization.id);
  const store = createAgenticStore({ storage });
  await store.mutateEvidence(owner, created.attestation.id, current => ({ value: { ...current, signature: "tampered" } }));
  const firstAudit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.ok(firstAudit.findings.some(item => /INVALID/.test(item.code)));
  assert.equal(firstAudit.replayIncidentLedger.status, "healthy");
  assert.ok(firstAudit.replayIncidentLedger.incidentCount >= 1);
  const count = firstAudit.replayIncidentLedger.incidentCount;
  const secondAudit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.equal(secondAudit.replayIncidentLedger.status, "healthy");
  assert.equal(secondAudit.replayIncidentLedger.incidentCount, count);
  const ledger = await app.auditRecoverySloCrossDomainReplayIncidentLedger(owner);
  assert.equal(ledger.status, "healthy");
  assert.equal(ledger.incidentCount, count);
  const ledgerId = `cross-domain-replay-incident-ledger-${sha256(owner).slice(0, 32)}`;
  await store.mutateEvidence(owner, ledgerId, current => ({ value: { ...current, events: [] } }));
  const corrupted = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner);
  assert.equal(corrupted.status, "unhealthy");
  assert.equal(corrupted.replayIncidentLedger.status, "unhealthy");
});

test("Batch 172: recovery-intent CAS finalization audit detects missing finalization and tampered finalization", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b172-cas-audit-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b172-cas-audit", clock = () => "2026-10-13T00:00:00.000Z";
  const { app, storage } = await setup(root, owner, { clock, requireLifecycle: false });
  const seeded = await seedFinalization(storage, owner, clock());
  const audit = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalization(owner);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.pendingCount, 0);
  const store = createAgenticStore({ storage });
  await store.mutateEvidence(owner, seeded.finalization.id, () => ({ delete: true }));
  const missing = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalization(owner);
  assert.equal(missing.status, "recovery_required");
  assert.ok(missing.pending.some(item => item.intentId === seeded.intent.id));
  await store.putEvidence(owner, seeded.finalization, { overwrite: false });
  await store.mutateEvidence(owner, seeded.finalization.id, current => ({ value: { ...current, digest: "0".repeat(64) } }));
  const tampered = await app.auditRecoverySloCrossDomainRecoveryIntentCASFinalization(owner);
  assert.equal(tampered.status, "unhealthy");
  assert.ok(tampered.findings.some(item => /FINALIZATION.*DIGEST_INVALID/.test(item.code)));
});

test("Batch 172: lifecycle, replay incident, and CAS finalization APIs are wired to authenticated HTTP routes", async () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b172-required-lifecycle-config" }),
    requireRecoverySloDriftRemediationFinalizationKeyLifecycleBinding: true }), /signer dan trusted public key Ed25519/);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const name of ["prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition",
    "applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition",
    "auditRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycle",
    "auditRecoverySloCrossDomainReplayIncidentLedger", "auditRecoverySloCrossDomainRecoveryIntentCASFinalization"])
    assert.match(server, new RegExp(`application\\.${name}\\b`));
  assert.match(server, /drift-remediation\/finalization-key-lifecycle\/challenges/);
  assert.match(server, /checkpoints\/replay-incidents\/audit/);
  assert.match(server, /recovery-intents\/cas-finalization\/audit/);
});
