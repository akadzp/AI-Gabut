import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
const hasCode = code => error => error?.code === code;

function createAnchorProvider() {
  const anchors = new Map();
  const provider = {
    failReads: false,
    async read(ownerId) {
      if (provider.failReads) throw Object.assign(new Error("anchor read unavailable"), { code: "ANCHOR_READ_DOWN" });
      const value = anchors.get(ownerId);
      return value ? structuredClone(value) : null;
    },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = anchors.get(ownerId) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: current ? structuredClone(current) : null };
      if (!current) {
        if (candidate.anchorSequence !== 1 || candidate.previousAnchorDigest !== null) return { applied: false, anchor: null };
      } else if (candidate.anchorSequence !== current.anchorSequence + 1 || candidate.previousAnchorDigest !== current.digest
        || candidate.revision <= current.revision) return { applied: false, anchor: structuredClone(current) };
      anchors.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
  return provider;
}

async function setup(t, { ownerId = "owner-b120", provider = null, root = null } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b120-slo-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const first = generateKeyPairSync("ed25519");
  const app = createAgenticApplication({ storage: createStorage({ root: storageRoot }), clock: () => new Date(time).toISOString(),
    integrityAttestationPublicKeys: { root1: first.publicKey }, attestationTrustAnchor: provider });
  return { app, ownerId, root: storageRoot, provider, first, advance: ms => { time += ms; }, now: () => new Date(time).toISOString() };
}

function signature(payload, privateKey) { return sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64url"); }

async function rotate(fixture) {
  const next = generateKeyPairSync("ed25519");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "next1", publicKey: next.publicKey });
  await fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, {
    authorizations: [{ keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) }],
    proofOfPossession: signature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: challenge.payload }, next.privateKey)
  });
}

async function alertRecord(fixture) {
  return (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-slo-alert-ledger") || null;
}

test("Batch 120: escalation policy has immutable hash-linked revisions and rejects stale updates", async t => {
  const fixture = await setup(t);
  const initial = await fixture.app.getRecoverySloEscalationPolicy(fixture.ownerId);
  assert.equal(initial.revision, 1);
  const updated = await fixture.app.updateRecoverySloEscalationPolicy(fixture.ownerId, {
    expectedRevision: 1, reason: "Adjust warning escalation after operational review.",
    changes: { highObservations: 4, highAfterMs: 6 * 60 * 1000 }
  });
  assert.equal(updated.revision, 2);
  assert.equal(updated.policy.highObservations, 4);
  await assert.rejects(fixture.app.updateRecoverySloEscalationPolicy(fixture.ownerId, {
    expectedRevision: 1, reason: "Attempt a stale policy update after concurrent change.", changes: { minSamples: 4 }
  }), hasCode("RECOVERY_SLO_POLICY_REVISION_CONFLICT"));
  const evaluation = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  assert.equal(evaluation.policyRevision, 2);
  assert.equal(evaluation.policyDigest, updated.policyDigest);
  assert.equal((await fixture.app.listRecoverySloPolicyEvents(fixture.ownerId)).total, 2);
  assert.equal((await fixture.app.auditRecoverySloEscalationPolicy(fixture.ownerId)).status, "healthy");
});

test("Batch 120: policy validation rejects unsafe escalation ordering and unknown fields", async t => {
  const fixture = await setup(t);
  await fixture.app.getRecoverySloEscalationPolicy(fixture.ownerId);
  await assert.rejects(fixture.app.updateRecoverySloEscalationPolicy(fixture.ownerId, {
    expectedRevision: 1, reason: "Reject unsafe threshold ordering before activation.", changes: { highObservations: 12, criticalObservations: 10 }
  }), hasCode("RECOVERY_SLO_POLICY_VALUES_INVALID"));
  await assert.rejects(fixture.app.updateRecoverySloEscalationPolicy(fixture.ownerId, {
    expectedRevision: 1, reason: "Reject unknown policy fields from an untrusted request.", changes: { allowRemediation: true }
  }), hasCode("RECOVERY_SLO_POLICY_CHANGES_INVALID"));
});

test("Batch 120: full SLO evaluation evidence is persisted, owner-scoped, and policy-bound", async t => {
  const fixture = await setup(t);
  const evaluation = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  assert.match(evaluation.evaluationEvidenceId, /^recovery-slo-evaluation-/);
  const record = await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, evaluation.evaluationEvidenceId);
  assert.equal(record.state, "active");
  assert.equal(record.evaluation.evaluationDigest, evaluation.evaluationDigest);
  assert.equal(record.policyRevision, evaluation.policyRevision);
  assert.equal((await fixture.app.listRecoverySloEvaluationEvidence(fixture.ownerId)).activeCount, 1);
  assert.equal((await fixture.app.auditRecoverySloEvaluationEvidence(fixture.ownerId)).status, "healthy");
  await assert.rejects(fixture.app.getRecoverySloEvaluationEvidence("other-owner", evaluation.evaluationEvidenceId), hasCode("RECOVERY_SLO_EVALUATION_EVIDENCE_NOT_FOUND"));
});

test("Batch 120: expired evaluation payload is redacted while a verifiable retention tombstone remains", async t => {
  const fixture = await setup(t);
  await fixture.app.updateRecoverySloEscalationPolicy(fixture.ownerId, {
    expectedRevision: 1, reason: "Use the minimum allowed evidence retention interval.", changes: { evaluationRetentionMs: 24 * 60 * 60 * 1000 }
  });
  const evaluation = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const before = await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, evaluation.evaluationEvidenceId);
  fixture.advance(25 * 60 * 60 * 1000);
  const prune = await fixture.app.pruneRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 10 });
  assert.equal(prune.expired, 1);
  const after = await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, evaluation.evaluationEvidenceId);
  assert.equal(after.state, "expired");
  assert.equal(after.evaluation, null);
  assert.equal(after.contentDigest, before.contentDigest);
  assert.equal(after.retentionTombstone.reason, "RETENTION_POLICY_ELAPSED");
  assert.equal((await fixture.app.auditRecoverySloEvaluationEvidence(fixture.ownerId)).status, "healthy");
});

test("Batch 120: unexpired evaluation evidence is not pruned", async t => {
  const fixture = await setup(t);
  const evaluation = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const result = await fixture.app.pruneRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 50 });
  assert.equal(result.expired, 0);
  assert.equal((await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, evaluation.evaluationEvidenceId)).state, "active");
});

test("Batch 120: alert archive preserves complete ordered event history and frees the active ledger tail", async t => {
  const fixture = await setup(t);
  await Promise.all(Array.from({ length: 6 }, () => fixture.app.evaluateRecoverySLOs(fixture.ownerId)));
  const before = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(before.eventCount, 6);
  const archived = await fixture.app.archiveRecoverySloAlertLedgerEvents(fixture.ownerId, { limit: 4, retainRecent: 2 });
  assert.equal(archived.status, "archived");
  assert.equal(archived.archivedEventCount, 4);
  const after = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(after.eventCount, 6);
  assert.equal(after.archivedEventCount, 4);
  assert.equal(after.retainedEventCount, 2);
  const events = await fixture.app.listRecoverySloAlertEvents(fixture.ownerId, { limit: 20 });
  assert.equal(events.total, 6);
  assert.deepEqual(events.items.map(item => item.sequence), [6, 5, 4, 3, 2, 1]);
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "healthy");
});

test("Batch 120: interrupted prepared archive is recovered idempotently without duplicate events", async t => {
  const fixture = await setup(t);
  await Promise.all(Array.from({ length: 4 }, () => fixture.app.evaluateRecoverySLOs(fixture.ownerId)));
  const ledger = await alertRecord(fixture);
  const events = ledger.snapshot.events.slice(0, 2);
  const startSequence = events[0].sequence;
  const endSequence = events.at(-1).sequence;
  const previousHash = events[0].previousHash;
  const endHash = events.at(-1).eventHash;
  const alertIds = [...new Set(events.map(item => item.alertId))].sort();
  const payload = { startSequence, endSequence, previousHash, endHash, events, archivedAlerts: [], alertIds };
  const archive = { id: `recovery-slo-alert-archive-${digest(canonical({ domain: "agentic-v4-recovery-slo-alert-archive", ownerId: fixture.ownerId, startSequence, endSequence, endHash })).slice(0, 40)}`,
    ownerId: fixture.ownerId, kind: "recovery-slo-alert-archive", state: "prepared", createdAt: fixture.now(), ...payload, payloadDigest: digest(canonical(payload)) };
  archive.digest = digest(canonical(archive));
  await fixture.app.store.putEvidence(fixture.ownerId, archive, { overwrite: false });
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "recovery_required");
  await assert.rejects(fixture.app.evaluateRecoverySLOs(fixture.ownerId), hasCode("RECOVERY_SLO_ALERT_ARCHIVE_RECOVERY_REQUIRED"));
  const recovered = await fixture.app.recoverRecoverySloAlertLedgerArchives(fixture.ownerId);
  assert.equal(recovered.status, "recovered");
  assert.equal((await fixture.app.recoverRecoverySloAlertLedgerArchives(fixture.ownerId)).recovered, false);
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "healthy");
  const eventsAfter = await fixture.app.listRecoverySloAlertEvents(fixture.ownerId, { limit: 20 });
  assert.deepEqual(eventsAfter.items.map(item => item.sequence), [4, 3, 2, 1]);
});

test("Batch 120: archive tampering is detected and SLO writes fail closed", async t => {
  const fixture = await setup(t);
  await Promise.all(Array.from({ length: 5 }, () => fixture.app.evaluateRecoverySLOs(fixture.ownerId)));
  await fixture.app.archiveRecoverySloAlertLedgerEvents(fixture.ownerId, { limit: 3, retainRecent: 2 });
  const archive = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-slo-alert-archive");
  const tampered = structuredClone(archive);
  tampered.events[0].severity = "critical";
  await fixture.app.store.putEvidence(fixture.ownerId, tampered, { expectedVersion: archive._storage.version });
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "unhealthy");
  await assert.rejects(fixture.app.evaluateRecoverySLOs(fixture.ownerId), hasCode("RECOVERY_SLO_ALERT_ARCHIVE_INTEGRITY_FAILED"));
});

test("Batch 120: archived resolved alerts remain queryable while no longer occupying active alert slots", async t => {
  const provider = createAnchorProvider();
  const fixture = await setup(t, { provider });
  await rotate(fixture);
  provider.failReads = true;
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId, { minSamples: 1 });
  provider.failReads = false;
  for (let index = 0; index < 12; index += 1) await fixture.app.evaluateRecoverySLOs(fixture.ownerId, { minSamples: 1, availabilityTarget: 0.9 });
  const ledger = await alertRecord(fixture);
  assert.ok(ledger.snapshot.alerts.some(alert => alert.status === "resolved"));
  const result = await fixture.app.archiveRecoverySloAlertLedgerEvents(fixture.ownerId, { limit: 500, retainRecent: 0 });
  assert.ok(result.archivedAlertCount >= 1);
  const restored = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.ok(restored.alerts.some(alert => alert.status === "resolved"));
  assert.ok(restored.archivedAlertCount >= 1);
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "healthy");
});

test("Batch 120: application APIs and HTTP routes expose archive, policy versioning, and evaluation retention", async t => {
  const fixture = await setup(t);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const method of ["archiveRecoverySloAlertLedgerEvents", "recoverRecoverySloAlertLedgerArchives", "getRecoverySloEscalationPolicy",
    "updateRecoverySloEscalationPolicy", "listRecoverySloPolicyEvents", "auditRecoverySloEscalationPolicy", "listRecoverySloEvaluationEvidence",
    "getRecoverySloEvaluationEvidence", "auditRecoverySloEvaluationEvidence", "pruneRecoverySloEvaluationEvidence"]) {
    assert.equal(typeof fixture.app[method], "function", `${method} must be exposed by application API`);
  }
  assert.match(source, /anchor\/slo\/alerts\/archive/);
  assert.match(source, /anchor\/slo\/policy\/events/);
  assert.match(source, /anchor\/slo\/evaluations\/audit/);
  assert.match(source, /anchor\/slo\/evaluations\/prune/);
});

test("Batch 120: successive archive segments maintain one continuous hash and sequence chain", async t => {
  const fixture = await setup(t);
  await Promise.all(Array.from({ length: 8 }, () => fixture.app.evaluateRecoverySLOs(fixture.ownerId)));
  const first = await fixture.app.archiveRecoverySloAlertLedgerEvents(fixture.ownerId, { limit: 3, retainRecent: 5 });
  assert.equal(first.status, "archived");
  const second = await fixture.app.archiveRecoverySloAlertLedgerEvents(fixture.ownerId, { limit: 3, retainRecent: 2 });
  assert.equal(second.status, "archived");
  const audit = await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.archiveCount, 2);
  assert.equal(audit.archivedEventCount, 6);
  const events = await fixture.app.listRecoverySloAlertEvents(fixture.ownerId, { limit: 20 });
  assert.deepEqual(events.items.map(item => item.sequence), [8, 7, 6, 5, 4, 3, 2, 1]);
});

test("Batch 120: tampered evaluation evidence breaks alert binding audit and blocks later SLO writes", async t => {
  const fixture = await setup(t);
  const evaluation = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const evidence = await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, evaluation.evaluationEvidenceId);
  const tampered = structuredClone(evidence);
  tampered.evaluation.objectives[0].status = "met";
  await fixture.app.store.putEvidence(fixture.ownerId, tampered, { expectedVersion: evidence._storage.version });
  assert.equal((await fixture.app.auditRecoverySloEvaluationEvidence(fixture.ownerId)).status, "unhealthy");
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "unhealthy");
  await assert.rejects(fixture.app.evaluateRecoverySLOs(fixture.ownerId), hasCode("RECOVERY_SLO_ALERT_EVIDENCE_BINDING_FAILED"));
});
