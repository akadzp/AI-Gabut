import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = structuredClone(value); delete copy.digest; delete copy._storage; return sha256(canonical(copy)); };
const hasCode = code => error => error?.code === code;
function provider({ enforceSequence = true } = {}) {
  const records = new Map();
  const capabilities = ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"];
  return {
    state: { records },
    contractInfo: { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
      capabilities, ownerScope: "ownerId", casSemantics: "digest-compare-and-set" },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId) throw Object.assign(new Error("owner scope mismatch"), { code: "OWNER_SCOPE_MISMATCH" });
      if (enforceSequence && (candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision <= (current?.revision ?? 0) || candidate.previousAnchorDigest !== (current?.digest ?? null))) {
        throw Object.assign(new Error("non-monotonic anchor"), { code: "NON_MONOTONIC_ANCHOR" });
      }
      records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b133-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const journalProvider = options.journalProvider === undefined ? provider() : options.journalProvider;
  const retentionProvider = options.retentionProvider === undefined ? provider() : options.retentionProvider;
  const app = createAgenticApplication({ storage: createStorage({ root }), clock,
    recoverySloRecoveryJournalAnchor: journalProvider,
    requireRecoverySloRecoveryJournalAnchor: options.requireJournalAnchor ?? false,
    recoverySloRetentionCheckpointAnchor: retentionProvider,
    requireRecoverySloRetentionCheckpointAnchor: options.requireRetentionAnchor ?? true });
  return { app, root, clock, now: () => nowMs, advance: ms => { nowMs += ms; },
    ownerId: options.ownerId || "owner-b133", journalProvider, retentionProvider };
}
async function runConformance(f, ownerId = f.ownerId) {
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(ownerId, {
    reason: "Verify the recovery journal anchor provider before enabling strict trust controls."
  });
  const result = await f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
  return { challenge, result };
}
async function bootstrapRetention(f) {
  return f.app.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId);
}
async function applyRetentionChange(f, days) {
  const planned = await f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: days, reason: "Adjust future evidence retention after an explicit policy review."
  });
  const approved = await f.app.approveRecoverySloEvidenceRetentionPolicyChange(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve the digest-bound retention change after reviewing its prospective impact."
  });
  return f.app.applyRecoverySloEvidenceRetentionPolicyChange(f.ownerId, approved.approval.id, {
    expectedRevision: 1, targetRetentionDays: days
  });
}

test("Batch 133: recovery-journal provider conformance validates CAS, monotonic sequence, read-after-write, and isolation", async t => {
  const f = await fixture(t);
  const { result } = await runConformance(f);
  assert.equal(result.status, "conformant");
  assert.equal(result.report.conformant, true);
  assert.equal(result.report.checksFailed, 0);
  assert.ok(result.report.checks.some(item => item.name === "stale_cas_rejection" && item.passed));
  assert.ok(result.report.checks.some(item => item.name === "monotonic_sequence_enforcement" && item.passed));
  assert.ok(result.report.checks.some(item => item.name === "concurrent_cas_single_winner" && item.passed));
  assert.equal(result.writesToProductionNamespace, false);
  assert.ok([...f.journalProvider.state.records.keys()].every(key => key.startsWith("__agentic_v4_recovery_journal_conformance__")));
});

test("Batch 133: provider that accepts sequence gaps is reported nonconformant", async t => {
  const f = await fixture(t, { journalProvider: provider({ enforceSequence: false }) });
  const { result } = await runConformance(f);
  assert.equal(result.status, "nonconformant");
  assert.equal(result.report.conformant, false);
  assert.ok(result.report.findings.some(item => item.code === "PROVIDER_MONOTONIC_SEQUENCE_ENFORCEMENT_FAILED"));
});

test("Batch 133: conformance requires explicit digest-bound confirmation and is idempotent after completion", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, {
    reason: "Run the provider contract checks in an isolated disposable namespace."
  });
  await assert.rejects(f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: "RUN JOURNAL ANCHOR CONFORMANCE wrong"
  }), hasCode("RECOVERY_SLO_JOURNAL_CONFORMANCE_CONFIRMATION_INVALID"));
  const first = await f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
  const second = await f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
  assert.equal(first.status, "conformant");
  assert.equal(second.idempotent, true);
  assert.equal(second.reportDigest, first.reportDigest);
});

test("Batch 133: conformance challenge is owner-scoped and expires after five minutes", async t => {
  const f = await fixture(t);
  const challenge = await f.app.prepareRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId);
  await assert.rejects(f.app.runRecoverySloRecoveryJournalAnchorProviderConformance("another-owner", challenge.challengeId, {
    confirmation: challenge.confirmation
  }), hasCode("RECOVERY_SLO_JOURNAL_CONFORMANCE_CHALLENGE_INVALID"));
  f.advance(5 * 60_001);
  await assert.rejects(f.app.runRecoverySloRecoveryJournalAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  }), hasCode("RECOVERY_SLO_JOURNAL_CONFORMANCE_CHALLENGE_EXPIRED"));
});

test("Batch 133: strict retention checkpoint anchoring bootstraps genesis and binds the external anchor", async t => {
  const f = await fixture(t);
  const status = await bootstrapRetention(f);
  assert.equal(status.status, "anchored");
  assert.equal(status.revision, 1);
  const audit = await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.externalAnchorStatus, "anchored");
  assert.equal(audit.externalAnchorRevision, 1);
  assert.equal(f.retentionProvider.state.records.size, 1);
  const [scope, anchor] = [...f.retentionProvider.state.records.entries()][0];
  assert.ok(scope.startsWith("retention-checkpoint-"));
  assert.equal(anchor.checkpointDigest, status.checkpointDigest);
});

test("Batch 133: retention checkpoint external anchor advances with policy revisions", async t => {
  const f = await fixture(t);
  await bootstrapRetention(f);
  const changed = await applyRetentionChange(f, 120);
  assert.equal(changed.revision, 2);
  const status = await f.app.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId);
  assert.equal(status.status, "anchored");
  assert.equal(status.anchorRevision, 2);
  assert.equal(status.anchorSequence, 2);
  assert.equal((await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId)).status, "healthy");
});

test("Batch 133: external retention anchor detects rollback of a valid local checkpoint snapshot", async t => {
  const f = await fixture(t);
  await bootstrapRetention(f);
  const policyId = `recovery-slo-evidence-retention-policy-${sha256(f.ownerId).slice(0, 48)}`;
  const checkpointId = `recovery-slo-evidence-retention-policy-checkpoint-${sha256(f.ownerId).slice(0, 48)}`;
  const oldCheckpoint = await f.app.store.getEvidence(f.ownerId, checkpointId);
  await applyRetentionChange(f, 120);
  const current = await f.app.store.getEvidence(f.ownerId, checkpointId);
  assert.equal((await f.app.store.getEvidence(f.ownerId, policyId)).revision, 2);
  await f.app.store.putEvidence(f.ownerId, { ...oldCheckpoint, _storage: undefined }, { expectedVersion: current._storage.version });
  const status = await f.app.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId);
  assert.equal(status.status, "rollback_detected");
  const audit = await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.equal(audit.externalAnchorStatus, "rollback_detected");
  f.advance(1000);
  await assert.rejects(f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 180, reason: "Attempt to change retention after an external checkpoint rollback was detected."
  }), hasCode("RECOVERY_SLO_RETENTION_ANCHOR_NOT_TRUSTED"));
});

test("Batch 133: deleting a previously anchored retention record is treated as rollback, not re-enrollment", async t => {
  const f = await fixture(t);
  await bootstrapRetention(f);
  const scope = [...f.retentionProvider.state.records.keys()][0];
  f.retentionProvider.state.records.delete(scope);
  const status = await f.app.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId);
  assert.equal(status.status, "rollback_suspected");
  assert.equal((await f.app.auditRecoverySloEvidenceRetentionPolicy(f.ownerId)).status, "unhealthy");
  await assert.rejects(f.app.planRecoverySloEvidenceRetentionPolicyChange(f.ownerId, {
    retentionDays: 120, reason: "Do not mutate retention policy after external anchor deletion was detected."
  }), hasCode("RECOVERY_SLO_RETENTION_ANCHOR_NOT_TRUSTED"));
});

test("Batch 133: legacy checkpoint requires explicit enrollment and preserves history limitation", async t => {
  const f = await fixture(t, { retentionProvider: null, requireRetentionAnchor: false });
  await f.app.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId);
  const checkpointId = `recovery-slo-evidence-retention-policy-checkpoint-${sha256(f.ownerId).slice(0, 48)}`;
  const old = await f.app.store.getEvidence(f.ownerId, checkpointId);
  const legacyUnsigned = { ...old, checkpointType: "legacy_enrollment" };
  delete legacyUnsigned.digest; delete legacyUnsigned._storage;
  const legacy = { ...legacyUnsigned, digest: digestRecord(legacyUnsigned) };
  await f.app.store.putEvidence(f.ownerId, legacy, { expectedVersion: old._storage.version });
  const replacementProvider = provider();
  const app2 = createAgenticApplication({ storage: createStorage({ root: f.root }), clock: f.clock,
    recoverySloRetentionCheckpointAnchor: replacementProvider, requireRecoverySloRetentionCheckpointAnchor: true });
  const status = await app2.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId);
  assert.equal(status.status, "enrollment_required");
  await assert.rejects(app2.anchorRecoverySloRetentionCheckpoint(f.ownerId, {
    confirmation: "ANCHOR RETENTION CHECKPOINT wrong", reason: "Explicitly enroll a pre-existing retention checkpoint."
  }), hasCode("RECOVERY_SLO_RETENTION_ANCHOR_CONFIRMATION_INVALID"));
  const result = await app2.anchorRecoverySloRetentionCheckpoint(f.ownerId, {
    confirmation: `ANCHOR RETENTION CHECKPOINT ${legacy.digest.slice(0, 12)}`,
    reason: "Explicitly enroll the existing checkpoint while documenting the unproven prior history."
  });
  assert.equal(result.status, "anchored");
  assert.equal(result.historyNotProven, true);
});

test("Batch 133: provider outage is visible and strict retention audit fails closed", async t => {
  const f = await fixture(t, { retentionProvider: null, requireRetentionAnchor: false });
  await f.app.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId);
  const outageProvider = { ...provider(), async read() { throw Object.assign(new Error("offline"), { code: "OFFLINE" }); } };
  const app2 = createAgenticApplication({ storage: createStorage({ root: f.root }), clock: f.clock,
    recoverySloRetentionCheckpointAnchor: outageProvider, requireRecoverySloRetentionCheckpointAnchor: true });
  assert.equal((await app2.getRecoverySloRetentionCheckpointAnchorStatus(f.ownerId)).status, "unavailable");
  assert.equal((await app2.auditRecoverySloEvidenceRetentionPolicy(f.ownerId)).status, "unhealthy");
});

test("Batch 133: journal and retention anchor trust domains must use independent providers", async t => {
  const shared = provider();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b133-shared-provider-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }),
    recoverySloRecoveryJournalAnchor: shared, recoverySloRetentionCheckpointAnchor: shared }),
  /provider terpisah/);
});

test("Batch 133: application APIs and HTTP routes expose conformance and retention checkpoint anchoring", async t => {
  const f = await fixture(t);
  for (const name of ["prepareRecoverySloRecoveryJournalAnchorProviderConformance", "runRecoverySloRecoveryJournalAnchorProviderConformance",
    "getRecoverySloRetentionCheckpointAnchorStatus", "anchorRecoverySloRetentionCheckpoint", "reconcileRecoverySloRetentionCheckpointAnchor"]) {
    assert.equal(typeof f.app[name], "function", `${name} must be exposed by the application`);
  }
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["recovery-journal-provider-conformance/challenges", "recovery-journal-provider-conformance/challenges/:id/run",
    "recovery-evidence-retention/checkpoint-anchor", "recovery-evidence-retention/checkpoint-anchor/anchor",
    "recovery-evidence-retention/checkpoint-anchor/reconcile"]) assert.ok(source.includes(route), `missing route ${route}`);
});

test("Batch 133: retention checkpoint anchoring fails closed when strict mode has no provider", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b133-strict-retention-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root },), requireRecoverySloRetentionCheckpointAnchor: true }),
    /Retention checkpoint anchor membutuhkan store/);
});
