import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const hasCode = code => error => error?.code === code;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");

async function setup(t, { ownerId = "owner-b123", storage = null, root = null, clock = () => new Date().toISOString() } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b123-restore-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: storage || createStorage({ root: storageRoot }), clock });
  return { app, ownerId, root: storageRoot };
}

async function sourceBundle(t, ownerId = "shared-b123-owner") {
  const source = await setup(t, { ownerId });
  await source.app.evaluateRecoverySLOs(ownerId);
  return { source, bundle: await source.app.exportRecoverySloEvidenceBundle(ownerId) };
}

async function approve(target, ownerId, bundle, plan = null, overrides = {}) {
  const restorePlan = plan || await target.app.planRecoverySloEvidenceRestore(ownerId, bundle);
  const reason = overrides.reason || "Reviewed source integrity and target restore impact.";
  const confirmation = overrides.confirmation || `APPROVE RESTORE ${restorePlan.planDigest.slice(0, 12)}`;
  return target.app.approveRecoverySloEvidenceRestorePlan(ownerId, restorePlan, bundle, { reason, confirmation });
}

function interruptedStorage(root) {
  const base = createStorage({ root });
  let quarantineCommitted = false;
  let failJournalUpdate = true;
  const decodeRecordId = key => {
    if (!key.startsWith("agentic/evidence/")) return "";
    const ownerScopedId = decodeURIComponent(key.slice("agentic/evidence/".length));
    const marker = ownerScopedId.indexOf("--");
    return marker < 0 ? "" : ownerScopedId.slice(marker + 2);
  };
  return {
    read: key => base.read(key), write: (key, value) => base.write(key, value),
    remove: key => base.remove(key), list: prefix => base.list(prefix),
    atomicUpdate: async (key, updater) => {
      const id = decodeRecordId(key);
      if (failJournalUpdate && quarantineCommitted && id.startsWith("recovery-slo-restore-import-")) {
        failJournalUpdate = false;
        throw Object.assign(new Error("simulated interruption after quarantine write"), { code: "TEST_INTERRUPTED" });
      }
      const result = await base.atomicUpdate(key, updater);
      if (failJournalUpdate && id.startsWith("recovery-slo-quarantine-")) quarantineCommitted = true;
      return result;
    }
  };
}

test("Batch 123: restore approval requires explicit digest confirmation, reason, and an untampered ready plan", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  await assert.rejects(target.app.approveRecoverySloEvidenceRestorePlan(target.ownerId, plan, bundle,
    { reason: "too short", confirmation: `APPROVE RESTORE ${plan.planDigest.slice(0, 12)}` }), hasCode("RECOVERY_SLO_RESTORE_APPROVAL_REASON_REQUIRED"));
  await assert.rejects(target.app.approveRecoverySloEvidenceRestorePlan(target.ownerId, plan, bundle,
    { reason: "Reviewed source integrity and target restore impact.", confirmation: "APPROVE RESTORE wrong" }), hasCode("RECOVERY_SLO_RESTORE_APPROVAL_CONFIRMATION_REQUIRED"));
  const changed = structuredClone(plan);
  changed.actions[0].recordId = "forged-record-id";
  await assert.rejects(target.app.approveRecoverySloEvidenceRestorePlan(target.ownerId, changed, bundle,
    { reason: "Reviewed source integrity and target restore impact.", confirmation: `APPROVE RESTORE ${changed.planDigest.slice(0, 12)}` }), hasCode("RECOVERY_SLO_RESTORE_PLAN_INVALID"));
});

test("Batch 123: approved restore stages source records only in quarantine and preserves active target state", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const before = await target.app.store.listEvidence(target.ownerId);
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const result = await target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle);
  assert.equal(result.status, "completed");
  assert.equal(result.quarantinedOnly, true);
  assert.equal(result.activated, false);
  assert.equal(result.mutationAllowed, false);
  assert.equal(result.counts.quarantined, plan.counts.import);
  const after = await target.app.store.listEvidence(target.ownerId);
  for (const action of plan.actions.filter(item => item.action === "import")) {
    assert.equal(await target.app.store.getEvidence(target.ownerId, action.recordId), null, "source record must not enter active evidence namespace");
  }
  assert.equal(after.filter(item => item.kind === "recovery-slo-restore-quarantined-evidence").length, plan.counts.import);
  assert.equal(after.filter(item => item.kind === "recovery-slo-evidence-restore-import-journal").length, 1);
  assert.ok(after.length > before.length);
  assert.equal((await target.app.auditRecoverySloEvidenceRestoreImports(target.ownerId)).status, "healthy");
});

test("Batch 123: import application is idempotent and reuses one journal and quarantine record per source record", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const repeatedApproval = await approve(target, target.ownerId, bundle, plan);
  assert.equal(repeatedApproval.approvalId, approval.approvalId);
  assert.equal(repeatedApproval.idempotent, true);
  const first = await target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle);
  const second = await target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle);
  assert.equal(second.journalId, first.journalId);
  assert.equal(second.status, "completed");
  assert.equal((await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).total, plan.counts.import);
  assert.equal((await target.app.listRecoverySloEvidenceRestoreImportJournals(target.ownerId)).total, 1);
});

test("Batch 123: a newly generated plan cannot create a second approval for the same source bundle", async t => {
  const { bundle } = await sourceBundle(t);
  let tick = 0;
  const target = await setup(t, { ownerId: bundle.ownerId,
    clock: () => new Date(Date.UTC(2026, 9, 11, 0, 0, tick++)).toISOString() });
  const firstPlan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  await approve(target, target.ownerId, bundle, firstPlan);
  const laterPlan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  assert.notEqual(laterPlan.planDigest, firstPlan.planDigest);
  await assert.rejects(target.app.approveRecoverySloEvidenceRestorePlan(target.ownerId, laterPlan, bundle,
    { reason: "Reviewed source integrity and target restore impact.", confirmation: `APPROVE RESTORE ${laterPlan.planDigest.slice(0, 12)}` }),
    hasCode("RECOVERY_SLO_RESTORE_SOURCE_ALREADY_APPROVED"));
});

test("Batch 123: source tampering after approval is rejected before any journal or quarantine write", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const altered = structuredClone(bundle);
  altered.sections.evaluationEvidence[0].summary.status = "tampered-after-approval";
  await assert.rejects(target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, altered),
    hasCode("RECOVERY_SLO_RESTORE_SOURCE_INVALID"));
  assert.equal((await target.app.listRecoverySloEvidenceRestoreImportJournals(target.ownerId)).total, 0);
  assert.equal((await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).total, 0);
});

test("Batch 123: target changes after approval make the plan stale and prevent import", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const sourceRecord = bundle.sections.evaluationEvidence[0];
  const conflict = structuredClone(sourceRecord);
  conflict.summary = { status: "different target record" };
  await target.app.store.putEvidence(target.ownerId, conflict, { overwrite: false });
  await assert.rejects(target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle),
    hasCode("RECOVERY_SLO_RESTORE_PLAN_STALE"));
  assert.equal((await target.app.listRecoverySloEvidenceRestoreImportJournals(target.ownerId)).total, 0);
  assert.equal((await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).total, 0);
});

test("Batch 123: recovery resumes after quarantine commit but before journal item update", async t => {
  const { bundle } = await sourceBundle(t);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b123-interrupt-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const target = await setup(t, { ownerId: bundle.ownerId, root, storage: interruptedStorage(root) });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  await assert.rejects(target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle),
    error => error?.code === "TEST_INTERRUPTED");
  const pending = await target.app.listRecoverySloEvidenceRestoreImportJournals(target.ownerId);
  assert.equal(pending.total, 1);
  assert.equal(pending.items[0].status, "applying");
  assert.ok((await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).total >= 1);
  assert.equal((await target.app.auditRecoverySloEvidenceRestoreImports(target.ownerId)).status, "recovery_required");
  const wrongBundle = structuredClone(bundle);
  wrongBundle.ownerId = "wrong-owner";
  await assert.rejects(target.app.recoverRecoverySloEvidenceRestoreImport(target.ownerId, pending.items[0].journalId, wrongBundle),
    hasCode("RECOVERY_SLO_RESTORE_SOURCE_INVALID"));
  const recovered = await target.app.recoverRecoverySloEvidenceRestoreImport(target.ownerId, pending.items[0].journalId, bundle);
  assert.equal(recovered.status, "completed");
  assert.equal(recovered.counts.pending, 0);
  assert.equal((await target.app.auditRecoverySloEvidenceRestoreImports(target.ownerId)).status, "healthy");
});

test("Batch 123: import audit detects journal and quarantined payload tampering", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const applied = await target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle);
  const quarantineSummary = (await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).items[0];
  const quarantine = await target.app.store.getEvidence(target.ownerId, quarantineSummary.id);
  const alteredQuarantine = structuredClone(quarantine);
  alteredQuarantine.payload.summary = { status: "forged" };
  alteredQuarantine.payloadDigest = sha256(canonical(alteredQuarantine.payload));
  const { digest: _oldDigest, _storage: _storage, ...alteredBase } = alteredQuarantine;
  alteredQuarantine.digest = sha256(canonical(alteredBase));
  await target.app.store.putEvidence(target.ownerId, alteredQuarantine, { overwrite: true });
  const audit = await target.app.auditRecoverySloEvidenceRestoreImports(target.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_SLO_RESTORE_QUARANTINE_BINDING_INVALID"));
  const journal = await target.app.store.getEvidence(target.ownerId, applied.journalId);
  journal.status = "applying";
  await target.app.store.putEvidence(target.ownerId, journal, { overwrite: true });
  const journalAudit = await target.app.auditRecoverySloEvidenceRestoreImports(target.ownerId);
  assert.equal(journalAudit.status, "unhealthy");
  assert.ok(journalAudit.findings.some(item => item.code === "RECOVERY_SLO_RESTORE_JOURNAL_SNAPSHOT_MISMATCH"));
});

test("Batch 123: owner isolation prevents reading or applying another owner's approval and journal", async t => {
  const { bundle } = await sourceBundle(t, "owner-b123-source");
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const applied = await target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle);
  await assert.rejects(target.app.applyRecoverySloEvidenceRestorePlan("different-owner", approval.approvalId, bundle),
    hasCode("RECOVERY_SLO_RESTORE_APPROVAL_NOT_FOUND"));
  await assert.rejects(target.app.getRecoverySloEvidenceRestoreImportJournal("different-owner", applied.journalId),
    hasCode("RECOVERY_SLO_RESTORE_JOURNAL_NOT_FOUND"));
  assert.equal((await target.app.listRecoverySloEvidenceRestoreImportJournals("different-owner")).total, 0);
  assert.equal((await target.app.listRecoverySloEvidenceRestoreQuarantine("different-owner")).total, 0);
});

test("Batch 123: import journal audit, listing, and quarantine listing are read-only and bounded", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const applied = await target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle);
  const before = await target.app.store.listEvidence(target.ownerId);
  const journal = await target.app.getRecoverySloEvidenceRestoreImportJournal(target.ownerId, applied.journalId);
  const journals = await target.app.listRecoverySloEvidenceRestoreImportJournals(target.ownerId, { limit: 1 });
  const quarantine = await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId, { limit: 1, journalId: applied.journalId });
  const audit = await target.app.auditRecoverySloEvidenceRestoreImports(target.ownerId);
  const after = await target.app.store.listEvidence(target.ownerId);
  assert.equal(journal.integrityValid, true);
  assert.equal(journals.items.length, 1);
  assert.equal(quarantine.items.length, 1);
  assert.equal(quarantine.items[0].activated, false);
  assert.equal(audit.status, "healthy");
  assert.deepEqual(after, before);
});

test("Batch 123: application API and HTTP routes expose approval, apply, recovery, journal audit, and quarantine", async t => {
  const fixture = await setup(t);
  const apiNames = ["approveRecoverySloEvidenceRestorePlan", "applyRecoverySloEvidenceRestorePlan",
    "recoverRecoverySloEvidenceRestoreImport", "getRecoverySloEvidenceRestoreImportJournal",
    "listRecoverySloEvidenceRestoreImportJournals", "listRecoverySloEvidenceRestoreQuarantine",
    "auditRecoverySloEvidenceRestoreImports"];
  for (const name of apiNames) assert.equal(typeof fixture.app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["restore-approvals", "restore-imports/apply", "restore-imports/:id/recover",
    "restore-imports/audit", "restore-imports/:id", "restore-quarantine"]) assert.ok(server.includes(route), route);
});

test("Batch 123: concurrent apply requests converge on one completed journal without duplicate quarantine records", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const approval = await approve(target, target.ownerId, bundle, plan);
  const results = await Promise.allSettled([
    target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle),
    target.app.applyRecoverySloEvidenceRestorePlan(target.ownerId, approval.approvalId, bundle)
  ]);
  assert.ok(results.some(item => item.status === "fulfilled" && item.value.status === "completed"));
  const journalList = await target.app.listRecoverySloEvidenceRestoreImportJournals(target.ownerId);
  assert.equal(journalList.total, 1);
  assert.equal((await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).total, plan.counts.import);
  assert.equal((await target.app.auditRecoverySloEvidenceRestoreImports(target.ownerId)).status, "healthy");
});
