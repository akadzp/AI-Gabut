import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b107") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b107-audit-plan-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  const work = await app.createWork(ownerId, { objective: "audit evidence and bounded reconciliation planning" });
  return { app, ownerId, work };
}

function codes(report) { return report.snapshot.issues.map(issue => issue.code); }

async function makeRunningWork(app, ownerId, workId) {
  await app.work.transition(ownerId, workId, "ready");
  await app.work.transition(ownerId, workId, "running");
}

test("Batch 107: captures immutable owner-scoped recovery audit evidence with a verifiable digest", async t => {
  const { app, ownerId, work } = await setup(t);
  await makeRunningWork(app, ownerId, work.id);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  assert.equal(evidence.kind, "recovery-audit-evidence");
  assert.equal(evidence.readOnly, true);
  assert.equal(evidence.snapshot.ownerId, ownerId);
  assert.match(evidence.digest, /^[a-f0-9]{64}$/);
  assert.ok(codes(evidence).includes("WORK_RUNNING_WITHOUT_ACTIVE_LEASE"));
  const stored = await app.getRecoveryAuditEvidence(ownerId, evidence.id);
  assert.equal(stored.digest, evidence.digest);
  assert.deepEqual(stored.snapshot, evidence.snapshot);
});

test("Batch 107: creates a persisted manual-review-only plan without changing recovery state", async t => {
  const { app, ownerId, work } = await setup(t);
  await makeRunningWork(app, ownerId, work.id);
  const before = await app.store.getWork(ownerId, work.id);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const after = await app.store.getWork(ownerId, work.id);
  assert.equal(after._storage.version, before._storage.version);
  assert.equal(plan.kind, "recovery-reconciliation-plan");
  assert.equal(plan.readOnly, true);
  assert.equal(plan.plan.executionPolicy, "manual-review-only");
  assert.equal(plan.plan.automaticExecutionAllowed, false);
  assert.ok(plan.plan.actions.length > 0);
  assert.ok(plan.plan.actions.every(action => action.requiresHumanApproval && action.automaticExecutionAllowed === false && action.mutation === "none-until-separately-approved"));
  assert.equal((await app.getRecoveryReconciliationPlan(ownerId, plan.id)).digest, plan.digest);
});

test("Batch 107: evidence and plan creation leave Work, task, execution, and lease versions unchanged", async t => {
  const { app, ownerId, work } = await setup(t);
  await makeRunningWork(app, ownerId, work.id);
  await app.store.putTask(ownerId, { id: "task-b107-readonly", ownerId, workId: work.id, status: "running", title: "test", createdAt: "2026-10-10T00:00:00.000Z" }, { overwrite: false });
  await app.store.putExecution(ownerId, { id: "exec-b107-readonly", ownerId, workId: work.id, taskId: "task-b107-readonly", status: "running" }, { overwrite: false });
  const leaseBefore = await app.workExecutionLeaseService.inspect(ownerId, work.id);
  const before = {
    work: (await app.store.getWork(ownerId, work.id))._storage.version,
    task: (await app.store.getTask(ownerId, "task-b107-readonly"))._storage.version,
    execution: (await app.store.getExecution(ownerId, "exec-b107-readonly"))._storage.version
  };
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  await app.planRecoveryReconciliation(ownerId, evidence.id);
  const after = {
    work: (await app.store.getWork(ownerId, work.id))._storage.version,
    task: (await app.store.getTask(ownerId, "task-b107-readonly"))._storage.version,
    execution: (await app.store.getExecution(ownerId, "exec-b107-readonly"))._storage.version
  };
  const leaseAfter = await app.workExecutionLeaseService.inspect(ownerId, work.id);
  assert.deepEqual(after, before);
  assert.deepEqual({ active: leaseAfter.active, executionId: leaseAfter.executionId, fence: leaseAfter.fence }, { active: leaseBefore.active, executionId: leaseBefore.executionId, fence: leaseBefore.fence });
});

test("Batch 107: action count is bounded and omitted findings are reported", async t => {
  const { app, ownerId } = await setup(t);
  for (const suffix of ["a", "b", "c"]) {
    await app.store.putExecution(ownerId, { id: `exec-orphan-${suffix}-b107`, ownerId, workId: `missing-work-${suffix}`, taskId: `missing-task-${suffix}`, status: "running" }, { overwrite: false });
  }
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id, { maxActions: 2 });
  assert.equal(plan.plan.maxActions, 2);
  assert.equal(plan.plan.actionCount, 2);
  assert.equal(plan.plan.truncated, true);
  assert.ok(plan.plan.omittedIssueCount > 0);
  assert.ok(plan.plan.actions.length <= 2);
});

test("Batch 107: incomplete audit evidence produces only a safe rerun-audit action", async t => {
  const { app, ownerId } = await setup(t);
  await app.store.putExecution(ownerId, { id: "exec-partial-b107", ownerId, workId: "missing-partial-work", taskId: "missing-partial-task", status: "running" }, { overwrite: false });
  const evidence = await app.captureRecoveryAuditEvidence(ownerId, { maxEvidenceIssues: 1 });
  assert.equal(evidence.snapshot.evidenceTruncated, true);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  assert.equal(plan.plan.actionCount, 1);
  assert.equal(plan.plan.actions[0].operation, "rerun_audit");
  assert.equal(plan.plan.actions[0].issueCode, "AUDIT_EVIDENCE_TRUNCATED");
  assert.equal(plan.plan.actions[0].automaticExecutionAllowed, false);
});

test("Batch 107: source audit truncation withholds issue-level reconciliation proposals", async t => {
  const { app, ownerId } = await setup(t);
  const first = await app.createWork(ownerId, { objective: "first" });
  await app.createWork(ownerId, { objective: "second" });
  await makeRunningWork(app, ownerId, first.id);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId, { limit: 1 });
  assert.equal(evidence.snapshot.sourceAuditTruncated, true);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  assert.equal(plan.plan.actions.length, 1);
  assert.equal(plan.plan.actions[0].operation, "rerun_audit");
  assert.equal(plan.plan.actions[0].issueCode, "AUDIT_RESULT_TRUNCATED");
});

test("Batch 107: clean audit yields a persisted empty plan", async t => {
  const { app, ownerId } = await setup(t);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  assert.equal(evidence.snapshot.auditStatus, "healthy");
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  assert.equal(plan.plan.actionCount, 0);
  assert.deepEqual(plan.plan.actions, []);
  assert.equal(plan.plan.truncated, false);
});

test("Batch 107: repeated planning from identical evidence is idempotent", async t => {
  const { app, ownerId, work } = await setup(t);
  await makeRunningWork(app, ownerId, work.id);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const first = await app.planRecoveryReconciliation(ownerId, evidence.id, { maxActions: 4 });
  const second = await app.planRecoveryReconciliation(ownerId, evidence.id, { maxActions: 4 });
  assert.equal(second.id, first.id);
  assert.equal(second.digest, first.digest);
  assert.deepEqual(second.plan, first.plan);
});

test("Batch 107: evidence and plan listings are bounded, owner-scoped summaries", async t => {
  const { app, ownerId } = await setup(t, "owner-a-b107");
  const other = "owner-b-b107";
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  await app.planRecoveryReconciliation(ownerId, evidence.id);
  await app.captureRecoveryAuditEvidence(other);
  const evidenceList = await app.listRecoveryAuditEvidence(ownerId, { limit: 1 });
  const planList = await app.listRecoveryReconciliationPlans(ownerId, { limit: 1 });
  assert.equal(evidenceList.total, 1);
  assert.equal(planList.total, 1);
  assert.equal("snapshot" in evidenceList.items[0], false);
  assert.equal("plan" in planList.items[0], false);
  assert.equal(evidenceList.items[0].kind, "recovery-audit-evidence");
  assert.equal(planList.items[0].kind, "recovery-reconciliation-plan");
});

test("Batch 107: cross-owner evidence and plan access are rejected", async t => {
  const { app, ownerId } = await setup(t, "owner-a-b107-cross");
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  await assert.rejects(() => app.getRecoveryAuditEvidence("owner-b-b107-cross", evidence.id), error => error.code === "RECOVERY_AUDIT_EVIDENCE_NOT_FOUND");
  await assert.rejects(() => app.getRecoveryReconciliationPlan("owner-b-b107-cross", plan.id), error => error.code === "RECOVERY_RECONCILIATION_PLAN_NOT_FOUND");
});

test("Batch 107: missing evidence and invalid owners fail closed", async t => {
  const { app, ownerId } = await setup(t);
  await assert.rejects(() => app.captureRecoveryAuditEvidence(""), error => error.code === "RECOVERY_AUDIT_OWNER_REQUIRED");
  await assert.rejects(() => app.planRecoveryReconciliation(ownerId, "missing-evidence-b107"), error => error.code === "RECOVERY_AUDIT_EVIDENCE_NOT_FOUND");
  await assert.rejects(() => app.getRecoveryReconciliationPlan(ownerId, "missing-plan-b107"), error => error.code === "RECOVERY_RECONCILIATION_PLAN_NOT_FOUND");
});

test("Batch 107: tampered evidence digest is rejected before planning", async t => {
  const { app, ownerId } = await setup(t);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const raw = await app.store.getEvidence(ownerId, evidence.id);
  await app.store.putEvidence(ownerId, { ...raw, snapshot: { ...raw.snapshot, auditStatus: "healthy-but-tampered" } }, { overwrite: true, expectedVersion: raw._storage?.version });
  await assert.rejects(() => app.planRecoveryReconciliation(ownerId, evidence.id), error => error.code === "RECOVERY_AUDIT_EVIDENCE_INTEGRITY_FAILED");
});

test("Batch 107: tampered plan digest is rejected on retrieval", async t => {
  const { app, ownerId } = await setup(t);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const raw = await app.store.getEvidence(ownerId, plan.id);
  await app.store.putEvidence(ownerId, { ...raw, snapshot: { ...raw.snapshot, automaticExecutionAllowed: true } }, { overwrite: true, expectedVersion: raw._storage?.version });
  await assert.rejects(() => app.getRecoveryReconciliationPlan(ownerId, plan.id), error => error.code === "RECOVERY_RECONCILIATION_PLAN_INTEGRITY_FAILED");
});

test("Batch 107: public evidence and plan objects cannot mutate stored snapshots by reference", async t => {
  const { app, ownerId } = await setup(t);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  evidence.snapshot.auditStatus = "tampered-in-caller";
  const loaded = await app.getRecoveryAuditEvidence(ownerId, evidence.id);
  assert.notEqual(loaded.snapshot.auditStatus, "tampered-in-caller");
  const plan = await app.planRecoveryReconciliation(ownerId, loaded.id);
  plan.plan.executionPolicy = "automatic";
  const loadedPlan = await app.getRecoveryReconciliationPlan(ownerId, plan.id);
  assert.equal(loadedPlan.plan.executionPolicy, "manual-review-only");
});
