import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b108") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b108-plan-freshness-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  return { app, ownerId };
}

async function makeRunningWork(app, ownerId, workId = undefined) {
  const work = await app.createWork(ownerId, { ...(workId ? { id: workId } : {}), objective: "Batch 108 freshness fixture" });
  await app.transitionWork(ownerId, work.id, "ready");
  await app.transitionWork(ownerId, work.id, "running");
  return await app.getWork(ownerId, work.id);
}

function actionCodes(result) {
  return result.actionResults.flatMap(action => action.mismatches.map(item => item.code));
}

test("Batch 108: unchanged evidence and record preconditions revalidate as fresh without mutation", async t => {
  const { app, ownerId } = await setup(t);
  const work = await makeRunningWork(app, ownerId);
  const before = await app.store.getWork(ownerId, work.id);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  const after = await app.store.getWork(ownerId, work.id);
  assert.equal(result.status, "fresh");
  assert.equal(result.preconditionsSatisfied, true);
  assert.equal(result.readyForHumanReview, true);
  assert.equal(result.executionAllowed, false);
  assert.equal(result.automaticExecutionAllowed, false);
  assert.equal(after._storage.version, before._storage.version);
  assert.equal(result.actionResults.every(action => action.status === "fresh"), true);
});

test("Batch 108: record version changes stale a plan even when the record still exists", async t => {
  const { app, ownerId } = await setup(t);
  const work = await makeRunningWork(app, ownerId);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const current = await app.store.getWork(ownerId, work.id);
  await app.store.putWork(ownerId, { ...current, auditMarker: "changed-after-plan" }, { expectedVersion: current._storage.version });
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  assert.equal(result.status, "stale");
  assert.ok(actionCodes(result).includes("RECORD_PRECONDITION_CHANGED"));
});

test("Batch 108: a finding that disappears after the plan was created is stale", async t => {
  const { app, ownerId } = await setup(t);
  const work = await makeRunningWork(app, ownerId);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  await app.transitionWork(ownerId, work.id, "paused");
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  assert.equal(result.status, "stale");
  assert.ok(actionCodes(result).includes("FINDING_NO_LONGER_PRESENT"));
});

test("Batch 108: a newly introduced audit finding invalidates a previously clean plan", async t => {
  const { app, ownerId } = await setup(t);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  assert.equal(plan.plan.actionCount, 0);
  await app.store.putExecution(ownerId, { id: "exec-new-finding-b108", ownerId, workId: "missing-work-b108", taskId: "missing-task-b108", status: "running" }, { overwrite: false });
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  assert.equal(result.status, "stale");
  assert.ok(result.findings.some(item => item.code === "AUDIT_FINDINGS_CHANGED"));
});

test("Batch 108: changing durable lease state invalidates lease-related preconditions", async t => {
  const { app, ownerId } = await setup(t);
  const work = await makeRunningWork(app, ownerId);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  await app.workExecutionLeaseService.acquire(ownerId, work.id, "exec-lease-appeared-b108");
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  assert.equal(result.status, "stale");
  assert.ok(actionCodes(result).some(code => code === "LEASE_PRECONDITION_CHANGED" || code === "FINDING_NO_LONGER_PRESENT"));
});

test("Batch 108: incomplete evidence fails closed and cannot be marked ready", async t => {
  const { app, ownerId } = await setup(t);
  for (const suffix of ["a", "b", "c"]) {
    await app.store.putExecution(ownerId, { id: `exec-partial-${suffix}-b108`, ownerId, workId: `missing-work-${suffix}`, taskId: `missing-task-${suffix}`, status: "running" }, { overwrite: false });
  }
  const evidence = await app.captureRecoveryAuditEvidence(ownerId, { maxEvidenceIssues: 1 });
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  assert.equal(result.status, "incomplete");
  assert.equal(result.readyForHumanReview, false);
  assert.equal(result.executionAllowed, false);
  assert.ok(result.findings.some(item => item.code === "EVIDENCE_PRECONDITIONS_INCOMPLETE"));
});

test("Batch 108: a truncated plan is incomplete even when included actions are fresh", async t => {
  const { app, ownerId } = await setup(t);
  for (const suffix of ["a", "b"]) {
    await app.store.putExecution(ownerId, { id: `exec-truncated-${suffix}-b108`, ownerId, workId: `missing-work-${suffix}`, taskId: `missing-task-${suffix}`, status: "running" }, { overwrite: false });
  }
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id, { maxActions: 1 });
  assert.equal(plan.plan.truncated, true);
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  assert.equal(result.status, "incomplete");
  assert.ok(result.findings.some(item => item.code === "PLAN_TRUNCATED"));
});

test("Batch 108: current audit truncation returns incomplete rather than a false fresh result", async t => {
  const { app, ownerId } = await setup(t);
  await app.createWork(ownerId, { objective: "audit limit one" });
  await app.createWork(ownerId, { objective: "audit limit two" });
  const evidence = await app.captureRecoveryAuditEvidence(ownerId, { limit: 250 });
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id, { limit: 1 });
  assert.equal(result.status, "incomplete");
  assert.ok(result.findings.some(item => item.code === "CURRENT_AUDIT_TRUNCATED"));
});

test("Batch 108: a truncated current audit does not falsely mark an uninspected finding stale", async t => {
  const { app, ownerId } = await setup(t);
  await app.store.putExecution(ownerId, { id: "exec-a-current-page-b108", ownerId, workId: "missing-work-a-b108", taskId: "missing-task-a-b108", status: "running" }, { overwrite: false });
  await app.store.putExecution(ownerId, { id: "zzzz-exec-outside-page-b108", ownerId, workId: "missing-work-z-b108", taskId: "missing-task-z-b108", status: "running" }, { overwrite: false });
  const evidence = await app.captureRecoveryAuditEvidence(ownerId, { limit: 250 });
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const result = await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id, { limit: 1 });
  assert.equal(result.status, "incomplete");
  assert.ok(result.findings.some(item => item.code === "CURRENT_AUDIT_TRUNCATED"));
  assert.equal(result.actionResults.some(action => action.mismatches.some(item => item.code === "FINDING_NO_LONGER_PRESENT")), false);
});

test("Batch 108: cross-owner plan revalidation is rejected", async t => {
  const { app, ownerId } = await setup(t, "owner-a-b108");
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  await assert.rejects(
    () => app.revalidateRecoveryReconciliationPlan("owner-b-b108", plan.id),
    error => error.code === "RECOVERY_RECONCILIATION_PLAN_NOT_FOUND"
  );
});

test("Batch 108: tampered evidence is rejected during plan revalidation", async t => {
  const { app, ownerId } = await setup(t);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const raw = await app.store.getEvidence(ownerId, evidence.id);
  await app.store.putEvidence(ownerId, { ...raw, snapshot: { ...raw.snapshot, auditStatus: "tampered" } }, { overwrite: true, expectedVersion: raw._storage.version });
  await assert.rejects(
    () => app.revalidateRecoveryReconciliationPlan(ownerId, plan.id),
    error => error.code === "RECOVERY_AUDIT_EVIDENCE_INTEGRITY_FAILED"
  );
});

test("Batch 108: revalidation does not change evidence, plan, Work, task, execution, or lease state", async t => {
  const { app, ownerId } = await setup(t);
  const work = await makeRunningWork(app, ownerId);
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id);
  const before = {
    evidenceVersion: (await app.store.getEvidence(ownerId, evidence.id))._storage.version,
    planVersion: (await app.store.getEvidence(ownerId, plan.id))._storage.version,
    workVersion: (await app.store.getWork(ownerId, work.id))._storage.version,
    lease: await app.workExecutionLeaseService.inspect(ownerId, work.id)
  };
  await app.revalidateRecoveryReconciliationPlan(ownerId, plan.id);
  const after = {
    evidenceVersion: (await app.store.getEvidence(ownerId, evidence.id))._storage.version,
    planVersion: (await app.store.getEvidence(ownerId, plan.id))._storage.version,
    workVersion: (await app.store.getWork(ownerId, work.id))._storage.version,
    lease: await app.workExecutionLeaseService.inspect(ownerId, work.id)
  };
  assert.deepEqual(after, before);
});

test("Batch 108: HTTP server exposes the read-only plan revalidation endpoint", async () => {
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(source, /recovery-audit\/plans\/:id\/revalidation/);
  assert.match(source, /revalidateRecoveryReconciliationPlan/);
});
