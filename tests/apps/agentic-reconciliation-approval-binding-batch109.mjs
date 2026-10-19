import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

async function setup(t, ownerId = "owner-b109") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b109-approval-binding-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root }), clock: () => new Date(now).toISOString() });
  return { app, ownerId, advance: ms => { now += ms; } };
}

async function makePlan(app, ownerId, { multiple = false, maxActions = 50 } = {}) {
  const work = await app.createWork(ownerId, { objective: "Batch 109 approval-bound precondition fixture" });
  await app.transitionWork(ownerId, work.id, "ready");
  await app.transitionWork(ownerId, work.id, "running");
  if (multiple) {
    for (const suffix of ["a", "b"]) {
      await app.store.putExecution(ownerId, {
        id: `exec-${suffix}-b109`, ownerId, workId: `missing-work-${suffix}-b109`,
        taskId: `missing-task-${suffix}-b109`, status: "running"
      }, { overwrite: false });
    }
  }
  const evidence = await app.captureRecoveryAuditEvidence(ownerId);
  const plan = await app.planRecoveryReconciliation(ownerId, evidence.id, { maxActions });
  return { work, evidence, plan };
}

function approvalCode(error, expected) { return error?.code === expected; }

test("Batch 109: persists bounded revalidation evidence with a stable precondition binding digest", async t => {
  const { app, ownerId } = await setup(t);
  const { work, plan } = await makePlan(app, ownerId);
  const before = await app.store.getWork(ownerId, work.id);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  assert.equal(evidence.kind, "recovery-reconciliation-revalidation-evidence");
  assert.equal(evidence.snapshot.status, "fresh");
  assert.equal(evidence.snapshot.readyForHumanReview, true);
  assert.equal(evidence.snapshot.executionAllowed, false);
  assert.match(evidence.snapshot.preconditionBindingDigest, /^[a-f0-9]{64}$/);
  assert.match(evidence.digest, /^[a-f0-9]{64}$/);
  assert.equal((await app.getRecoveryReconciliationRevalidationEvidence(ownerId, evidence.id)).digest, evidence.digest);
  const listed = await app.listRecoveryReconciliationRevalidationEvidence(ownerId, { limit: 1 });
  assert.equal(listed.items[0].id, evidence.id);
  assert.equal((await app.store.getWork(ownerId, work.id))._storage.version, before._storage.version);
});

test("Batch 109: approval binds exact plan, source evidence, and fresh precondition digest", async t => {
  const { app, ownerId } = await setup(t);
  const { plan } = await makePlan(app, ownerId);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const approval = await app.approveRecoveryReconciliationPlan(ownerId, plan.id, evidence.id, { ttlMs: 30_000 });
  assert.equal(approval.kind, "recovery-reconciliation-approval");
  assert.equal(approval.approval.status, "approved");
  assert.equal(approval.approval.planDigest, plan.digest);
  assert.equal(approval.approval.revalidationEvidenceDigest, evidence.digest);
  assert.equal(approval.approval.preconditionBindingDigest, evidence.snapshot.preconditionBindingDigest);
  assert.equal(approval.approval.humanApprovalSatisfied, true);
  assert.equal(approval.approval.executionAllowed, false);
  assert.equal(approval.approval.automaticExecutionAllowed, false);
  const verification = await app.verifyRecoveryReconciliationApproval(ownerId, approval.id);
  assert.equal(verification.status, "valid");
  assert.equal(verification.approvalValid, true);
  assert.equal(verification.currentPreconditionBindingDigest, approval.approval.preconditionBindingDigest);
  assert.equal(verification.executionAllowed, false);
  assert.equal((await app.getRecoveryReconciliationApproval(ownerId, approval.id)).digest, approval.digest);
});

test("Batch 109: changed state between evidence capture and approval fails closed", async t => {
  const { app, ownerId } = await setup(t);
  const { work, plan } = await makePlan(app, ownerId);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const current = await app.store.getWork(ownerId, work.id);
  await app.store.putWork(ownerId, { ...current, auditMarker: "changed-before-approval" }, { expectedVersion: current._storage.version });
  await assert.rejects(
    () => app.approveRecoveryReconciliationPlan(ownerId, plan.id, evidence.id),
    error => approvalCode(error, "RECOVERY_RECONCILIATION_APPROVAL_PRECONDITIONS_CHANGED")
  );
});

test("Batch 109: approval verification becomes stale when a bound record changes after approval", async t => {
  const { app, ownerId } = await setup(t);
  const { work, plan } = await makePlan(app, ownerId);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const approval = await app.approveRecoveryReconciliationPlan(ownerId, plan.id, evidence.id);
  const current = await app.store.getWork(ownerId, work.id);
  await app.store.putWork(ownerId, { ...current, auditMarker: "changed-after-approval" }, { expectedVersion: current._storage.version });
  const verification = await app.verifyRecoveryReconciliationApproval(ownerId, approval.id);
  assert.equal(verification.status, "stale");
  assert.equal(verification.approvalValid, false);
  assert.equal(verification.reasonCode, "CURRENT_PRECONDITIONS_STALE");
  assert.equal(verification.executionAllowed, false);
});

test("Batch 109: incomplete or truncated revalidation evidence cannot be approved", async t => {
  const { app, ownerId } = await setup(t);
  const { plan } = await makePlan(app, ownerId, { multiple: true, maxActions: 1 });
  assert.equal(plan.plan.truncated, true);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  assert.equal(evidence.snapshot.status, "incomplete");
  await assert.rejects(
    () => app.approveRecoveryReconciliationPlan(ownerId, plan.id, evidence.id),
    error => approvalCode(error, "RECOVERY_RECONCILIATION_APPROVAL_REVALIDATION_NOT_FRESH")
  );
});

test("Batch 109: revalidation evidence cannot authorize a different plan", async t => {
  const { app, ownerId } = await setup(t);
  const { evidence: sourceEvidence, plan: planA } = await makePlan(app, ownerId, { multiple: true, maxActions: 1 });
  const planB = await app.planRecoveryReconciliation(ownerId, sourceEvidence.id, { maxActions: 2 });
  const revalidation = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, planA.id);
  await assert.rejects(
    () => app.approveRecoveryReconciliationPlan(ownerId, planB.id, revalidation.id),
    error => approvalCode(error, "RECOVERY_RECONCILIATION_APPROVAL_PLAN_MISMATCH")
  );
});

test("Batch 109: approval expires and is no longer valid", async t => {
  const { app, ownerId, advance } = await setup(t);
  const { plan } = await makePlan(app, ownerId);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const approval = await app.approveRecoveryReconciliationPlan(ownerId, plan.id, evidence.id, { ttlMs: 1_000 });
  advance(1_001);
  const verification = await app.verifyRecoveryReconciliationApproval(ownerId, approval.id);
  assert.equal(verification.status, "expired");
  assert.equal(verification.reasonCode, "APPROVAL_EXPIRED");
  assert.equal(verification.executionAllowed, false);
});

test("Batch 109: cross-owner access to revalidation evidence and approval is rejected", async t => {
  const { app, ownerId } = await setup(t, "owner-a-b109");
  const { plan } = await makePlan(app, ownerId);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const approval = await app.approveRecoveryReconciliationPlan(ownerId, plan.id, evidence.id);
  await assert.rejects(
    () => app.getRecoveryReconciliationRevalidationEvidence("owner-b-b109", evidence.id),
    error => approvalCode(error, "RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_NOT_FOUND")
  );
  await assert.rejects(
    () => app.verifyRecoveryReconciliationApproval("owner-b-b109", approval.id),
    error => approvalCode(error, "RECOVERY_RECONCILIATION_APPROVAL_NOT_FOUND")
  );
});

test("Batch 109: tampered revalidation evidence fails digest verification", async t => {
  const { app, ownerId } = await setup(t);
  const { plan } = await makePlan(app, ownerId);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const raw = await app.store.getEvidence(ownerId, evidence.id);
  await app.store.putEvidence(ownerId, { ...raw, snapshot: { ...raw.snapshot, status: "fresh-but-tampered" } }, { expectedVersion: raw._storage.version });
  await assert.rejects(
    () => app.getRecoveryReconciliationRevalidationEvidence(ownerId, evidence.id),
    error => approvalCode(error, "RECOVERY_RECONCILIATION_REVALIDATION_EVIDENCE_INTEGRITY_FAILED")
  );
});

test("Batch 109: approval verification is read-only and listings are bounded", async t => {
  const { app, ownerId } = await setup(t);
  const { work, plan } = await makePlan(app, ownerId);
  const evidence = await app.captureRecoveryReconciliationRevalidationEvidence(ownerId, plan.id);
  const approval = await app.approveRecoveryReconciliationPlan(ownerId, plan.id, evidence.id);
  const before = {
    work: (await app.store.getWork(ownerId, work.id))._storage.version,
    plan: (await app.store.getEvidence(ownerId, plan.id))._storage.version,
    evidence: (await app.store.getEvidence(ownerId, evidence.id))._storage.version,
    approval: (await app.store.getEvidence(ownerId, approval.id))._storage.version
  };
  const verify = await app.verifyRecoveryReconciliationApproval(ownerId, approval.id);
  const after = {
    work: (await app.store.getWork(ownerId, work.id))._storage.version,
    plan: (await app.store.getEvidence(ownerId, plan.id))._storage.version,
    evidence: (await app.store.getEvidence(ownerId, evidence.id))._storage.version,
    approval: (await app.store.getEvidence(ownerId, approval.id))._storage.version
  };
  assert.equal(verify.status, "valid");
  assert.deepEqual(after, before);
  assert.equal((await app.listRecoveryReconciliationApprovals(ownerId, { limit: 1 })).items.length, 1);
  assert.equal((await app.listRecoveryReconciliationRevalidationEvidence(ownerId, { limit: 1 })).items.length, 1);
});

test("Batch 109: HTTP routes and application boundary expose evidence and approval operations", async () => {
  const source = await readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  const applicationSource = await readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  for (const name of [
    "captureRecoveryReconciliationRevalidationEvidence", "getRecoveryReconciliationRevalidationEvidence",
    "listRecoveryReconciliationRevalidationEvidence", "approveRecoveryReconciliationPlan",
    "getRecoveryReconciliationApproval", "listRecoveryReconciliationApprovals", "verifyRecoveryReconciliationApproval"
  ]) assert.match(applicationSource, new RegExp(name));
  assert.match(source, /recovery-audit\/plans\/:id\/revalidation-evidence/);
  assert.match(source, /recovery-audit\/plans\/:id\/approval/);
  assert.match(source, /recovery-audit\/approvals\/:id\/verification/);
  assert.match(source, /recovery-audit\/revalidation-evidence/);
});
