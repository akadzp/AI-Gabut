import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const hasCode = code => error => error?.code === code;

async function setup(t, { ownerId = "owner-b124", storage = null, root = null, clock = () => new Date().toISOString() } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b124-restore-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: storage || createStorage({ root: storageRoot }), clock });
  return { app, ownerId, root: storageRoot };
}

async function sourceBundle(t, ownerId = "shared-b124-owner") {
  const source = await setup(t, { ownerId });
  await source.app.evaluateRecoverySLOs(ownerId);
  return { source, bundle: await source.app.exportRecoverySloEvidenceBundle(ownerId) };
}

async function importToQuarantine(target, ownerId, bundle) {
  const plan = await target.app.planRecoverySloEvidenceRestore(ownerId, bundle);
  assert.equal(plan.status, "ready");
  const importApproval = await target.app.approveRecoverySloEvidenceRestorePlan(ownerId, plan, bundle, {
    reason: "Reviewed source integrity and target restore impact.",
    confirmation: `APPROVE RESTORE ${plan.planDigest.slice(0, 12)}`
  });
  const imported = await target.app.applyRecoverySloEvidenceRestorePlan(ownerId, importApproval.approvalId, bundle);
  assert.equal(imported.status, "completed");
  return { plan, importApproval, imported };
}

async function reviewAndApprovePromotion(target, ownerId, imported, overrides = {}) {
  const review = await target.app.reviewRecoverySloEvidenceRestoreQuarantine(ownerId, imported.journalId, {
    reason: overrides.reviewReason || "Reviewed quarantined evidence and target activation impact."
  });
  const reviewDetails = await target.app.getRecoverySloEvidenceRestoreQuarantineReview(ownerId, review.reviewId);
  const approval = await target.app.approveRecoverySloEvidencePromotion(ownerId, review.reviewId, {
    reason: overrides.approvalReason || "Approved promotion after independent evidence integrity review.",
    confirmation: overrides.confirmation || `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}`
  });
  return { review, reviewDetails, approval };
}

function interruptedPromotionStorage(root) {
  const base = createStorage({ root });
  let activeRecordWritten = false;
  let failPromotionJournalUpdate = true;
  const decodeRecordId = key => {
    if (!key.startsWith("agentic/evidence/")) return "";
    const ownerScopedId = decodeURIComponent(key.slice("agentic/evidence/".length));
    const marker = ownerScopedId.indexOf("--");
    return marker < 0 ? "" : ownerScopedId.slice(marker + 2);
  };
  return {
    read: key => base.read(key), write: (key, value) => base.write(key, value), remove: key => base.remove(key), list: prefix => base.list(prefix),
    atomicUpdate: async (key, updater) => {
      const id = decodeRecordId(key);
      if (failPromotionJournalUpdate && activeRecordWritten && id.startsWith("recovery-slo-evidence-promotion-")
        && !id.startsWith("recovery-slo-evidence-promotion-approval-")) {
        failPromotionJournalUpdate = false;
        throw Object.assign(new Error("simulated interruption after active evidence write"), { code: "TEST_PROMOTION_INTERRUPTED" });
      }
      const result = await base.atomicUpdate(key, updater);
      if (failPromotionJournalUpdate && ["recovery-slo-policy-ledger-", "recovery-slo-alert-ledger-", "recovery-slo-evaluation-", "recovery-slo-evaluation-archive-index-"]
        .some(prefix => id.startsWith(prefix))) activeRecordWritten = true;
      return result;
    }
  };
}

test("Batch 124: quarantine review requires a completed healthy import and records a digest-bound snapshot", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const before = await target.app.store.listEvidence(target.ownerId);
  const review = await target.app.reviewRecoverySloEvidenceRestoreQuarantine(target.ownerId, imported.journalId,
    { reason: "Reviewed quarantine contents before any activation." });
  assert.equal(review.status, "ready");
  assert.ok(review.counts.promote > 0);
  const details = await target.app.getRecoverySloEvidenceRestoreQuarantineReview(target.ownerId, review.reviewId);
  assert.equal(details.reviewDigest, review.reviewDigest);
  assert.equal(details.items.length, review.counts.total);
  assert.equal((await target.app.store.listEvidence(target.ownerId)).length, before.length + 1);
  assert.equal((await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).items.every(item => item.activated === false), true);
});

test("Batch 124: review rejects quarantine tampering", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const quarantine = (await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId, { journalId: imported.journalId })).items[0];
  const stored = await target.app.store.getEvidence(target.ownerId, quarantine.id);
  const tampered = structuredClone(stored);
  tampered.payloadDigest = "0".repeat(64);
  await target.app.store.putEvidence(target.ownerId, tampered, { overwrite: true });
  await assert.rejects(target.app.reviewRecoverySloEvidenceRestoreQuarantine(target.ownerId, imported.journalId,
    { reason: "Review attempted after evidence tampering was found." }), hasCode("RECOVERY_SLO_RESTORE_IMPORT_AUDIT_FAILED"));
});


test("Batch 124: a pre-existing conflicting target produces a blocked review and cannot be approved", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const quarantine = (await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId, { journalId: imported.journalId })).items[0];
  const sourceRecord = structuredClone((await target.app.store.getEvidence(target.ownerId, quarantine.id)).payload);
  sourceRecord.injectedConflict = true;
  await target.app.store.putEvidence(target.ownerId, sourceRecord, { overwrite: false });
  const review = await target.app.reviewRecoverySloEvidenceRestoreQuarantine(target.ownerId, imported.journalId,
    { reason: "Reviewed a target conflict before approving evidence activation." });
  assert.equal(review.status, "blocked");
  assert.equal(review.counts.conflicts, 1);
  await assert.rejects(target.app.approveRecoverySloEvidencePromotion(target.ownerId, review.reviewId,
    { reason: "Approval attempted despite a detected target conflict.", confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}` }),
    hasCode("RECOVERY_SLO_RESTORE_REVIEW_BLOCKED"));
});

test("Batch 124: promotion approval requires a valid review, reason, and digest confirmation", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const review = await target.app.reviewRecoverySloEvidenceRestoreQuarantine(target.ownerId, imported.journalId,
    { reason: "Reviewed quarantined evidence before approval." });
  await assert.rejects(target.app.approveRecoverySloEvidencePromotion(target.ownerId, review.reviewId,
    { reason: "short", confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}` }),
    hasCode("RECOVERY_SLO_EVIDENCE_PROMOTION_REASON_REQUIRED"));
  await assert.rejects(target.app.approveRecoverySloEvidencePromotion(target.ownerId, review.reviewId,
    { reason: "Approved after review of the quarantine set.", confirmation: "APPROVE PROMOTION wrong" }),
    hasCode("RECOVERY_SLO_EVIDENCE_PROMOTION_CONFIRMATION_REQUIRED"));
  const approved = await target.app.approveRecoverySloEvidencePromotion(target.ownerId, review.reviewId,
    { reason: "Approved after review of the quarantine set.", confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}` });
  const repeated = await target.app.approveRecoverySloEvidencePromotion(target.ownerId, review.reviewId,
    { reason: "Approved after review of the quarantine set.", confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}` });
  assert.equal(repeated.approvalId, approved.approvalId);
  assert.equal(repeated.idempotent, true);
});

test("Batch 124: target change after review invalidates the review before promotion approval", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const review = await target.app.reviewRecoverySloEvidenceRestoreQuarantine(target.ownerId, imported.journalId,
    { reason: "Reviewed target before promoting restored evidence." });
  const details = await target.app.getRecoverySloEvidenceRestoreQuarantineReview(target.ownerId, review.reviewId);
  const item = details.items[0];
  const q = await target.app.store.getEvidence(target.ownerId, item.quarantineRecordId);
  const conflict = structuredClone(q.payload);
  conflict.injectedConflict = true;
  await target.app.store.putEvidence(target.ownerId, conflict, { overwrite: false });
  await assert.rejects(target.app.approveRecoverySloEvidencePromotion(target.ownerId, review.reviewId,
    { reason: "Approved after review of the quarantine set.", confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}` }),
    hasCode("RECOVERY_SLO_RESTORE_REVIEW_STALE"));
});

test("Batch 124: promotion writes active copies only after approval and holds SLO APIs until finalization", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { review, approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  const before = await target.app.store.listEvidence(target.ownerId);
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId);
  assert.equal(promoted.status, "completed");
  assert.equal(promoted.counts.promoted + promoted.counts.alreadyPresent, review.counts.total);
  const activeRecordIds = (await target.app.getRecoverySloEvidencePromotionJournal(target.ownerId, promoted.journalId)).items.map(item => item.sourceRecordId);
  for (const id of activeRecordIds) assert.ok(await target.app.store.getEvidence(target.ownerId, id));
  assert.ok((await target.app.store.listEvidence(target.ownerId)).length > before.length);
  await assert.rejects(target.app.getRecoverySloEscalationPolicy(target.ownerId), hasCode("RECOVERY_SLO_RESTORE_PROMOTION_FINALIZATION_REQUIRED"));
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "recovery_required");
  assert.equal((await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId)).items.every(item => item.activated === false), true);
});

test("Batch 124: finalization verifies active payloads, creates an idempotent receipt, and releases the SLO gate", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId);
  const finalization = await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, promoted.journalId);
  assert.equal(finalization.status, "finalized");
  assert.equal(finalization.activeRecordCount, promoted.counts.promoted + promoted.counts.alreadyPresent);
  const repeated = await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, promoted.journalId);
  assert.equal(repeated.finalizationId, finalization.finalizationId);
  assert.equal(repeated.idempotent, true);
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "healthy");
  const quarantine = await target.app.listRecoverySloEvidenceRestoreQuarantine(target.ownerId, { journalId: imported.journalId });
  assert.ok(quarantine.items.every(item => item.activated === true && item.promoted === true));
  const policy = await target.app.getRecoverySloEscalationPolicy(target.ownerId);
  assert.equal(policy.initialized, false);
  await target.app.evaluateRecoverySLOs(target.ownerId);
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "healthy",
    "legitimate SLO evolution after finalization must not invalidate the source snapshot receipt");
  assert.equal((await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, promoted.journalId)).idempotent, true,
    "repeated finalization must remain idempotent after legitimate SLO evolution");
});

test("Batch 124: finalization fails closed when any active record no longer matches quarantine", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId);
  const journal = await target.app.getRecoverySloEvidencePromotionJournal(target.ownerId, promoted.journalId);
  const active = await target.app.store.getEvidence(target.ownerId, journal.items[0].sourceRecordId);
  const changed = structuredClone(active);
  changed.injectedTampering = true;
  await target.app.store.putEvidence(target.ownerId, changed, { overwrite: true });
  await assert.rejects(target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, promoted.journalId),
    hasCode("RECOVERY_SLO_RESTORE_FINALIZATION_ACTIVE_RECORD_MISMATCH"));
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "unhealthy");
  await assert.rejects(target.app.getRecoverySloEscalationPolicy(target.ownerId), hasCode("RECOVERY_SLO_RESTORE_PROMOTION_FINALIZATION_REQUIRED"));
});


test("Batch 124: after finalization, normal SLO changes remain allowed but invalid active ledger data is still rejected", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId);
  await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, promoted.journalId);
  await target.app.evaluateRecoverySLOs(target.ownerId);
  const all = await target.app.store.listEvidence(target.ownerId);
  const policyLedger = all.find(item => item.kind === "recovery-slo-policy-ledger");
  const tampered = structuredClone(policyLedger);
  tampered.snapshot.currentPolicy.windowMs += 1000;
  await target.app.store.putEvidence(target.ownerId, tampered, { overwrite: true });
  await assert.rejects(target.app.getRecoverySloEscalationPolicy(target.ownerId), hasCode("RECOVERY_SLO_POLICY_LEDGER_INTEGRITY_FAILED"));
});

test("Batch 124: promotion recovery resumes after active write but before journal item update", async t => {
  const { bundle } = await sourceBundle(t);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b124-interrupt-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const target = await setup(t, { ownerId: bundle.ownerId, root, storage: interruptedPromotionStorage(root) });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  await assert.rejects(target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId),
    hasCode("TEST_PROMOTION_INTERRUPTED"));
  const pending = await target.app.listRecoverySloEvidencePromotionJournals(target.ownerId);
  assert.equal(pending.total, 1);
  assert.equal(pending.items[0].status, "applying");
  const recovered = await target.app.recoverRecoverySloEvidencePromotion(target.ownerId, pending.items[0].journalId);
  assert.equal(recovered.status, "completed");
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "recovery_required");
  const finalization = await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, recovered.journalId);
  assert.equal(finalization.status, "finalized");
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "healthy");
});

test("Batch 124: concurrent promotion calls converge on one journal without overwriting active records", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  const results = await Promise.allSettled([
    target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId),
    target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId)
  ]);
  assert.ok(results.some(item => item.status === "fulfilled" && item.value.status === "completed"));
  assert.equal((await target.app.listRecoverySloEvidencePromotionJournals(target.ownerId)).total, 1);
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "recovery_required");
  const journal = (await target.app.listRecoverySloEvidencePromotionJournals(target.ownerId)).items[0];
  assert.equal((await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, journal.journalId)).status, "finalized");
  assert.equal((await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId)).status, "healthy");
});

test("Batch 124: owner isolation protects review, approval, promotion journal, and finalization", async t => {
  const { bundle } = await sourceBundle(t, "owner-b124-source");
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { review, approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId);
  await assert.rejects(target.app.getRecoverySloEvidenceRestoreQuarantineReview("different-owner", review.reviewId),
    hasCode("RECOVERY_SLO_RESTORE_REVIEW_NOT_FOUND"));
  await assert.rejects(target.app.getRecoverySloEvidencePromotionJournal("different-owner", promoted.journalId),
    hasCode("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND"));
  await assert.rejects(target.app.finalizeRecoverySloEvidenceRestore("different-owner", promoted.journalId),
    hasCode("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND"));
});

test("Batch 124: promotion audit detects finalization receipt tampering and remains read-only", async t => {
  const { bundle } = await sourceBundle(t);
  const target = await setup(t, { ownerId: bundle.ownerId });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const { approval } = await reviewAndApprovePromotion(target, target.ownerId, imported);
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId);
  await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, promoted.journalId);
  const before = await target.app.store.listEvidence(target.ownerId);
  const receipt = before.find(item => item.kind === "recovery-slo-evidence-restore-finalization");
  const changed = structuredClone(receipt);
  changed.activeRecordCount += 1;
  await target.app.store.putEvidence(target.ownerId, changed, { overwrite: true });
  const after = await target.app.store.listEvidence(target.ownerId);
  const audit = await target.app.auditRecoverySloEvidenceRestorePromotions(target.ownerId);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_SLO_RESTORE_FINALIZATION_INVALID"));
  assert.equal(after.length, before.length);
  await assert.rejects(target.app.evaluateRecoverySLOs(target.ownerId), hasCode("RECOVERY_SLO_RESTORE_PROMOTION_FINALIZATION_REQUIRED"));
});

test("Batch 124: application APIs and HTTP routes expose review, promotion, recovery, finalization, and audit", async t => {
  const target = await setup(t);
  const apiNames = ["reviewRecoverySloEvidenceRestoreQuarantine", "getRecoverySloEvidenceRestoreQuarantineReview",
    "listRecoverySloEvidenceRestoreQuarantineReviews", "approveRecoverySloEvidencePromotion", "promoteRecoverySloQuarantinedEvidence",
    "recoverRecoverySloEvidencePromotion", "getRecoverySloEvidencePromotionJournal", "listRecoverySloEvidencePromotionJournals",
    "finalizeRecoverySloEvidenceRestore", "auditRecoverySloEvidenceRestorePromotions"];
  for (const name of apiNames) assert.equal(typeof target.app[name], "function", name);
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const route of ["restore-quarantine/:journalId/review", "restore-reviews/:id/approve-promotion", "restore-promotions/apply",
    "restore-promotions/:id/recover", "restore-promotions/:id/finalize", "restore-promotions/audit"]) assert.ok(server.includes(route), route);
});
