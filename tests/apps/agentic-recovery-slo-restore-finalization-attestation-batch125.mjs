import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const hasCode = code => error => error?.code === code;
const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};

function signingFixture() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId: "v4-finalizer-test-key",
    publicKey,
    privateKey,
    signer: async payload => sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64url"),
    publicKeys: { "v4-finalizer-test-key": publicKey }
  };
}

async function setup(t, { ownerId = "owner-b125", root = null, signing = null, requireAttestation = false } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b125-finalization-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  const app = createAgenticApplication({
    storage: createStorage({ root: storageRoot }),
    ...(signing ? {
      recoverySloFinalizationSigner: signing.signer,
      recoverySloFinalizationKeyId: signing.keyId,
      recoverySloFinalizationPublicKeys: signing.publicKeys
    } : {}),
    requireRecoverySloFinalizationAttestation: requireAttestation
  });
  return { app, ownerId, root: storageRoot };
}

async function sourceBundle(t, ownerId = "shared-b125-owner") {
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
  return { imported };
}

async function finalizeFixture(t, { signed = true, ownerId = "shared-b125-owner" } = {}) {
  const { bundle } = await sourceBundle(t, ownerId);
  const signing = signed ? signingFixture() : null;
  const target = await setup(t, { ownerId: bundle.ownerId, signing, requireAttestation: signed });
  const { imported } = await importToQuarantine(target, target.ownerId, bundle);
  const review = await target.app.reviewRecoverySloEvidenceRestoreQuarantine(target.ownerId, imported.journalId,
    { reason: "Reviewed restored evidence and verified the target snapshot." });
  const approval = await target.app.approveRecoverySloEvidencePromotion(target.ownerId, review.reviewId, {
    reason: "Approved evidence activation after integrity review.",
    confirmation: `APPROVE PROMOTION ${review.reviewDigest.slice(0, 12)}`
  });
  const promoted = await target.app.promoteRecoverySloQuarantinedEvidence(target.ownerId, approval.approvalId);
  const finalization = await target.app.finalizeRecoverySloEvidenceRestore(target.ownerId, promoted.journalId);
  return { target, ownerId: target.ownerId, signing, imported, review, approval, promoted, finalization };
}

test("Batch 125: finalization receipt is signed by an external Ed25519 signer and verifies against the trusted public key", async t => {
  const fixture = await finalizeFixture(t, { signed: true });
  const verified = await fixture.target.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, true);
  assert.equal(verified.status, "valid_signed");
  assert.equal(verified.keyId, fixture.signing.keyId);
  assert.equal(fixture.finalization.status, "finalized");
  const reconciliation = await fixture.target.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(reconciliation.status, "healthy");
  assert.equal(reconciliation.attestationStatus, "valid_signed");
});

test("Batch 125: invalid or modified external signature fails closed", async t => {
  const fixture = await finalizeFixture(t, { signed: true });
  const receipt = await fixture.target.app.store.getEvidence(fixture.ownerId, fixture.finalization.finalizationId);
  const tampered = structuredClone(receipt);
  tampered.attestation.signature = `${tampered.attestation.signature.slice(0, -1)}${tampered.attestation.signature.endsWith("A") ? "B" : "A"}`;
  await fixture.target.app.store.putEvidence(fixture.ownerId, tampered, { overwrite: true });
  const verified = await fixture.target.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, false);
  assert.equal(verified.status, "invalid");
  const reconciliation = await fixture.target.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(reconciliation.status, "unhealthy");
  await assert.rejects(fixture.target.app.getRecoverySloEscalationPolicy(fixture.ownerId), hasCode("RECOVERY_SLO_RESTORE_PROMOTION_FINALIZATION_REQUIRED"));
});

test("Batch 125: reconciliation detects active evidence drift after a valid finalization", async t => {
  const fixture = await finalizeFixture(t, { signed: true });
  const journal = await fixture.target.app.getRecoverySloEvidencePromotionJournal(fixture.ownerId, fixture.promoted.journalId);
  const policyItem = journal.items.find(item => item.section === "policyLedger");
  assert.ok(policyItem, "restore bundle includes a policy ledger for domain-level reconciliation");
  const active = await fixture.target.app.store.getEvidence(fixture.ownerId, policyItem.sourceRecordId);
  const tampered = structuredClone(active);
  tampered.snapshot.currentPolicy.windowMs += 1000;
  await fixture.target.app.store.putEvidence(fixture.ownerId, tampered, { overwrite: true });
  const reconciliation = await fixture.target.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(reconciliation.status, "unhealthy");
  assert.ok(reconciliation.findings.some(item => item.code === "RECOVERY_SLO_POST_PROMOTION_DOMAIN_AUDIT_FAILED"));
  assert.equal((await fixture.target.app.auditRecoverySloEvidenceRestorePromotions(fixture.ownerId)).status, "unhealthy");
  await assert.rejects(fixture.target.app.getRecoverySloEscalationPolicy(fixture.ownerId), hasCode("RECOVERY_SLO_POLICY_LEDGER_INTEGRITY_FAILED"));
});

test("Batch 125: reconciliation detects an altered finalization snapshot even when the signature field remains unchanged", async t => {
  const fixture = await finalizeFixture(t, { signed: true });
  const receipt = await fixture.target.app.store.getEvidence(fixture.ownerId, fixture.finalization.finalizationId);
  const tampered = structuredClone(receipt);
  tampered.activeSetDigest = "0".repeat(64);
  await fixture.target.app.store.putEvidence(fixture.ownerId, tampered, { overwrite: true });
  const result = await fixture.target.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(result.status, "unhealthy");
  assert.equal((await fixture.target.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId)).valid, false);
});

test("Batch 125: unsigned legacy mode remains explicit, while strict attestation mode rejects missing signer configuration", async t => {
  const fixture = await finalizeFixture(t, { signed: false });
  const verified = await fixture.target.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(verified.valid, true);
  assert.equal(verified.status, "valid_integrity_only");
  assert.throws(() => createAgenticApplication({ requireRecoverySloFinalizationAttestation: true }), /signer dan trusted public key/i);
});

test("Batch 125: untrusted key IDs cannot be used to validate a signed finalization receipt", async t => {
  const fixture = await finalizeFixture(t, { signed: true });
  const other = signingFixture();
  const verifier = await setup(t, { ownerId: fixture.ownerId, root: fixture.target.root, signing: {
    ...other,
    keyId: "another-key",
    publicKeys: { "another-key": other.publicKey }
  }, requireAttestation: true });
  const result = await verifier.app.verifyRecoverySloEvidenceRestoreFinalizationAttestation(fixture.ownerId, fixture.promoted.journalId);
  assert.equal(result.valid, false);
  assert.ok(result.findings.includes("ATTESTATION_KEY_UNTRUSTED") || result.findings.includes("FINALIZATION_RECEIPT_INVALID"));
});

test("Batch 125: finalization reconciliation is owner-scoped and read-only", async t => {
  const fixture = await finalizeFixture(t, { signed: true });
  await assert.rejects(fixture.target.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity("other-owner", fixture.promoted.journalId),
    hasCode("RECOVERY_SLO_PROMOTION_JOURNAL_NOT_FOUND"));
  const before = (await fixture.target.app.store.listEvidence(fixture.ownerId)).length;
  const result = await fixture.target.app.reconcileRecoverySloEvidenceRestoreFinalizationIntegrity(fixture.ownerId, fixture.promoted.journalId);
  const after = (await fixture.target.app.store.listEvidence(fixture.ownerId)).length;
  assert.equal(result.readOnly, true);
  assert.equal(result.mutationAllowed, false);
  assert.equal(before, after);
});

test("Batch 125: application API and HTTP routes expose finalization attestation verification and reconciliation", async () => {
  const applicationSource = await readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const serverSource = await readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(applicationSource, /verifyRecoverySloEvidenceRestoreFinalizationAttestation/);
  assert.match(applicationSource, /reconcileRecoverySloEvidenceRestoreFinalizationIntegrity/);
  assert.match(serverSource, /restore-promotions\/:id\/finalization-attestation/);
  assert.match(serverSource, /restore-promotions\/:id\/reconcile/);
});
