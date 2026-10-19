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
  return { baseUrl, records,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate)); return { applied: true };
    } };
}
async function setup(root, extra = {}, clock = () => "2026-10-14T00:00:00.000Z") {
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519");
  const pairs = { finalization_key_old: oldPair, finalization_key_next: nextPair };
  const storage = createStorage({ root });
  const app = createAgenticApplication({ storage, clock,
    recoverySloDriftRemediationFinalizationAttestationSigner: signer(oldPair),
    recoverySloDriftRemediationFinalizationAttestationKeyId: "finalization_key_old",
    recoverySloDriftRemediationFinalizationAttestationPublicKeys: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, pair.publicKey])),
    recoverySloDriftRemediationFinalizationAttestationSigners: Object.fromEntries(Object.entries(pairs).map(([id, pair]) => [id, signer(pair)])),
    ...extra });
  return { app, storage, pairs };
}

test("Batch 179: required decision-gate receipt attestation fails closed without a trusted signer", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b179-required-attestation" }),
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true }),
  /decision-gate audit receipt attestation diwajibkan/);
});

test("Batch 179: receipt Ed25519 attestation binds receipt, checkpoint snapshot, and policy state", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-attestation-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app, pairs } = await setup(root, { requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const owner = "b179-attestation";
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-signed-receipt" });
  assert.equal(audit.decisionGateAuditReceipt.status, "recorded");
  const receipt = audit.decisionGateAuditReceipt.receipt;
  assert.equal(receipt.schemaVersion, 3);
  assert.equal(receipt.attestation.algorithm, "Ed25519");
  assert.equal(receipt.attestation.receiptPayloadDigest, sha256(canonical(Object.fromEntries(Object.entries(receipt).filter(([key]) => !["digest", "attestation", "_storage"].includes(key))))));
  assert.equal(receipt.attestation.policyStateDigest, receipt.policyStateDigest);
  assert.equal(receipt.attestation.decisionEvidenceBindingDigest, receipt.decisionEvidenceBindingDigest);
  assert.equal(receipt.attestation.receiptCheckpointBindingDigest, receipt.receiptCheckpointBindingDigest);
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner, receipt.id);
  assert.equal(verification.status, "verified_current");
  assert.equal(verification.signingKeyId, "finalization_key_old");
  assert.ok(pairs.finalization_key_old.publicKey);
  const ledgerAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false });
  assert.equal(ledgerAudit.status, "healthy");
  assert.equal(ledgerAudit.latestAttestationVerification.status, "verified_current");
  assert.equal(ledgerAudit.usableForCurrentDecision, false, "the decision itself was blocked/local-only even though the attestation is current");
});

test("Batch 179: strict attestation preserves legacy receipt integrity but does not treat legacy receipts as current evidence", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-legacy-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const first = await setup(root);
  const owner = "b179-legacy";
  const legacy = await first.app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-legacy-receipt" });
  assert.equal(legacy.decisionGateAuditReceipt.receipt.schemaVersion, 2);
  const second = await setup(root, { requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const before = await second.app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false });
  assert.equal(before.status, "healthy");
  assert.equal(before.legacyUnattestedCount, 1);
  assert.equal(before.usableForCurrentDecision, false);
  const current = await second.app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-new-signed-receipt" });
  assert.equal(current.decisionGateAuditReceipt.status, "recorded");
  assert.equal(current.decisionGateAuditReceipt.receipt.schemaVersion, 3);
  const after = await second.app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false });
  assert.equal(after.status, "healthy");
  assert.equal(after.receiptCount, 2);
  assert.equal(after.legacyUnattestedCount, 1);
  assert.equal(after.latestAttestationVerification.status, "verified_current");
});

test("Batch 179: altered signature is rejected even when an attacker recomputes local digests", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-tamper-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app } = await setup(root, { requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const owner = "b179-tamper";
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-tamper-source" });
  const original = audit.decisionGateAuditReceipt.receipt;
  const tampered = structuredClone(original);
  tampered.attestation.signature = "A".repeat(86);
  tampered.digest = digestRecord(tampered);
  const result = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner, tampered);
  assert.equal(result.status, "unhealthy");
  assert.equal(result.reasonCode, "RECOVERY_DECISION_GATE_RECEIPT_ATTESTATION_SIGNATURE_INVALID");
});

test("Batch 179: attestation expires to historical-only status instead of remaining current", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-expiry-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  let now = Date.parse("2026-10-14T00:00:00.000Z");
  const clock = () => new Date(now).toISOString();
  const { app } = await setup(root, { requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true,
    recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationMaxAgeMs: 60000 }, clock);
  const owner = "b179-expiry";
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-expiring-receipt" });
  const receiptId = audit.decisionGateAuditReceipt.receipt.id;
  now += 120000;
  const result = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner, receiptId);
  assert.equal(result.status, "historically_valid_stale");
  assert.equal(result.historicallyValid, true);
  assert.equal(result.usableForCurrentDecision, false);
  assert.ok(result.staleReasons.includes("ATTESTATION_EXPIRED"));
});


test("Batch 179: a signed receipt bound to a different policy state is historical-only", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-policy-change-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const first = await setup(root, { requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const owner = "b179-policy-change";
  const audit = await first.app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-policy-bound-receipt" });
  const receipt = structuredClone(audit.decisionGateAuditReceipt.receipt);
  const pair = first.pairs.finalization_key_old;
  const changedPolicyDigest = "f".repeat(64);
  receipt.policyStateDigest = changedPolicyDigest;
  receipt.evidenceBinding.decisionEvidenceBinding.policyStateDigest = changedPolicyDigest;
  receipt.decisionEvidenceBindingDigest = sha256(canonical(receipt.evidenceBinding.decisionEvidenceBinding));
  receipt.evidenceBinding.decisionEvidenceBindingDigest = receipt.decisionEvidenceBindingDigest;
  receipt.evidenceBindingDigest = sha256(canonical(receipt.evidenceBinding));
  receipt.replayFingerprint = sha256(canonical({ ownerId: owner, requestId: receipt.requestId, decisionStatus: receipt.decisionStatus,
    decisionEvidenceBindingDigest: receipt.decisionEvidenceBindingDigest, decisionReasonsDigest: receipt.decisionReasonsDigest }));
  receipt.attestation.policyStateDigest = changedPolicyDigest;
  receipt.attestation.decisionEvidenceBindingDigest = receipt.decisionEvidenceBindingDigest;
  const receiptPayload = Object.fromEntries(Object.entries(receipt).filter(([key]) => !["digest", "attestation", "_storage"].includes(key)));
  receipt.attestation.receiptPayloadDigest = sha256(canonical(receiptPayload));
  const unsignedAttestation = structuredClone(receipt.attestation);
  delete unsignedAttestation.signature;
  delete unsignedAttestation.payloadDigest;
  receipt.attestation.payloadDigest = sha256(canonical(unsignedAttestation));
  receipt.attestation.signature = sign(null, Buffer.from(canonical({ ...unsignedAttestation, payloadDigest: receipt.attestation.payloadDigest })), pair.privateKey).toString("base64url");
  receipt.digest = digestRecord(receipt);
  const verification = await first.app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner, receipt);
  assert.equal(verification.status, "historically_valid_stale");
  assert.equal(verification.historicallyValid, true);
  assert.equal(verification.usableForCurrentDecision, false);
  assert.ok(verification.staleReasons.includes("POLICY_STATE_CHANGED"));
});

test("Batch 179: a signing-key lifecycle transition makes an older receipt attestation historical-only", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-key-cutoff-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app } = await setup(root, { requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const owner = "b179-key-cutoff";
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-key-cutoff-receipt" });
  const receiptId = audit.decisionGateAuditReceipt.receipt.id;
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Bind subsequent attestations to the explicit active key lifecycle." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner, receiptId);
  assert.equal(verification.status, "historically_valid_stale");
  assert.equal(verification.historicallyValid, true);
  assert.equal(verification.usableForCurrentDecision, false);
  assert.ok(verification.staleReasons.includes("SIGNING_KEY_LIFECYCLE_CHANGED"));
});

test("Batch 179: pending receipt checkpoint marker can be recovered without appending another receipt", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-marker-recovery-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b179-marker-recovery", provider = anchorProvider("https://b179-decision-receipt-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-bootstrap" });
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    { reason: "Enroll bootstrap receipt history before Batch 179 recovery testing." });
  await app.applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-anchored" });
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  const beforeCount = (await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false })).receiptCount;
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingRecovery(owner);
  assert.equal(inspection.status, "recoverable");
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.receiptCount, beforeCount);
  assert.equal((await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceipts(owner, { includeCheckpoint: false })).receiptCount, beforeCount);
});

test("Batch 179: receipt checkpoint recovery blocks an external rollback instead of guessing continuity", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-gap-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const owner = "b179-gap", provider = anchorProvider("https://b179-gap-anchor.example");
  const { app } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-gap-bootstrap" });
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    { reason: "Enroll before testing bounded receipt continuity." });
  await app.applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-gap-one" });
  const scope = `agentic-v4-cross_domain_recovery_decision_gate_audit_receipts-${sha256(owner).slice(0, 32)}`;
  const anchored = structuredClone(provider.records.get(scope));
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-gap-two" });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b179-gap-three" });
  provider.records.set(scope, anchored);
  const inspection = await app.inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingRecovery(owner);
  assert.equal(inspection.status, "unhealthy");
  assert.equal(inspection.recoverable, false);
  assert.ok(inspection.findings.some(item => item.code === "EXTERNAL_SNAPSHOT_CHECKPOINT_ROLLBACK_SUSPECTED"
    || item.code === "EXTERNAL_SNAPSHOT_CHECKPOINT_ANCHOR_ROLLBACK_SUSPECTED"
    || /ROLLBACK/.test(item.code || "")));
});

test("Batch 179: attestation and pending-recovery APIs are exported", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b179-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app } = await setup(root);
  for (const name of [
    "verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation",
    "inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingRecovery",
    "recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState"
  ]) assert.equal(typeof app[name], "function", `${name} must be exported`);
  const server = await fs.readFile(path.resolve("apps/agentic/backend/server.js"), "utf8");
  for (const route of [
    "/receipts/:id/attestation/verify",
    "/receipts/recovery/inspect",
    "/receipts/recovery"
  ]) assert.ok(server.includes(route), `HTTP route ${route} must be registered`);
});
