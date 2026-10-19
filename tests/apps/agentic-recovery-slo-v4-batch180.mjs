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
async function enrollAttestationCheckpoint(app, owner, reason = "Enroll the attestation-history trust domain from a known baseline.") {
  const challenge = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointEnrollment(owner, { reason });
  return app.applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointEnrollment(owner,
    challenge.challengeId, { confirmation: challenge.confirmation });
}

test("Batch 180: required independent attestation checkpoint fails closed without provider", () => {
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root: "/tmp/agentic-b180-required-anchor" }),
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationAnchor: true }),
  /External recovery decision-gate receipt attestation checkpoint diwajibkan/);
});

test("Batch 180: independently anchored attestation history becomes current after enrollment and append", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b180-attestation-anchor-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const provider = anchorProvider("https://b180-attestation-anchor.example");
  const { app } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const owner = "b180-attestation-anchor";
  const enrolled = await enrollAttestationCheckpoint(app, owner);
  assert.equal(enrolled.status, "anchored");
  assert.equal(enrolled.historyNotProven, false);
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b180-first-signed-receipt" });
  assert.equal(audit.decisionGateAuditReceipt.status, "recorded");
  assert.equal(audit.decisionGateAuditReceipt.receipt.schemaVersion, 3);
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointStatus(owner);
  assert.equal(checkpoint.status, "anchored");
  assert.equal(checkpoint.freshnessStatus, "fresh");
  assert.equal(checkpoint.historyNotProven, false);
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner,
    audit.decisionGateAuditReceipt.receipt.id);
  assert.equal(verification.status, "verified_current");
  const checkpointAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpoint(owner);
  assert.equal(checkpointAudit.status, "healthy");
  assert.equal(checkpointAudit.usableForCurrentDecision, true);
});

test("Batch 180: signing-key cutoff revalidation makes old attestation historical-only despite a fresh attestation anchor", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b180-key-cutoff-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const provider = anchorProvider("https://b180-key-cutoff-anchor.example");
  const { app } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const owner = "b180-key-cutoff";
  await enrollAttestationCheckpoint(app, owner);
  const audit = await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b180-cutoff-receipt" });
  const receiptId = audit.decisionGateAuditReceipt.receipt.id;
  assert.equal((await app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner, receiptId)).status, "verified_current");
  const challenge = await app.prepareRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner,
    { action: "activate", keyId: "finalization_key_old", reason: "Explicitly bind subsequent attestations to current key lifecycle." });
  await app.applyRecoverySloCrossDomainDriftRemediationFinalizationKeyLifecycleTransition(owner, challenge.challengeId,
    { confirmation: challenge.confirmation });
  const checkpoint = await app.getRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointStatus(owner);
  assert.equal(checkpoint.status, "anchored");
  assert.equal(checkpoint.freshnessStatus, "fresh");
  const verification = await app.verifyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation(owner, receiptId);
  assert.equal(verification.status, "historically_valid_stale");
  assert.ok(verification.staleReasons.includes("SIGNING_KEY_LIFECYCLE_CHANGED"));
  assert.equal(verification.usableForCurrentDecision, false);
});

test("Batch 180: tampered receipt signature is detected by independent attestation source audit", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b180-attestation-tamper-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const provider = anchorProvider("https://b180-tamper-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationAnchor: true,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestation: true });
  const owner = "b180-attestation-tamper";
  await enrollAttestationCheckpoint(app, owner);
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b180-tamper-receipt" });
  const store = createAgenticStore({ storage });
  const ledgerId = `cross-domain-recovery-decision-gate-audit-receipts-${sha256(owner).slice(0, 40)}`;
  const ledger = await store.getEvidence(owner, ledgerId);
  const events = structuredClone(ledger.events);
  events[0].attestation.signature = "A".repeat(86);
  events[0].digest = digestRecord(events[0]);
  const unsigned = { ...ledger, events, eventCount: events.length, headDigest: events.at(-1).digest };
  delete unsigned._storage; delete unsigned.digest;
  const candidate = { ...unsigned, digest: digestRecord(unsigned) };
  await store.putEvidence(owner, candidate, { expectedVersion: ledger._storage?.version });
  const audit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpoint(owner);
  assert.equal(audit.status, "unhealthy");
  assert.ok(audit.findings.some(item => item.code === "RECOVERY_DECISION_GATE_RECEIPT_ATTESTATION_SOURCE_SIGNATURE_INVALID"));
});

test("Batch 180: receipt recovery finalization uses CAS and is idempotent for the same anchored postcondition", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b180-recovery-finalization-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const provider = anchorProvider("https://b180-recovery-anchor.example");
  const { app, storage } = await setup(root, { recoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: provider,
    requireRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAnchor: true });
  const owner = "b180-recovery-finalization";
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b180-bootstrap" });
  const enrollment = await app.prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner,
    { reason: "Enroll the existing receipt ledger before recovery testing." });
  await app.applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  await app.auditRecoverySloCrossDomainCheckpointFreshnessReplay(owner, { requestId: "b180-anchored-receipt" });
  const store = createAgenticStore({ storage });
  const markerId = `cross-domain-recovery-decision-gate-audit-receipt-checkpoint-marker-${sha256(owner).slice(0, 40)}`;
  const marker = await store.getEvidence(owner, markerId);
  assert.ok(marker);
  await store.state.delete("evidence", `${owner}--${markerId}`, { expectedVersion: marker._storage?.version });
  const recovered = await app.recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptPendingState(owner);
  assert.equal(recovered.status, "recovered");
  assert.equal(recovered.finalizationReceipt.status, "finalized");
  const firstAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(firstAudit.status, "healthy");
  assert.equal(firstAudit.receiptCount, 1);
  const secondFinalization = await app.finalizeRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryCAS(owner, recovered.result);
  assert.equal(secondFinalization.status, "finalized");
  assert.equal(secondFinalization.idempotent, true);
  const secondAudit = await app.auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations(owner);
  assert.equal(secondAudit.receiptCount, 1);
  assert.equal(secondAudit.status, "healthy");
});

test("Batch 180: new checkpoint and recovery-finalization APIs/routes are exported", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b180-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const { app } = await setup(root);
  for (const name of [
    "getRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointStatus",
    "prepareRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointEnrollment",
    "applyRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointEnrollment",
    "auditRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpoint",
    "inspectRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpointRecovery",
    "recoverRecoverySloCrossDomainRecoveryDecisionGateAuditReceiptAttestationCheckpoint",
    "auditRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryFinalizations",
    "finalizeRecoverySloCrossDomainRecoveryDecisionGateReceiptRecoveryCAS"
  ]) assert.equal(typeof app[name], "function", `${name} must be exported`);
  const server = await fs.readFile(path.resolve("apps/agentic/backend/server.js"), "utf8");
  for (const route of ["/receipts/attestation-checkpoint/status", "/receipts/attestation-checkpoint/enrollment-challenges",
    "/receipts/attestation-checkpoint/recovery/inspect", "/receipts/recovery/finalizations/audit"])
    assert.ok(server.includes(route), `HTTP route ${route} must be registered`);
});
