import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import { verifyRecoverySloEvidenceExportBundle } from "../../apps/agentic/backend/recovery-slo-alerting.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
const hasCode = code => error => error?.code === code;

async function setup(t, { ownerId = "owner-b121", signer = null, keyId = null, publicKey = null, root = null } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b121-slo-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const app = createAgenticApplication({ storage: createStorage({ root: storageRoot }),
    clock: () => new Date(time).toISOString(), recoverySloExportSigner: signer, recoverySloExportKeyId: keyId, recoverySloExportPublicKey: publicKey });
  return { app, ownerId, root: storageRoot, advance: ms => { time += ms; }, now: () => new Date(time).toISOString() };
}

async function createExpiredEvidence(fixture, count = 3) {
  await fixture.app.updateRecoverySloEscalationPolicy(fixture.ownerId, { expectedRevision: 1,
    reason: "Use minimum retention to exercise bounded archive recovery.", changes: { evaluationRetentionMs: 24 * 60 * 60 * 1000 } });
  const ids = [];
  for (let i = 0; i < count; i += 1) {
    const result = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
    ids.push(result.evaluationEvidenceId);
    fixture.advance(1000);
  }
  fixture.advance(25 * 60 * 60 * 1000);
  const prune = await fixture.app.pruneRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 100 });
  assert.equal(prune.expired, count);
  return ids;
}

function signerFor(privateKey) {
  return payload => sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64url");
}

test("Batch 121: expired evaluation evidence is compacted into a hash-linked archive and remains queryable", async t => {
  const fixture = await setup(t);
  const ids = await createExpiredEvidence(fixture, 3);
  const archived = await fixture.app.archiveExpiredRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 2 });
  assert.equal(archived.status, "archived");
  assert.equal(archived.archivedCount, 2);
  assert.equal(archived.removedSourceCount, 2);
  const stored = (await fixture.app.store.listEvidence(fixture.ownerId)).filter(item => item.kind === "recovery-slo-evaluation-evidence");
  assert.equal(stored.length, 1);
  const listing = await fixture.app.listRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 20 });
  assert.equal(listing.total, 3);
  assert.equal(listing.storedRecordCount, 1);
  assert.equal(listing.archivedCount, 2);
  const restored = await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, ids[0]);
  assert.equal(restored.state, "expired");
  assert.equal(restored.evaluation, null);
  assert.equal((await fixture.app.auditRecoverySloEvaluationEvidence(fixture.ownerId)).status, "healthy");
  assert.equal((await fixture.app.auditRecoverySloEvaluationEvidenceArchives(fixture.ownerId)).status, "healthy");
});

test("Batch 121: retention archive recovers an interrupted index write and source cleanup idempotently", async t => {
  const fixture = await setup(t);
  const ids = await createExpiredEvidence(fixture, 2);
  const originalTombstone = await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, ids[0]);
  const archived = await fixture.app.archiveExpiredRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 2 });
  const index = (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-slo-evaluation-archive-index");
  assert.ok(index);
  await fixture.app.store.mutateEvidence(fixture.ownerId, index.id, () => ({ delete: true, result: true }));
  await fixture.app.store.putEvidence(fixture.ownerId, originalTombstone, { overwrite: false });
  const before = await fixture.app.auditRecoverySloEvaluationEvidenceArchives(fixture.ownerId);
  assert.equal(before.status, "recovery_required");
  const recovered = await fixture.app.recoverRecoverySloEvaluationEvidenceArchives(fixture.ownerId);
  assert.equal(recovered.status, "healthy");
  assert.equal(recovered.indexRebuilt, true);
  assert.equal(recovered.removedSourceCount, 1);
  assert.equal((await fixture.app.auditRecoverySloEvaluationEvidenceArchives(fixture.ownerId)).status, "healthy");
  assert.equal((await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, ids[1])).state, "expired");
  assert.equal((await fixture.app.recoverRecoverySloEvaluationEvidenceArchives(fixture.ownerId)).status, "healthy");
  assert.ok(archived.archiveId);
});

test("Batch 121: conflicting archived source is never deleted during recovery", async t => {
  const fixture = await setup(t);
  const ids = await createExpiredEvidence(fixture, 1);
  await fixture.app.archiveExpiredRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 1 });
  const tombstone = await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, ids[0]);
  const altered = structuredClone(tombstone);
  altered.expiredAt = new Date(Date.parse(altered.expiredAt) + 1000).toISOString();
  altered.retentionTombstone.expiredAt = altered.expiredAt;
  altered.digest = digest(canonical(Object.fromEntries(Object.entries(altered).filter(([key]) => key !== "digest" && key !== "_storage"))));
  await fixture.app.store.putEvidence(fixture.ownerId, altered, { overwrite: false });
  const audit = await fixture.app.auditRecoverySloEvaluationEvidenceArchives(fixture.ownerId);
  assert.equal(audit.status, "unhealthy");
  await assert.rejects(fixture.app.recoverRecoverySloEvaluationEvidenceArchives(fixture.ownerId), hasCode("RECOVERY_SLO_EVALUATION_ARCHIVE_INTEGRITY_FAILED"));
  assert.ok(await fixture.app.store.getEvidence(fixture.ownerId, ids[0]));
});

test("Batch 121: export bundle contains complete alert/evaluation archives and verifies without application storage", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  fixture.advance(1000);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  await fixture.app.archiveRecoverySloAlertLedgerEvents(fixture.ownerId, { limit: 1, retainRecent: 1 });
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  assert.equal(bundle.kind, "recovery-slo-evidence-export-bundle");
  assert.equal(bundle.sections.evaluationEvidence.length, 2);
  assert.equal(bundle.sections.alertArchives.length, 1);
  assert.equal(bundle.attestation.status, "integrity_only");
  assert.equal(verifyRecoverySloEvidenceExportBundle(bundle).status, "valid_integrity_only");
  assert.equal(fixture.app.verifyRecoverySloEvidenceExportBundle(bundle).valid, true);
  const tampered = structuredClone(bundle);
  tampered.sections.evaluationEvidence[0].summary.status = "forged";
  assert.equal(verifyRecoverySloEvidenceExportBundle(tampered).status, "invalid");
  await assert.rejects(fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId, { maxBytes: 1 }), hasCode("RECOVERY_SLO_EXPORT_SIZE_LIMIT_EXCEEDED"));
});

test("Batch 121: external Ed25519 signer creates an independently verifiable export attestation", async t => {
  const keys = generateKeyPairSync("ed25519");
  const fixture = await setup(t, { signer: signerFor(keys.privateKey), keyId: "export-root-1", publicKey: keys.publicKey });
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  assert.equal(bundle.attestation.status, "signed");
  assert.equal(verifyRecoverySloEvidenceExportBundle(bundle, { publicKey: keys.publicKey }).status, "valid_signed");
  assert.equal(verifyRecoverySloEvidenceExportBundle(bundle).status, "valid_integrity_signature_unverified");
  const wrongKeys = generateKeyPairSync("ed25519");
  assert.equal(verifyRecoverySloEvidenceExportBundle(bundle, { publicKey: wrongKeys.publicKey }).status, "invalid");
  const changedKeyId = structuredClone(bundle);
  changedKeyId.attestation.keyId = "different-root";
  assert.equal(verifyRecoverySloEvidenceExportBundle(changedKeyId, { publicKey: keys.publicKey }).status, "invalid");
});

test("Batch 121: export fails closed when source evidence audit is unhealthy", async t => {
  const fixture = await setup(t);
  const result = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const record = await fixture.app.store.getEvidence(fixture.ownerId, result.evaluationEvidenceId);
  const tampered = structuredClone(record);
  tampered.summary.status = "forged";
  await fixture.app.store.putEvidence(fixture.ownerId, tampered, { expectedVersion: record._storage.version });
  await assert.rejects(fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId), hasCode("RECOVERY_SLO_EXPORT_SOURCE_AUDIT_FAILED"));
});

test("Batch 121: concurrent retention compaction serializes and never duplicates archive sequences", async t => {
  const fixture = await setup(t);
  await createExpiredEvidence(fixture, 4);
  const results = await Promise.all([
    fixture.app.archiveExpiredRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 3 }),
    fixture.app.archiveExpiredRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 3 })
  ]);
  assert.equal(results.reduce((sum, item) => sum + (item.archivedCount || 0), 0), 4);
  const audit = await fixture.app.auditRecoverySloEvaluationEvidenceArchives(fixture.ownerId);
  assert.equal(audit.status, "healthy");
  assert.equal(audit.archiveCount, 2);
  assert.deepEqual((await fixture.app.listRecoverySloEvaluationEvidenceArchives(fixture.ownerId)).items.map(item => item.sequence).sort(), [1, 2]);
});

test("Batch 121: archived evaluation evidence remains bound to alert history after compaction", async t => {
  const fixture = await setup(t);
  const ids = await createExpiredEvidence(fixture, 2);
  await fixture.app.archiveExpiredRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 2 });
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "healthy");
  fixture.advance(1000);
  const next = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  assert.ok(next.evaluationEvidenceId);
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "healthy");
  assert.equal((await fixture.app.getRecoverySloEvaluationEvidence(fixture.ownerId, ids[0])).state, "expired");
});

test("Batch 121: archive tampering is detected and blocks export", async t => {
  const fixture = await setup(t);
  await createExpiredEvidence(fixture, 1);
  const archived = await fixture.app.archiveExpiredRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 1 });
  const archive = await fixture.app.store.getEvidence(fixture.ownerId, archived.archiveId);
  const tampered = structuredClone(archive);
  tampered.entries[0].contentDigest = "0".repeat(64);
  await fixture.app.store.putEvidence(fixture.ownerId, tampered, { expectedVersion: archive._storage.version });
  assert.equal((await fixture.app.auditRecoverySloEvaluationEvidenceArchives(fixture.ownerId)).status, "unhealthy");
  await assert.rejects(fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId), hasCode("RECOVERY_SLO_EXPORT_SOURCE_AUDIT_FAILED"));
});

test("Batch 121: application APIs and HTTP routes expose export, archive recovery, and standalone verification", async t => {
  const fixture = await setup(t);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  for (const method of ["auditRecoverySloEvaluationEvidenceArchives", "getRecoverySloEvaluationEvidenceArchiveStatus",
    "listRecoverySloEvaluationEvidenceArchives", "archiveExpiredRecoverySloEvaluationEvidence", "recoverRecoverySloEvaluationEvidenceArchives",
    "exportRecoverySloEvidenceBundle", "verifyRecoverySloEvidenceExportBundle"]) assert.equal(typeof fixture.app[method], "function");
  assert.match(source, /anchor\/slo\/evaluations\/archive-expired/);
  assert.match(source, /anchor\/slo\/evaluations\/archives\/audit/);
  assert.match(source, /anchor\/slo\/evidence-export/);
  assert.match(source, /OWNER_SCOPE_MISMATCH/);
});

test("Batch 121: signer failure is not downgraded to an unsigned export", async t => {
  const keys = generateKeyPairSync("ed25519");
  const fixture = await setup(t, { signer: async () => { throw new Error("signer offline"); }, keyId: "export-root-1", publicKey: keys.publicKey });
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  await assert.rejects(fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId), hasCode("RECOVERY_SLO_EXPORT_ATTESTATION_FAILED"));
});
