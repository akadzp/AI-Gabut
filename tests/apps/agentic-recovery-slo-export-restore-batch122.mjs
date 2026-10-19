import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";
import { inspectRecoverySloEvidenceExportBundle } from "../../apps/agentic/backend/recovery-slo-export-restore.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
const hasCode = code => error => error?.code === code;
const cliPath = fileURLToPath(new URL("../../scripts/verify-recovery-slo-export.mjs", import.meta.url));

async function setup(t, { ownerId = "owner-b122", signer = null, keyId = null, publicKey = null, root = null } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b122-restore-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root: storageRoot }),
    clock: () => "2026-10-11T00:00:00.000Z", recoverySloExportSigner: signer,
    recoverySloExportKeyId: keyId, recoverySloExportPublicKey: publicKey });
  return { app, ownerId, root: storageRoot };
}

function signerFor(privateKey) {
  return payload => sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64url");
}

function resealIntegrityOnlyBundle(bundle) {
  const copy = structuredClone(bundle);
  const names = Object.keys(copy.sections).sort();
  const countOf = value => value == null ? 0 : Array.isArray(value) ? value.length : 1;
  const manifestSections = names.map(name => ({ name, count: countOf(copy.sections[name]), digest: digest(canonical(copy.sections[name])) }));
  copy.manifest.sections = manifestSections;
  copy.manifest.bundleDigest = digest(canonical({ domain: "agentic-v4-recovery-slo-evidence-export", schemaVersion: 1,
    ownerId: copy.ownerId, exportedAt: copy.exportedAt, sections: copy.sections, manifestSections }));
  copy.attestation.payload = { domain: "agentic-v4-recovery-slo-export-attestation", schemaVersion: 1,
    ownerId: copy.ownerId, exportedAt: copy.exportedAt, bundleDigest: copy.manifest.bundleDigest, keyId: null };
  copy.byteLength = Buffer.byteLength(canonical(copy), "utf8");
  return copy;
}

function runCli(args) {
  return spawnSync(process.execPath, [cliPath, ...args], { encoding: "utf8", timeout: 10000 });
}

test("Batch 122: standalone CLI verifies an integrity-only export without opening application storage", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  const file = path.join(fixture.root, "bundle.json");
  await fs.writeFile(file, JSON.stringify(bundle));
  const result = runCli(["--bundle", file, "--expected-owner", fixture.ownerId]);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "valid_integrity_only");
  assert.equal(report.mutationAllowed, false);
  assert.equal(report.readOnly, true);
});

test("Batch 122: standalone CLI rejects tampered bundles and owner mismatch", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  bundle.sections.evaluationEvidence[0].summary.status = "forged";
  const file = path.join(fixture.root, "tampered.json");
  await fs.writeFile(file, JSON.stringify(bundle));
  const tampered = runCli(["--bundle", file]);
  assert.equal(tampered.status, 2);
  assert.equal(JSON.parse(tampered.stdout).valid, false);
  const clean = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  await fs.writeFile(file, JSON.stringify(clean));
  const mismatch = runCli(["--bundle", file, "--expected-owner", "different-owner"]);
  assert.equal(mismatch.status, 2);
  assert.ok(JSON.parse(mismatch.stdout).findings.some(item => item.code === "RECOVERY_SLO_EXPORT_OWNER_SCOPE_MISMATCH"));
});

test("Batch 122: standalone CLI verifies Ed25519 only when a public key is supplied and required", async t => {
  const keys = generateKeyPairSync("ed25519");
  const fixture = await setup(t, { signer: signerFor(keys.privateKey), keyId: "b122-export-root", publicKey: keys.publicKey });
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  const bundleFile = path.join(fixture.root, "signed.json");
  const keyFile = path.join(fixture.root, "public.pem");
  await fs.writeFile(bundleFile, JSON.stringify(bundle));
  await fs.writeFile(keyFile, keys.publicKey.export({ type: "spki", format: "pem" }));
  const missingKey = runCli(["--bundle", bundleFile, "--require-signature"]);
  assert.equal(missingKey.status, 2);
  const verified = runCli(["--bundle", bundleFile, "--public-key", keyFile, "--require-signature"]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stdout).status, "valid_signed");
  const wrong = generateKeyPairSync("ed25519");
  const wrongFile = path.join(fixture.root, "wrong.pem");
  await fs.writeFile(wrongFile, wrong.publicKey.export({ type: "spki", format: "pem" }));
  assert.equal(runCli(["--bundle", bundleFile, "--public-key", wrongFile, "--require-signature"]).status, 2);
});

test("Batch 122: restore planning is dry-run only and leaves target storage unchanged", async t => {
  const source = await setup(t, { ownerId: "shared-owner" });
  await source.app.evaluateRecoverySLOs(source.ownerId);
  const bundle = await source.app.exportRecoverySloEvidenceBundle(source.ownerId);
  const target = await setup(t, { ownerId: "shared-owner" });
  const before = await target.app.store.listEvidence(target.ownerId);
  const plan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  const after = await target.app.store.listEvidence(target.ownerId);
  assert.equal(plan.status, "ready");
  assert.equal(plan.dryRun, true);
  assert.equal(plan.restoreExecuted, false);
  assert.equal(plan.mutationAllowed, false);
  assert.ok(plan.counts.import > 0);
  assert.deepEqual(after, before);
  assert.match(plan.planDigest, /^[a-f0-9]{64}$/);
});

test("Batch 122: restore planner marks identical records as present and blocks conflicting IDs", async t => {
  const source = await setup(t, { ownerId: "shared-owner" });
  const result = await source.app.evaluateRecoverySLOs(source.ownerId);
  const bundle = await source.app.exportRecoverySloEvidenceBundle(source.ownerId);
  const target = await setup(t, { ownerId: "shared-owner" });
  const evidence = bundle.sections.evaluationEvidence.find(item => item.id === result.evaluationEvidenceId);
  await target.app.store.putEvidence(target.ownerId, structuredClone(evidence), { overwrite: false });
  const identicalPlan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  assert.equal(identicalPlan.status, "ready");
  assert.ok(identicalPlan.actions.some(item => item.recordId === evidence.id && item.action === "already_present"));

  const altered = structuredClone(evidence);
  altered.summary.status = "different-target-content";
  await target.app.store.putEvidence(target.ownerId, altered, { overwrite: true });
  const conflictPlan = await target.app.planRecoverySloEvidenceRestore(target.ownerId, bundle);
  assert.equal(conflictPlan.status, "blocked");
  assert.ok(conflictPlan.findings.some(item => item.code === "RECOVERY_SLO_RESTORE_RECORD_CONFLICT"));
  assert.ok(conflictPlan.actions.some(item => item.recordId === evidence.id && item.action === "conflict"));
});

test("Batch 122: restore planner blocks owner mismatch and missing archive dependencies", async t => {
  const fixture = await setup(t, { ownerId: "source-owner" });
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  const other = await setup(t, { ownerId: "target-owner" });
  const ownerPlan = await other.app.planRecoverySloEvidenceRestore(other.ownerId, bundle);
  assert.equal(ownerPlan.status, "blocked");
  assert.ok(ownerPlan.findings.some(item => item.code === "RECOVERY_SLO_EXPORT_OWNER_SCOPE_MISMATCH"));

  const ids = await fixture.app.listRecoverySloEvaluationEvidence(fixture.ownerId, { limit: 10 });
  assert.ok(ids.total > 0);
  const expired = await setup(t, { ownerId: "archive-owner" });
  await expired.app.evaluateRecoverySLOs(expired.ownerId);
  // Construct a structurally sealed bundle with a missing archive dependency for the pure inspector.
  const archiveBundle = await expired.app.exportRecoverySloEvidenceBundle(expired.ownerId);
  archiveBundle.sections.evaluationEvidenceArchiveIndex = { id: "index", ownerId: expired.ownerId,
    kind: "recovery-slo-evaluation-archive-index", digest: "a".repeat(64),
    snapshot: { archives: [{ id: "missing-archive", digest: "b".repeat(64) }] } };
  const resealed = resealIntegrityOnlyBundle(archiveBundle);
  const inspected = inspectRecoverySloEvidenceExportBundle(resealed, { expectedOwnerId: expired.ownerId });
  assert.equal(inspected.valid, false);
  assert.ok(inspected.findings.some(item => item.code === "RECOVERY_SLO_EXPORT_ARCHIVE_INDEX_DEPENDENCY_MISSING"));
});

test("Batch 122: restore planner requires the configured trusted key when strict signature policy is requested", async t => {
  const keys = generateKeyPairSync("ed25519");
  const fixture = await setup(t, { signer: signerFor(keys.privateKey), keyId: "trusted-export-key", publicKey: keys.publicKey });
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  const plan = await fixture.app.planRecoverySloEvidenceRestore(fixture.ownerId, bundle, { requireTrustedSignature: true });
  assert.equal(plan.status, "ready");
  assert.equal(plan.sourceVerificationStatus, "valid_signed");
  const unsignedFixture = await setup(t, { ownerId: fixture.ownerId });
  const unsigned = await unsignedFixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  const blocked = await fixture.app.planRecoverySloEvidenceRestore(fixture.ownerId, unsigned, { requireTrustedSignature: true });
  assert.equal(blocked.status, "blocked");
  assert.ok(blocked.findings.some(item => item.code === "RECOVERY_SLO_RESTORE_TRUSTED_SIGNATURE_REQUIRED"));
});

test("Batch 122: inspector rejects storage metadata and duplicate record IDs even with recomputed integrity digests", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  bundle.sections.evaluationEvidence[0]._storage = { version: 1 };
  const withStorage = inspectRecoverySloEvidenceExportBundle(resealIntegrityOnlyBundle(bundle), { expectedOwnerId: fixture.ownerId });
  assert.equal(withStorage.valid, false);
  assert.ok(withStorage.findings.some(item => item.code === "RECOVERY_SLO_EXPORT_STORAGE_METADATA_FORBIDDEN"));

  const duplicate = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  duplicate.sections.alertLedger = structuredClone(duplicate.sections.evaluationEvidence[0]);
  duplicate.sections.alertLedger.kind = "recovery-slo-alert-ledger";
  const inspected = inspectRecoverySloEvidenceExportBundle(resealIntegrityOnlyBundle(duplicate), { expectedOwnerId: fixture.ownerId });
  assert.equal(inspected.valid, false);
  assert.ok(inspected.findings.some(item => item.code === "RECOVERY_SLO_EXPORT_DUPLICATE_RECORD_ID"));
});

test("Batch 122: restore planning is bounded, read-only, and exposed through application API and HTTP route", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const bundle = await fixture.app.exportRecoverySloEvidenceBundle(fixture.ownerId);
  const plan = await fixture.app.planRecoverySloEvidenceRestore(fixture.ownerId, bundle, { maxActions: 1 });
  assert.equal(plan.status, "blocked");
  assert.ok(plan.findings.some(item => item.code === "RECOVERY_SLO_RESTORE_ACTION_LIMIT_EXCEEDED"));
  const server = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.equal(typeof fixture.app.planRecoverySloEvidenceRestore, "function");
  assert.match(server, /evidence-export\/restore-plan/);
});

test("Batch 122: CLI fails with stable exit codes for usage and missing files", () => {
  assert.equal(runCli([]).status, 64);
  assert.equal(runCli(["--bundle", "/definitely/missing/recovery-slo-export.json"]).status, 66);
});
