import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createAgenticStore } from "../../apps/agentic/backend/store.js";
import { createStorage } from "../../core/storage/index.js";
import { createRecoverySloCrossDomainGovernanceHardeningService } from "../../apps/agentic/backend/recovery-slo-cross-domain-governance-hardening.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const digestRecord = value => { const copy = structuredClone(value); delete copy._storage; delete copy.digest; return sha256(canonical(copy)); };
function anchorProvider(baseUrl) {
  const records = new Map();
  return {
    baseUrl,
    async read(scope) { const value = records.get(scope); return value ? structuredClone(value) : null; },
    async compareAndSet(scope, expectedDigest, candidate) {
      const current = records.get(scope) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false };
      records.set(scope, structuredClone(candidate));
      return { applied: true };
    }
  };
}
function makeReceipt(ownerId, domain, suffix) {
  const unsigned = { id: `receipt-${suffix}`, ownerId,
    kind: "recovery-slo-cross-domain-provider-baseline-transition-receipt", schemaVersion: 1,
    domain, revision: 1, previousReceiptDigest: null, transitionChallengeId: `transition-${suffix}`,
    sourceReportDigest: suffix.padEnd(64, suffix).slice(0, 64), historyNotProven: false, createdAt: "2026-10-10T00:00:00.000Z" };
  return { ...unsigned, digest: digestRecord(unsigned) };
}
function manifestContext() {
  return { guardrails: { status: "healthy", compactionEligible: true, blockers: [], receiptAuditStatus: "healthy", baselineAuditStatus: "healthy",
    receiptCount: 2, receiptHeads: { alpha: { id: "receipt-a", digest: "a".repeat(64), revision: 1 }, beta: { id: "receipt-b", digest: "b".repeat(64), revision: 1 } } },
    checkpointStatus: { status: "anchored", anchorSequence: 2, anchorDigest: "c".repeat(64), policyBindingStatus: "current",
      anchoredPolicyDigest: "d".repeat(64), currentPolicyDigest: "d".repeat(64), sourceDigest: "e".repeat(64), sourceCount: 2 } };
}
async function waitForFile(file, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { await fs.access(file); return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 15));
  }
  throw new Error(`Timed out waiting for ${file}`);
}

 test("Batch 158: key-lifecycle checkpoint follows rotation/revocation across restart and rejects unproven registry drift", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b158-key-checkpoint-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const oldPair = generateKeyPairSync("ed25519"), nextPair = generateKeyPairSync("ed25519"), changedPair = generateKeyPairSync("ed25519");
  const makeSigner = pair => payload => sign(null, Buffer.from(canonical(payload)), pair.privateKey).toString("base64url");
  const signers = { key_old: makeSigner(oldPair), key_next: makeSigner(nextPair) };
  const publicKeys = { key_old: oldPair.publicKey, key_next: nextPair.publicKey };
  const provider = anchorProvider("https://key-lifecycle-anchor.example");
  const storage = createStorage({ root });
  const options = { storage, clock: () => "2026-10-13T00:00:00.000Z", recoverySloPolicyBindingAuditCheckpointAttestationSigner: signers.key_old,
    recoverySloPolicyBindingAuditCheckpointAttestationKeyId: "key_old", recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: publicKeys,
    recoverySloPolicyBindingAuditCheckpointAttestationSigners: signers,
    recoverySloCrossDomainAttestationKeyLifecycleAnchor: provider, requireRecoverySloCrossDomainAttestationKeyLifecycleAnchor: true };
  const app = createAgenticApplication(options), owner = "owner-b158-keys";
  assert.equal((await app.getRecoverySloCrossDomainAttestationKeyLifecycleCheckpointStatus(owner)).status, "enrollment_required");
  const enrollment = await app.prepareRecoverySloCrossDomainAttestationKeyLifecycleCheckpointEnrollment(owner,
    { reason: "Enroll the initial attestation key lifecycle baseline before key transitions." });
  await app.applyRecoverySloCrossDomainAttestationKeyLifecycleCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  const rotation = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, "key_next",
    { reason: "Rotate to the replacement key before retiring the original signer." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRotation(owner, rotation.challengeId, { confirmation: rotation.confirmation });
  assert.equal((await app.getRecoverySloCrossDomainAttestationKeyLifecycleCheckpointStatus(owner)).status, "behind_local");
  const advanced = await app.reconcileRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint(owner);
  assert.equal(advanced.status, "anchored");
  const revocation = await app.prepareRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation(owner, "key_old",
    { reason: "Revoke the retired signing key after confirming the replacement is active." });
  await app.applyRecoverySloPolicyBindingAuditCheckpointAttestationKeyRevocation(owner, revocation.challengeId, { confirmation: revocation.confirmation });
  assert.equal((await app.reconcileRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint(owner)).status, "anchored");

  const restarted = createAgenticApplication(options);
  const lifecycle = await restarted.auditRecoverySloPolicyBindingAuditCheckpointAttestationKeyLifecycle(owner);
  assert.equal(lifecycle.status, "healthy");
  assert.equal(lifecycle.activeKeyId, "key_next");
  assert.equal(lifecycle.keys.find(item => item.keyId === "key_old").status, "revoked");
  const checkpoint = await restarted.getRecoverySloCrossDomainAttestationKeyLifecycleCheckpointStatus(owner);
  assert.equal(checkpoint.status, "anchored");
  assert.equal(checkpoint.freshnessStatus, "fresh");
  assert.equal(checkpoint.historyNotProven, true, "initial enrollment must preserve the pre-enrollment history limitation");
  const changedRegistry = createAgenticApplication({ ...options, recoverySloPolicyBindingAuditCheckpointAttestationPublicKeys: {
    key_old: oldPair.publicKey, key_next: changedPair.publicKey } });
  const drift = await changedRegistry.getRecoverySloCrossDomainAttestationKeyLifecycleCheckpointStatus(owner);
  assert.equal(drift.status, "behind_local");
  await assert.rejects(() => changedRegistry.reconcileRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint(owner),
    error => error.code === "CROSS_DOMAIN_KEY_LIFECYCLE_CONTINUITY_UNPROVEN");
});

test("Batch 158: manifest ledger freshness and retention audit is read-only and prioritizes stale checkpoints", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b158-ledger-retention-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const storage = createStorage({ root }), store = createAgenticStore({ storage }), owner = "owner-b158-ledger";
  const createdAt = "2026-10-10T00:00:00.000Z";
  await store.putEvidence(owner, makeReceipt(owner, "alpha", "a"), { overwrite: false });
  await store.putEvidence(owner, makeReceipt(owner, "beta", "b"), { overwrite: false });
  let nowMs = Date.parse(createdAt);
  const governance = createRecoverySloCrossDomainGovernanceHardeningService({ store, clock: () => new Date(nowMs).toISOString() });
  const context = manifestContext();
  const manifest = await governance.createProviderBaselineReceiptCompactionManifest(owner, context);
  const challenge = await governance.prepareProviderBaselineReceiptCompactionManifestApproval(owner, manifest.manifest.id,
    { ...context, reason: "Approve this receipt manifest for review only, without compacting evidence." });
  const approval = await governance.applyProviderBaselineReceiptCompactionManifestApproval(owner, challenge.challengeId,
    { ...context, confirmation: challenge.confirmation });
  context.checkpointStatus = { ...context.checkpointStatus, status: "behind_local", anchorSequence: 3, anchorDigest: "f".repeat(64) };
  await governance.recordProviderBaselineReceiptCompactionManifestApprovalSupersession(owner, approval.approval.id,
    { verifyManifest: (targetOwnerId, manifestId) => governance.verifyProviderBaselineReceiptCompactionManifest(targetOwnerId, manifestId, context),
      reason: "Record supersession after the source checkpoint moved behind local state." });

  nowMs = Date.parse("2026-10-13T00:00:00.000Z");
  const provider = anchorProvider("https://manifest-ledger-anchor.example");
  const app = createAgenticApplication({ storage, clock: () => new Date(nowMs).toISOString(), recoverySloCrossDomainManifestApprovalLedgerAnchor: provider,
    recoverySloCrossDomainSnapshotAnchorMaxAgeMs: 86400000, recoverySloCrossDomainSnapshotAnchorFutureSkewMs: 60000,
    recoverySloCrossDomainSnapshotAnchorRetentionDays: 1 });
  const enrollment = await app.prepareRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner,
    { reason: "Enroll the manifest approval event ledger before freshness review." });
  await app.applyRecoverySloCrossDomainManifestApprovalLedgerCheckpointEnrollment(owner, enrollment.challengeId,
    { confirmation: enrollment.confirmation });
  let audit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerFreshnessRetention(owner);
  assert.equal(audit.status, "retention_review_due");
  assert.equal(audit.retentionReviewDue, true);
  assert.equal(audit.events.length, 1);
  assert.equal(audit.deletionPerformed, false);
  nowMs += 2 * 86400000;
  audit = await app.auditRecoverySloCrossDomainManifestApprovalLedgerFreshnessRetention(owner);
  assert.equal(audit.status, "stale");
  assert.equal(audit.freshnessStatus, "stale");
  assert.equal(audit.mutationAllowed, false);
  assert.equal(audit.deletionPerformed, false);
});

test("Batch 158: durable lease fencing serializes separate OS processes sharing one atomic store", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b158-lease-contention-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const store = createAgenticStore({ storage: createStorage({ root }) });
  const service = createRecoverySloCrossDomainGovernanceHardeningService({ store });
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const running = service.runLeasedRevalidation("owner-b158-process", "approval-shared", async () => {
    await gate;
    return { status: "current", usableForCurrentDecision: true };
  }, { leaseMs: 3000 });
  await new Promise(resolve => setTimeout(resolve, 100));
  const moduleUrl = new URL("../../apps/agentic/backend/recovery-slo-cross-domain-governance-hardening.js", import.meta.url).href;
  const storeUrl = new URL("../../apps/agentic/backend/store.js", import.meta.url).href;
  const storageUrl = new URL("../../core/storage/index.js", import.meta.url).href;
  const code = `import {createAgenticStore} from ${JSON.stringify(storeUrl)}; import {createStorage} from ${JSON.stringify(storageUrl)}; import {createRecoverySloCrossDomainGovernanceHardeningService} from ${JSON.stringify(moduleUrl)}; const store=createAgenticStore({storage:createStorage({root:process.env.AGENTIC_TEST_ROOT})}); const s=createRecoverySloCrossDomainGovernanceHardeningService({store}); const r=await s.runLeasedRevalidation("owner-b158-process","approval-shared",async()=>({status:"wrong"}),{leaseMs:3000}); process.stdout.write(JSON.stringify(r));`;
  const child = await new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, ["--input-type=module", "-e", code], { env: { ...process.env, AGENTIC_TEST_ROOT: root }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    proc.stdout.on("data", chunk => stdout += chunk);
    proc.stderr.on("data", chunk => stderr += chunk);
    proc.on("error", reject);
    proc.on("close", code => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`child exit ${code}: ${stderr}`)));
  });
  assert.equal(JSON.parse(child.stdout).status, "revalidation_in_progress");
  release();
  assert.equal((await running).status, "current");
  const audit = await service.auditRevalidationLeases("owner-b158-process");
  assert.equal(audit.status, "healthy");
});

test("Batch 158: crashed lease owner is recoverable after expiry and stale worker cannot publish", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b158-lease-crash-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const marker = path.join(root, "worker-acquired.marker");
  const moduleUrl = new URL("../../apps/agentic/backend/recovery-slo-cross-domain-governance-hardening.js", import.meta.url).href;
  const storeUrl = new URL("../../apps/agentic/backend/store.js", import.meta.url).href;
  const storageUrl = new URL("../../core/storage/index.js", import.meta.url).href;
  const code = `import fs from "node:fs"; import {createAgenticStore} from ${JSON.stringify(storeUrl)}; import {createStorage} from ${JSON.stringify(storageUrl)}; import {createRecoverySloCrossDomainGovernanceHardeningService} from ${JSON.stringify(moduleUrl)}; const store=createAgenticStore({storage:createStorage({root:process.env.AGENTIC_TEST_ROOT})}); const s=createRecoverySloCrossDomainGovernanceHardeningService({store}); await s.runLeasedRevalidation("owner-b158-crash","approval-crash",async()=>{fs.writeFileSync(process.env.AGENTIC_TEST_MARKER,"acquired"); await new Promise(()=>{});},{leaseMs:1000});`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", code], { env: { ...process.env, AGENTIC_TEST_ROOT: root, AGENTIC_TEST_MARKER: marker }, stdio: "ignore" });
  await waitForFile(marker);
  const childClosed = new Promise(resolve => {
    if (child.exitCode !== null || child.signalCode !== null) resolve();
    else child.once("close", resolve);
  });
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  await childClosed;
  const store = createAgenticStore({ storage: createStorage({ root }) });
  const service = createRecoverySloCrossDomainGovernanceHardeningService({ store });
  const before = await service.auditRevalidationLeases("owner-b158-crash");
  assert.equal(before.activeCount, 1);
  const lease = before.leases[0];
  await new Promise(resolve => setTimeout(resolve, Math.max(0, Date.parse(lease.leaseExpiresAt) - Date.now() + 30)));
  const expired = await service.auditRevalidationLeases("owner-b158-crash");
  assert.equal(expired.expiredCount, 1);
  assert.equal(expired.status, "recovery_required");
  const recovered = await service.recoverRevalidationLease("owner-b158-crash", "approval-crash");
  assert.equal(recovered.status, "recovered");
  const result = await service.runLeasedRevalidation("owner-b158-crash", "approval-crash", async ({ fencingToken }) => ({ status: "current", fencingToken }), { leaseMs: 1000 });
  assert.equal(result.status, "current");
  assert.ok(result.lease.fencingToken > recovered.fencingToken);
  assert.equal((await service.auditRevalidationLeases("owner-b158-crash")).status, "healthy");
});

test("Batch 158: APIs, HTTP routes, required-provider fail-closed, and provider independence are enforced", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b158-api-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const app = createAgenticApplication({ storage: createStorage({ root }) });
  for (const name of [
    "getRecoverySloCrossDomainAttestationKeyLifecycleCheckpointStatus", "reconcileRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint",
    "prepareRecoverySloCrossDomainAttestationKeyLifecycleCheckpointEnrollment", "applyRecoverySloCrossDomainAttestationKeyLifecycleCheckpointEnrollment",
    "auditRecoverySloCrossDomainAttestationKeyLifecycleCheckpoint", "auditRecoverySloCrossDomainManifestApprovalLedgerFreshnessRetention"
  ]) assert.equal(typeof app[name], "function", name);
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /attestation-key-lifecycle\/checkpoint\/status/);
  assert.match(serverSource, /manifest-approval-ledger\/freshness-retention\/audit/);
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloCrossDomainAttestationKeyLifecycleAnchor: true }),
    /attestation key-lifecycle checkpoint diwajibkan tetapi belum dikonfigurasi/);
  const shared = anchorProvider("https://shared-anchor.example");
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), recoverySloCrossDomainManifestApprovalLedgerAnchor: shared,
    recoverySloCrossDomainAttestationKeyLifecycleAnchor: shared }), /external anchor provider terpisah/);
});
