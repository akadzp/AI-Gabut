import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createAgenticApplication } from "../../apps/agentic/backend/application.js";
import { createStorage } from "../../core/storage/index.js";

const canonical = value => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");
const hasCode = code => error => error?.code === code;
function keyPair() {
  const pair = generateKeyPairSync("ed25519");
  return { ...pair, publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString() };
}
const signPayload = (payload, pair) => sign(null, Buffer.from(canonical(payload), "utf8"), pair.privateKey).toString("base64url");
function provider(version = "1.0.0") {
  const records = new Map();
  const v11 = ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"];
  const out = {
    state: { records },
    async read(ownerId) { return structuredClone(records.get(ownerId) ?? null); },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      const current = records.get(ownerId) ?? null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: structuredClone(current) };
      if (candidate.ownerId !== ownerId || candidate.anchorSequence !== (current ? current.anchorSequence + 1 : 1)
        || candidate.revision <= (current?.revision ?? 0) || candidate.previousAnchorDigest !== (current?.digest ?? null)) {
        const error = new Error("non-monotonic candidate rejected"); error.code = "TEST_ANCHOR_NON_MONOTONIC"; throw error;
      }
      records.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    },
    contractInfo: version === "1.1.0" ? { contractId: "agentic-v4-trust-anchor-provider", version, schemaVersion: 1,
      capabilities: v11, ownerScope: "ownerId", casSemantics: "digest-compare-and-set" }
      : { contractId: "agentic-v4-trust-anchor-provider", version, schemaVersion: 1,
        capabilities: ["read", "compareAndSet"], ownerScope: "ownerId", casSemantics: "digest-compare-and-set" }
  };
  return out;
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b130-governance-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const finalizer = keyPair();
  const continuity = keyPair();
  const runbook = keyPair();
  let nowMs = Date.parse("2026-10-12T00:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const anchor = options.anchor || provider(options.providerVersion || "1.0.0");
  const app = createAgenticApplication({
    storage: createStorage({ root }), clock,
    recoverySloFinalizationSigner: async payload => signPayload(payload, finalizer),
    recoverySloFinalizationKeyId: "finalizer-root",
    recoverySloFinalizationPublicKeys: { "finalizer-root": finalizer.publicKey },
    requireRecoverySloFinalizationAttestation: true,
    recoverySloFinalizationRecoveryPublicKeys: { "recovery-root": keyPair().publicKey },
    recoverySloFinalizationKeyPolicyAnchor: anchor,
    requireRecoverySloFinalizationKeyPolicyAnchor: true,
    recoverySloFinalizationKeyPolicyAnchorContractVersion: options.baseContractVersion || "1.0.0",
    recoverySloAnchorContinuitySigner: async payload => signPayload(payload, continuity),
    recoverySloAnchorContinuityKeyId: "continuity-root",
    recoverySloAnchorContinuityPublicKeys: { "continuity-root": continuity.publicKey },
    recoverySloRunbookSigner: options.disableRunbookSigner ? null : async payload => signPayload(payload, runbook),
    recoverySloRunbookKeyId: options.disableRunbookSigner ? null : "runbook-root",
    recoverySloRunbookPublicKeys: options.disableRunbookSigner ? null : { "runbook-root": runbook.publicKey },
    requireRecoverySloSignedRunbookAttestation: options.requireSignedRunbook || false,
    recoverySloEvidenceRetentionDays: options.retentionDays || 90
  });
  return { app, anchor, finalizer, continuity, runbook, ownerId: options.ownerId || "owner-b130", root,
    clock, advance: ms => { nowMs += ms; }, now: () => nowMs };
}
async function runConformance(f) {
  const challenge = await f.app.prepareRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, {
    reason: "Validate provider semantics before approving the contract migration."
  });
  return f.app.runRecoverySloFinalizationKeyPolicyAnchorProviderConformance(f.ownerId, challenge.challengeId, {
    confirmation: challenge.confirmation
  });
}

test("Batch 130: contract migration requires recent behavioral conformance and does not change the active version during planning", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  await assert.rejects(f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Move the provider contract to the validated target version."
  }), hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_CONFORMANCE_REQUIRED"));
  const conformance = await runConformance(f);
  assert.equal(conformance.status, "conformant");
  const planned = await f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Move the provider contract to the validated target version."
  });
  assert.equal(planned.status, "planned");
  assert.equal(planned.approvalRequired, true);
  assert.equal((await f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId)).expectedVersion, "1.0.0");
  assert.equal((await f.app.auditRecoverySloAnchorContractMigration(f.ownerId)).status, "empty");
});

test("Batch 130: contract migration requires digest-bound approval and applies idempotently", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  await runConformance(f);
  const planned = await f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Migrate only after the provider behavior was checked."
  });
  await assert.rejects(f.app.applyRecoverySloFinalizationAnchorContractMigration(f.ownerId, "missing-approval", {
    expectedVersion: "1.0.0", targetVersion: "1.1.0"
  }), hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_APPROVAL_INVALID"));
  await assert.rejects(f.app.approveRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: "APPROVE CONTRACT MIGRATION wrong-token",
    reason: "Approve this migration after validating the target contract."
  }), hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_CONFIRMATION_INVALID"));
  const approved = await f.app.approveRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve this migration after validating the target contract."
  });
  assert.equal(approved.status, "approved");
  const applied = await f.app.applyRecoverySloFinalizationAnchorContractMigration(f.ownerId, approved.approval.id, {
    expectedVersion: "1.0.0", targetVersion: "1.1.0"
  });
  assert.equal(applied.status, "applied");
  assert.equal(applied.activeVersion, "1.1.0");
  assert.equal((await f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId)).expectedVersion, "1.1.0");
  const restarted = createAgenticApplication({ storage: createStorage({ root: f.root }), clock: f.clock,
    recoverySloFinalizationKeyPolicyAnchor: f.anchor, requireRecoverySloFinalizationKeyPolicyAnchor: true,
    recoverySloFinalizationKeyPolicyAnchorContractVersion: "1.0.0" });
  assert.equal((await restarted.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId)).expectedVersion, "1.1.0");
  const repeated = await f.app.applyRecoverySloFinalizationAnchorContractMigration(f.ownerId, approved.approval.id, {
    expectedVersion: "1.0.0", targetVersion: "1.1.0"
  });
  assert.equal(repeated.idempotent, true);
  assert.equal((await f.app.auditRecoverySloAnchorContractMigration(f.ownerId)).status, "healthy");
  await assert.rejects(f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.0.0", reason: "Attempt a prohibited downgrade to the older contract."
  }), hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_DOWNGRADE_BLOCKED"));
  const events = await f.app.listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId, { limit: 100 });
  assert.ok(events.items.some(item => item.type === "contract_migration_applied" && item.payload.targetVersion === "1.1.0"));
});

test("Batch 130: migration is blocked by stale plans, stale conformance, and downgrades", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  await runConformance(f);
  const planned = await f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Prepare a migration whose approval will be time-bounded."
  });
  f.advance(31 * 60 * 1000);
  await assert.rejects(f.app.approveRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve this migration after validating the target contract."
  }), hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_PLAN_EXPIRED"));
  f.advance(25 * 60 * 60 * 1000);
  await assert.rejects(f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Prepare migration after conformance proof has expired."
  }), hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_CONFORMANCE_REQUIRED"));
});

test("Batch 130: entire runbook is Ed25519-attested and rejects altered content or signatures", async t => {
  const f = await fixture(t, { requireSignedRunbook: true });
  const exported = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  assert.equal(exported.signedRunbookAttestation, true);
  assert.equal(exported.runbook.attestation.signing.algorithm, "Ed25519");
  const verified = await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, exported.runbook);
  assert.equal(verified.valid, true);
  assert.equal(verified.runbookAttestationValid, true);
  assert.equal(verified.runbookIntegrityValid, true);
  const changed = structuredClone(exported.runbook);
  changed.recommendedActions[0].instruction = "Silently overwrite the production trust anchor.";
  assert.equal((await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, changed)).valid, false);
  const badSignature = structuredClone(exported.runbook);
  badSignature.attestation.signature = `${badSignature.attestation.signature.slice(0, -1)}${badSignature.attestation.signature.endsWith("A") ? "B" : "A"}`;
  assert.equal((await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, badSignature)).valid, false);
});

test("Batch 130: strict runbook attestation rejects missing signer configuration", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b130-strict-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloSignedRunbookAttestation: true }),
    /Signed runbook memerlukan signer/);
});

test("Batch 130: recovery evidence retention prunes expired payloads to digest-preserving tombstones", async t => {
  const f = await fixture(t, { retentionDays: 1, requireSignedRunbook: true });
  const exported = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  assert.ok(exported.retention.id);
  let audit = await f.app.auditRecoverySloRecoveryEvidenceRetention(f.ownerId);
  assert.equal(audit.status, "healthy");
  f.advance(2 * 86400_000);
  audit = await f.app.auditRecoverySloRecoveryEvidenceRetention(f.ownerId);
  assert.equal(audit.status, "degraded");
  assert.equal(audit.dueCount, 1);
  const pruned = await f.app.pruneRecoverySloRecoveryEvidenceRetention(f.ownerId, { limit: 10 });
  assert.equal(pruned.prunedCount, 1);
  assert.equal(pruned.audit.status, "healthy");
  const listing = await f.app.listRecoverySloRecoveryEvidenceRetention(f.ownerId, { limit: 10 });
  assert.equal(listing.items[0].status, "expired");
  assert.equal(listing.items[0].tombstone.reason, "RETENTION_POLICY_ELAPSED");
  const stored = await f.app.store.getEvidence(f.ownerId, listing.items[0].id);
  assert.equal(stored.payload, null);
  assert.equal(stored.tombstone.originalPayloadDigest, stored.payloadDigest);
  assert.match(stored.tombstone.originalRecordDigest, /^[a-f0-9]{64}$/);
});

test("Batch 130: retention audit detects tampering and remains owner-scoped", async t => {
  const f = await fixture(t);
  const exported = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  const other = await f.app.listRecoverySloRecoveryEvidenceRetention("other-owner", { limit: 10 });
  assert.equal(other.recordCount, 0);
  const stored = await f.app.store.getEvidence(f.ownerId, exported.retention.id);
  stored.payloadDigest = sha256("tampered-payload-digest");
  await f.app.store.putEvidence(f.ownerId, stored);
  const audit = await f.app.auditRecoverySloRecoveryEvidenceRetention(f.ownerId);
  assert.equal(audit.status, "unhealthy");
  await assert.rejects(f.app.pruneRecoverySloRecoveryEvidenceRetention(f.ownerId), hasCode("RECOVERY_SLO_EVIDENCE_RETENTION_UNHEALTHY"));
});

test("Batch 130: continuity exports are retained and application APIs expose migration, attestation, and retention routes", async t => {
  const f = await fixture(t);
  await f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, { action: "rotate", expectedRevision: 1,
    newKeyId: "finalizer-next", newPublicKey: keyPair().publicPem, reason: "Initialize the finalization policy for continuity evidence retention." });
  const exported = await f.app.exportRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence(f.ownerId);
  assert.ok(exported.retention.id);
  const listing = await f.app.listRecoverySloRecoveryEvidenceRetention(f.ownerId, { limit: 10 });
  assert.ok(listing.items.some(item => item.id === exported.retention.id));
  const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(appSource, /createRecoverySloFinalizationAnchorGovernanceService/);
  assert.equal(typeof f.app.planRecoverySloFinalizationAnchorContractMigration, "function");
  assert.equal(typeof f.app.approveRecoverySloFinalizationAnchorContractMigration, "function");
  assert.equal(typeof f.app.applyRecoverySloFinalizationAnchorContractMigration, "function");
  assert.equal(typeof f.app.pruneRecoverySloRecoveryEvidenceRetention, "function");
  assert.match(serverSource, /contract-migrations\/plan/);
  assert.match(serverSource, /recovery-evidence-retention\/prune/);
});

test("Batch 130: migration approval rejects a conformance proof that expires after planning", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  await runConformance(f);
  f.advance(23 * 60 * 60 * 1000 + 59 * 60 * 1000);
  const planned = await f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Plan while the conformance proof is still within policy age."
  });
  f.advance(2 * 60 * 1000);
  await assert.rejects(f.app.approveRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approval must recheck the age of the behavioral conformance proof."
  }), hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_CONFORMANCE_REQUIRED"));
});

test("Batch 130: migration ledger tampering makes the persisted active contract version untrustworthy", async t => {
  const f = await fixture(t, { providerVersion: "1.1.0" });
  await runConformance(f);
  const planned = await f.app.planRecoverySloFinalizationAnchorContractMigration(f.ownerId, {
    targetVersion: "1.1.0", reason: "Create a valid migration ledger before the integrity test."
  });
  const approved = await f.app.approveRecoverySloFinalizationAnchorContractMigration(f.ownerId, planned.plan.id, {
    planDigest: planned.planDigest, confirmation: planned.confirmation,
    reason: "Approve a valid migration to establish a durable policy ledger."
  });
  await f.app.applyRecoverySloFinalizationAnchorContractMigration(f.ownerId, approved.approval.id, {
    expectedVersion: "1.0.0", targetVersion: "1.1.0"
  });
  const ledger = (await f.app.store.listEvidence(f.ownerId)).find(item => item.kind === "recovery-slo-anchor-contract-migration-ledger");
  assert.ok(ledger);
  ledger.activeVersion = "1.0.0";
  await f.app.store.putEvidence(f.ownerId, ledger);
  await assert.rejects(f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId),
    hasCode("RECOVERY_SLO_CONTRACT_MIGRATION_POLICY_UNHEALTHY"));
  assert.equal((await f.app.auditRecoverySloAnchorContractMigration(f.ownerId)).status, "unhealthy");
});

test("Batch 130: a configured runbook signer failure never falls back to an unsigned export", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b130-signer-failure-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const pair = keyPair();
  const app = createAgenticApplication({ storage: createStorage({ root }),
    recoverySloRunbookSigner: async () => { throw new Error("offline"); },
    recoverySloRunbookKeyId: "runbook-root", recoverySloRunbookPublicKeys: { "runbook-root": pair.publicKey } });
  await assert.rejects(app.exportRecoverySloFinalizationAnchorRecoveryRunbook("owner-b130-signer-failure"),
    hasCode("RECOVERY_SLO_RUNBOOK_SIGNER_FAILED"));
});
