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
function anchorProvider(options = {}) {
  const records = new Map();
  const provider = {
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
    }
  };
  if (options.contractInfo !== false) provider.contractInfo = options.contractInfo || {
    contractId: "agentic-v4-trust-anchor-provider", version: "1.0.0", schemaVersion: 1,
    capabilities: ["read", "compareAndSet"], ownerScope: "ownerId", casSemantics: "digest-compare-and-set"
  };
  return provider;
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b129-anchor-evidence-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const finalizer = keyPair();
  const continuity = keyPair();
  const provider = options.provider || anchorProvider(options.providerOptions);
  const app = createAgenticApplication({
    storage: createStorage({ root }), clock: () => "2026-10-12T00:00:00.000Z",
    recoverySloFinalizationSigner: async payload => signPayload(payload, finalizer),
    recoverySloFinalizationKeyId: "finalizer-root",
    recoverySloFinalizationPublicKeys: { "finalizer-root": finalizer.publicKey },
    requireRecoverySloFinalizationAttestation: true,
    recoverySloFinalizationRecoveryPublicKeys: { "recovery-root": keyPair().publicKey },
    recoverySloFinalizationKeyPolicyAnchor: provider,
    requireRecoverySloFinalizationKeyPolicyAnchor: true,
    recoverySloFinalizationKeyPolicyAnchorContractVersion: options.contractVersion || "1.0.0",
    recoverySloAnchorContinuitySigner: options.disableSigner ? null : async payload => {
      if (options.signerFailure) throw new Error("test signer failure");
      return signPayload(payload, continuity);
    },
    recoverySloAnchorContinuityKeyId: options.disableSigner ? null : "continuity-root",
    recoverySloAnchorContinuityPublicKeys: options.disableSigner ? null : { "continuity-root": continuity.publicKey },
    requireRecoverySloSignedContinuityEvidence: options.requireSigned || false
  });
  return { app, provider, finalizer, continuity, ownerId: options.ownerId || "owner-b129", root };
}
async function initializePolicy(f) {
  return f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "finalizer-next", newPublicKey: keyPair().publicPem,
    reason: "Initialize and externally anchor the finalization key policy before export."
  });
}

test("Batch 129: provider contract is explicitly versioned and legacy implicit v1 remains visible", async t => {
  const f = await fixture(t, { providerOptions: { contractInfo: false } });
  const status = await f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId);
  assert.equal(status.status, "compatible_legacy");
  assert.equal(status.expectedVersion, "1.0.0");
  assert.equal(status.actualVersion, "1.0.0");
  assert.ok(status.findings.some(item => item.code === "PROVIDER_CONTRACT_DECLARATION_MISSING"));
});

test("Batch 129: provider contract v1.1 requires explicit semantics and the complete capability declaration", async t => {
  const contractInfo = { contractId: "agentic-v4-trust-anchor-provider", version: "1.1.0", schemaVersion: 1,
    capabilities: ["read", "compareAndSet", "ownerIsolation", "monotonicSequence", "staleCasRejection", "consistentReadAfterWrite"],
    ownerScope: "ownerId", casSemantics: "digest-compare-and-set" };
  const good = await fixture(t, { contractVersion: "1.1.0", providerOptions: { contractInfo } });
  const goodStatus = await good.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(good.ownerId);
  assert.equal(goodStatus.status, "compatible_declared");
  assert.equal(goodStatus.behavioralConformanceRequired, true);
  assert.equal(goodStatus.providerMetadataAuthenticated, false);
  const weakInfo = { ...contractInfo, capabilities: ["read", "compareAndSet"] };
  const weak = await fixture(t, { contractVersion: "1.1.0", providerOptions: { contractInfo: weakInfo } });
  const status = await weak.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(weak.ownerId);
  assert.equal(status.status, "incompatible");
  assert.ok(status.findings.some(item => item.code === "PROVIDER_CAPABILITY_MISSING_OWNERISOLATION"));
});

test("Batch 129: contract version mismatch is explicit and recommends stopping trust-sensitive operations", async t => {
  const f = await fixture(t, { contractVersion: "1.1.0" });
  const status = await f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus(f.ownerId);
  assert.equal(status.status, "incompatible");
  assert.ok(status.findings.some(item => item.code === "PROVIDER_CONTRACT_VERSION_MISMATCH"));
  await assert.rejects(f.app.createRecoverySloFinalizationKeyTransitionChallenge(f.ownerId, {
    action: "rotate", expectedRevision: 1, newKeyId: "blocked-key", newPublicKey: keyPair().publicPem,
    reason: "Trust mutation must stop when the provider contract version mismatches."
  }), hasCode("RECOVERY_SLO_FINALIZATION_KEY_POLICY_PROVIDER_CONTRACT_INCOMPATIBLE"));
});

test("Batch 129: signed continuity evidence verifies independently and detects payload, signature, and owner tampering", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const exported = await f.app.exportRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence(f.ownerId);
  assert.equal(exported.status, "signed");
  assert.equal(exported.evidence.signing.algorithm, "Ed25519");
  assert.equal(exported.evidence.claims.providerObservationAuthenticated, false);
  const verified = await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence(f.ownerId, exported.evidence);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureValid, true);
  assert.equal(verified.proofValid, true);
  const changed = structuredClone(exported.evidence);
  changed.contract.actualVersion = "9.9.9";
  assert.equal((await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence(f.ownerId, changed)).valid, false);
  const wrongOwner = await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence("other-owner", exported.evidence);
  assert.equal(wrongOwner.valid, false);
  const wrongSignature = structuredClone(exported.evidence);
  wrongSignature.signature = `${wrongSignature.signature.slice(0, -1)}${wrongSignature.signature.endsWith("A") ? "B" : "A"}`;
  assert.equal((await f.app.verifyRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence(f.ownerId, wrongSignature)).valid, false);
});

test("Batch 129: strict signed continuity mode rejects missing signer configuration", async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b129-strict-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  assert.throws(() => createAgenticApplication({ storage: createStorage({ root }), requireRecoverySloSignedContinuityEvidence: true }),
    /Signed continuity evidence memerlukan signer/);
});

test("Batch 129: recovery runbook export is digest-bound, includes signed evidence, and never authorizes mutation", async t => {
  const f = await fixture(t, { requireSigned: true });
  await initializePolicy(f);
  const exported = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  assert.equal(exported.status, "exported");
  assert.equal(exported.signedContinuityEvidence, true);
  assert.equal(exported.runbook.safety.automaticMutationAuthorized, false);
  assert.equal(exported.runbook.safety.privateKeysIncluded, false);
  assert.equal(exported.runbook.safety.accessTokensIncluded, false);
  assert.equal(exported.runbook.continuityEvidence.mode, "signed");
  const verified = await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, exported.runbook);
  assert.equal(verified.valid, true);
  assert.equal(verified.runbookIntegrityValid, true);
  assert.equal(verified.continuityEvidenceValid, true);
  const audit = await f.app.auditRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId);
  assert.equal(audit.status, "healthy");
  const events = await f.app.listRecoverySloFinalizationKeyPolicyAnchorOperatorEvidence(f.ownerId, { limit: 100 });
  assert.ok(events.items.some(item => item.type === "recovery_runbook_exported" && item.payload.runbookDigest === exported.runbookDigest));
});


test("Batch 129: configured signer failures never downgrade a runbook to unsigned evidence", async t => {
  const f = await fixture(t, { signerFailure: true });
  await initializePolicy(f);
  await assert.rejects(f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId), hasCode("RECOVERY_SLO_CONTINUITY_SIGNER_FAILED"));
});

test("Batch 129: runbook tampering fails integrity verification", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  const { runbook } = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  const changed = structuredClone(runbook);
  changed.recommendedActions[0].instruction = "Overwrite the anchor without review.";
  const result = await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, changed);
  assert.equal(result.valid, false);
  assert.ok(result.findings.includes("RECOVERY_RUNBOOK_DIGEST_MISMATCH"));
});

test("Batch 129: runbook remains exportable for missing local policy and clearly marks continuity evidence unavailable", async t => {
  const f = await fixture(t);
  const { runbook } = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  assert.equal(runbook.continuityEvidence.mode, "unavailable");
  assert.ok(runbook.recommendedActions.some(action => action.code === "REVIEW_GENESIS_ENROLLMENT"));
  const verified = await f.app.verifyRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, runbook);
  assert.equal(verified.valid, true);
  assert.equal(verified.runbookIntegrityValid, true);
  assert.equal(verified.continuityEvidenceValid, false);
});

test("Batch 129: runbook export enforces a bounded output size", async t => {
  const f = await fixture(t);
  await initializePolicy(f);
  await assert.rejects(f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId, { maxBytes: 1024 }), hasCode("RECOVERY_SLO_RUNBOOK_SIZE_LIMIT"));
});

test("Batch 129: contract incompatibility is included in runbook recovery guidance", async t => {
  const f = await fixture(t, { contractVersion: "1.1.0" });
  const { runbook } = await f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook(f.ownerId);
  assert.equal(runbook.contractStatus.status, "incompatible");
  assert.ok(runbook.recommendedActions.some(action => action.code === "STOP_TRUST_SENSITIVE_OPERATIONS"));
});

test("Batch 129: APIs and HTTP routes expose contract status, signed continuity, and runbook export/verification", async t => {
  const f = await fixture(t);
  const appSource = await fs.readFile(new URL("../../apps/agentic/backend/application.js", import.meta.url), "utf8");
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(appSource, /createRecoverySloFinalizationAnchorEvidenceService/);
  assert.equal(typeof f.app.getRecoverySloFinalizationKeyPolicyAnchorContractStatus, "function");
  assert.equal(typeof f.app.exportRecoverySloFinalizationKeyPolicyAnchorSignedContinuityEvidence, "function");
  assert.equal(typeof f.app.exportRecoverySloFinalizationAnchorRecoveryRunbook, "function");
  assert.match(serverSource, /finalization-keys\/anchor\/contract/);
  assert.match(serverSource, /finalization-keys\/anchor\/continuity-evidence\/verify/);
  assert.match(serverSource, /finalization-keys\/anchor\/recovery-runbook\/export/);
  assert.match(serverSource, /finalization-keys\/anchor\/recovery-runbook\/verify/);
});
