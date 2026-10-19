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
const digest = value => createHash("sha256").update(value, "utf8").digest("hex");
const signature = (payload, privateKey) => sign(null, Buffer.from(canonical(payload), "utf8"), privateKey).toString("base64url");
const hasCode = code => error => error?.code === code;

function createAnchorProvider() {
  const anchors = new Map();
  const provider = {
    failReads: false,
    failWrites: false,
    async read(ownerId) {
      if (provider.failReads) throw Object.assign(new Error("anchor read unavailable"), { code: "ANCHOR_READ_DOWN" });
      const value = anchors.get(ownerId);
      return value ? structuredClone(value) : null;
    },
    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (provider.failWrites) throw Object.assign(new Error("anchor write unavailable"), { code: "ANCHOR_WRITE_DOWN" });
      const current = anchors.get(ownerId) || null;
      if ((current?.digest ?? null) !== expectedDigest) return { applied: false, anchor: current ? structuredClone(current) : null };
      if (!current) {
        if (candidate.anchorSequence !== 1 || candidate.previousAnchorDigest !== null) return { applied: false, anchor: null };
      } else if (candidate.anchorSequence !== current.anchorSequence + 1 || candidate.previousAnchorDigest !== current.digest
        || candidate.revision <= current.revision) return { applied: false, anchor: structuredClone(current) };
      anchors.set(ownerId, structuredClone(candidate));
      return { applied: true, anchor: structuredClone(candidate) };
    }
  };
  return provider;
}

async function setup(t, { ownerId = "owner-b119", provider = null, root = null } = {}) {
  const storageRoot = root || await fs.mkdtemp(path.join(os.tmpdir(), "agentic-b119-slo-"));
  if (!root) t.after(() => fs.rm(storageRoot, { recursive: true, force: true }));
  let time = Date.parse("2026-10-11T00:00:00.000Z");
  const first = generateKeyPairSync("ed25519");
  const anchorProvider = provider === null ? null : provider;
  const app = createAgenticApplication({ storage: createStorage({ root: storageRoot }), clock: () => new Date(time).toISOString(),
    integrityAttestationPublicKeys: { root1: first.publicKey }, attestationTrustAnchor: anchorProvider });
  return { app, ownerId, root: storageRoot, provider: anchorProvider, first, advance: ms => { time += ms; }, now: () => new Date(time).toISOString() };
}

async function rotate(fixture) {
  const next = generateKeyPairSync("ed25519");
  const challenge = await fixture.app.createRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransitionChallenge(
    fixture.ownerId, { action: "rotate", keyId: "next1", publicKey: next.publicKey });
  const input = {
    authorizations: [{ keyId: "root1", signature: signature(challenge.payload, fixture.first.privateKey) }],
    proofOfPossession: signature({ domain: "agentic-v4-attestation-trust-proof-of-possession", payload: challenge.payload }, next.privateKey)
  };
  return fixture.app.applyRecoveryReconciliationMutationOutcomeLedgerAttestationTrustTransition(fixture.ownerId, challenge.id, input);
}

async function alertRecord(fixture) {
  return (await fixture.app.store.listEvidence(fixture.ownerId)).find(item => item.kind === "recovery-slo-alert-ledger") || null;
}

test("Batch 119: SLO evaluation reports bounded objectives and opens one deduplicated configuration alert", async t => {
  const fixture = await setup(t);
  const first = await fixture.app.evaluateRecoverySLOs(fixture.ownerId, { minSamples: 0, windowMs: 1 });
  const second = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  assert.equal(first.status, "breached");
  assert.equal(first.windowMs, 60_000);
  assert.equal(first.minSamples, 1);
  assert.ok(first.objectives.some(item => item.code === "external_anchor_configured" && item.status === "breached"));
  assert.equal(first.alerts.opened, 1);
  assert.equal(second.alerts.opened, 0);
  assert.equal(second.alerts.deduplicated, 1);
  const ledger = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(ledger.activeCount, 1);
  assert.equal(ledger.alerts[0].observationCount, 2);
  assert.match(ledger.digest, /^[a-f0-9]{64}$/);
});

test("Batch 119: alert deduplication is concurrency-safe for parallel SLO evaluations", async t => {
  const fixture = await setup(t);
  const results = await Promise.all(Array.from({ length: 5 }, () => fixture.app.evaluateRecoverySLOs(fixture.ownerId)));
  assert.equal(results.reduce((sum, item) => sum + item.alerts.opened, 0), 1);
  const ledger = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(ledger.activeCount, 1);
  assert.equal(ledger.alerts[0].observationCount, 5);
  assert.equal(ledger.eventCount, 5);
});

test("Batch 119: persistent alert history survives application recreation", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const restored = createAgenticApplication({ storage: createStorage({ root: fixture.root }), clock: fixture.now });
  const ledger = await restored.getRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(ledger.activeCount, 1);
  assert.equal(ledger.alerts[0].alertKey, "external_anchor_configured");
  assert.equal((await restored.auditRecoverySloAlertLedger(fixture.ownerId)).status, "healthy");
});

test("Batch 119: acknowledgement requires a meaningful reason and is idempotent", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const alert = (await fixture.app.getRecoverySloAlertLedger(fixture.ownerId)).alerts[0];
  await assert.rejects(fixture.app.acknowledgeRecoverySloAlert(fixture.ownerId, alert.id, "short"), hasCode("RECOVERY_SLO_ALERT_ACKNOWLEDGEMENT_REASON_INVALID"));
  const ack = await fixture.app.acknowledgeRecoverySloAlert(fixture.ownerId, alert.id, "Operator reviewed the missing anchor configuration.");
  assert.equal(ack.status, "acknowledged");
  assert.equal(ack.alert.status, "acknowledged");
  const repeated = await fixture.app.acknowledgeRecoverySloAlert(fixture.ownerId, alert.id, "Repeated acknowledgement with another reason.");
  assert.equal(repeated.status, "already_acknowledged");
  const events = await fixture.app.listRecoverySloAlertEvents(fixture.ownerId);
  assert.equal(events.items.filter(item => item.type === "alert_acknowledged").length, 1);
  assert.equal(events.items[0].reason, "Operator reviewed the missing anchor configuration.");
});

test("Batch 119: sustained breach escalates with hash-linked operator evidence", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  fixture.advance(16 * 60 * 1000);
  const evaluation = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  assert.equal(evaluation.alerts.escalated, 1);
  const ledger = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(ledger.alerts[0].severity, "critical");
  const events = await fixture.app.listRecoverySloAlertEvents(fixture.ownerId);
  const escalation = events.items.find(item => item.type === "alert_escalated");
  assert.ok(escalation);
  assert.equal(escalation.reason, "BREACH_DURATION_THRESHOLD");
  assert.match(escalation.evaluationDigest, /^[a-f0-9]{64}$/);
  assert.match(escalation.eventHash, /^[a-f0-9]{64}$/);
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "healthy");
});

test("Batch 119: recovered anchor resolves the active availability alert", async t => {
  const provider = createAnchorProvider();
  const fixture = await setup(t, { provider });
  await rotate(fixture);
  provider.failReads = true;
  const failed = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  assert.ok(failed.objectives.some(item => item.code === "anchor_availability" && item.status === "breached"));
  provider.failReads = false;
  const recovered = await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  assert.ok(recovered.alerts.resolved >= 1);
  const ledger = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.ok(ledger.alerts.some(item => item.alertKey === "anchor_availability" && item.status === "resolved"));
  const events = await fixture.app.listRecoverySloAlertEvents(fixture.ownerId);
  assert.ok(events.items.some(item => item.type === "alert_resolved" && item.reason === "SLO_BREACH_CLEARED"));
});

test("Batch 119: alert ledger tampering is reported and subsequent writes fail closed", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const record = await alertRecord(fixture);
  const changed = structuredClone(record);
  changed.snapshot.alerts[0].severity = "critical";
  await fixture.app.store.putEvidence(fixture.ownerId, changed, { expectedVersion: record._storage.version });
  assert.equal((await fixture.app.auditRecoverySloAlertLedger(fixture.ownerId)).status, "unhealthy");
  await assert.rejects(fixture.app.evaluateRecoverySLOs(fixture.ownerId), hasCode("RECOVERY_SLO_ALERT_LEDGER_INTEGRITY_FAILED"));
  assert.equal((await fixture.app.getRecoverySloAlertLedger(fixture.ownerId).catch(() => null)), null);
});

test("Batch 119: alert listing and acknowledgement are owner-scoped", async t => {
  const fixture = await setup(t);
  await fixture.app.evaluateRecoverySLOs(fixture.ownerId);
  const alert = (await fixture.app.getRecoverySloAlertLedger(fixture.ownerId)).alerts[0];
  assert.equal((await fixture.app.getRecoverySloAlertLedger("other-owner")).totalAlerts, 0);
  await assert.rejects(fixture.app.acknowledgeRecoverySloAlert("other-owner", alert.id, "Operator reviewed the issue and its impact."), hasCode("RECOVERY_SLO_ALERT_NOT_FOUND"));
  assert.equal((await fixture.app.getRecoverySloAlertLedger(fixture.ownerId)).alerts[0].status, "active");
});

test("Batch 119: healthy anchored service can meet SLOs with a sufficient sample threshold", async t => {
  const provider = createAnchorProvider();
  const fixture = await setup(t, { provider });
  await rotate(fixture);
  const evaluation = await fixture.app.evaluateRecoverySLOs(fixture.ownerId, { minSamples: 1, availabilityTarget: 0.9 });
  assert.equal(evaluation.status, "met");
  assert.ok(evaluation.objectives.every(item => !["breached"].includes(item.status)));
  assert.equal(evaluation.automaticRemediationAllowed, false);
});

test("Batch 119: application API and HTTP routes expose SLO evaluation, alert history, audit, and acknowledgement", async t => {
  const fixture = await setup(t);
  const source = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.equal(typeof fixture.app.evaluateRecoverySLOs, "function");
  assert.equal(typeof fixture.app.getRecoverySloAlertLedger, "function");
  assert.equal(typeof fixture.app.listRecoverySloAlertEvents, "function");
  assert.equal(typeof fixture.app.auditRecoverySloAlertLedger, "function");
  assert.equal(typeof fixture.app.acknowledgeRecoverySloAlert, "function");
  assert.match(source, /anchor\/slo\/evaluate/);
  assert.match(source, /anchor\/slo\/alerts\/events/);
  assert.match(source, /anchor\/slo\/alerts\/audit/);
  assert.match(source, /anchor\/slo\/alerts\/:id\/acknowledge/);
});

test("Batch 119: event listing is bounded and read-only", async t => {
  const fixture = await setup(t);
  await Promise.all(Array.from({ length: 4 }, () => fixture.app.evaluateRecoverySLOs(fixture.ownerId)));
  const before = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  const limited = await fixture.app.listRecoverySloAlertEvents(fixture.ownerId, { limit: 2 });
  const after = await fixture.app.getRecoverySloAlertLedger(fixture.ownerId);
  assert.equal(limited.items.length, 2);
  assert.equal(limited.truncated, true);
  assert.equal(limited.readOnly, true);
  assert.equal(after.eventCount, before.eventCount);
});
