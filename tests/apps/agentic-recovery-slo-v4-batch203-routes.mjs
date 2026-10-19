import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";

test("Batch 203: checkpoint enrollment, audit, reconciliation, and proof routes are registered", async () => {
  const serverSource = await fs.readFile(new URL("../../apps/agentic/backend/server.js", import.meta.url), "utf8");
  assert.match(serverSource, /recovery-gate\/proof\/checkpoint\/status/);
  assert.match(serverSource, /recovery-gate\/proof\/checkpoint\/audit/);
  assert.match(serverSource, /recovery-gate\/proof\/checkpoint\/enrollment\/prepare/);
  assert.match(serverSource, /recovery-gate\/proof\/checkpoint\/enrollment\/apply/);
  assert.match(serverSource, /recovery-gate\/proof\/checkpoint\/reconcile/);
  const serviceSource = await fs.readFile(new URL("../../apps/agentic/backend/recovery-slo-cross-domain-recovery-intent-closure.js", import.meta.url), "utf8");
  assert.match(serviceSource, /getRevalidationLifecycleRecoveryGateProofSnapshot/);
  assert.match(serviceSource, /revalidation_lifecycle_recovery_gate_proof/);
});
