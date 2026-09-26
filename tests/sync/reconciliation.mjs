import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createStorage } from "../../core/storage/index.js";
import { createStateService } from "../../core/storage/state/index.js";
import { createSyncManager, planReconciliation, diffSnapshots } from "../../core/sync/index.js";

const snapshot = (source, value) => ({ source, resources: { "item.txt": { hash: value, value } } });
const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-gabut-sync-"));
try {
  const storage = createStorage({ root });
  const state = createStateService({ storage, namespace: "test-sync", scopes: ["syncs"] });
  const manager = createSyncManager({ stateService: state, adapter: { apply: async plan => ({ ok: true, applied: plan.changes.filter(x => x.action === "apply-remote").map(x => x.key) }) } });

  const created = await manager.create({ name: "demo", source: "local", target: "remote" });
  assert.equal(created.status, "idle");

  await manager.capture(created.id, "base", snapshot("base", "a"));
  await manager.capture(created.id, "local", snapshot("local", "local"));
  await manager.capture(created.id, "remote", snapshot("remote", "remote"));

  const diff = await manager.inspect(created.id);
  assert.equal(diff.counts.update, 1);

  const plan = await manager.plan(created.id);
  assert.equal(plan.conflicts.length, 1);
  assert.equal(plan.changes[0].action, "manual");

  const dryRun = await manager.apply(created.id, { plan, readOnly: true });
  assert.equal(dryRun.lastResult.ok, false);
  assert.equal(dryRun.status, "conflicted");

  const remoteOnly = planReconciliation({
    base: snapshot("base", "a"),
    local: snapshot("local", "a"),
    remote: snapshot("remote", "b"),
    strategy: "manual"
  });
  assert.equal(remoteOnly.conflicts.length, 0);
  assert.equal(diffSnapshots(snapshot("base", "a"), snapshot("remote", "b")).counts.update, 1);

  const reopened = createSyncManager({ stateService: createStateService({ storage, namespace: "test-sync", scopes: ["syncs"] }) });
  assert.equal((await reopened.get(created.id)).id, created.id);
  console.log("Synchronization/reconciliation contract: PASS");
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
