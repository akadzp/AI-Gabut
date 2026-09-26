import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createStorage } from "../../core/storage/index.js";
import { createStateService } from "../../core/storage/state/index.js";
import { createWorkspaceChangeSystem } from "../../core/workspace/change-system.js";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "ai-gabut-workspace-"));
const storageRoot = path.join(root, "storage");
process.env.AI_WORKSPACE_ROOT = root;
try {
  await fs.writeFile(path.join(root, "sample.js"), "export const value = 1;\n", "utf8");
  const storage = createStorage({ root: storageRoot });
  const state = createStateService({ storage, namespace: "test-workspace", scopes: ["changes"] });
  const changes = createWorkspaceChangeSystem({ stateService: state });
  const planned = await changes.create({ task: "update sample.js", paths: ["sample.js"] });
  assert.equal(planned.status, "planned");
  const captured = await changes.capture(planned.id, "sample.js");
  assert.match(captured.baselineHash, /^[a-f0-9]{64}$/);
  const edited = await changes.edit(planned.id, { path: "sample.js", operation: "replace", oldText: "value = 1", newText: "value = 2" });
  assert.equal(edited.ok, true);
  const persisted = await changes.get(planned.id);
  assert.equal(persisted.status, "changed");
  assert.equal(persisted.files["sample.js"].lastEdit.afterHash, edited.afterHash);
  const reopened = createWorkspaceChangeSystem({ stateService: createStateService({ storage, namespace: "test-workspace", scopes: ["changes"] }) });
  assert.equal((await reopened.get(planned.id)).id, planned.id);
  await reopened.close(planned.id, "completed");
  assert.equal((await reopened.get(planned.id)).status, "completed");
  assert.equal((await reopened.list()).length, 1);
  console.log("Workspace change-system contract: PASS");
} finally { await fs.rm(root, { recursive: true, force: true }); }
