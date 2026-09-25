import assert from "node:assert/strict";
import fs from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { safeEditFile } from "../../core/workspace/safe-editor.js";
import { resolveWorkspacePath } from "../../core/linux/terminal/workspace.js";

const relative = "workspace/.safe-edit-test.mjs";
const full = resolveWorkspacePath(relative);
const original = "export function hello() { return 1; }\n";
await fs.mkdir(path.dirname(full), { recursive: true });
await fs.writeFile(full, original, "utf8");
const hash = crypto.createHash("sha256").update(original, "utf8").digest("hex");

const ok = await safeEditFile({ path: relative, expectedHash: hash, oldText: "return 1", newText: "return 2" });
assert.equal(ok.ok, true);
assert.equal(ok.validation.ok, true);
assert.equal(await fs.readFile(full, "utf8"), "export function hello() { return 2; }\n");

const stale = await safeEditFile({ path: relative, expectedHash: hash, oldText: "return 2", newText: "return 3" });
assert.equal(stale.ok, false);
assert.equal(stale.conflict, true);

const current = await fs.readFile(full, "utf8");
const currentHash = crypto.createHash("sha256").update(current, "utf8").digest("hex");
const invalid = await safeEditFile({ path: relative, expectedHash: currentHash, oldText: "return 2", newText: "return (" });
assert.equal(invalid.ok, false);
assert.equal(invalid.validationFailed, true);
assert.equal(await fs.readFile(full, "utf8"), current);

await fs.rm(full, { force: true });
console.log("Safe Edit Intelligence: OK (hash guard + syntax rollback)");
