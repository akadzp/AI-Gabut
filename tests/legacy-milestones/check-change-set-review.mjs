import assert from "node:assert/strict";
import { reviewChangeSet } from "../../core/workspace/change-set-review.js";

const result = await reviewChangeSet({ includeGit: false, paths: ["package.json"] });
assert.equal(result.ok, true);
assert.ok(result.summary);
assert.ok(Array.isArray(result.files));
assert.ok(Array.isArray(result.findings));
assert.ok(Array.isArray(result.reviewBeforeCommit));
assert.ok(Array.isArray(result.limitations));
assert.ok(result.evidence && result.evidence.diffStats);

const scoped = await reviewChangeSet({ includeGit: false, paths: ["package.json"], limit: 5 });
assert.equal(scoped.ok, true);
assert.equal(scoped.scope.length, 1);
assert.equal(scoped.scope[0], "package.json");

console.log(`Change Set Review: OK (${result.summary.files} files, ${result.risks.length} risks)`);
