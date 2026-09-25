import assert from "node:assert/strict";
import { planMigration } from "../../core/workspace/migration-intelligence.js";

const result = await planMigration({
  task: "migrate the Express dependency to a newer version",
  packages: ["express"]
});

assert.equal(result.ok, true);
assert.ok(result.migrationKinds.includes("dependency-version-migration"));
assert.ok(result.requestedPackages.includes("express"));
assert.ok(result.dependencyEvidence.some(item => item.name === "express"));
assert.ok(Array.isArray(result.affectedFiles));
assert.ok(Array.isArray(result.readBeforeEdit));
assert.ok(Array.isArray(result.verification));
assert.ok(Array.isArray(result.limitations));

console.log(`Migration Intelligence: OK (${result.affectedFiles.length} affected files)`);
