import assert from "node:assert/strict";
import { analyzeFrameworks } from "../../core/workspace/framework-intelligence.js";

const result = await analyzeFrameworks({ paths: ["package.json", "core/api/server.js", "public/index.html"] });
assert.equal(result.ok, true);
assert.ok(Array.isArray(result.frameworks));
assert.ok(result.frameworks.some(item => item.name === "Express"), "Express should be detected from package.json");
assert.ok(result.counts.frameworks >= 1);
console.log(`Framework Intelligence: OK (${result.counts.frameworks} frameworks, ${result.counts.configFiles} configs)`);
