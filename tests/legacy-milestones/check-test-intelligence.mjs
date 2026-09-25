import fs from "node:fs/promises";
import { analyzeTestIntelligence } from "../../core/workspace/test-intelligence.js";

await fs.writeFile("workspace/test-intelligence-fixture.js", "export function fixtureExample() { return 1; }\n", "utf8");
await fs.writeFile("workspace/test-intelligence-fixture.test.js", "import { fixtureExample } from './test-intelligence-fixture.js';\ntest('fixture', () => fixtureExample());\n", "utf8");
const result = await analyzeTestIntelligence({ paths: ["workspace/test-intelligence-fixture.js"], includeGit: false, refresh: true });
await fs.rm("workspace/test-intelligence-fixture.js");
await fs.rm("workspace/test-intelligence-fixture.test.js");
if (!result.ok || !result.testFiles.includes("workspace/test-intelligence-fixture.test.js") || !result.relatedTests.some(x => x.test === "workspace/test-intelligence-fixture.test.js")) {
  console.error(result);
  process.exit(1);
}
console.log("Test Intelligence: OK");
