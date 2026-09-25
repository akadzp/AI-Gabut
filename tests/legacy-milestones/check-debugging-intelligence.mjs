import { diagnoseVerificationFailure } from "../../core/workspace/debugging-intelligence.js";
import fs from "node:fs/promises";

await fs.writeFile("workspace/debug-fixture.js", "export const x = 1;\n", "utf8");

const result = await diagnoseVerificationFailure({
  verification: {
    results: [{ id: "syntax", label: "node --check", ok: false, exitCode: 1, stderr: "SyntaxError: workspace/debug-fixture.js:3\nUnexpected token" }]
  }
});

if (!result.ok || result.analyzedFailures !== 1 || result.diagnoses[0]?.category !== "syntax-error" || !result.diagnoses[0]?.relevantFiles.includes("workspace/debug-fixture.js")) {
  console.error("Debugging Intelligence: FAILED");
  process.exit(1);
}
console.log(`Debugging Intelligence: OK (${result.diagnoses[0].category})`);
await fs.rm("workspace/debug-fixture.js");
