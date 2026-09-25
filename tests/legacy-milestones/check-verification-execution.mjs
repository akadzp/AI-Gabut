import { writeFile, rm } from "node:fs/promises";
import { executeVerification } from "../../core/workspace/verification-executor.js";

const fixture = "verification-execution-fixture.js";
await writeFile(fixture, "export function fixture() { return 42; }\n", "utf8");

try {
  const result = await executeVerification({
    paths: [fixture],
    includeGit: false,
    checkIds: [`syntax-${fixture}`],
    stopOnFailure: true
  });

  if (!result.ok) throw new Error(`verification execution gagal: ${JSON.stringify(result.summary)}`);
  if (result.summary.total !== 1) throw new Error("jumlah verification execution tidak sesuai");
  if (result.summary.passed !== 1) throw new Error("syntax verification tidak lulus");
  if (result.results[0].command !== `node --check ${fixture}`) throw new Error("command tidak berasal dari verification planner");
  if (result.results[0].status !== "passed") throw new Error("status execution bukan passed");
  console.log(`Verification Execution: OK (${result.summary.passed}/${result.summary.total} passed)`);
} finally {
  await rm(fixture, { force: true });
}
