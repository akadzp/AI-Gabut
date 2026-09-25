import { writeFile } from "node:fs/promises";
import { planVerification } from "../../core/workspace/verification-planner.js";

await writeFile("verification-intelligence-fixture.js", "export function fixture() { return 42; }\n", "utf8");
try {
  const result = await planVerification({ paths: ["verification-intelligence-fixture.js"] , includeGit: true });
  if (!result.ok) throw new Error(result.error || "verification plan gagal");
  const syntax = result.checks.find(check => check.command === "node --check verification-intelligence-fixture.js");
  if (!syntax) throw new Error("syntax verification tidak ditemukan");
  if (syntax.confidence !== "high") throw new Error("confidence syntax tidak high");
  if (result.execution.performed !== false) throw new Error("plan_verification tidak boleh mengeksekusi command");
  console.log(`Verification Intelligence: OK (${result.checks.length} checks planned)`);
} finally {
  await import("node:fs/promises").then(fs => fs.rm("verification-intelligence-fixture.js", { force: true }));
}
