import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";

const root = path.resolve("core");
const facade = await fs.readFile(path.join(root, "agent-engine", "index.js"), "utf8");
const server = await fs.readFile(path.join(root, "api", "server.js"), "utf8");
const capabilities = await fs.readFile(path.join(root, "system", "capabilities.js"), "utf8");

for (const symbol of [
  "runAgent",
  "getOrCreateSession",
  "getMemories",
  "runGitTool",
  "TOOL_CATALOG",
  "buildToolIntelligence",
  "listModels",
  "routeModel",
  "getEvaluationCases",
  "scoreTrajectory",
  "getSpecialists",
  "resumeExecution"
]) {
  assert.match(facade, new RegExp(`\\b${symbol}\\b`), `Facade missing ${symbol}`);
}

assert.match(server, /from ["']\.\.\/agent-engine\/index\.js["']/);
assert.doesNotMatch(server, /from ["']\.\.\/agent-engine\/(?!index\.js)/);
assert.match(capabilities, /from ["']\.\.\/agent-engine\/index\.js["']/);
assert.doesNotMatch(capabilities, /from ["']\.\.\/agent-engine\/(?!index\.js)/);

console.log("AGENT ENGINE PUBLIC BOUNDARY PASS");
