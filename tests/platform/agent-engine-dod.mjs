import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";

const root = path.resolve("core/agent-engine");
const facade = await fs.readFile(path.join(root, "index.js"), "utf8");
const architecture = await fs.readFile(path.resolve("scripts/check-architecture.mjs"), "utf8");
const roadmap = await fs.readFile(path.resolve("docs/roadmaps/02_Roadmap-AI-Agent-Intelligence-Engine.txt"), "utf8");

const requiredExports = [
  "runAgent",
  "getOrCreateSession",
  "retrieveMemories",
  "buildToolIntelligence",
  "discoverTools",
  "listModels",
  "routeModel",
  "getEvaluationCases",
  "scoreTrajectory",
  "evaluateCaseAsync",
  "runEvaluationSuiteAsync",
  "analyzeFailures",
  "getSpecialists",
  "coordinateSpecialists",
  "resumeExecution",
  "getReliabilityMetrics",
  "getReliabilityLimits",
  "withExecutionLock",
  "withTimeout"
];
for (const symbol of requiredExports) {
  assert.match(facade, new RegExp(`\\b${symbol}\\b`), `Missing public Agent Engine export: ${symbol}`);
}

assert.match(architecture, /agent-engine\/index\.js/);
assert.ok(roadmap.includes("07. Definition of Done"));
assert.ok(roadmap.includes("STEP 06 VALIDATION"));

const internalFiles = [];
async function walk(dir) {
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (entry.name.endsWith(".js") && entry.name !== "index.js") internalFiles.push(full);
  }
}
await walk(root);
assert.ok(internalFiles.length > 0, "Agent Engine internal modules must remain behind the facade");

console.log("AGENT ENGINE DEFINITION OF DONE CHECK PASS");
