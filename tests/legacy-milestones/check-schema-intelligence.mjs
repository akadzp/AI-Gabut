import { analyzeSchemas } from "../../core/workspace/schema-intelligence.js";

const result = await analyzeSchemas({ paths: ["core/agent-engine/context/session.js", "core/api/server.js"] });
if (!Array.isArray(result.scannedFiles)) throw new Error("scannedFiles missing");
if (!Array.isArray(result.schemas)) throw new Error("schema result missing");
if (!result.counts || typeof result.counts.schemas !== "number") throw new Error("schema counts missing");
console.log(`Schema Intelligence: OK (${result.counts.schemas} schemas, ${result.counts.files} files)`);
