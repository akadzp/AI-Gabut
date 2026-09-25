import { analyzeContracts } from "../../core/workspace/contract-intelligence.js";

const result = await analyzeContracts({ paths: ["core/api/server.js"] });
if (!result.scannedFiles.includes("core/api/server.js")) throw new Error("server.js was not scanned");
if (!Array.isArray(result.endpoints)) throw new Error("endpoint result missing");
if (!Array.isArray(result.exports)) throw new Error("export result missing");
if (!Array.isArray(result.imports)) throw new Error("import result missing");
console.log(`Contract Intelligence: OK (${result.counts.endpoints} endpoints, ${result.counts.exports} exports, ${result.counts.imports} imports)`);
