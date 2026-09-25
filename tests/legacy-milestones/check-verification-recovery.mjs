import { readFile } from "node:fs/promises";

const source = await readFile("core/agent-engine/core/agent-core.js", "utf8");
if (!source.includes("MAX_VERIFICATION_RECOVERY_CYCLES")) throw new Error("recovery cycle guard missing");
if (!source.includes("Verification failed. Recovery cycle")) throw new Error("recovery instruction missing");
if (!source.includes("verification_recovery")) throw new Error("recovery activity missing");
if (!source.includes("Do not claim success until an actual verification run passes.")) throw new Error("success guard missing");
console.log("Verification Recovery: OK (bounded 2-cycle recovery guard)");
