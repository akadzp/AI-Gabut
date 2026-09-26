import assert from "node:assert/strict";
import {
  AGENTIC_APP,
  BUKAOLSHOP_CS_APP,
  createAgenticApplication,
  createBukaOlshopCsApplication
} from "../../apps/index.js";

const calls = [];
const platform = {
  resolve(id) {
    calls.push(id);
    return { id };
  }
};

const agentic = createAgenticApplication({ platform });
const cs = createBukaOlshopCsApplication({ platform });

assert.equal(agentic.manifest.id, "agentic");
assert.equal(cs.manifest.id, "bukaolshop-cs");
assert.equal(AGENTIC_APP.type, "ai-application");
assert.equal(BUKAOLSHOP_CS_APP.type, "domain-application");
assert.equal(agentic.getCapability("agent-engine").id, "agent-engine");
assert.equal(cs.getCapability("connector-runtime").id, "connector-runtime");
assert.deepEqual(calls, ["agent-engine", "connector-runtime"]);

assert.throws(() => createAgenticApplication(), /platform capability registry/);
assert.throws(() => createBukaOlshopCsApplication(), /platform capability registry/);

console.log("Application layer contract: PASS");
