import assert from "node:assert/strict";
import { loadConfiguration } from "../../core/platform/config/index.js";

const config = loadConfiguration({
  PORT: "8080",
  HOST: "0.0.0.0",
  SHUTDOWN_TIMEOUT_MS: "5000",
  REQUEST_BODY_LIMIT: "4mb"
});

assert.equal(config.port, 8080);
assert.equal(config.host, "0.0.0.0");
assert.equal(config.shutdownTimeoutMs, 5000);
assert.equal(config.requestBodyLimit, "4mb");

assert.throws(
  () => loadConfiguration({ PORT: "70000" }),
  /Invalid PORT/
);

assert.throws(
  () => loadConfiguration({ SHUTDOWN_TIMEOUT_MS: "50" }),
  /Invalid duration/
);

console.log("Production configuration contract: PASS");
