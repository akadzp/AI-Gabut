import { bootstrap } from "../platform/bootstrap/index.js";
import { createServer } from "../api/server.js";
import { registerCoreCapabilities } from "./capabilities.js";

export async function startRuntime() {
  return bootstrap({
    start: ({ configuration, environment, health, registry, operations }) => {
      registerCoreCapabilities(registry);
      return createServer({ configuration, environment, health, registry, operations });
    },
    stop: async server => new Promise(resolve => {
      if (!server || typeof server.close !== "function") return resolve();
      server.close(() => resolve());
    })
  });
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const runtime = await startRuntime();
  const shutdown = async () => {
    try {
      await runtime.stop();
      process.exit(0);
    } catch (error) {
      console.error("Graceful shutdown failed:", error);
      process.exit(1);
    }
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
