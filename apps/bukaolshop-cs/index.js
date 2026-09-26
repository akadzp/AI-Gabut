export const BUKAOLSHOP_CS_APP = Object.freeze({
  id: "bukaolshop-cs",
  name: "BukaOlshop CS",
  version: "1.0.0",
  type: "domain-application",
  description: "Customer-service AI application identity built on the AI-Gabut platform.",
  capabilities: Object.freeze([
    "agent-engine",
    "agent-reliability",
    "security-governance",
    "connector-runtime"
  ])
});

export function createBukaOlshopCsApplication({ platform } = {}) {
  if (!platform || typeof platform.resolve !== "function") {
    throw new TypeError("BukaOlshop CS membutuhkan platform capability registry");
  }

  return Object.freeze({
    manifest: BUKAOLSHOP_CS_APP,
    platform,
    getCapability(id) {
      return platform.resolve(id);
    }
  });
}
