import { randomUUID } from "node:crypto";

export function createIdentity({ type = "runtime", name = "ai-gabut" } = {}) {
  return Object.freeze({ id: randomUUID(), type, name });
}
