import assert from "node:assert/strict";
import test from "node:test";
import { createConnectionService } from "../../apps/agentic/backend/connections.js";

function makeStore() {
  const data = new Map();
  return {
    async putConnection(ownerId, value) {
      data.set(`${ownerId}--${value.id}`, { ...value, ownerId });
      return data.get(`${ownerId}--${value.id}`);
    },
    async getConnection(ownerId, id) {
      return data.get(`${ownerId}--${id}`) || null;
    },
    async listConnections(ownerId) {
      return [...data.values()].filter(x => x.ownerId === ownerId);
    }
  };
}

test("connection ownership and secret opacity", async () => {
  const service = createConnectionService({ store: makeStore() });
  const c = await service.create("user-a", {
    provider: "example",
    name: "Example",
    credential: "encrypted-secret"
  });

  assert.equal(c.provider, "example");
  assert.equal(c.status, "created");
  assert.equal(c.credential, undefined);
  assert.deepEqual(c.credentialRef, { type: "provider-credential", id: c.id });
  await assert.rejects(
    () => service.get("user-b", c.id),
    e => e.code === "CONNECTION_NOT_FOUND"
  );
});

test("connection lifecycle is explicit and ownership-bound", async () => {
  const service = createConnectionService({ store: makeStore() });
  const c = await service.create("user-a", { provider: "example" });

  assert.equal((await service.transition("user-a", c.id, "authenticating")).status, "authenticating");
  assert.equal((await service.transition("user-a", c.id, "active")).status, "active");
  assert.equal((await service.transition("user-a", c.id, "requires_reauth")).status, "requires_reauth");
  assert.equal((await service.transition("user-a", c.id, "active")).status, "active");
  assert.equal((await service.disconnect("user-a", c.id)).status, "disconnected");

  await assert.rejects(
    () => service.get("user-b", c.id),
    e => e.code === "CONNECTION_NOT_FOUND"
  );
});

test("validation and health are provider adapters, not generic provider branches", async () => {
  const service = createConnectionService({ store: makeStore() });
  let calls = 0;
  service.registerProvider("example", {
    async validate() {
      calls += 1;
      return { status: "active", patch: { account: { id: "acct-1" } } };
    },
    async health() {
      calls += 1;
      return { health: { status: "healthy", checkedAt: new Date().toISOString() } };
    }
  });

  const c = await service.create("user-a", { provider: "example" });
  const validated = await service.validate("user-a", c.id);
  const health = await service.health("user-a", c.id);

  assert.equal(validated.status, "active");
  assert.equal(validated.account.id, "acct-1");
  assert.equal(health.status, "healthy");
  assert.equal(calls, 2);
});
