import assert from "node:assert/strict";
import test from "node:test";
import { createGitHubConnector, GitHubConnectorError } from "../../connectors/github/index.js";
import { createGitHubService } from "../../apps/agentic/backend/github.js";
import { encryptSecret } from "../../apps/agentic/backend/crypto.js";

process.env.AGENTIC_CREDENTIAL_KEY ||= "test-only-agentic-key-that-is-long-enough";

function response(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    async text() { return JSON.stringify(body); }
  };
}

test("GitHub connector normalizes repository metadata and search", async () => {
  const seen = [];
  const connector = createGitHubConnector({
    fetchImpl: async (url) => {
      seen.push(url);
      if (url.includes("/repos/acme/project")) return response(200, { id: 1, name: "project", full_name: "acme/project", owner: { login: "acme" }, private: true, default_branch: "main", html_url: "https://github.com/acme/project", visibility: "private" });
      return response(200, { total_count: 1, incomplete_results: false, items: [{ name: "app.js", path: "src/app.js", sha: "abc", html_url: "https://github.com/acme/project/blob/main/src/app.js", repository: { full_name: "acme/project" } }] });
    }
  });
  const repo = await connector.repository("token", "acme", "project");
  const result = await connector.search("token", "acme", "project", "connection", { branch: "main" });
  assert.equal(repo.fullName, "acme/project");
  assert.equal(result.items[0].path, "src/app.js");
  assert.match(seen[1], /repo%3Aacme%2Fproject/);
  assert.match(seen[1], /ref%3Amain/);
});

test("GitHub connector maps exhausted rate limit", async () => {
  const connector = createGitHubConnector({
    fetchImpl: async () => response(403, { message: "API rate limit exceeded" }, { "x-ratelimit-remaining": "0", "x-ratelimit-limit": "5000", "x-ratelimit-reset": "1900000000" })
  });
  await assert.rejects(() => connector.repositories("token"), error => {
    assert.ok(error instanceof GitHubConnectorError);
    assert.equal(error.code, "GITHUB_RATE_LIMITED");
    assert.equal(error.status, 429);
    assert.equal(error.details.rateLimit.remaining, 0);
    return true;
  });
});

test("GitHub connector maps authentication failure", async () => {
  const connector = createGitHubConnector({
    fetchImpl: async () => response(401, { message: "Bad credentials" })
  });
  await assert.rejects(() => connector.account("bad-token"), error => {
    assert.equal(error.code, "GITHUB_AUTH_FAILED");
    assert.equal(error.status, 401);
    return true;
  });
});

test("GitHub Agentic service uses the connector boundary", async () => {
  const calls = [];
  const connector = {
    async account(token) { calls.push(["account", token]); return { login: "jaja", id: 7, avatarUrl: null }; },
    async repositories(token) { calls.push(["repositories", token]); return [{ fullName: "acme/project" }]; },
    async rateLimits(token) { calls.push(["rateLimits", token]); return { remaining: 4999, limit: 5000, resetAt: null }; }
  };
  const records = new Map();
  const store = {
    async putConnection(ownerId, value) { records.set(`${ownerId}--${value.id}`, { ...value, ownerId }); return records.get(`${ownerId}--${value.id}`); },
    async getConnection(ownerId, id) { return records.get(`${ownerId}--${id}`) || null; }
  };
  const connections = {
    async create(ownerId, input) { const c = { ...input, id: "conn-1", ownerId, createdAt: "now", updatedAt: "now" }; await store.putConnection(ownerId, c); return { id: c.id, provider: c.provider, status: c.status, account: c.account }; },
    async raw(ownerId, id) { const c = await store.getConnection(ownerId, id); if (!c) throw new Error("missing"); return c; }
  };
  const service = createGitHubService({ store, connections, connector });
  const created = await service.connect("user-a", { token: "secret-token-123" });
  await service.repositories("user-a", created.id);
  await service.healthConnection("user-a", { credential: encryptSecret("secret-token-123") });
  assert.deepEqual(calls, [["account", "secret-token-123"], ["repositories", "secret-token-123"], ["rateLimits", "secret-token-123"]]);
});
