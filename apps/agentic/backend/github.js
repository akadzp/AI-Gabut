import { encryptSecret, decryptSecret } from "./crypto.js";
import { createId } from "./ids.js";
import { AgenticError } from "./errors.js";
import { createGitHubConnector, GitHubConnectorError } from "../../../connectors/github/index.js";

function mapError(error) {
  if (!(error instanceof GitHubConnectorError)) return error;
  return new AgenticError(error.code, error.message, error.status, error.details);
}

export function createGitHubService({ store, connections, connector = createGitHubConnector() }) {
  async function tokenFor(u, id) {
    const c = await connections.raw(u, id);
    if (!c || c.provider !== "github") throw new AgenticError("CONNECTION_NOT_FOUND", "GitHub connection tidak ditemukan", 404);
    if (c.status !== "active") throw new AgenticError("CONNECTION_INACTIVE", "GitHub connection tidak aktif", 409);
    try { return { connection: c, token: decryptSecret(c.credential) }; }
    catch { throw new AgenticError("GITHUB_CREDENTIAL_INVALID", "Credential GitHub tidak dapat digunakan", 409); }
  }

  async function connect(u, { token, name = "GitHub" } = {}) {
    if (typeof token !== "string" || token.length < 10) throw new AgenticError("INVALID_GITHUB_TOKEN", "GitHub token tidak valid");
    try {
      const account = await connector.account(token);
      return connections.create(u, {
        provider: "github",
        name: String(name).trim().slice(0, 120) || "GitHub",
        account,
        credential: encryptSecret(token),
        status: "active"
      });
    } catch (error) { throw mapError(error); }
  }

  async function validateConnection(_u, { credential }) {
    try {
      const account = await connector.account(decryptSecret(credential));
      return { status: "active", patch: { account } };
    } catch (error) { throw mapError(error); }
  }

  async function healthConnection(_u, { credential }) {
    try {
      const limits = await connector.rateLimits(decryptSecret(credential));
      const status = limits.remaining === 0 ? "degraded" : "healthy";
      return { health: { status, rateLimitRemaining: limits.remaining, rateLimitLimit: limits.limit, resetAt: limits.resetAt, checkedAt: new Date().toISOString() } };
    } catch (error) { throw mapError(error); }
  }

  async function repositories(u, id) { const { token } = await tokenFor(u, id); try { return connector.repositories(token); } catch (error) { throw mapError(error); } }
  async function repository(u, id, owner, name) { const { token } = await tokenFor(u, id); try { return connector.repository(token, owner, name); } catch (error) { throw mapError(error); } }
  async function branches(u, id, owner, name) { const { token } = await tokenFor(u, id); try { return connector.branches(token, owner, name); } catch (error) { throw mapError(error); } }
  async function tree(u, id, owner, name, branch = null) { const { token } = await tokenFor(u, id); try { return connector.tree(token, owner, name, branch); } catch (error) { throw mapError(error); } }
  async function file(u, id, owner, name, path, ref = null) { const { token } = await tokenFor(u, id); try { return connector.file(token, owner, name, path, ref); } catch (error) { throw mapError(error); } }
  async function search(u, id, owner, name, query, options = {}) { const { token } = await tokenFor(u, id); try { return connector.search(token, owner, name, query, options); } catch (error) { throw mapError(error); } }

  function publicConnection(c) {
    return { id: c.id, provider: c.provider, name: c.name, account: c.account, status: c.status, createdAt: c.createdAt, updatedAt: c.updatedAt };
  }

  return Object.freeze({ connect, validateConnection, healthConnection, repositories, repository, branches, tree, file, search, publicConnection });
}
