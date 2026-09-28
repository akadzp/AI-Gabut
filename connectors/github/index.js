export const GITHUB_API = "https://api.github.com";

export class GitHubConnectorError extends Error {
  constructor(code, message, status = 502, details = null) {
    super(message);
    this.name = "GitHubConnectorError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function rateLimit(headers) {
  const remaining = headers.get("x-ratelimit-remaining");
  const limit = headers.get("x-ratelimit-limit");
  const reset = headers.get("x-ratelimit-reset");
  return {
    remaining: remaining == null ? null : Number(remaining),
    limit: limit == null ? null : Number(limit),
    resetAt: reset == null ? null : new Date(Number(reset) * 1000).toISOString()
  };
}

function encodePath(value) {
  return String(value).split("/").map(encodeURIComponent).join("/");
}

export function createGitHubConnector({ fetchImpl = globalThis.fetch, api = GITHUB_API } = {}) {
  if (typeof fetchImpl !== "function") throw new GitHubConnectorError("GITHUB_TRANSPORT_UNAVAILABLE", "GitHub connector membutuhkan fetch", 500);

  async function request(token, path) {
    let response;
    try {
      response = await fetchImpl(`${api}${path}`, {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "X-GitHub-Api-Version": "2022-11-28"
        }
      });
    } catch (error) {
      throw new GitHubConnectorError("GITHUB_NETWORK_ERROR", error?.message || "GitHub network request failed", 502);
    }

    const text = await response.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }
    const limits = rateLimit(response.headers);

    if (!response.ok) {
      const remaining = limits.remaining;
      const code = response.status === 401
        ? "GITHUB_AUTH_FAILED"
        : response.status === 403 && remaining === 0
          ? "GITHUB_RATE_LIMITED"
          : response.status === 403
            ? "GITHUB_FORBIDDEN"
            : response.status === 404
              ? "GITHUB_NOT_FOUND"
              : response.status === 422
                ? "GITHUB_VALIDATION"
                : response.status === 429
                  ? "GITHUB_RATE_LIMITED"
                  : response.status >= 500
                    ? "GITHUB_UNAVAILABLE"
                    : "GITHUB_REQUEST_FAILED";
      const status = code === "GITHUB_RATE_LIMITED" ? 429 : response.status >= 500 ? 502 : response.status;
      throw new GitHubConnectorError(
        code,
        body?.message || `GitHub request failed (${response.status})`,
        status,
        { rateLimit: limits, githubStatus: response.status }
      );
    }

    return { body, rateLimit: limits };
  }

  async function account(token) {
    const { body } = await request(token, "/user");
    return { login: body.login, id: body.id, avatarUrl: body.avatar_url || null };
  }

  async function repositories(token) {
    const { body } = await request(token, "/user/repos?per_page=100&sort=updated");
    return (body || []).map(repository => ({
      id: repository.id,
      name: repository.name,
      fullName: repository.full_name,
      private: repository.private,
      defaultBranch: repository.default_branch,
      htmlUrl: repository.html_url,
      description: repository.description
    }));
  }

  async function repository(token, owner, name) {
    const { body } = await request(token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`);
    return {
      id: body.id,
      name: body.name,
      fullName: body.full_name,
      owner: body.owner?.login || owner,
      private: Boolean(body.private),
      defaultBranch: body.default_branch,
      description: body.description,
      htmlUrl: body.html_url,
      visibility: body.visibility || null,
      archived: Boolean(body.archived),
      fork: Boolean(body.fork),
      pushedAt: body.pushed_at || null,
      updatedAt: body.updated_at || null
    };
  }

  async function branches(token, owner, name) {
    const { body } = await request(token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/branches?per_page=100`);
    return (body || []).map(branch => ({ name: branch.name, sha: branch.commit?.sha || null, protected: Boolean(branch.protected) }));
  }

  async function tree(token, owner, name, branch = null) {
    const ref = branch ? encodeURIComponent(branch) : "HEAD";
    const { body } = await request(token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/git/trees/${ref}?recursive=1`);
    return {
      sha: body.sha,
      truncated: Boolean(body.truncated),
      entries: (body.tree || []).map(entry => ({ path: entry.path, type: entry.type, size: entry.size || 0, sha: entry.sha }))
    };
  }

  async function file(token, owner, name, path, ref = null) {
    const suffix = ref ? `?ref=${encodeURIComponent(ref)}` : "";
    const { body } = await request(token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/contents/${encodePath(path)}${suffix}`);
    if (!body || Array.isArray(body) || body.type !== "file") {
      throw new GitHubConnectorError("GITHUB_FILE_NOT_FOUND", "Resource bukan file", 404);
    }
    return {
      path: body.path,
      sha: body.sha,
      size: body.size,
      content: body.encoding === "base64" ? Buffer.from(body.content.replace(/\s+/g, ""), "base64").toString("utf8") : String(body.content || "")
    };
  }

  async function search(token, owner, name, query, { branch = null, perPage = 30 } = {}) {
    const terms = [`repo:${owner}/${name}`, String(query || "").trim()];
    if (branch) terms.push(`ref:${branch}`);
    if (!String(query || "").trim()) throw new GitHubConnectorError("GITHUB_SEARCH_QUERY_REQUIRED", "Query pencarian GitHub wajib diisi", 400);
    const q = encodeURIComponent(terms.join(" "));
    const { body } = await request(token, `/search/code?q=${q}&per_page=${Math.max(1, Math.min(Number(perPage) || 30, 100))}`);
    return {
      total: Number(body?.total_count || 0),
      incomplete: Boolean(body?.incomplete_results),
      items: (body?.items || []).map(item => ({
        name: item.name,
        path: item.path,
        sha: item.sha,
        htmlUrl: item.html_url,
        repository: item.repository?.full_name || `${owner}/${name}`
      }))
    };
  }

  async function rateLimits(token) {
    const { body, rateLimit: limits } = await request(token, "/rate_limit");
    return {
      remaining: Number(body?.rate?.remaining ?? limits.remaining ?? 0),
      limit: Number(body?.rate?.limit ?? limits.limit ?? 0),
      resetAt: body?.rate?.reset ? new Date(Number(body.rate.reset) * 1000).toISOString() : limits.resetAt
    };
  }

  return Object.freeze({ account, repositories, repository, branches, tree, file, search, rateLimits });
}

export const githubIntegration = {
  name: "github",
  description: "GitHub repository metadata, branches, trees, files, search, and account operations.",
  status: "scaffold",
  tools: [],
};

export const githubToolDefinitions = [];

// The generic integration registry remains compatible with the V2 catalog,
// but authenticated GitHub operations are application-owned and require a
// user connection. They must not receive raw credentials through generic tool input.
export async function executeGitHubTool(name) {
  throw new GitHubConnectorError(
    "GITHUB_CONNECTION_REQUIRED",
    `GitHub operation '${name}' requires an authenticated Agentic connection`,
    409
  );
}
