const MAX_OWNER_ID = 200;
const MAX_TOKEN_LENGTH = 4096;

function providerError(code, message, status = null) {
  const error = new Error(message);
  error.code = code;
  if (status != null) error.status = status;
  return error;
}

function normalizeBaseUrl(value) {
  let url;
  try { url = new URL(String(value || "")); }
  catch { throw new TypeError("External trust anchor URL harus berupa URL absolut yang valid"); }
  const localHost = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]).has(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && localHost)) {
    throw new TypeError("External trust anchor wajib memakai HTTPS; HTTP hanya diizinkan untuk loopback lokal");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("External trust anchor URL tidak boleh berisi kredensial, query, atau fragment");
  }
  return url.toString().replace(/\/+$/, "");
}

async function responseJson(response) {
  try { return await response.json(); }
  catch { return null; }
}

/**
 * HTTP adapter for an independently operated, monotonic trust-anchor service.
 * The remote service must enforce append-only CAS semantics; this client never
 * treats local application storage as the external anchor.
 */
export function createHttpExternalTrustAnchorProvider({ baseUrl, token, fetchImpl = globalThis.fetch, timeoutMs = 5000 } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  const bearer = String(token || "");
  if (!bearer || bearer.length > MAX_TOKEN_LENGTH || /[\r\n]/.test(bearer)) {
    throw new TypeError("External trust anchor memerlukan bearer token yang valid");
  }
  if (typeof fetchImpl !== "function") throw new TypeError("External trust anchor memerlukan fetch implementation");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new TypeError("External trust anchor timeout harus 100–30000 ms");
  }

  function endpoint(ownerId) {
    const owner = String(ownerId || "");
    if (!owner || owner.length > MAX_OWNER_ID || /[\u0000-\u001f]/.test(owner)) {
      throw providerError("EXTERNAL_TRUST_ANCHOR_OWNER_INVALID", "Owner ID external trust anchor tidak valid");
    }
    return `${base}/v1/anchors/${encodeURIComponent(owner)}`;
  }

  async function request(url, options) {
    let response;
    try {
      response = await fetchImpl(url, { ...options, redirect: "error", cache: "no-store", signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      throw providerError("EXTERNAL_TRUST_ANCHOR_NETWORK_ERROR", "External trust anchor tidak dapat dihubungi", error?.status || null);
    }
    return response;
  }

  return Object.freeze({
    providerIdentity: base,
    baseUrl: base,
    contractInfo: Object.freeze({ contractId: "agentic-v4-trust-anchor-provider", version: "1.0.0", schemaVersion: 1,
      capabilities: Object.freeze(["read", "compareAndSet"]), ownerScope: "ownerId", casSemantics: "digest-compare-and-set" }),
    async read(ownerId) {
      const response = await request(endpoint(ownerId), { method: "GET", headers: {
        Authorization: `Bearer ${bearer}`, Accept: "application/json"
      } });
      if (response.status === 404) return null;
      if (!response.ok) throw providerError("EXTERNAL_TRUST_ANCHOR_READ_FAILED", "External trust anchor menolak pembacaan", response.status);
      const body = await responseJson(response);
      if (!body || !Object.prototype.hasOwnProperty.call(body, "anchor")) {
        throw providerError("EXTERNAL_TRUST_ANCHOR_RESPONSE_INVALID", "Respons external trust anchor tidak memiliki field anchor", response.status);
      }
      return body.anchor == null ? null : body.anchor;
    },

    async compareAndSet(ownerId, expectedDigest, candidate) {
      if (expectedDigest !== null && (typeof expectedDigest !== "string" || !/^[a-f0-9]{64}$/.test(expectedDigest))) {
        throw providerError("EXTERNAL_TRUST_ANCHOR_EXPECTED_DIGEST_INVALID", "Expected digest external trust anchor tidak valid");
      }
      if (!candidate || candidate.ownerId !== ownerId || !Number.isSafeInteger(candidate.anchorSequence)
        || !Number.isSafeInteger(candidate.revision) || typeof candidate.digest !== "string" || !/^[a-f0-9]{64}$/.test(candidate.digest)) {
        throw providerError("EXTERNAL_TRUST_ANCHOR_CANDIDATE_INVALID", "Candidate external trust anchor tidak valid");
      }
      const headers = { Authorization: `Bearer ${bearer}`, Accept: "application/json", "Content-Type": "application/json" };
      if (expectedDigest === null) headers["If-None-Match"] = "*";
      else headers["If-Match"] = `"${expectedDigest}"`;
      const response = await request(endpoint(ownerId), { method: "PUT", headers, body: JSON.stringify({ anchor: candidate }) });
      const body = await responseJson(response);
      if (response.status === 409 || response.status === 412) {
        return { applied: false, anchor: body?.anchor ?? null };
      }
      if (!response.ok) throw providerError("EXTERNAL_TRUST_ANCHOR_WRITE_FAILED", "External trust anchor menolak pembaruan", response.status);
      return { applied: true, anchor: body?.anchor ?? candidate };
    }
  });
}
