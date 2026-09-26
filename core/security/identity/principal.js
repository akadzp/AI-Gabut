const PRINCIPAL_TYPES = new Set(["user", "agent", "app", "service", "connector", "system"]);

export function normalizePrincipal(principal = {}, { sessionId = null, fallbackType = "agent", fallbackSource = "agent-engine" } = {}) {
  const sourcePrincipal = principal && typeof principal === "object" ? principal : {};
  const type = String(sourcePrincipal.type || fallbackType).trim();
  const id = String(sourcePrincipal.id || (sessionId ? `${type}:${sessionId}` : `${type}:anonymous`)).trim();
  const source = String(sourcePrincipal.source || fallbackSource).trim();

  if (!PRINCIPAL_TYPES.has(type)) {
    return { id, type: "unknown", source, sessionId: sessionId || null, metadata: {} };
  }

  return {
    id,
    type,
    source,
    sessionId: sourcePrincipal.sessionId || sessionId || null,
    metadata: sourcePrincipal.metadata && typeof sourcePrincipal.metadata === "object" ? { ...sourcePrincipal.metadata } : {}
  };
}

export function isKnownPrincipal(principal) {
  return Boolean(
    principal &&
    typeof principal.id === "string" &&
    principal.id.trim() &&
    PRINCIPAL_TYPES.has(principal.type) &&
    typeof principal.source === "string" &&
    principal.source.trim()
  );
}
