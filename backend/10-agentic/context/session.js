const MAX_MESSAGES = 20;
const sessions = new Map();

function normalizeMessage(message) {
  return {
    role: message.role === "assistant" ? "assistant" : "user",
    content: String(message.content ?? "").slice(0, 12_000),
    createdAt: message.createdAt || new Date().toISOString()
  };
}

export function getSession(sessionId) {
  if (!sessionId || typeof sessionId !== "string") return null;
  return sessions.get(sessionId) || null;
}

export function getOrCreateSession(sessionId) {
  const id = typeof sessionId === "string" && sessionId.trim()
    ? sessionId.trim().slice(0, 128)
    : crypto.randomUUID();

  let session = sessions.get(id);
  if (!session) {
    session = { id, messages: [], memories: [], createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    sessions.set(id, session);
  }
  return session;
}

export function addMessage(session, role, content) {
  session.messages.push(normalizeMessage({ role, content }));
  if (session.messages.length > MAX_MESSAGES) {
    session.messages.splice(0, session.messages.length - MAX_MESSAGES);
  }
  session.updatedAt = new Date().toISOString();
}

export function getRecentMessages(session) {
  return session?.messages?.slice(-MAX_MESSAGES) || [];
}

export function getMemories(session) {
  return session?.memories || [];
}
