const MAX_MEMORIES = 100;
const MAX_MEMORY_CONTENT = 1200;

const MEMORY_PATTERNS = [
  { type: "project_rule", pattern: /(?:mulai sekarang|ke depannya|harus selalu|jangan|wajib|aturan(?:nya)?|tidak boleh)/i, importance: 0.95 },
  { type: "decision", pattern: /(?:kita sepakat|diputuskan|keputusan(?:nya)?|kita pilih|gunakan .* untuk|menggunakan .* sebagai|memakai .* sebagai|(?:sekarang|mulai sekarang|ke depannya) .*menggunakan)/i, importance: 0.9 },
  { type: "preference", pattern: /(?:saya (?:ingin|suka|lebih suka)|preferensi saya|tolong selalu)/i, importance: 0.8 },
  { type: "fact", pattern: /(?:ingat bahwa|ingat:|catat bahwa|perlu diingat)/i, importance: 0.85 }
];

const TOPIC_GROUPS = [
  { key: "backend", pattern: /\b(?:backend|server|express|fastify|nestjs|node(?:\.js)?)\b/i },
  { key: "git-approval", pattern: /\b(?:commit|push|approval|persetujuan)\b/i },
  { key: "workspace", pattern: /\b(?:workspace|folder kerja|direktori kerja)\b/i },
  { key: "provider", pattern: /\b(?:openai|gemini|provider|model llm)\b/i },
  { key: "frontend", pattern: /\b(?:frontend|ui|ux|browser|public|web chat)\b/i },
  { key: "memory", pattern: /\b(?:memory|memori|context|konteks)\b/i },
  { key: "terminal", pattern: /\b(?:terminal|command|perintah|shell)\b/i }
];

function normalize(text) {
  return String(text ?? "").replace(/\s+/g, " ").trim().slice(0, MAX_MEMORY_CONTENT);
}

function tokens(text) {
  return new Set(normalize(text).toLowerCase().split(/[^a-z0-9_]+/).filter(token => token.length >= 3));
}

function inferTopic(text) {
  const match = TOPIC_GROUPS.find(item => item.pattern.test(text));
  return match?.key || null;
}

function now() {
  return new Date().toISOString();
}

function makeMemory(candidate) {
  const createdAt = candidate.createdAt || now();
  return {
    id: candidate.id || crypto.randomUUID(),
    type: candidate.type,
    content: normalize(candidate.content),
    importance: Number(candidate.importance || 0.5),
    source: candidate.source || "conversation",
    topic: candidate.topic || inferTopic(candidate.content),
    status: "active",
    createdAt,
    updatedAt: candidate.updatedAt || createdAt,
    supersededBy: null,
    supersessionReason: null,
    confidence: Number(candidate.confidence ?? 0.9)
  };
}

export function createMemoryStore(existing = []) {
  if (!Array.isArray(existing)) return [];
  return existing
    .map(item => makeMemory(item))
    .filter(item => item.content && item.status !== "archived")
    .slice(-MAX_MEMORIES);
}

export function extractMemoryCandidates(text) {
  const content = normalize(text);
  if (!content) return [];
  const matches = MEMORY_PATTERNS.filter(item => item.pattern.test(content));
  if (!matches.length) return [];

  return matches.slice(0, 2).map(match => ({
    type: match.type,
    content,
    importance: match.importance,
    source: "conversation",
    topic: inferTopic(content),
    createdAt: now()
  }));
}

const STOPWORDS = new Set([
  "yang", "dan", "atau", "untuk", "dari", "dengan", "ini", "itu", "apa", "saya",
  "kita", "akan", "harus", "bisa", "agar", "pada", "dalam", "jadi", "lebih", "juga",
  "the", "and", "or", "for", "from", "with", "this", "that", "what", "how", "use", "using"
]);

function similarity(a, b) {
  const aTokens = tokens(a);
  const bTokens = tokens(b);
  if (!aTokens.size || !bTokens.size) return 0;
  let overlap = 0;
  for (const token of aTokens) if (bTokens.has(token)) overlap += 1;
  return overlap / Math.max(Math.min(aTokens.size, bTokens.size), 1);
}

function topicMatches(memory, query) {
  if (!memory.topic) return false;
  const q = String(query ?? "").toLowerCase();
  const topicTerms = memory.topic.split("-").filter(Boolean);
  return topicTerms.some(term => q.includes(term));
}

function normalizeTokens(text) {
  return [...tokens(text)].filter(token => !STOPWORDS.has(token));
}

function lexicalScore(memory, query) {
  const queryTokens = normalizeTokens(query);
  const memoryTokens = new Set(normalizeTokens(memory.content));
  if (!queryTokens.length || !memoryTokens.size) return 0;
  let overlap = 0;
  for (const token of queryTokens) if (memoryTokens.has(token)) overlap += 1;
  return overlap / queryTokens.length;
}

function recencyScore(memory, nowMs = Date.now()) {
  const updatedMs = Date.parse(memory.updatedAt || memory.createdAt || "");
  if (!Number.isFinite(updatedMs)) return 0.2;
  const ageDays = Math.max(0, (nowMs - updatedMs) / 86_400_000);
  return Math.exp(-ageDays / 30);
}

function typeScore(memory, query) {
  const q = String(query ?? "").toLowerCase();
  const hints = {
    project_rule: ["aturan", "rule", "wajib", "tidak boleh", "approval", "policy"],
    decision: ["keputusan", "sepakat", "pilih", "gunakan", "framework", "arsitektur"],
    preference: ["preferensi", "suka", "ingin", "prefer"],
    fact: ["fakta", "ingat", "catat", "apa", "siapa", "kapan"]
  };
  const terms = hints[memory.type] || [];
  return terms.some(term => q.includes(term)) ? 1 : 0;
}

export function scoreMemory(memory, query, nowMs = Date.now()) {
  const lexical = lexicalScore(memory, query);
  const semanticLike = similarity(memory.content, query);
  const topic = topicMatches(memory, query) ? 1 : 0;
  const recency = recencyScore(memory, nowMs);
  const importance = Math.max(0, Math.min(1, Number(memory.importance || 0)));
  const type = typeScore(memory, query);

  // Lexical relevance is dominant. Topic, importance and recency break ties;
  // type is a small signal so a generic question does not overpower content relevance.
  const score =
    lexical * 0.52 +
    semanticLike * 0.16 +
    topic * 0.12 +
    importance * 0.12 +
    recency * 0.05 +
    type * 0.03;

  return {
    score,
    factors: { lexical, semanticLike, topic, importance, recency, type }
  };
}

function canSupersede(previous, candidate) {
  if (previous.status !== "active") return false;
  if (previous.type !== candidate.type) return false;
  if (previous.topic && candidate.topic) return previous.topic === candidate.topic;
  return similarity(previous.content, candidate.content) >= 0.55;
}

function isExplicitUpdate(candidate) {
  return /(?:mulai sekarang|ke depannya|sekarang|ganti|ubah|tidak lagi|bukan lagi|mulai berlaku)/i.test(candidate.content);
}

/**
 * Store memories and apply a conservative lifecycle rule:
 * a new memory only supersedes an active memory when the type/topic match
 * and the new statement looks like an explicit update, or when the two
 * statements are strongly overlapping.
 */
export function addMemories(store, candidates) {
  if (!Array.isArray(store) || !Array.isArray(candidates)) return { added: [], superseded: [], store };

  const added = [];
  const superseded = [];

  for (const raw of candidates) {
    if (!raw?.content) continue;
    const candidate = makeMemory(raw);
    const duplicate = store.find(item =>
      item.status === "active" &&
      item.type === candidate.type &&
      item.content.toLowerCase() === candidate.content.toLowerCase()
    );
    if (duplicate) {
      duplicate.updatedAt = now();
      continue;
    }

    const previous = store
      .filter(item => canSupersede(item, candidate))
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))[0];

    const overlap = previous ? similarity(previous.content, candidate.content) : 0;
    if (previous && (isExplicitUpdate(candidate) || overlap >= 0.7)) {
      previous.status = "superseded";
      previous.updatedAt = now();
      previous.supersededBy = candidate.id;
      previous.supersessionReason = isExplicitUpdate(candidate)
        ? "explicit-update"
        : "strong-overlap";
      superseded.push(previous.id);
    }

    store.push(candidate);
    added.push(candidate);
  }

  if (store.length > MAX_MEMORIES) {
    const removable = store.filter(item => item.status !== "active");
    while (store.length > MAX_MEMORIES && removable.length) {
      const item = removable.shift();
      const index = store.indexOf(item);
      if (index >= 0) store.splice(index, 1);
    }
    if (store.length > MAX_MEMORIES) store.splice(0, store.length - MAX_MEMORIES);
  }

  return { added, superseded, store };
}

export function archiveMemory(store, memoryId) {
  const memory = store?.find(item => item.id === memoryId);
  if (!memory) return null;
  memory.status = "archived";
  memory.updatedAt = now();
  return memory;
}

export function retrieveMemories(store, query, limit = 8) {
  if (!String(query ?? "").trim()) return [];
  return retrieveMemoryMatches(store, query, limit).map(item => item.memory);
}

export function retrieveMemoryMatches(store, query, limit = 8) {
  const queryTokens = normalizeTokens(query);
  if (!queryTokens.length) return [];

  return (Array.isArray(store) ? store : [])
    .filter(memory => memory.status === "active")
    .map(memory => ({ memory, ...scoreMemory(memory, query) }))
    .filter(item => item.score >= 0.10 && item.factors.lexical > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, Math.max(1, limit));
}

export function resolveMemoryConflicts(store) {
  if (!Array.isArray(store)) return { resolved: [], active: [] };
  const resolved = [];
  const groups = new Map();

  for (const memory of store.filter(item => item.status === "active")) {
    const key = `${memory.type}:${memory.topic || "general"}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(memory);
  }

  for (const [key, memories] of groups) {
    if (memories.length < 2) continue;
    const ordered = [...memories].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    const newest = ordered[0];
    for (const older of ordered.slice(1)) {
      const overlap = similarity(older.content, newest.content);
      if (isExplicitUpdate(newest) && overlap >= 0.15) {
        older.status = "superseded";
        older.supersededBy = newest.id;
        older.supersessionReason = "conflict-resolution";
        older.updatedAt = now();
        resolved.push({ oldId: older.id, newId: newest.id, key });
      }
    }
  }

  return { resolved, active: getActiveMemories(store) };
}

export function getMemoryById(store, memoryId) {
  return (Array.isArray(store) ? store : []).find(memory => memory.id === memoryId) || null;
}

export function getActiveMemories(store) {
  return (Array.isArray(store) ? store : []).filter(memory => memory.status === "active");
}
