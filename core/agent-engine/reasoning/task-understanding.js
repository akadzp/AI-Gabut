const MAX_TEXT = 12000;
const FILE_RE = /(?:^|[\s`'"(])([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.@-]+)*(?:\.[A-Za-z0-9_.-]+))(?:[\s`'"),]|$)/g;
const QUOTED_RE = /["'`]([^"'`\n]{2,180})["'`]/g;

const ACTIONS = [
  { key: "inspect", patterns: [/\b(periksa|cek|inspect|analisis|analyze|review|lihat|baca)\b/i] },
  { key: "create", patterns: [/\b(buat|create|tambah|add)\b/i] },
  { key: "edit", patterns: [/\b(ubah|edit|modify|update|perbaiki|fix|refactor|rewrite)\b/i] },
  { key: "delete", patterns: [/\b(hapus|delete|remove)\b/i] },
  { key: "test", patterns: [/\b(test|testing|uji|verifikasi|verify)\b/i] },
  { key: "explain", patterns: [/\b(jelaskan|explain|terangkan|describe)\b/i] },
  { key: "migrate", patterns: [/\b(migrasi|migrate|upgrade|downgrade)\b/i] },
  { key: "review", patterns: [/\b(review|audit|auditkan|tinjau)\b/i] }
];

const CONSTRAINT_PATTERNS = [
  ["no-change", /\b(jangan|tanpa|tidak boleh|do not|don't|without)\b[^.\n]*(?:ubah|edit|modif|change|write|touch)/i],
  ["read-only", /\b(read[- ]only|hanya baca|jangan mengubah|tanpa perubahan)\b/i],
  ["approval-required", /\b(approval|persetujuan|izin|approve|approved)\b/i],
  ["preserve-api", /\b(jangan ubah|pertahankan|preserve)\b[^.\n]*(?:api|contract|endpoint)/i],
  ["scope-limited", /\b(hanya|only|just|khusus)\b/i]
];

function unique(values) { return [...new Set(values.filter(Boolean))]; }

function extractFiles(text) {
  const values = [];
  for (const match of text.matchAll(FILE_RE)) values.push(match[1]);
  for (const match of text.matchAll(QUOTED_RE)) {
    if (/\.(?:js|mjs|cjs|ts|tsx|jsx|json|md|css|html)$/i.test(match[1]) || match[1].includes("/")) values.push(match[1]);
  }
  return unique(values).slice(0, 40);
}

function detectActions(text) {
  return unique(ACTIONS.flatMap(item => item.patterns.some(pattern => pattern.test(text)) ? [item.key] : []));
}

function detectTaskType(actions, text) {
  if (actions.includes("migrate")) return "migration";
  if (actions.includes("review")) return "review";
  if (actions.includes("test")) return "verification";
  if (actions.includes("edit") || actions.includes("create") || actions.includes("delete")) return "modification";
  if (actions.includes("inspect")) return "analysis";
  if (actions.includes("explain")) return "explanation";
  if (/\b(github|gitlab|replit|bitbucket)\b/i.test(text)) return "integration-related";
  return "general";
}

function extractConstraints(text) {
  const constraints = CONSTRAINT_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
  if (/\b(jangan|do not|don't)\b/i.test(text) && /\b(commit|push)\b/i.test(text)) constraints.push("no-commit-or-push");
  return unique(constraints);
}

function ambiguitySignals({ actions, files, text }) {
  const signals = [];
  if (!actions.length) signals.push("action-not-explicit");
  if ((actions.includes("edit") || actions.includes("create") || actions.includes("delete")) && !files.length && !/\b(project|workspace|code|aplikasi|application)\b/i.test(text)) signals.push("target-not-explicit");
  if (/\b(it|itu|ini|that|this|tersebut)\b/i.test(text) && text.length < 80) signals.push("referent-may-depend-on-context");
  return signals;
}

export function understandTask({ prompt = "", conversation = [] } = {}) {
  const text = String(prompt || "").trim().slice(0, MAX_TEXT);
  const actions = detectActions(text);
  const files = extractFiles(text);
  const constraints = extractConstraints(text);
  const ambiguity = ambiguitySignals({ actions, files, text });
  const taskType = detectTaskType(actions, text);
  const contextMessages = Array.isArray(conversation) ? conversation.slice(-6).map(item => ({ role: item?.role, content: String(item?.content || "").slice(0, 1200) })) : [];

  return {
    ok: true,
    taskType,
    goal: text,
    actions,
    targets: { files, mentionedObjects: unique([...text.matchAll(QUOTED_RE)].map(match => match[1])).slice(0, 30) },
    constraints,
    ambiguity,
    context: { recentMessages: contextMessages.length },
    confidence: ambiguity.length ? "partial" : actions.length ? "high" : "low",
    limitations: [
      "Task understanding is a bounded lexical/context extraction layer, not a substitute for model reasoning.",
      "Implicit goals, domain terminology, and references may require conversation context and workspace tools.",
      "This tool does not edit files, execute commands, commit, push, or make approval decisions."
    ]
  };
}
