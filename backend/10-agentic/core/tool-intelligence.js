const DEFAULT_DISCOVERY_LIMIT = 12;
const DEFAULT_CHAIN_LIMIT = 6;

const TOOL_HINTS = [
  { tools: ["inspect_project", "search_files", "find_symbol", "search_code"], terms: /\b(?:project|repo|repository|codebase|struktur|struktur|file|berkas|source|kode)\b/i, reason: "Map or locate relevant project evidence before reading broadly." },
  { tools: ["read_file", "inspect_code", "find_semantic_references", "resolve_symbol", "call_graph"], terms: /\b(?:fungsi|function|class|symbol|implement|implementation|import|reference|referensi|AST|semantic)\b/i, reason: "Inspect source structure and symbol relationships." },
  { tools: ["find_references", "find_file_references", "analyze_impact", "dependency_graph"], terms: /\b(?:impact|dampak|dependency|dependensi|dipakai|used|imported|affected|terpengaruh)\b/i, reason: "Trace reverse dependencies before a consequential change." },
  { tools: ["understand_task", "establish_task_goal_context", "decompose_task", "build_reasoning_plan", "reasoning_lifecycle"], terms: /\b(?:plan|planning|rencana|task|tugas|goal|tujuan|requirement|kebutuhan|multi-step|beberapa langkah)\b/i, reason: "Establish task and planning context before execution." },
  { tools: ["edit_file", "write_file", "plan_change"], terms: /\b(?:edit|ubah|modify|perbaiki|fix|implement|buat|tambah|hapus|refactor|refactoring)\b/i, reason: "Plan and apply a bounded source change." },
  { tools: ["analyze_tests", "plan_verification", "execute_verification", "diagnose_verification_failure"], terms: /\b(?:test|testing|verify|verification|cek|validasi|bug|fail|gagal|error)\b/i, reason: "Select targeted verification and failure diagnostics." },
  { tools: ["git_changes", "git_diff", "review_change_set", "git_status"], terms: /\b(?:git|diff|change|changes|commit|staged|unstaged|review)\b/i, reason: "Inspect the complete local change set and Git state." },
  { tools: ["git_add", "git_commit", "git_push"], terms: /\b(?:stage|staging|commit|push)\b/i, reason: "Use explicit Git operations; commit and push require approval." },
  { tools: ["terminal"], terms: /\b(?:terminal|shell|command|perintah|run|jalankan)\b/i, reason: "Run only policy-approved workspace commands." },
  { tools: ["analyze_contracts", "analyze_schemas", "analyze_frameworks", "plan_migration"], terms: /\b(?:API|endpoint|contract|schema|skema|framework|migration|migrasi|upgrade|upgrade)\b/i, reason: "Use specialized static intelligence before broad changes." }
];

function normalizeText(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function tokenize(value) {
  return new Set(normalizeText(value).toLowerCase().split(/[^a-z0-9_]+/).filter(token => token.length >= 3));
}

function toolText(tool) {
  return `${tool.name} ${tool.description || ""} ${tool.capability || ""}`;
}

function overlapScore(a, b) {
  const left = tokenize(a);
  const right = tokenize(b);
  if (!left.size || !right.size) return 0;
  let overlap = 0;
  for (const token of left) if (right.has(token)) overlap += 1;
  return overlap / Math.max(left.size, 1);
}

export function discoverTools({ query = "", definitions = [], capability, permission, limit = DEFAULT_DISCOVERY_LIMIT } = {}) {
  const normalized = normalizeText(query);
  const scored = definitions
    .filter(tool => !capability || tool.capability === capability)
    .filter(tool => !permission || tool.permission === permission)
    .map(tool => {
      let score = overlapScore(normalized, toolText(tool));
      for (const hint of TOOL_HINTS) {
        if (hint.tools.includes(tool.name) && hint.terms.test(normalized)) score += 0.35;
      }
      if (tool.permission === "read") score += 0.02;
      return { tool, score };
    })
    .sort((a, b) => b.score - a.score || a.tool.name.localeCompare(b.tool.name));

  return scored.slice(0, Math.max(1, limit)).map(({ tool, score }) => ({
    name: tool.name,
    description: tool.description,
    permission: tool.permission,
    capability: tool.capability,
    relevance: Number(score.toFixed(4))
  }));
}

export function selectTool({ query = "", definitions = [], preferred = [], limit = 8 } = {}) {
  const discovered = discoverTools({ query, definitions, limit: Math.max(limit, preferred.length) + 4 });
  const preferredSet = new Set(preferred);
  return discovered
    .map(item => ({ ...item, selected: preferredSet.has(item.name) || item.relevance >= 0.2 }))
    .filter(item => item.selected)
    .slice(0, limit);
}

function requiredFieldsFor(tool) {
  if (["read_file", "inspect_code", "find_file_references"].includes(tool)) return ["path"];
  if (tool === "edit_file") return ["path", "expectedHash", "operation"];
  if (tool === "write_file") return ["path", "content"];
  if (tool === "terminal") return ["command"];
  if (tool === "git_add") return ["paths"];
  if (tool === "git_commit") return ["message"];
  return [];
}

export function validateToolCall({ name, input = {}, definitions = [] } = {}) {
  const definition = definitions.find(tool => tool.name === name);
  if (!definition) return { ok: false, code: "unknown_tool", error: `Tool tidak dikenal: ${name}` };
  if (!input || typeof input !== "object" || Array.isArray(input)) return { ok: false, code: "invalid_input", error: `Input ${name} harus berupa object` };

  const required = requiredFieldsFor(name);
  const missing = required.filter(field => {
    const value = input[field];
    return value === undefined || value === null || (typeof value === "string" && !value.trim()) || (Array.isArray(value) && value.length === 0);
  });
  if (missing.length) return { ok: false, code: "missing_parameters", error: `Parameter wajib belum lengkap: ${missing.join(", ")}`, missing };

  if (definition.permission === "approval" && input.approved !== true) {
    return { ok: false, code: "approval_required", error: `${name} requires explicit approval` };
  }

  return { ok: true, tool: definition };
}

export function normalizeToolInput(name, input = {}) {
  const normalized = { ...input };
  if (typeof normalized.path === "string") normalized.path = normalized.path.trim();
  if (typeof normalized.command === "string") normalized.command = normalized.command.trim();
  if (typeof normalized.message === "string") normalized.message = normalized.message.trim();
  if (typeof normalized.expectedHash === "string") normalized.expectedHash = normalized.expectedHash.trim();
  if (Array.isArray(normalized.paths)) normalized.paths = normalized.paths.map(item => String(item).trim()).filter(Boolean);
  if (name === "edit_file" && typeof normalized.operation === "string") normalized.operation = normalized.operation.trim();
  return normalized;
}

export function buildToolChain({ query = "", selectedTools = [], limit = DEFAULT_CHAIN_LIMIT } = {}) {
  const names = selectedTools.map(item => typeof item === "string" ? item : item.name);
  const chain = [];
  const add = (name, reason) => {
    if (chain.some(item => item.tool === name) || chain.length >= limit) return;
    chain.push({ order: chain.length + 1, tool: name, reason });
  };

  if (/\b(?:edit|ubah|modify|fix|implement|refactor|refactoring)\b/i.test(query)) add("plan_change", "Establish bounded change scope before editing.");
  if (/\b(?:project|repo|repository|codebase|struktur|file|source|kode)\b/i.test(query)) add("inspect_project", "Get structural workspace evidence when scope is broad.");
  if (/\b(?:symbol|function|class|import|reference|referensi)\b/i.test(query)) add("find_references", "Resolve actual symbol/reference usage before changing code.");
  if (/\b(?:edit|ubah|modify|fix|implement|refactor|refactoring)\b/i.test(query)) add("edit_file", "Apply the bounded change with stale-write protection.");
  if (/\b(?:test|verify|verification|cek|validasi|bug|error|gagal)\b/i.test(query)) add("plan_verification", "Derive checks from actual changed files and project scripts.");
  if (/\b(?:test|verify|verification|cek|validasi|bug|error|gagal)\b/i.test(query)) add("execute_verification", "Execute only planner-generated verification checks.");
  if (/\b(?:git|diff|change|changes|review|commit|push)\b/i.test(query)) add("review_change_set", "Review staged, unstaged, and untracked changes before approval.");

  for (const name of names) add(name, "Relevant tool discovered for the current request.");
  return chain;
}

export function interpretToolResult({ name, input = {}, result } = {}) {
  const ok = result?.ok !== false;
  const base = { tool: name, ok, status: ok ? "completed" : "failed" };
  if (!ok) {
    const error = normalizeText(result?.error || "Tool returned a failure without an error message.");
    return { ...base, error, recovery: recoveryFor(name, error) };
  }

  const summary = {};
  if (Array.isArray(result?.files)) summary.files = result.files.length;
  if (Array.isArray(result?.results)) summary.matches = result.results.length;
  if (Array.isArray(result?.checks)) summary.checks = result.checks.length;
  if (result?.summary) summary.execution = result.summary;
  if (result?.path) summary.path = result.path;
  if (result?.branch) summary.branch = result.branch;
  if (result?.blocked) summary.blocked = true;
  return { ...base, summary };
}

function recoveryFor(name, error) {
  if (/approval/i.test(error)) return { action: "request_approval", reason: "The tool requires explicit user approval." };
  if (/not found|no such file|path/i.test(error)) return { action: "inspect_path", suggestedTools: ["list_files", "search_files"] };
  if (/hash|stale|conflict/i.test(error)) return { action: "refresh_file", suggestedTools: ["read_file", "plan_change"] };
  if (/test|verification|exit code|syntax/i.test(error)) return { action: "diagnose_failure", suggestedTools: ["diagnose_verification_failure", "plan_verification"] };
  if (name === "terminal") return { action: "inspect_command_result", suggestedTools: ["read_file", "search_code"] };
  return { action: "inspect_actual_error", suggestedTools: ["search_code", "read_file"] };
}

export function buildToolIntelligence({ query = "", definitions = [], context } = {}) {
  const selected = selectTool({ query, definitions });
  const chain = buildToolChain({ query, selectedTools: selected });
  return {
    query: normalizeText(query),
    discovered: discoverTools({ query, definitions }),
    selected,
    chain,
    context: context ? {
      recentMessages: context.sourceCounts?.recentConversation || 0,
      relevantMemories: context.sourceCounts?.relevantMemories || 0
    } : null
  };
}

export const TOOL_INTELLIGENCE_CAPABILITIES = [
  "tool_discovery",
  "tool_selection",
  "tool_parameter_validation",
  "tool_parameter_normalization",
  "tool_chaining",
  "tool_result_interpretation",
  "tool_failure_handling",
  "capability_discovery"
];
