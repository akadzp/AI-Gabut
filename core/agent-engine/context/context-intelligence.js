import { getActiveMemories, resolveMemoryConflicts, retrieveMemoryMatches } from "./memory.js";

const DEFAULT_CHAR_BUDGET = 36_000;
const DEFAULT_MEMORY_LIMIT = 8;
const DEFAULT_RECENT_MESSAGES = 10;
const SUMMARY_MESSAGE_LIMIT = 12;

function text(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

export function estimateTokens(value) {
  return Math.ceil(String(value ?? "").length / 4);
}

function normalizeMessages(messages) {
  return (Array.isArray(messages) ? messages : [])
    .filter(message => message && (message.role === "user" || message.role === "assistant"))
    .map(message => ({
      role: message.role,
      content: String(message.content ?? "").slice(0, 12_000),
      createdAt: message.createdAt || null
    }));
}

function summarizeMessages(messages) {
  const source = messages.slice(0, SUMMARY_MESSAGE_LIMIT);
  if (!source.length) return null;

  const bullets = source.map(message => {
    const content = text(message.content).slice(0, 320);
    const label = message.role === "user" ? "User" : "Agent";
    return `${label}: ${content}`;
  });

  return {
    role: "system",
    content: `Conversation context summary (heuristic, not a hidden reasoning trace):\n- ${bullets.join("\n- ")}`,
    summarizedCount: source.length
  };
}

function fitMessages(messages, budget) {
  const selected = [];
  let used = 0;
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    const cost = estimateTokens(message.content) + 8;
    if (selected.length && used + cost > budget) break;
    selected.unshift(message);
    used += cost;
  }
  return { messages: selected, estimatedTokens: used };
}

function memoryPayload(matches) {
  return matches.map(({ memory, score, factors }) => ({
    memory,
    relevance: Number(score.toFixed(4)),
    factors
  }));
}

export function prepareContext({
  prompt,
  conversation = [],
  memories = [],
  charBudget = DEFAULT_CHAR_BUDGET,
  memoryLimit = DEFAULT_MEMORY_LIMIT,
  recentMessages = DEFAULT_RECENT_MESSAGES
} = {}) {
  const normalizedConversation = normalizeMessages(conversation);
  const normalizedPrompt = text(prompt);

  const conflictResolution = resolveMemoryConflicts(memories);
  const activeMemories = getActiveMemories(memories);
  const matches = retrieveMemoryMatches(activeMemories, normalizedPrompt, memoryLimit);
  const relevantMemories = memoryPayload(matches);

  const recent = normalizedConversation.slice(-Math.max(1, recentMessages));
  const older = normalizedConversation.slice(0, Math.max(0, normalizedConversation.length - recent.length));
  const summary = older.length ? summarizeMessages(older) : null;

  const memoryText = relevantMemories.map(item =>
    `${item.memory.type}: ${item.memory.content}`
  ).join("\n");
  const memoryTokens = estimateTokens(memoryText);
  const promptTokens = estimateTokens(normalizedPrompt);
  const fixedTokens = promptTokens + memoryTokens + 64;
  const conversationBudget = Math.max(512, Math.floor((charBudget / 4) - fixedTokens));
  const fitted = fitMessages(recent, conversationBudget);

  return {
    prompt: normalizedPrompt,
    conversation: fitted.messages,
    conversationSummary: summary,
    memories: relevantMemories.map(item => item.memory),
    memoryMatches: relevantMemories,
    conflictResolution,
    budget: {
      estimatedTokens: fixedTokens + fitted.estimatedTokens + (summary ? estimateTokens(summary.content) : 0),
      maxEstimatedTokens: Math.floor(charBudget / 4),
      conversationEstimatedTokens: fitted.estimatedTokens,
      memoryEstimatedTokens: memoryTokens
    },
    sourceCounts: {
      conversation: normalizedConversation.length,
      recentConversation: fitted.messages.length,
      summarizedConversation: older.length,
      activeMemories: activeMemories.length,
      relevantMemories: relevantMemories.length
    }
  };
}

export function buildContextPrompt(context) {
  const summary = context?.conversationSummary?.content;
  const memoryLines = (context?.memoryMatches || []).map(item =>
    `- ${item.memory.type}: ${item.memory.content}`
  );
  const sections = [];
  if (summary) sections.push(summary);
  if (memoryLines.length) sections.push(`Relevant remembered project context:\n${memoryLines.join("\n")}`);
  return sections.join("\n\n");
}

export function compactContextForActivity(context) {
  return {
    recentMessages: context?.sourceCounts?.recentConversation || 0,
    summarizedMessages: context?.sourceCounts?.summarizedConversation || 0,
    activeMemories: context?.sourceCounts?.activeMemories || 0,
    relevantMemories: context?.sourceCounts?.relevantMemories || 0,
    estimatedTokens: context?.budget?.estimatedTokens || 0,
    maxEstimatedTokens: context?.budget?.maxEstimatedTokens || 0,
    conflictsResolved: context?.conflictResolution?.resolved?.length || 0
  };
}
