const PROVIDERS = ['openai', 'gemini'];
const DEFAULT_CONTEXT_TOKENS = 128000;

function clean(value, max = 200) {
  return String(value ?? '').trim().slice(0, max);
}

function number(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function estimateTokens(messages = []) {
  const chars = messages.reduce((total, message) => total + String(message?.content ?? '').length, 0);
  return Math.max(1, Math.ceil(chars / 4));
}

function classifyTask(text = '') {
  const value = text.toLowerCase();
  const types = [];
  if (/debug|bug|error|failure|stack trace|diagnos|perbaiki|gagal/.test(value)) types.push('debugging');
  if (/refactor|migration|upgrade|schema|contract|architecture|arsitektur/.test(value)) types.push('deep-reasoning');
  if (/code|coding|implement|edit|write|modify|file|javascript|typescript|kode/.test(value)) types.push('coding');
  if (/plan|planning|roadmap|decompose|break down|rencana/.test(value)) types.push('planning');
  if (/summarize|summary|explain|jelaskan|ringkas|review/.test(value)) types.push('analysis');
  if (!types.length) types.push('general');
  return [...new Set(types)];
}

function inferProfile(provider, model) {
  const id = String(model || '').toLowerCase();
  const fast = /mini|flash|haiku|nano|small|lite/.test(id);
  const reasoning = /reason|o[1-9]|thinking|pro|sonnet|opus/.test(id);
  return {
    provider,
    model,
    maxContextTokens: fast ? 65536 : DEFAULT_CONTEXT_TOKENS,
    latencyMs: fast ? 900 : reasoning ? 2800 : 1800,
    inputCost: fast ? 0.5 : reasoning ? 5 : 2,
    outputCost: fast ? 1.5 : reasoning ? 15 : 6,
    capabilities: [
      'general', 'analysis', 'coding', 'planning',
      ...(reasoning ? ['deep-reasoning', 'debugging'] : [])
    ],
    tags: [fast ? 'fast' : 'balanced', ...(reasoning ? ['reasoning'] : [])]
  };
}

function parseConfiguredProfiles() {
  const raw = process.env.AI_ROUTER_MODELS;
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(item => PROVIDERS.includes(item?.provider) && item?.model)
      .map(item => ({
        ...inferProfile(item.provider, item.model),
        ...item,
        model: clean(item.model, 120),
        capabilities: Array.isArray(item.capabilities) ? item.capabilities : inferProfile(item.provider, item.model).capabilities,
        maxContextTokens: number(item.maxContextTokens, DEFAULT_CONTEXT_TOKENS),
        latencyMs: number(item.latencyMs, 1800),
        inputCost: number(item.inputCost, 0),
        outputCost: number(item.outputCost, 0)
      }));
  } catch {
    return [];
  }
}

export function getModelCandidates() {
  const configured = parseConfiguredProfiles();
  if (configured.length) return configured;

  const candidates = [];
  for (const provider of PROVIDERS) {
    const model = process.env[provider === 'openai' ? 'OPENAI_MODEL' : 'GEMINI_MODEL'];
    if (model) candidates.push(inferProfile(provider, model));
  }
  return candidates;
}

function scoreCandidate(candidate, { taskTypes, estimatedTokens, preferences }) {
  if (!candidate?.model) return -Infinity;
  if (estimatedTokens > candidate.maxContextTokens) return -Infinity;

  let score = 50;
  const capabilities = new Set(candidate.capabilities || []);
  for (const type of taskTypes) score += capabilities.has(type) ? 18 : -4;

  if (preferences?.provider && candidate.provider === preferences.provider) score += 30;
  if (preferences?.model && candidate.model === preferences.model) score += 100;

  const costWeight = preferences?.costSensitive ? 8 : 2;
  const latencyWeight = preferences?.latencySensitive ? 8 : 2;
  score -= Math.min(20, candidate.inputCost * costWeight);
  score -= Math.min(20, candidate.latencyMs / 1000 * latencyWeight);

  if (preferences?.preferReasoning && candidate.tags?.includes('reasoning')) score += 15;
  if (preferences?.preferFast && candidate.tags?.includes('fast')) score += 15;

  return score;
}

export function routeModel({ prompt = '', messages = [], provider, model } = {}) {
  const explicit = Boolean(provider || model);
  const candidates = getModelCandidates();
  const taskTypes = classifyTask(prompt);
  const estimatedTokens = estimateTokens(messages);
  const preferences = {
    provider: provider || null,
    model: model || null,
    costSensitive: /cheap|low cost|hemat biaya|murah/.test(prompt.toLowerCase()),
    latencySensitive: /fast|quick|cepat|segera/.test(prompt.toLowerCase()),
    preferReasoning: taskTypes.includes('deep-reasoning') || taskTypes.includes('debugging'),
    preferFast: taskTypes.includes('general') && !taskTypes.includes('deep-reasoning')
  };

  if (explicit) {
    const selectedProvider = provider || process.env.AI_PROVIDER || 'openai';
    const selectedModel = model || process.env[selectedProvider === 'openai' ? 'OPENAI_MODEL' : 'GEMINI_MODEL'];
    return {
      ok: Boolean(selectedModel),
      mode: 'explicit',
      provider: selectedProvider,
      model: selectedModel || null,
      taskTypes,
      estimatedTokens,
      candidates: candidates.map(candidate => ({ provider: candidate.provider, model: candidate.model })),
      fallbackCandidates: []
    };
  }

  const ranked = candidates
    .map(candidate => ({ candidate, score: scoreCandidate(candidate, { taskTypes, estimatedTokens, preferences }) }))
    .filter(item => Number.isFinite(item.score))
    .sort((a, b) => b.score - a.score);

  const primary = ranked[0]?.candidate;
  return {
    ok: Boolean(primary),
    mode: 'automatic',
    provider: primary?.provider || null,
    model: primary?.model || null,
    taskTypes,
    estimatedTokens,
    score: ranked[0]?.score ?? null,
    candidates: ranked.map(item => ({ provider: item.candidate.provider, model: item.candidate.model, score: item.score })),
    fallbackCandidates: ranked.slice(1).map(item => ({ provider: item.candidate.provider, model: item.candidate.model }))
  };
}

export async function chatWithRoutedProvider({ prompt = '', messages = [], provider, model, route = null } = {}) {
  const selected = route || routeModel({ prompt, messages, provider, model });
  if (!selected.ok) throw new Error('Tidak ada model yang dapat dipilih. Set OPENAI_MODEL/GEMINI_MODEL atau AI_ROUTER_MODELS.');

  const candidates = [
    { provider: selected.provider, model: selected.model },
    ...(selected.mode === 'automatic' ? selected.fallbackCandidates : [])
  ];
  let lastError = null;

  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index];
    try {
      const { chatWithProvider } = await import('./index.js');
      const response = await chatWithProvider({ provider: candidate.provider, model: candidate.model, messages });
      return {
        ...response,
        routing: {
          mode: selected.mode,
          requestedProvider: provider || null,
          requestedModel: model || null,
          selectedProvider: selected.provider,
          selectedModel: selected.model,
          usedProvider: candidate.provider,
          usedModel: candidate.model,
          fallbackUsed: index > 0,
          taskTypes: selected.taskTypes,
          estimatedTokens: selected.estimatedTokens,
          candidates: selected.candidates
        }
      };
    } catch (error) {
      lastError = error;
      if (selected.mode !== 'automatic') break;
    }
  }

  throw lastError || new Error('Model routing gagal.');
}
