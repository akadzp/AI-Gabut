import { createExecutionId, ExecutionRuntime } from "./reliability/runtime.js";

const providers = new Map();
const MAX_MEMORIES = 200;
const clean = (value, max = 12000) => String(value ?? "").trim().slice(0, max);
const tokens = value => new Set(clean(value, 4000).toLowerCase().match(/[\p{L}\p{N}_-]{2,}/gu) || []);

export function registerAgentProvider(name, adapter) {
  const key = clean(name, 80).toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(key) || typeof adapter !== "function" && typeof adapter?.run !== "function") {
    throw new TypeError("Agent provider membutuhkan nama valid dan adapter function atau objek run()");
  }
  providers.set(key, typeof adapter === "function" ? adapter : adapter.run.bind(adapter));
  return () => providers.delete(key);
}

export function listAgentProviders() { return [...providers.keys()].sort(); }

export function createPlan({ prompt, objective, maxSteps = 5 } = {}) {
  const goal = clean(objective || prompt, 4000);
  if (!goal) throw new TypeError("Prompt atau objective wajib diisi untuk membuat plan");
  const cap = Math.max(1, Math.min(Number(maxSteps) || 5, 20));
  const defaults = [
    { id: "understand", goal: "Pahami tujuan, batasan, dan kriteria keberhasilan", tools: [] },
    { id: "execute", goal: "Kerjakan langkah yang berada dalam capability dan authority yang tersedia", tools: [] },
    { id: "verify", goal: "Verifikasi hasil dan laporkan keterbatasan yang tersisa", tools: [] }
  ];
  return defaults.slice(0, cap).map((step, index) => ({ ...step, order: index + 1, status: "planned" }));
}

export async function runAgent(options = {}) {
  const prompt = clean(options.prompt, 12000);
  if (!prompt) throw new TypeError("Prompt wajib diisi");
  const executionId = clean(options.agentExecutionId || options.executionId || createExecutionId(), 240);
  const runtime = new ExecutionRuntime({ id: executionId, maxSteps: 20 });
  const plan = createPlan({ prompt, maxSteps: 3 });
  runtime.start();
  const emit = async event => { if (typeof options.onActivity === "function") await options.onActivity(event); };
  await emit({ action: "planning", status: "running", label: "Menyusun rencana", meta: { stepCount: plan.length } });
  await emit({ action: "planning", status: "completed", label: "Rencana tersedia", meta: { steps: plan } });
  const requestedProvider = typeof options.provider === "string" ? options.provider.trim().toLowerCase() : "";
  const adapter = typeof options.provider === "function" ? options.provider :
    (options.provider && typeof options.provider.run === "function" ? options.provider.run.bind(options.provider) : providers.get(requestedProvider));
  if (!adapter) {
    const message = requestedProvider
      ? `Provider model '${requestedProvider}' belum terdaftar. Daftarkan adapter dengan registerAgentProvider() sebelum menjalankan execution.`
      : "Belum ada model provider yang dikonfigurasi. Runtime dan workflow tersedia, tetapi prompt ini belum dieksekusi oleh model. Daftarkan adapter dengan registerAgentProvider() terlebih dahulu.";
    runtime.finish("failed", { code: "MODEL_PROVIDER_NOT_CONFIGURED" });
    await emit({ action: "execution", status: "failed", label: "Model provider belum dikonfigurasi", error: message });
    return { text: message, status: "failed", execution: { ...runtime.snapshot(), status: "failed", error: message }, plan: { version: 1, status: "blocked", steps: plan }, provider: requestedProvider || null };
  }
  const externalSignal = options.signal;
  const timeoutValue = Number(options.timeoutMs);
  const timeoutMs = Number.isFinite(timeoutValue) && timeoutValue > 0
    ? Math.max(1, Math.min(timeoutValue, 300000))
    : 120000;
  const controller = new AbortController();
  let timeout = null;
  let externalAbort = null;
  let abortListener = null;
  const abortReason = (code, message) => Object.assign(new Error(message), { code });
  const abortPromise = new Promise((_, reject) => {
    abortListener = () => {
      const reason = controller.signal.reason;
      const error = reason instanceof Error ? reason : abortReason("AGENT_EXECUTION_CANCELLED", "Execution dibatalkan");
      reject(error);
    };
    controller.signal.addEventListener("abort", abortListener, { once: true });
  });
  if (externalSignal) {
    externalAbort = () => {
      const reason = externalSignal.reason;
      controller.abort(reason instanceof Error ? reason : abortReason("AGENT_EXECUTION_CANCELLED", "Execution dibatalkan oleh pemanggil"));
    };
    if (externalSignal.aborted) externalAbort();
    else externalSignal.addEventListener("abort", externalAbort, { once: true });
  }
  if (!controller.signal.aborted) {
    timeout = setTimeout(() => controller.abort(abortReason("AGENT_EXECUTION_TIMEOUT", `Execution melewati batas waktu ${timeoutMs} ms`)), timeoutMs);
  }
  try {
    const providerPromise = controller.signal.aborted
      ? Promise.reject(controller.signal.reason instanceof Error ? controller.signal.reason : abortReason("AGENT_EXECUTION_CANCELLED", "Execution dibatalkan"))
      : Promise.resolve().then(() => {
          if (controller.signal.aborted) throw controller.signal.reason;
          return adapter({ ...options, signal: controller.signal, prompt, executionId, plan });
        });
    const result = await Promise.race([providerPromise, abortPromise]);
    const normalized = typeof result === "string" ? { text: result } : result && typeof result === "object" ? result : { text: String(result ?? "") };
    const status = ["failed", "cancelled", "stopped", "max_turns"].includes(normalized.status || normalized.execution?.status) ? (normalized.status || normalized.execution.status) : "completed";
    runtime.finish(status === "max_turns" ? "stopped" : status, { provider: requestedProvider || "custom" });
    const text = clean(normalized.text ?? normalized.message ?? "", 12000);
    await emit({ action: "execution", status: status === "completed" ? "completed" : "finished", label: status === "completed" ? "Execution selesai" : `Execution ${status}`, meta: { status } });
    return { ...normalized, text, status, execution: { ...runtime.snapshot(), ...(normalized.execution || {}), status }, plan: normalized.plan || { version: 1, status: "completed", steps: plan }, provider: normalized.provider || requestedProvider || "custom" };
  } catch (error) {
    const code = error?.code || "AGENT_PROVIDER_FAILED";
    const cancelled = code === "AGENT_EXECUTION_CANCELLED" || code === "WORK_CANCELLED" || code === "WORK_PAUSED" || code === "WORK_STOPPED" || Boolean(externalSignal?.aborted && code !== "AGENT_EXECUTION_TIMEOUT");
    const timedOut = code === "AGENT_EXECUTION_TIMEOUT";
    const status = timedOut ? "stopped" : cancelled ? "cancelled" : "failed";
    const message = clean(error?.message || error, 1000);
    runtime.finish(status, { code });
    await emit({ action: "execution", status, label: timedOut ? "Execution melewati batas waktu" : cancelled ? "Execution dibatalkan" : "Execution gagal", error: message });
    return { text: `${timedOut ? "Execution timeout" : cancelled ? "Execution dibatalkan" : "Execution gagal"}: ${message}`, status, execution: { ...runtime.snapshot(), status, error: message }, plan: { version: 1, status, steps: plan }, error: { code, message } };
  } finally {
    if (timeout) clearTimeout(timeout);
    if (externalSignal && externalAbort) externalSignal.removeEventListener("abort", externalAbort);
    if (abortListener) controller.signal.removeEventListener("abort", abortListener);
  }
}

export function extractMemoryCandidates(text) {
  const input = clean(text, 12000);
  const candidates = [];
  const patterns = [/(?:remember|ingat(?:lah)?|catat(?:lah)?|prefer(?:ensi)? saya adalah|my preference is)\s*[:,-]?\s*(.{8,500})/i];
  for (const pattern of patterns) {
    const match = input.match(pattern);
    if (match?.[1]) candidates.push({ id: `memory-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`, content: clean(match[1], 500), status: "active", createdAt: new Date().toISOString(), source: "explicit-user-memory" });
  }
  return candidates;
}

export function addMemories(memoryList, candidates = []) {
  if (!Array.isArray(memoryList)) throw new TypeError("Memory list harus berupa array");
  const existing = new Set(memoryList.map(item => clean(item?.content, 500).toLowerCase()).filter(Boolean));
  for (const candidate of Array.isArray(candidates) ? candidates.slice(0, 20) : []) {
    const content = clean(candidate?.content, 500);
    if (!content || existing.has(content.toLowerCase())) continue;
    memoryList.push({ ...candidate, content, status: "active", createdAt: candidate.createdAt || new Date().toISOString() });
    existing.add(content.toLowerCase());
  }
  if (memoryList.length > MAX_MEMORIES) memoryList.splice(0, memoryList.length - MAX_MEMORIES);
  return memoryList;
}

export function retrieveMemories(memoryList = [], query = "", { limit = 10 } = {}) {
  const queryTokens = tokens(query);
  if (!queryTokens.size) return [];
  return (Array.isArray(memoryList) ? memoryList : []).filter(item => item?.status !== "deleted" && item?.status !== "superseded")
    .map(item => ({ item, score: [...tokens(item.content)].filter(token => queryTokens.has(token)).length }))
    .filter(result => result.score > 0).sort((a, b) => b.score - a.score || String(a.item.createdAt).localeCompare(String(b.item.createdAt)))
    .slice(0, Math.max(1, Math.min(Number(limit) || 10, 50))).map(result => ({ ...result.item, relevance: result.score }));
}

export function resolveMemoryConflicts(memoryList = []) {
  if (!Array.isArray(memoryList)) return [];
  const latestByKey = new Map();
  for (const item of memoryList) {
    const key = clean(item?.key || item?.topic || "", 120).toLowerCase();
    if (!key || item.status === "deleted") continue;
    const previous = latestByKey.get(key);
    if (!previous || String(item.updatedAt || item.createdAt || "") >= String(previous.updatedAt || previous.createdAt || "")) {
      if (previous) previous.status = "superseded";
      latestByKey.set(key, item);
    } else item.status = "superseded";
  }
  return memoryList;
}

export function getActiveMemories(memoryList = []) {
  return (Array.isArray(memoryList) ? memoryList : []).filter(item => item && item.status !== "deleted" && item.status !== "superseded" && item.status !== "inactive").slice(-MAX_MEMORIES);
}

export { createExecutionId, ExecutionRuntime };
