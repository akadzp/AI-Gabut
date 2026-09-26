import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const ROOT = path.resolve(process.env.AI_RELIABILITY_DIR || path.join(process.cwd(), '.ai-gabut', 'executions'));
const MAX_CHECKPOINTS = 100;
const DEFAULT_TIMEOUT_MS = 120_000;
const locks = new Map();
const metrics = { started: 0, completed: 0, failed: 0, resumed: 0, timeouts: 0 };
function safeId(value) { return String(value || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120); }
function fileFor(id) { return path.join(ROOT, `${safeId(id)}.json`); }
async function ensureRoot() { await fs.mkdir(ROOT, { recursive: true }); }
export function createExecutionId() { return crypto.randomUUID(); }
export function fingerprint(input) { return crypto.createHash('sha256').update(JSON.stringify(input)).digest('hex'); }
export async function loadExecution(id) { if (!id) return null; try { return JSON.parse(await fs.readFile(fileFor(id), 'utf8')); } catch { return null; } }
export async function saveExecution(state) {
  await ensureRoot();
  const current = await loadExecution(state.id);
  const checkpoints = [...(current?.checkpoints || []), state.checkpoint].filter(Boolean).slice(-MAX_CHECKPOINTS);
  const next = { ...state, checkpoints, updatedAt: new Date().toISOString() };
  const tmp = `${fileFor(state.id)}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(next, null, 2), 'utf8'); await fs.rename(tmp, fileFor(state.id)); return next;
}
export async function startExecution({ id = createExecutionId(), sessionId = null, prompt }) {
  metrics.started++;
  return saveExecution({ id, sessionId, prompt, status: 'running', startedAt: new Date().toISOString(), checkpoint: { type: 'started', turn: 0, steps: [], messages: [], createdAt: new Date().toISOString() } });
}
export async function checkpointExecutionState({ id, checkpoint, status = 'running', meta = {} }) { return saveExecution({ id, status, meta, checkpoint: { ...checkpoint, createdAt: new Date().toISOString() } }); }
export async function finishExecution({ id, status, result = null, error = null }) { const current = await loadExecution(id) || { id }; const next = { ...current, status, result, error, finishedAt: new Date().toISOString(), updatedAt: new Date().toISOString() }; await ensureRoot(); await fs.writeFile(fileFor(id), JSON.stringify(next, null, 2), 'utf8'); if (status === 'completed') metrics.completed++; else metrics.failed++; return next; }
export async function resumeExecution(id) { const state = await loadExecution(id); if (!state) throw new Error('Execution checkpoint tidak ditemukan'); const checkpoint = state.checkpoints?.filter(item => item?.type !== 'started').at(-1) || state.checkpoints?.[0]; if (!checkpoint) throw new Error('Execution tidak memiliki checkpoint'); metrics.resumed++; return { ...state, checkpoint }; }
export async function withExecutionLock(key, fn) {
  const previous = locks.get(key) || Promise.resolve();
  let release;
  const current = new Promise(resolve => { release = resolve; });
  const queued = previous.then(() => current);
  locks.set(key, queued);
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (locks.get(key) === queued) locks.delete(key);
  }
}
export async function withTimeout(promise, timeoutMs = DEFAULT_TIMEOUT_MS, label = 'operation') {
  const ms = Math.max(100, Number(timeoutMs) || DEFAULT_TIMEOUT_MS);
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          metrics.timeouts++;
          reject(new Error(`${label} timeout setelah ${ms}ms`));
        }, ms);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}
export function getReliabilityMetrics() { return { ...metrics, activeLocks: locks.size, checkpointDirectory: ROOT }; }
export function getReliabilityLimits() { return { maxAgentTurns: Number(process.env.AI_MAX_AGENT_TURNS || 24), operationTimeoutMs: Number(process.env.AI_OPERATION_TIMEOUT_MS || DEFAULT_TIMEOUT_MS), maxConcurrentSessions: 1 }; }
