import { spawn } from "node:child_process";
import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const TERMINAL = new Set(["completed", "failed", "cancelled", "stopped"]);
const MAX_ATTEMPTS = 3;
const MAX_OUTPUT = 250_000;

function commandSpec(input) {
  if (Array.isArray(input)) {
    if (!input.length) throw new AgenticError("INVALID_VERIFICATION_COMMAND", "Verification command wajib diisi");
    return { executable: String(input[0]), args: input.slice(1).map(String) };
  }
  if (input && typeof input === "object" && input.executable) {
    return { executable: String(input.executable), args: Array.isArray(input.args) ? input.args.map(String) : [] };
  }
  throw new AgenticError("INVALID_VERIFICATION_COMMAND", "Verification command harus berupa array atau executable + args");
}

function extractFailures(stdout, stderr) {
  const lines = `${stderr || ""}\n${stdout || ""}`.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const matches = lines.filter(line => /\b(error|failed|failure|failing|exception|assert(?:ion)?error)\b/i.test(line));
  return [...new Set(matches)].slice(0, 20);
}

function normalize(result) {
  if (result.timedOut) return "timed_out";
  if (result.error?.code === "ENOENT") return "failed";
  return result.exitCode === 0 && !result.signal ? "passed" : "failed";
}

function boundedAppend(state, chunk, field) {
  const text = String(chunk);
  const room = Math.max(0, state.limit - Buffer.byteLength(state[field], "utf8"));
  if (!room) { state.truncated = true; return; }
  const bytes = Buffer.from(text, "utf8");
  state[field] += bytes.length <= room ? text : bytes.subarray(0, room).toString("utf8");
  if (bytes.length > room) state.truncated = true;
}

export function createVerificationService({ store, work, cwdResolver = null, runner = null } = {}) {
  if (!store?.putVerification || !store?.getVerification || !store?.listVerifications || !work?.raw || !work?.attachReference ) {
    throw new TypeError("Verification membutuhkan store dan work verification contract");
  }

  async function runCommand(spec, options = {}) {
    if (runner) return runner(spec, options);
    const timeoutMs = Math.max(100, Math.min(Number(options.timeoutMs) || 120000, 900000));
    const limit = Math.max(1024, Math.min(Number(options.maxOutputBytes) || MAX_OUTPUT, MAX_OUTPUT));
    const cwd = options.cwd;
    if (!cwd) throw new AgenticError("VERIFICATION_CWD_REQUIRED", "Verification membutuhkan execution directory lokal yang eksplisit");
    return new Promise(resolve => {
      const state = { stdout: "", stderr: "", truncated: false, limit };
      let settled = false;
      const child = spawn(spec.executable, spec.args, { cwd, shell: false, windowsHide: true, env: options.env ? { ...process.env, ...options.env } : process.env });
      const timer = setTimeout(() => {
        if (settled) return;
        state.timedOut = true;
        child.kill("SIGTERM");
        setTimeout(() => { if (!settled) child.kill("SIGKILL"); }, 1000).unref();
      }, timeoutMs);
      const finish = result => { if (settled) return; settled = true; clearTimeout(timer); resolve({ ...result, stdout: state.stdout, stderr: state.stderr, outputTruncated: state.truncated }); };
      child.stdout?.on("data", chunk => boundedAppend(state, chunk, "stdout"));
      child.stderr?.on("data", chunk => boundedAppend(state, chunk, "stderr"));
      child.on("error", error => finish({ exitCode: null, signal: null, error: { code: error.code, message: error.message } }));
      child.on("close", (exitCode, signal) => finish({ exitCode, signal, timedOut: Boolean(state.timedOut) }));
    });
  }

  async function resolveCwd(ownerId, current, options) {
    if (options.cwd) return String(options.cwd);
    if (cwdResolver) return cwdResolver(ownerId, current);
    return null;
  }

  async function verify(ownerId, workId, options = {}) {
    const current = await work.raw(ownerId, workId);
    if (!["completed", "failed"].includes(current.state)) {
      throw new AgenticError("WORK_NOT_VERIFIABLE", "Verification hanya dapat dijalankan setelah Work selesai atau gagal", 409);
    }
    const configured = options.command || current.context?.verification?.command || ["npm", "test"];
    const spec = commandSpec(configured);
    const attempts = Math.max(1, Math.min(Number(options.maxAttempts || options.retry?.maxAttempts || 1), MAX_ATTEMPTS));
    const retryOn = Array.isArray(options.retryOn || options.retry?.on) ? (options.retryOn || options.retry.on).map(String) : ["failed", "timed_out"];
    const cwd = await resolveCwd(ownerId, current, options);
    if (!cwd) throw new AgenticError("VERIFICATION_CWD_REQUIRED", "Verification membutuhkan execution directory lokal yang eksplisit");
    const startedAt = new Date().toISOString();
    const history = [];
    for (let attempt = 1; attempt <= attempts; attempt++) {
      const raw = await runCommand(spec, { cwd, timeoutMs: options.timeoutMs, maxOutputBytes: options.maxOutputBytes, env: options.env });
      const status = normalize(raw);
      const result = {
        id: createId("verification"), workId, ownerId, status, attempt, command: spec, cwd,
        exitCode: raw.exitCode ?? null, signal: raw.signal || null, timedOut: Boolean(raw.timedOut),
        stdout: raw.stdout || "", stderr: raw.stderr || "", outputTruncated: Boolean(raw.outputTruncated),
        failures: extractFailures(raw.stdout, raw.stderr), startedAt, finishedAt: new Date().toISOString(),
        resourceLimit: { timeoutMs: Math.max(100, Math.min(Number(options.timeoutMs) || 120000, 900000)), maxOutputBytes: Math.max(1024, Math.min(Number(options.maxOutputBytes) || MAX_OUTPUT, MAX_OUTPUT)) }
      };
      history.push(result);
      await store.putVerification(ownerId, result, { overwrite: false });
      if (status === "passed" || !retryOn.includes(status) || attempt === attempts) {
        const summary = { verificationId: result.id, status, attempts: history.length, command: spec, failures: result.failures, evidence: { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode, signal: result.signal, timedOut: result.timedOut, outputTruncated: result.outputTruncated }, finishedAt: result.finishedAt };
        await work.attachReference(ownerId, workId, "evidence", result.id);
        const latest = await work.raw(ownerId, workId);
        const updated = { ...latest, result: { ...(latest.result && typeof latest.result === "object" ? latest.result : {}), verification: summary }, evidenceIds: [...new Set([...(latest.evidenceIds || []), result.id])], updatedAt: new Date().toISOString() };
        await store.putWork(ownerId, updated, { overwrite: true, expectedVersion: latest._storage?.version });
        return { verification: result, history, work: await work.get(ownerId, workId) };
      }
    }
    throw new AgenticError("VERIFICATION_FAILED", "Verification tidak menghasilkan result", 500);
  }

  async function get(ownerId, id) {
    const result = await store.getVerification(ownerId, id);
    if (!result) throw new AgenticError("VERIFICATION_NOT_FOUND", "Verification tidak ditemukan", 404);
    return result;
  }
  async function list(ownerId, workId = null) {
    const results = await store.listVerifications(ownerId);
    return results.filter(item => !workId || item.workId === workId).sort((a,b) => String(b.finishedAt).localeCompare(String(a.finishedAt)));
  }

  return Object.freeze({ verify, get, list });
}
