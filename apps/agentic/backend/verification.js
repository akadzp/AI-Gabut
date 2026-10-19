import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { AgenticError } from "./errors.js";
import { createId } from "./ids.js";

const now = () => new Date().toISOString();
const OUTPUT_LIMIT = 32_000;
const ALLOWED = new Map([
  ["npm test", ["npm", ["test"]]],
  ["npm run test", ["npm", ["run", "test"]]],
  ["npm run test:agentic-artifacts", ["npm", ["run", "test:agentic-artifacts"]]],
  ["node --test", [process.execPath, ["--test"]]],
  ["git diff --check", ["git", ["diff", "--check"]]]
]);
function normalizeCommand(input) {
  if (Array.isArray(input)) return input.map(value => String(value));
  if (typeof input === "string") return input.trim().split(/\s+/).filter(Boolean);
  return ["npm", "test"];
}
function allowedCommand(input) {
  const parts = normalizeCommand(input);
  const key = parts.join(" ");
  const found = ALLOWED.get(key);
  if (!found) throw new AgenticError("VERIFICATION_COMMAND_NOT_ALLOWED", "Command verification tidak diizinkan. Gunakan npm test, npm run test:agentic-artifacts, node --test, atau git diff --check.", 403, { command: key.slice(0, 200) });
  return { display: key, executable: found[0], args: found[1] };
}
function runProcess(command, cwd, timeoutMs) {
  return new Promise(resolve => {
    const child = spawn(command.executable, command.args, { cwd, shell: false, windowsHide: true, env: { ...process.env, CI: "1", NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "", timedOut = false, settled = false;
    const append = (current, chunk) => (current + chunk.toString("utf8")).slice(-OUTPUT_LIMIT);
    const finish = result => { if (settled) return; settled = true; clearTimeout(timer); resolve(result); };
    child.stdout.on("data", chunk => { stdout = append(stdout, chunk); });
    child.stderr.on("data", chunk => { stderr = append(stderr, chunk); });
    child.on("error", error => finish({ code: null, signal: null, stdout, stderr: append(stderr, error.message), timedOut }));
    child.on("close", (code, signal) => finish({ code, signal, stdout, stderr, timedOut }));
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); setTimeout(() => child.kill("SIGKILL"), 1500).unref?.(); }, timeoutMs);
    timer.unref?.();
  });
}

export function createVerificationService({ store, work, cwdResolver = async () => null, clock = () => new Date().toISOString() } = {}) {
  if (!store?.putVerification || !store?.getVerification || !store?.listVerifications || !work?.raw) throw new TypeError("Verification service membutuhkan verification store dan work contract");
  async function verify(ownerId, workId, options = {}) {
    const linkedWork = await work.raw(ownerId, workId);
    const command = allowedCommand(options.command || options.commands || "npm test");
    const id = createId("verification");
    const startedAt = clock();
    let cwd = await cwdResolver(ownerId, linkedWork);
    if (cwd && typeof cwd === "object") cwd = cwd.cwd || cwd.rootPath || null;
    if (!cwd) {
      const verification = { id, ownerId, workId, status: "skipped", command: command.display, cwd: null, exitCode: null, stdout: "", stderr: "", failures: [], reason: "verification_cwd_not_configured", startedAt, finishedAt: clock(), durationMs: 0 };
      await store.putVerification(ownerId, verification, { overwrite: false });
      return { verification, work: await work.get(ownerId, workId) };
    }
    const resolvedCwd = path.resolve(String(cwd));
    let stat;
    try { stat = await fs.stat(resolvedCwd); }
    catch { throw new AgenticError("VERIFICATION_CWD_INVALID", "Verification working directory tidak ditemukan", 400); }
    if (!stat.isDirectory()) throw new AgenticError("VERIFICATION_CWD_INVALID", "Verification working directory bukan direktori", 400);
    const timeoutMs = Math.max(1000, Math.min(Number(options.timeoutMs) || 120000, 180000));
    const result = await runProcess(command, resolvedCwd, timeoutMs);
    const finishedAt = clock();
    const status = result.timedOut ? "timed_out" : result.code === 0 ? "passed" : "failed";
    const verification = {
      id, ownerId, workId, status, command: command.display, cwd: resolvedCwd, exitCode: result.code,
      signal: result.signal, stdout: result.stdout, stderr: result.stderr,
      failures: status === "failed" ? [result.stderr.trim() || `Command keluar dengan kode ${result.code}`].map(value => value.slice(0, 2000)) : [],
      startedAt, finishedAt, durationMs: Math.max(0, Date.parse(finishedAt) - Date.parse(startedAt)), timedOut: result.timedOut
    };
    await store.putVerification(ownerId, verification, { overwrite: false });
    return { verification, work: await work.get(ownerId, workId) };
  }
  async function get(ownerId, id) {
    const verification = await store.getVerification(ownerId, id);
    if (!verification || verification.ownerId !== ownerId) throw new AgenticError("VERIFICATION_NOT_FOUND", "Verification tidak ditemukan", 404);
    return verification;
  }
  async function list(ownerId, workId = null) {
    const items = await store.listVerifications(ownerId);
    return items.filter(item => item.ownerId === ownerId && (!workId || item.workId === workId)).sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
  }
  return Object.freeze({ verify, get, list, allowedCommands: Object.freeze([...ALLOWED.keys()]) });
}
