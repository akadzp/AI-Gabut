import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { WORKSPACE_ROOT } from "../terminal/workspace.js";

const execFileAsync = promisify(execFile);

async function git(args, options = {}) {
  try {
    const { stdout, stderr } = await execFileAsync("git", args, {
      cwd: WORKSPACE_ROOT,
      timeout: options.timeout ?? 15_000,
      maxBuffer: options.maxBuffer ?? 2 * 1024 * 1024,
      env: { ...process.env, GIT_PAGER: "cat", PAGER: "cat" }
    });
    return { ok: true, stdout: stdout ?? "", stderr: stderr ?? "" };
  } catch (error) {
    return {
      ok: false,
      error: error?.message || "Git command failed",
      stdout: error?.stdout ?? "",
      stderr: error?.stderr ?? ""
    };
  }
}

export async function gitStatus() {
  return git(["status", "--short", "--branch"]);
}

export async function gitDiff({ staged = false } = {}) {
  return git(staged ? ["diff", "--cached", "--"] : ["diff", "--"]);
}

export async function gitChanges() {
  const status = await git(["status", "--short", "--branch"]);
  if (!status.ok) return status;

  const [unstaged, staged] = await Promise.all([
    gitDiff({ staged: false }),
    gitDiff({ staged: true })
  ]);

  const lines = status.stdout.split("\n").filter(Boolean);
  const branch = lines.find(line => line.startsWith("##"))?.replace(/^##\s*/, "") || "unknown";
  const files = { staged: [], unstaged: [], untracked: [], deleted: [] };

  for (const line of lines.filter(line => !line.startsWith("##"))) {
    const code = line.slice(0, 2);
    const file = line.slice(3).trim();
    if (!file) continue;
    if (code === "??") files.untracked.push(file);
    if (code[0] !== " " && code[0] !== "?") files.staged.push(file);
    if (code[1] !== " " && code[1] !== "?") files.unstaged.push(file);
    if (code.includes("D")) files.deleted.push(file);
  }

  return {
    ok: true,
    branch,
    status: status.stdout,
    stagedDiff: staged.stdout,
    unstagedDiff: unstaged.stdout,
    files
  };
}

export async function gitLog({ limit = 10 } = {}) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 10, 50));
  return git(["log", `-${safeLimit}`, "--date=short", "--pretty=format:%h|%ad|%an|%s"]);
}

export async function gitAdd({ paths = [] } = {}) {
  if (!Array.isArray(paths) || paths.length === 0) {
    return { ok: false, error: "paths harus berupa array dan tidak boleh kosong" };
  }
  for (const path of paths) {
    if (typeof path !== "string" || !path.trim() || path.startsWith("/") || path.includes("\\")) {
      return { ok: false, error: `Path Git tidak valid: ${path}` };
    }
    if (path.split("/").filter(Boolean).includes("..")) {
      return { ok: false, error: `Path traversal tidak diizinkan: ${path}` };
    }
  }
  return git(["add", "--", ...paths]);
}

export async function gitCommit({ message } = {}) {
  if (typeof message !== "string" || !message.trim()) {
    return { ok: false, error: "Commit message wajib diisi" };
  }
  return git(["commit", "-m", message.trim()]);
}

export async function gitPush({ remote = "origin", branch = "" } = {}) {
  const args = ["push", remote];
  if (branch) args.push(branch);
  return git(args);
}

export async function gitUnstagedAndStagedDiff() {
  const [unstaged, staged] = await Promise.all([
    gitDiff({ staged: false }),
    gitDiff({ staged: true })
  ]);
  return { unstaged, staged };
}
