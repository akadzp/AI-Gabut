import { spawn } from "node:child_process";
import { classifyCommand } from "../../80-security/policies/terminal-command.js";
import { resolveWorkspacePath } from "./workspace.js";

const TIMEOUT_MS = Number(process.env.TERMINAL_TIMEOUT_MS || 10000);
const MAX_OUTPUT = Number(process.env.TERMINAL_MAX_OUTPUT || 20000);

function sanitizeEnv() {
  const blocked = /KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH/i;
  return Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !blocked.test(key))
  );
}

export async function executeTerminal({ command, cwd = "." }) {
  const policy = classifyCommand(command);

  if (!policy.allowed) {
    const error = new Error(policy.reason);
    error.code = policy.risky ? "RISKY_COMMAND" : "COMMAND_NOT_ALLOWED";
    throw error;
  }

  const workingDirectory = resolveWorkspacePath(cwd);

  return new Promise((resolve, reject) => {
    const shell = process.platform === "win32" ? "cmd.exe" : "/bin/sh";
    const args = process.platform === "win32"
      ? ["/d", "/s", "/c", command]
      : ["-c", command];

    const child = spawn(shell, args, {
      cwd: workingDirectory,
      env: sanitizeEnv(),
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let outputLimitReached = false;

    const append = (current, chunk) => {
      const value = chunk.toString();
      const remaining = MAX_OUTPUT - current.length;

      if (remaining <= 0) {
        outputLimitReached = true;
        return current;
      }

      if (value.length > remaining) {
        outputLimitReached = true;
        return current + value.slice(0, remaining);
      }

      return current + value;
    };

    child.stdout.on("data", chunk => {
      stdout = append(stdout, chunk);
      if (outputLimitReached) child.kill();
    });

    child.stderr.on("data", chunk => {
      stderr = append(stderr, chunk);
      if (outputLimitReached) child.kill();
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, TIMEOUT_MS);

    child.on("error", error => {
      clearTimeout(timer);
      reject(error);
    });

    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        command,
        cwd: workingDirectory,
        code,
        signal,
        timedOut,
        outputLimitReached,
        stdout,
        stderr
      });
    });
  });
}
