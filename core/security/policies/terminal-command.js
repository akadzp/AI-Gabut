const SAFE_COMMANDS = new Set([
  "pwd", "ls", "find", "cat", "head", "tail", "wc", "grep",
  "git", "node", "npm"
]);

const RISKY_PATTERNS = [
  /\brm\s+-rf\b/i, /\brm\b/i, /\bmv\b/i, /\bcp\b/i,
  /\bchmod\b/i, /\bchown\b/i, /\bsudo\b/i, /\bcurl\b/i,
  /\bwget\b/i, /\bssh\b/i, /\bscp\b/i, /\bkill\b/i,
  /\bpkill\b/i, /\bshutdown\b/i, /\breboot\b/i,
  />\s*\/(?!dev\/null)/i, /\|\s*(bash|sh|zsh)\b/i, /`/, /\$\(/
];

export function classifyCommand(command) {
  const trimmed = command.trim();

  if (!trimmed) {
    return { allowed: false, risky: false, reason: "Command kosong" };
  }

  const first = trimmed.split(/\s+/)[0];
  const base = first.includes("/") ? first.split("/").pop() : first;

  if (RISKY_PATTERNS.some(pattern => pattern.test(trimmed))) {
    return {
      allowed: false,
      risky: true,
      reason: "Command berpotensi mengubah/menghapus sistem atau mengakses jaringan"
    };
  }

  if (!SAFE_COMMANDS.has(base)) {
    return {
      allowed: false,
      risky: false,
      reason: `Command '${base}' belum masuk allowlist`
    };
  }

  return { allowed: true, risky: false };
}
