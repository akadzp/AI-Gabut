const SECRET_KEY = /key|token|secret|password|passwd|credential|authorization|cookie|private/i;
const SECRET_VALUE = /(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|AIza[A-Za-z0-9_-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,})/g;
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i;
const SENSITIVE_FILE = /(?:^|\/)(?:\.env(?:\.[^/]+)?|id_(?:rsa|ed25519)|credentials(?:\.[^/]+)?)$/i;

export function isSensitiveKey(key) {
  return SECRET_KEY.test(String(key || ""));
}

export function containsSecret(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return PRIVATE_KEY.test(text) || SECRET_VALUE.test(text);
}

export function assertSecretSafe(value, label = "input") {
  if (containsSecret(value)) {
    throw new Error(`Secret/private key terdeteksi pada ${label}`);
  }
  return true;
}

export function redactSecrets(value, depth = 0) {
  if (depth > 5) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 30).map(item => redactSecrets(item, depth + 1));
  if (!value || typeof value !== "object") {
    return String(value ?? "").replace(PRIVATE_KEY, "[redacted-private-key]").replace(SECRET_VALUE, "[redacted-secret]").slice(0, 2000);
  }
  const output = {};
  for (const [key, item] of Object.entries(value).slice(0, 80)) {
    output[key] = isSensitiveKey(key) ? "[redacted]" : redactSecrets(item, depth + 1);
  }
  return output;
}

export function isSensitivePath(relativePath) {
  return SENSITIVE_FILE.test(String(relativePath || "").replaceAll("\\", "/"));
}

export function sanitizeEnvironment(environment = process.env) {
  const blocked = /KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE/i;
  return Object.fromEntries(Object.entries(environment).filter(([key]) => !blocked.test(key)));
}
