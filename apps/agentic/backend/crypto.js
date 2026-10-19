import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const PREFIX = "agsec:v1:";
function encryptionKey() {
  const configured = process.env.AGENTIC_ENCRYPTION_KEY || process.env.AGENTIC_SECRET_KEY;
  if (!configured && process.env.NODE_ENV === "production") {
    const error = new Error("AGENTIC_ENCRYPTION_KEY wajib dikonfigurasi pada production");
    error.code = "CREDENTIAL_ENCRYPTION_KEY_REQUIRED";
    throw error;
  }
  // The fallback is explicitly development-only; production refuses to start encryption without a secret.
  return createHash("sha256").update(configured || "agentic-v4-local-development-only-key-change-before-deployment").digest();
}

export function encryptSecret(value) {
  if (typeof value !== "string" || !value.length) throw new TypeError("Secret harus berupa string non-kosong");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("base64url")}:${tag.toString("base64url")}:${ciphertext.toString("base64url")}`;
}

export function decryptSecret(value) {
  if (typeof value !== "string" || !value.startsWith(PREFIX)) {
    const error = new Error("Credential terenkripsi tidak valid");
    error.code = "CREDENTIAL_CIPHERTEXT_INVALID";
    throw error;
  }
  const [ivText, tagText, cipherText, extra] = value.slice(PREFIX.length).split(":");
  if (!ivText || !tagText || cipherText === undefined || extra !== undefined) {
    const error = new Error("Format credential terenkripsi tidak valid");
    error.code = "CREDENTIAL_CIPHERTEXT_INVALID";
    throw error;
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(ivText, "base64url"));
    decipher.setAuthTag(Buffer.from(tagText, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(cipherText, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    const error = new Error("Credential tidak dapat didekripsi; periksa kunci enkripsi");
    error.code = "CREDENTIAL_DECRYPTION_FAILED";
    throw error;
  }
}
