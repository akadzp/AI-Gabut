import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { AgenticError } from "./errors.js";

const scrypt = promisify(scryptCallback);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const digest = value => createHash("sha256").update(String(value)).digest("hex");
const publicUser = user => ({ id: user.id, email: user.email, name: user.name, createdAt: user.createdAt });

export function createAuthService({ store, clock = () => Date.now(), tokenTtlMs = 7 * 24 * 60 * 60 * 1000 } = {}) {
  if (!store?.createUser || !store?.getUser || !store?.listUsers || !store?.putAuthSession || !store?.getAuthSession) {
    throw new TypeError("Auth service membutuhkan user dan auth-session store contract");
  }
  const ttl = Math.max(60_000, Math.min(Number(tokenTtlMs) || 7 * 24 * 60 * 60 * 1000, 90 * 24 * 60 * 60 * 1000));

  async function hashPassword(password, salt = randomBytes(16).toString("hex")) {
    const key = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    return `scrypt$${salt}$${Buffer.from(key).toString("hex")}`;
  }
  async function verifyPassword(password, encoded) {
    const [scheme, salt, hash] = String(encoded || "").split("$");
    if (scheme !== "scrypt" || !salt || !/^[a-f0-9]{128}$/i.test(hash || "")) return false;
    const candidate = Buffer.from(await hashPassword(password, salt).then(value => value.split("$")[2]), "hex");
    const expected = Buffer.from(hash, "hex");
    return candidate.length === expected.length && timingSafeEqual(candidate, expected);
  }

  async function register(input = {}) {
    const email = String(input.email || "").trim().toLowerCase();
    const password = String(input.password || "");
    const name = String(input.name || input.displayName || "").trim().slice(0, 120);
    if (!emailPattern.test(email) || email.length > 254) throw new AgenticError("INVALID_EMAIL", "Alamat email tidak valid", 400);
    if (password.length < 8 || password.length > 256) throw new AgenticError("INVALID_PASSWORD", "Password harus berisi 8–256 karakter", 400);
    if (!name) throw new AgenticError("INVALID_NAME", "Nama wajib diisi", 400);
    if ((await store.listUsers()).some(user => String(user.email || "").toLowerCase() === email)) throw new AgenticError("EMAIL_ALREADY_REGISTERED", "Email sudah terdaftar", 409);
    const now = new Date(clock()).toISOString();
    const user = { id: `user-${digest(email).slice(0, 40)}`, email, name, passwordHash: await hashPassword(password), createdAt: now, updatedAt: now };
    try { await store.createUser(user); }
    catch (error) {
      if (error?.code === "STATE_RECORD_EXISTS") throw new AgenticError("EMAIL_ALREADY_REGISTERED", "Akun sudah terdaftar", 409);
      throw error;
    }
    return publicUser(user);
  }

  async function login(input = {}) {
    const email = String(input.email || "").trim().toLowerCase();
    const password = String(input.password || "");
    const user = (await store.listUsers()).find(item => String(item.email || "").toLowerCase() === email);
    if (!user || !(await verifyPassword(password, user.passwordHash))) throw new AgenticError("INVALID_CREDENTIALS", "Email atau password salah", 401);
    const token = randomBytes(32).toString("base64url");
    const now = clock();
    const session = { id: digest(token), ownerId: user.id, createdAt: new Date(now).toISOString(), expiresAt: new Date(now + ttl).toISOString(), revokedAt: null };
    await store.putAuthSession(session);
    return { token, tokenType: "Bearer", expiresAt: session.expiresAt, user: publicUser(user) };
  }

  async function authenticate(token) {
    const raw = String(token || "").trim();
    if (!raw || raw.length > 512) throw new AgenticError("AUTH_REQUIRED", "Bearer token wajib disediakan", 401);
    const session = await store.getAuthSession(digest(raw));
    if (!session || session.revokedAt || Date.parse(session.expiresAt) <= clock()) throw new AgenticError("AUTH_INVALID", "Sesi tidak valid atau sudah kedaluwarsa", 401);
    const user = await store.getUser(session.ownerId);
    if (!user) throw new AgenticError("AUTH_INVALID", "Pengguna sesi tidak ditemukan", 401);
    return { user: publicUser(user), session: { id: session.id, createdAt: session.createdAt, expiresAt: session.expiresAt } };
  }

  async function logout(token) {
    const raw = String(token || "").trim();
    if (!raw) return { loggedOut: false };
    const id = digest(raw);
    const session = await store.getAuthSession(id);
    if (!session) return { loggedOut: false };
    if (store.state?.delete) await store.state.delete("auth-sessions", id, { expectedVersion: session._storage?.version });
    else await store.putAuthSession({ ...session, revokedAt: new Date(clock()).toISOString() });
    return { loggedOut: true };
  }

  return Object.freeze({ register, login, authenticate, logout, publicUser });
}
