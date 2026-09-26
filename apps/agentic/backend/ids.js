import crypto from "node:crypto";
export function createId(prefix) { return `${prefix}-${crypto.randomUUID()}`; }
export function assertId(value, label = "id") { if (typeof value !== "string" || !value.trim() || value.length > 200) throw new TypeError(`${label} tidak valid`); return value.trim(); }
