export const createId = prefix => `${String(prefix || "id")}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

export function assertId(value, label = "id") {
  if (typeof value !== "string" || !value.trim() || value.length > 240 || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
    const error = new TypeError(`${label} tidak valid`);
    error.code = "INVALID_ID";
    throw error;
  }
  return value;
}
