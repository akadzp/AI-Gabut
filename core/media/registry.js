import { MediaError, MEDIA_ERRORS } from "./errors.js";
import { normalizeId, normalizeMediaType } from "./contracts.js";

export function createMediaRegistry() {
  const entries = new Map();
  let sealed = false;

  function register(definition = {}, processor) {
    if (sealed) {
      throw new MediaError(MEDIA_ERRORS.PROCESSING, "Media registry sudah sealed");
    }

    const id = normalizeId(definition.id, "Processor ID");
    if (!processor || typeof processor.execute !== "function") {
      throw new MediaError(MEDIA_ERRORS.VALIDATION, `Processor execute wajib tersedia: ${id}`);
    }

    const mediaTypes = [...new Set(definition.mediaTypes || [])].map(normalizeMediaType);
    const operations = [...new Set(definition.operations || ["inspect"])].filter(Boolean);
    if (!mediaTypes.length) {
      throw new MediaError(MEDIA_ERRORS.VALIDATION, `Processor ${id} harus memiliki mediaTypes`);
    }
    if (!operations.length) {
      throw new MediaError(MEDIA_ERRORS.VALIDATION, `Processor ${id} harus memiliki operations`);
    }

    if (entries.has(id)) {
      throw new MediaError(MEDIA_ERRORS.PROCESSING, `Processor sudah terdaftar: ${id}`);
    }

    const normalized = Object.freeze({
      id,
      name: String(definition.name || id).trim().slice(0, 200),
      version: String(definition.version || "1"),
      mediaTypes,
      operations,
      metadata: definition.metadata && typeof definition.metadata === "object"
        ? { ...definition.metadata }
        : {}
    });

    entries.set(id, Object.freeze({ definition: normalized, processor }));
    return api;
  }

  function get(id) {
    const key = normalizeId(id, "Processor ID");
    return entries.get(key) || null;
  }

  function resolve(id) {
    const entry = get(id);
    if (!entry) {
      throw new MediaError(MEDIA_ERRORS.NOT_FOUND, `Processor tidak ditemukan: ${id}`);
    }
    return entry;
  }

  function list() {
    return [...entries.values()].map(({ definition }) => ({ ...definition }));
  }

  function seal() {
    sealed = true;
    return api;
  }

  const api = Object.freeze({
    register,
    get,
    resolve,
    list,
    seal,
    get sealed() { return sealed; }
  });

  return api;
}
