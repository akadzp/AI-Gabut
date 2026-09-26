import { createHash } from "node:crypto";
import { MediaError, MEDIA_ERRORS } from "./errors.js";

export const MEDIA_TYPES = Object.freeze(["image", "audio", "video", "document", "binary"]);
export const MEDIA_OPERATIONS = Object.freeze(["inspect", "transform", "transcode", "extract"]);
export const MEDIA_STATES = Object.freeze(["registered", "enabled", "disabled", "error"]);

const SAFE_ID = /^[a-zA-Z0-9._-]+$/;

export function normalizeId(value, label = "ID") {
  if (typeof value !== "string" || !value.trim() || !SAFE_ID.test(value.trim())) {
    throw new MediaError(MEDIA_ERRORS.VALIDATION, `${label} tidak valid`);
  }
  return value.trim();
}

export function normalizeMediaType(value) {
  const type = String(value || "").trim().toLowerCase();
  if (!MEDIA_TYPES.includes(type)) {
    throw new MediaError(MEDIA_ERRORS.UNSUPPORTED, `Media type tidak didukung: ${value}`);
  }
  return type;
}

export function normalizeMediaDescriptor(input = {}) {
  const id = input.id ? normalizeId(input.id, "Media ID") : null;
  const mimeType = String(input.mimeType || "").trim().toLowerCase();
  if (!mimeType || !mimeType.includes("/")) {
    throw new MediaError(MEDIA_ERRORS.VALIDATION, "mimeType wajib valid");
  }

  const mediaType = normalizeMediaType(input.mediaType);
  const size = input.size == null ? null : Number(input.size);
  if (size != null && (!Number.isSafeInteger(size) || size < 0)) {
    throw new MediaError(MEDIA_ERRORS.VALIDATION, "size media tidak valid");
  }

  const descriptor = {
    id,
    mediaType,
    mimeType,
    size,
    name: input.name == null ? null : String(input.name).slice(0, 255),
    source: input.source == null ? null : String(input.source).slice(0, 2048),
    checksum: input.checksum == null ? null : String(input.checksum).slice(0, 128),
    metadata: input.metadata && typeof input.metadata === "object" ? { ...input.metadata } : {}
  };

  return Object.freeze(descriptor);
}

export function normalizeMediaOperation(operation = {}) {
  const processorId = normalizeId(operation.processorId, "Processor ID");
  const name = String(operation.name || "").trim();
  if (!name) {
    throw new MediaError(MEDIA_ERRORS.VALIDATION, "Operation name wajib diisi");
  }

  const type = String(operation.type || "inspect").trim().toLowerCase();
  if (!MEDIA_OPERATIONS.includes(type)) {
    throw new MediaError(MEDIA_ERRORS.UNSUPPORTED, `Media operation tidak didukung: ${type}`);
  }

  return {
    processorId,
    name,
    type,
    input: operation.input && typeof operation.input === "object" ? operation.input : {},
    output: operation.output && typeof operation.output === "object" ? operation.output : {},
    metadata: operation.metadata && typeof operation.metadata === "object" ? operation.metadata : {}
  };
}

export function hashMediaBytes(bytes) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new MediaError(MEDIA_ERRORS.VALIDATION, "Media bytes harus Buffer atau Uint8Array");
  }
  return createHash("sha256").update(bytes).digest("hex");
}
