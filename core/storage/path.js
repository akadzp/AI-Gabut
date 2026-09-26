import path from "node:path";
import { StorageError, STORAGE_ERRORS } from "./errors.js";

const SAFE_SEGMENT = /^[a-zA-Z0-9._-]+$/;

export function assertStorageSegment(value, name = "segment") {
  if (typeof value !== "string" || !value || !SAFE_SEGMENT.test(value)) {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, `Invalid storage ${name}`);
  }
  return value;
}

export function normalizeStorageKey(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Storage key is required");
  }
  const normalized = value.replaceAll("\\", "/");
  if (normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Absolute storage key is not allowed");
  }
  const parts = normalized.split("/");
  if (parts.some(part => !part || part === "." || part === ".." || !SAFE_SEGMENT.test(part))) {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Unsafe storage key");
  }
  return parts.join("/");
}

export function resolveStoragePath(root, namespace, key, extension = ".json") {
  assertStorageSegment(namespace, "namespace");
  const safeKey = normalizeStorageKey(key);
  const target = path.resolve(root, namespace, `${safeKey}${extension}`);
  const base = path.resolve(root, namespace) + path.sep;
  if (!target.startsWith(base)) throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Storage path escapes namespace");
  return target;
}
