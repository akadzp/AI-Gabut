import path from "node:path";
import { createRecordStore } from "./record/index.js";
import { createObjectStore } from "./object/index.js";
export { StorageError, STORAGE_ERRORS } from "./errors.js";
export { createRecordStore } from "./record/index.js";
export { createObjectStore } from "./object/index.js";

export const DEFAULT_STORAGE_ROOT = path.resolve(process.env.AI_STORAGE_DIR || path.join(process.cwd(), "data", "storage"));

export function createStorage({ root = DEFAULT_STORAGE_ROOT } = {}) {
  return Object.freeze({
    root: path.resolve(root),
    records: namespace => createRecordStore({ root, namespace }),
    objects: namespace => createObjectStore({ root, namespace })
  });
}
