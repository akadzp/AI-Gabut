import { createStorage } from "../index.js";
import { StorageError, STORAGE_ERRORS } from "../errors.js";

const DEFAULT_SCOPES = Object.freeze(["sessions", "memories", "executions", "runtime"]);
const SAFE_SCOPE = /^[a-zA-Z0-9._-]+$/;

function assertNamespace(namespace) {
  if (typeof namespace !== "string" || !namespace || !SAFE_SCOPE.test(namespace)) {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Invalid state namespace");
  }
  return namespace;
}

function assertScope(scope) {
  if (typeof scope !== "string" || !scope || !SAFE_SCOPE.test(scope)) {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "Invalid state scope");
  }
  return scope;
}

function assertStateKey(key) {
  if (typeof key !== "string" || !key.trim()) {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "State key is required");
  }
  return key;
}

export function createStateService({ storage = createStorage(), namespace = "state", scopes = DEFAULT_SCOPES } = {}) {
  if (!storage || typeof storage.records !== "function") {
    throw new StorageError(STORAGE_ERRORS.VALIDATION_ERROR, "A storage service is required");
  }

  const safeNamespace = assertNamespace(namespace);
  const configuredScopes = [...new Set(scopes)].map(assertScope);
  const stores = new Map(configuredScopes.map(scope => [scope, storage.records(`${safeNamespace}-${scope}`)]));

  function store(scope) {
    assertScope(scope);
    const result = stores.get(scope);
    if (!result) throw new StorageError(STORAGE_ERRORS.NOT_FOUND, `State scope not configured: ${scope}`);
    return result;
  }

  async function get(scope, key) {
    return store(scope).get(assertStateKey(key));
  }

  async function put(scope, key, value, options = {}) {
    return store(scope).put(assertStateKey(key), value, options);
  }

  async function update(scope, key, value, options = {}) {
    return store(scope).update(assertStateKey(key), value, options);
  }

  async function remove(scope, key, options = {}) {
    return store(scope).delete(assertStateKey(key), options);
  }

  async function exists(scope, key) {
    return store(scope).exists(assertStateKey(key));
  }

  async function list(scope) {
    return store(scope).list();
  }

  function hasScope(scope) {
    return typeof scope === "string" && stores.has(scope);
  }

  function listScopes() {
    return [...stores.keys()];
  }

  return Object.freeze({
    get,
    put,
    update,
    delete: remove,
    exists,
    list,
    hasScope,
    listScopes,
    sessions: () => store("sessions"),
    memories: () => store("memories"),
    executions: () => store("executions"),
    runtime: () => store("runtime")
  });
}
