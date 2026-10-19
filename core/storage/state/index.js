const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const absentExpectedVersion = value => value === undefined || value === null || value === false;

function stateError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

/**
 * Adapts records(namespace) or read/write/remove/list storage into scoped state.
 * If the backing storage exposes atomicUpdate, optimistic writes are serialized
 * across processes sharing that backend, not merely within this service instance.
 */
export function createStateService({ storage, namespace = "default", scopes = [] } = {}) {
  if (!storage || (typeof storage.records !== "function" && ![
    "read", "write", "remove", "list"
  ].every(method => typeof storage[method] === "function"))) {
    throw new TypeError("State service membutuhkan storage.records() atau read/write/remove/list");
  }

  const allowedScopes = new Set(scopes.map(String));
  const adapters = new Map();
  const locks = new Map();

  function assertScope(scope) {
    const value = String(scope ?? "");
    if (!value || (allowedScopes.size && !allowedScopes.has(value))) {
      throw stateError("STATE_SCOPE_INVALID", `State scope tidak diizinkan: ${value.slice(0, 100)}`);
    }
    return value;
  }

  function backend(scope) {
    if (adapters.has(scope)) return adapters.get(scope);
    let result;
    if (typeof storage.records === "function") {
      const records = storage.records(`${namespace}:${scope}`);
      if (!records || typeof records.get !== "function" || typeof records.put !== "function" || typeof records.delete !== "function" || typeof records.list !== "function") {
        throw new TypeError(`Storage records contract tidak lengkap untuk scope ${scope}`);
      }
      result = { kind: "records", records };
    } else {
      const prefix = `${namespace}/${scope}/`;
      result = {
        kind: "key-value",
        key: id => `${prefix}${encodeURIComponent(String(id))}`,
        prefix
      };
    }
    adapters.set(scope, result);
    return result;
  }

  async function withLock(key, operation) {
    const previous = locks.get(key) || Promise.resolve();
    let release;
    const current = new Promise(resolve => { release = resolve; });
    locks.set(key, current);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (locks.get(key) === current) locks.delete(key);
    }
  }

  async function get(scope, id) {
    const s = assertScope(scope);
    if (id === undefined || id === null || String(id) === "") return null;
    const b = backend(s);
    return b.kind === "records" ? (await b.records.get(String(id))) ?? null : (await storage.read(b.key(id))) ?? null;
  }

  async function mutate(scope, id, mutator) {
    const s = assertScope(scope);
    const recordId = String(id ?? "");
    if (!recordId) throw stateError("STATE_ID_INVALID", "State record ID wajib diisi");
    if (typeof mutator !== "function") throw new TypeError("State mutator must be a function");
    const b = backend(s);
    const lockKey = `${namespace}:${s}:${recordId}`;

    async function decide(currentValue) {
      const current = currentValue ?? null;
      const decision = await mutator(current);
      if (!decision || typeof decision !== "object" || Array.isArray(decision)) {
        throw stateError("STATE_MUTATION_INVALID", "State mutator harus mengembalikan decision object");
      }
      if (decision.write === false) return { write: false, result: decision.result };
      if (decision.delete === true) return { delete: true, result: decision.result };
      if (!decision.value || typeof decision.value !== "object" || Array.isArray(decision.value)) {
        throw stateError("STATE_VALUE_INVALID", "State record harus berupa object");
      }
      const next = {
        ...decision.value,
        _storage: {
          ...(decision.value._storage && typeof decision.value._storage === "object" ? decision.value._storage : {}),
          version: (Number(current?._storage?.version) || 0) + 1
        }
      };
      return { write: true, value: next, result: hasOwn(decision, "result") ? decision.result : next };
    }

    if (b.kind === "key-value" && typeof storage.atomicUpdate === "function") {
      return storage.atomicUpdate(b.key(recordId), current => decide(current));
    }
    if (b.kind === "records" && typeof b.records.atomicUpdate === "function") {
      return b.records.atomicUpdate(recordId, current => decide(current));
    }

    return withLock(lockKey, async () => {
      const current = b.kind === "records" ? (await b.records.get(recordId)) ?? null : (await storage.read(b.key(recordId))) ?? null;
      const outcome = await decide(current);
      if (outcome.write === false) return outcome.result;
      if (outcome.delete === true) {
        if (current === null) return outcome.result;
        if (b.kind === "records") await b.records.delete(recordId, { expectedVersion: current?._storage?.version });
        else await storage.remove(b.key(recordId));
        return outcome.result;
      }
      if (b.kind === "records") {
        const saved = await b.records.put(recordId, outcome.value, {
          overwrite: true,
          ...(current?._storage?.version == null ? {} : { expectedVersion: current._storage.version })
        });
        return hasOwn(outcome, "result") && outcome.result !== undefined ? outcome.result : (saved ?? outcome.value);
      }
      await storage.write(b.key(recordId), outcome.value);
      return hasOwn(outcome, "result") && outcome.result !== undefined ? outcome.result : outcome.value;
    });
  }

  async function put(scope, id, value, options = {}) {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw stateError("STATE_VALUE_INVALID", "State record harus berupa object");
    return mutate(scope, id, current => {
      const expected = options.expectedVersion;
      if (!absentExpectedVersion(expected) && (current?._storage?.version ?? null) !== expected) {
        throw stateError("VERSION_CONFLICT", "State record berubah sejak terakhir dibaca");
      }
      if (options.overwrite === false && current !== null) {
        throw stateError("STATE_RECORD_EXISTS", "State record sudah ada");
      }
      return { value };
    });
  }

  async function remove(scope, id, options = {}) {
    const s = assertScope(scope);
    const recordId = String(id ?? "");
    if (!recordId) return false;
    return mutate(s, recordId, current => {
      if (current === null) return { write: false, result: false };
      const expected = options.expectedVersion;
      if (!absentExpectedVersion(expected) && (current?._storage?.version ?? null) !== expected) {
        throw stateError("VERSION_CONFLICT", "State record berubah sejak terakhir dibaca");
      }
      return { delete: true, result: true };
    });
  }

  async function list(scope) {
    const s = assertScope(scope);
    const b = backend(s);
    if (b.kind === "records") return [...new Set((await b.records.list()).map(String))].sort();
    const keys = await storage.list(b.prefix);
    return keys.map(key => decodeURIComponent(key.slice(b.prefix.length))).sort();
  }

  async function exists(scope, id) {
    return (await get(scope, id)) !== null;
  }

  return Object.freeze({ get, put, delete: remove, remove, list, exists, mutate });
}
