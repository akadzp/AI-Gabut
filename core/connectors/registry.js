import { ConnectorError, CONNECTOR_ERRORS } from "./errors.js";
import { normalizeConnectorDefinition, normalizeId } from "./contracts.js";

export function createConnectorRegistry() {
  const entries = new Map();
  let sealed = false;

  function register(definition, adapter) {
    if (sealed) throw new ConnectorError(CONNECTOR_ERRORS.OPERATION, "Connector registry sudah sealed");
    const normalized = normalizeConnectorDefinition(definition);
    if (!adapter || typeof adapter.execute !== "function") {
      throw new ConnectorError(CONNECTOR_ERRORS.VALIDATION, `Adapter execute wajib tersedia: ${normalized.id}`);
    }
    if (entries.has(normalized.id)) throw new ConnectorError(CONNECTOR_ERRORS.OPERATION, `Connector sudah terdaftar: ${normalized.id}`);
    entries.set(normalized.id, Object.freeze({ definition: normalized, adapter }));
    return api;
  }

  function get(id) {
    const key = normalizeId(id, "Connector ID");
    return entries.get(key) || null;
  }

  function resolve(id) {
    const entry = get(id);
    if (!entry) throw new ConnectorError(CONNECTOR_ERRORS.NOT_FOUND, `Connector tidak ditemukan: ${id}`);
    return entry;
  }

  function list() {
    return [...entries.values()].map(({ definition }) => ({ ...definition }));
  }

  function seal() { sealed = true; return api; }

  const api = Object.freeze({ register, get, resolve, list, seal, get sealed() { return sealed; } });
  return api;
}
