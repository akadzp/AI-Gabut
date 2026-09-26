import { ConnectorError, CONNECTOR_ERRORS } from "./errors.js";

export const CONNECTOR_STATES = Object.freeze(["registered", "enabled", "disabled", "error"]);
export const OPERATION_TYPES = Object.freeze(["read", "write", "sync"]);
export const AUTH_MODES = Object.freeze(["none", "token", "oauth", "custom"]);

const SAFE_ID = /^[a-zA-Z0-9._-]+$/;

export function normalizeId(value, label = "ID") {
  if (typeof value !== "string" || !value.trim() || !SAFE_ID.test(value.trim())) {
    throw new ConnectorError(CONNECTOR_ERRORS.VALIDATION, `${label} tidak valid`);
  }
  return value.trim();
}

export function normalizeConnectorDefinition(definition = {}) {
  const id = normalizeId(definition.id, "Connector ID");
  const name = String(definition.name || id).trim().slice(0, 200);
  const operations = [...new Set(definition.operations || ["read"])].filter(item => OPERATION_TYPES.includes(item));
  if (!operations.length) throw new ConnectorError(CONNECTOR_ERRORS.VALIDATION, "Connector harus memiliki operation");
  const auth = definition.auth || {};
  const authMode = AUTH_MODES.includes(auth.mode) ? auth.mode : "none";
  return {
    id,
    name,
    version: String(definition.version || "1"),
    provider: String(definition.provider || id),
    operations,
    auth: Object.freeze({ mode: authMode, required: Boolean(auth.required) }),
    metadata: definition.metadata && typeof definition.metadata === "object" ? { ...definition.metadata } : {}
  };
}

export function normalizeOperation(operation = {}) {
  const connectorId = normalizeId(operation.connectorId, "Connector ID");
  const name = String(operation.name || "").trim();
  if (!name) throw new ConnectorError(CONNECTOR_ERRORS.VALIDATION, "Operation name wajib diisi");
  const type = OPERATION_TYPES.includes(operation.type) ? operation.type : "read";
  return { connectorId, name, type, input: operation.input && typeof operation.input === "object" ? operation.input : {}, metadata: operation.metadata || {} };
}
