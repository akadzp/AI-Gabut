import { ConnectorError, CONNECTOR_ERRORS } from "./errors.js";
import { normalizeOperation } from "./contracts.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRIES = 2;

export function createConnectorRuntime({ registry, timeoutMs = DEFAULT_TIMEOUT_MS, retries = DEFAULT_RETRIES, onEvent = null } = {}) {
  if (!registry || typeof registry.resolve !== "function") {
    throw new ConnectorError(CONNECTOR_ERRORS.VALIDATION, "Connector registry wajib tersedia");
  }

  async function emit(event) {
    if (typeof onEvent === "function") await onEvent({ at: new Date().toISOString(), ...event });
  }

  async function execute(operation = {}) {
    const normalized = normalizeOperation(operation);
    const entry = registry.resolve(normalized.connectorId);
    if (entry.definition.operations.includes(normalized.type) === false) {
      throw new ConnectorError(CONNECTOR_ERRORS.OPERATION, `Operation '${normalized.type}' tidak didukung connector ${normalized.connectorId}`);
    }

    const enabled = entry.definition.metadata.enabled !== false;
    if (!enabled) throw new ConnectorError(CONNECTOR_ERRORS.DISABLED, `Connector disabled: ${normalized.connectorId}`);

    const attempts = Math.max(1, Number(retries) + 1);
    const timeout = Math.max(100, Number(timeoutMs) || DEFAULT_TIMEOUT_MS);
    let lastError = null;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      await emit({ connectorId: normalized.connectorId, operation: normalized.name, type: normalized.type, action: "start", attempt });
      try {
        const result = await Promise.race([
          entry.adapter.execute({ ...normalized, attempt }),
          new Promise((_, reject) => setTimeout(() => reject(new ConnectorError(CONNECTOR_ERRORS.TIMEOUT, `Connector timeout setelah ${timeout}ms`)), timeout))
        ]);
        await emit({ connectorId: normalized.connectorId, operation: normalized.name, type: normalized.type, action: "completed", attempt });
        return { ok: true, connectorId: normalized.connectorId, operation: normalized.name, attempt, result };
      } catch (error) {
        lastError = error;
        await emit({ connectorId: normalized.connectorId, operation: normalized.name, type: normalized.type, action: "failed", attempt, error: error instanceof Error ? error.message : String(error) });
        if (attempt < attempts) await new Promise(resolve => setTimeout(resolve, Math.min(1000 * 2 ** (attempt - 1), 5000)));
      }
    }

    if (lastError instanceof ConnectorError) throw lastError;
    throw new ConnectorError(CONNECTOR_ERRORS.TRANSPORT, "Connector execution gagal", { cause: lastError?.message });
  }

  return Object.freeze({ execute });
}
