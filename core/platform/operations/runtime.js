import { OperationsError, OPERATIONS_ERRORS } from "./errors.js";

const DEFAULT_SHUTDOWN_TIMEOUT_MS = 30_000;

export function createOperationsRuntime({
  lifecycle,
  health,
  diagnostics,
  identity,
  configuration = {},
  processRef = process,
  now = () => new Date().toISOString()
} = {}) {
  if (!lifecycle || typeof lifecycle.state !== "string") {
    throw new OperationsError(OPERATIONS_ERRORS.VALIDATION, "Lifecycle wajib tersedia");
  }
  if (!health || typeof health.status !== "function") {
    throw new OperationsError(OPERATIONS_ERRORS.VALIDATION, "Health service wajib tersedia");
  }

  let shuttingDown = false;
  let shutdownPromise = null;

  function snapshot() {
    const healthState = health.status();
    return Object.freeze({
      identity: identity?.id ?? null,
      version: identity?.version ?? null,
      environment: configuration.environment ?? null,
      lifecycle: lifecycle.state,
      health: healthState,
      pid: processRef.pid,
      uptimeSeconds: Number(processRef.uptime?.().toFixed?.(3) ?? 0),
      timestamp: now()
    });
  }

  function readiness() {
    const state = snapshot();
    return Object.freeze({
      ready: state.health.status === "ready" && !shuttingDown,
      state: state.lifecycle,
      health: state.health.status,
      shuttingDown,
      timestamp: state.timestamp
    });
  }

  async function shutdown(stop = async () => {}, { timeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS } = {}) {
    if (shutdownPromise) return shutdownPromise;

    shuttingDown = true;
    diagnostics?.record?.({
      component: "operations",
      message: "Shutdown requested",
      metadata: { timeoutMs }
    });

    const timeout = Math.max(100, Number(timeoutMs) || DEFAULT_SHUTDOWN_TIMEOUT_MS);

    shutdownPromise = Promise.race([
      Promise.resolve().then(stop),
      new Promise((_, reject) => {
        setTimeout(() => reject(
          new OperationsError(
            OPERATIONS_ERRORS.SHUTDOWN,
            `Shutdown timeout setelah ${timeout}ms`
          )
        ), timeout);
      })
    ]).then(
      result => {
        diagnostics?.record?.({
          component: "operations",
          message: "Shutdown completed"
        });
        return result;
      },
      error => {
        diagnostics?.record?.({
          component: "operations",
          message: "Shutdown failed",
          metadata: { error: error instanceof Error ? error.message : String(error) }
        });
        throw error;
      }
    );

    return shutdownPromise;
  }

  return Object.freeze({
    snapshot,
    readiness,
    shutdown,
    get shuttingDown() { return shuttingDown; }
  });
}
