export function createDiagnostics({ logger = console } = {}) {
  const entries = [];
  return Object.freeze({
    record({ level = "info", component = "runtime", message, metadata = {} } = {}) {
      const entry = Object.freeze({ timestamp: new Date().toISOString(), level, component, message, metadata: Object.freeze({ ...metadata }) });
      entries.push(entry);
      const method = typeof logger[level] === "function" ? logger[level] : logger.log;
      method.call(logger, `[${component}] ${message}`, metadata);
      return entry;
    },
    list() { return entries.slice(); },
    clear() { entries.length = 0; }
  });
}
