export function createLogger({ sink = console, component = "ai-gabut" } = {}) {
  const write = (level, message, metadata = {}) => {
    const entry = Object.freeze({ timestamp: new Date().toISOString(), level, component, message, metadata: Object.freeze({ ...metadata }) });
    const method = typeof sink[level] === "function" ? sink[level] : sink.log;
    method.call(sink, JSON.stringify(entry));
    return entry;
  };
  return Object.freeze({
    debug: (message, metadata) => write("debug", message, metadata),
    info: (message, metadata) => write("info", message, metadata),
    warn: (message, metadata) => write("warn", message, metadata),
    error: (message, metadata) => write("error", message, metadata)
  });
}
