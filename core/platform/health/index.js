export function createHealth({ lifecycle, dependencies } = {}) {
  return Object.freeze({
    status() {
      const state = lifecycle?.state ?? "unknown";
      return {
        status: state === "ready" ? "ready" : state === "failed" ? "failed" : "not-ready",
        state,
        dependencies: dependencies?.names?.() ?? []
      };
    }
  });
}
