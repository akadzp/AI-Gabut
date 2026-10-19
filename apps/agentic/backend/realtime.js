import { createId, assertId } from "./ids.js";

const bounded = (value, max = 300) => String(value ?? "").slice(0, max);
export function createRealtimeService({ maxEvents = 2000, clock = () => new Date().toISOString() } = {}) {
  const limit = Math.max(100, Math.min(Number(maxEvents) || 2000, 10000));
  const histories = new Map();
  const listeners = new Map();
  function ownerEvents(ownerId) {
    if (!histories.has(ownerId)) histories.set(ownerId, []);
    return histories.get(ownerId);
  }
  function ownerListeners(ownerId) {
    if (!listeners.has(ownerId)) listeners.set(ownerId, new Set());
    return listeners.get(ownerId);
  }
  function matches(event, filters = {}) {
    return (!filters.executionId || event.executionId === filters.executionId) &&
      (!filters.sessionId || event.sessionId === filters.sessionId);
  }
  async function publish(ownerId, input = {}) {
    assertId(ownerId, "ownerId");
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("Realtime event harus berupa object");
    const eventId = bounded(input.id || createId("event"), 240);
    const event = Object.freeze({
      ...input,
      id: eventId,
      ownerId,
      type: bounded(input.type || "activity", 100),
      action: bounded(input.action || "unknown", 160),
      status: bounded(input.status || "unknown", 80),
      label: bounded(input.label || input.action || "Event", 300),
      createdAt: input.createdAt || clock(),
      cursor: bounded(input.cursor || eventId, 240)
    });
    const history = ownerEvents(ownerId);
    const duplicate = history.find(item => item.id === event.id);
    if (duplicate) return duplicate;
    history.push(event);
    if (history.length > limit) history.splice(0, history.length - limit);
    for (const subscription of ownerListeners(ownerId)) {
      if (!matches(event, subscription.filters)) continue;
      try { subscription.listener(event); } catch { /* Listener failures must not break event publication. */ }
    }
    return event;
  }
  function subscribe(ownerId, listener, filters = {}) {
    assertId(ownerId, "ownerId");
    if (typeof listener !== "function") throw new TypeError("Realtime listener harus berupa function");
    const subscription = { listener, filters: { executionId: filters.executionId || null, sessionId: filters.sessionId || null } };
    ownerListeners(ownerId).add(subscription);
    return () => {
      const set = ownerListeners(ownerId);
      set.delete(subscription);
      if (!set.size) listeners.delete(ownerId);
    };
  }
  async function replay(ownerId, { after = null, executionId = null, sessionId = null, limit: requestedLimit = 500 } = {}) {
    assertId(ownerId, "ownerId");
    const history = ownerEvents(ownerId);
    let start = 0;
    if (after) {
      const index = history.findIndex(item => item.cursor === after || item.id === after);
      start = index >= 0 ? index + 1 : history.length;
    }
    const cap = Math.max(1, Math.min(Number(requestedLimit) || 500, 1000));
    return history.slice(start).filter(item => matches(item, { executionId, sessionId })).slice(-cap).map(item => ({ ...item }));
  }
  function clear(ownerId) {
    if (ownerId == null) { histories.clear(); listeners.clear(); return; }
    histories.delete(ownerId);
    listeners.delete(ownerId);
  }
  return Object.freeze({ publish, subscribe, replay, clear, maxEvents: limit });
}
