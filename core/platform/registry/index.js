export class CapabilityRegistry {
  #entries = new Map();
  #sealed = false;

  register(name, capability, metadata = {}) {
    if (this.#sealed) throw new Error("Capability registry is sealed");
    if (typeof name !== "string" || !name.trim()) throw new TypeError("Capability name is required");
    if (this.#entries.has(name)) throw new Error(`Capability already registered: ${name}`);
    this.#entries.set(name, Object.freeze({
      name,
      capability,
      metadata: Object.freeze({ ...metadata })
    }));
    return this;
  }

  has(name) {
    return this.#entries.has(name);
  }

  resolve(name) {
    const entry = this.#entries.get(name);
    if (!entry) throw new Error(`Capability not found: ${name}`);
    return entry.capability;
  }

  describe(name) {
    const entry = this.#entries.get(name);
    return entry ? entry.metadata : null;
  }

  list() {
    return [...this.#entries.values()].map(({ name, metadata }) => ({
      name,
      ...metadata
    }));
  }

  seal() {
    this.#sealed = true;
    return this;
  }

  get sealed() {
    return this.#sealed;
  }
}
