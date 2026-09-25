export class DependencyContainer {
  #entries = new Map();
  #sealed = false;

  register(name, value) {
    if (this.#sealed) throw new Error("Dependency container is sealed");
    if (typeof name !== "string" || !name.trim()) throw new TypeError("Dependency name is required");
    if (this.#entries.has(name)) throw new Error(`Dependency already registered: ${name}`);
    this.#entries.set(name, value);
    return value;
  }

  has(name) {
    return this.#entries.has(name);
  }

  resolve(name) {
    if (!this.#entries.has(name)) throw new Error(`Dependency not found: ${name}`);
    return this.#entries.get(name);
  }

  optional(name) {
    return this.#entries.get(name);
  }

  names() {
    return [...this.#entries.keys()];
  }

  seal() {
    this.#sealed = true;
    return this;
  }

  get sealed() {
    return this.#sealed;
  }
}
