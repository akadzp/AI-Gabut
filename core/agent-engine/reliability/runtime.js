import { randomUUID } from "node:crypto";

export function createExecutionId() { return `exec-${randomUUID()}`; }

export class ExecutionRuntime {
  #state = "created";
  #checkpoint = null;
  #startedAt = new Date().toISOString();
  #finishedAt = null;
  constructor({ id = createExecutionId(), maxSteps = 100 } = {}) {
    this.id = String(id).slice(0, 240);
    this.maxSteps = Math.max(1, Math.min(Number(maxSteps) || 100, 1000));
    this.steps = 0;
  }
  start() {
    if (this.#state !== "created" && this.#state !== "paused") throw new Error(`Cannot start execution from ${this.#state}`);
    this.#state = "running";
    return this.snapshot();
  }
  checkpoint(value) {
    if (this.#state !== "running") throw new Error("Checkpoint requires a running execution");
    if (this.steps >= this.maxSteps) throw new Error("Execution step limit reached");
    const checkpoint = structuredClone(value ?? null);
    this.#checkpoint = checkpoint;
    this.steps += 1;
    return this.snapshot();
  }
  pause(reason = null) {
    if (this.#state !== "running") throw new Error(`Cannot pause execution from ${this.#state}`);
    this.#state = "paused";
    this.reason = String(reason ?? "").slice(0, 1000) || null;
    return this.snapshot();
  }
  finish(status = "completed", result = null) {
    if (!["completed", "failed", "cancelled", "stopped"].includes(status)) throw new TypeError("Terminal execution status tidak valid");
    if (["completed", "failed", "cancelled", "stopped"].includes(this.#state)) return this.snapshot();
    this.#state = status;
    this.#finishedAt = new Date().toISOString();
    this.result = result;
    return this.snapshot();
  }
  snapshot() {
    return Object.freeze({ id: this.id, status: this.#state, steps: this.steps, maxSteps: this.maxSteps,
      checkpoint: this.#checkpoint == null ? null : structuredClone(this.#checkpoint), startedAt: this.#startedAt,
      finishedAt: this.#finishedAt, reason: this.reason || null, result: this.result ?? null });
  }
}
