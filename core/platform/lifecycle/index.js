export const LIFECYCLE_STATES = Object.freeze({
  NEW: "new",
  INITIALIZING: "initializing",
  INITIALIZED: "initialized",
  STARTING: "starting",
  RUNNING: "running",
  READY: "ready",
  STOPPING: "stopping",
  STOPPED: "stopped",
  FAILED: "failed"
});

export class Lifecycle {
  #state = LIFECYCLE_STATES.NEW;
  #component;

  constructor(component = "runtime") {
    this.#component = component;
  }

  get component() { return this.#component; }
  get state() { return this.#state; }

  async initialize(fn = async () => {}) {
    this.#transition(LIFECYCLE_STATES.INITIALIZING);
    try {
      await fn();
      this.#transition(LIFECYCLE_STATES.INITIALIZED);
    } catch (error) {
      this.#state = LIFECYCLE_STATES.FAILED;
      throw error;
    }
  }

  async start(fn = async () => {}) {
    this.#transition(LIFECYCLE_STATES.STARTING);
    try {
      await fn();
      this.#transition(LIFECYCLE_STATES.RUNNING);
      this.#transition(LIFECYCLE_STATES.READY);
    } catch (error) {
      this.#state = LIFECYCLE_STATES.FAILED;
      throw error;
    }
  }

  async stop(fn = async () => {}) {
    if ([LIFECYCLE_STATES.NEW, LIFECYCLE_STATES.STOPPED].includes(this.#state)) return;
    this.#transition(LIFECYCLE_STATES.STOPPING);
    try {
      await fn();
      this.#transition(LIFECYCLE_STATES.STOPPED);
    } catch (error) {
      this.#state = LIFECYCLE_STATES.FAILED;
      throw error;
    }
  }

  #transition(next) {
    const allowed = {
      [LIFECYCLE_STATES.NEW]: [LIFECYCLE_STATES.INITIALIZING],
      [LIFECYCLE_STATES.INITIALIZING]: [LIFECYCLE_STATES.INITIALIZED],
      [LIFECYCLE_STATES.INITIALIZED]: [LIFECYCLE_STATES.STARTING],
      [LIFECYCLE_STATES.STARTING]: [LIFECYCLE_STATES.RUNNING],
      [LIFECYCLE_STATES.RUNNING]: [LIFECYCLE_STATES.READY],
      [LIFECYCLE_STATES.READY]: [LIFECYCLE_STATES.STOPPING],
      [LIFECYCLE_STATES.STOPPING]: [LIFECYCLE_STATES.STOPPED],
      [LIFECYCLE_STATES.STOPPED]: [],
      [LIFECYCLE_STATES.FAILED]: []
    };
    if (!allowed[this.#state]?.includes(next)) {
      throw new Error(`Invalid lifecycle transition: ${this.#state} -> ${next}`);
    }
    this.#state = next;
  }
}
