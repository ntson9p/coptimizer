// store holds what the page knows and tells the views when it changes.
export const store = {
  state: {
    status: null,
    drives: [],
    scan: null, // the latest scan
    progress: null, // the latest progress of that scan
    system: [], // the latest result of each probe
    jobs: {}, // cleanups by ID, as the server last described them
    jobProgress: {}, // cleanup ID → its latest progress
    jobLog: {}, // cleanup ID → the lines its tool printed
    conn: 'connecting',
  },
  listeners: new Set(),

  set(patch) {
    Object.assign(this.state, patch);
    for (const fn of this.listeners) fn(this.state);
  },

  subscribe(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  },
};
