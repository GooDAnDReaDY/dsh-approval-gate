// lib/breaker.js
// Session-scoped Circuit Breaker for dsh-approval-gate.
// Protects against agent thrashing / loops when blocked by security gates.

export const DEFAULT_MAX_CONSECUTIVE_DENIES = 3;
export const DEFAULT_MAX_TOTAL_DENIES = 20;

export class CircuitBreaker {
  /**
   * @param {{ maxConsecutive?: number, maxTotal?: number }} [options]
   */
  constructor(options = {}) {
    this.maxConsecutive = options.maxConsecutive || DEFAULT_MAX_CONSECUTIVE_DENIES;
    this.maxTotal = options.maxTotal || DEFAULT_MAX_TOTAL_DENIES;
    /** @type {Map<string, { consecutive: number, total: number, tripped: boolean }>} */
    this.sessions = new Map();
  }

  /**
   * Get current state snapshot for a session.
   * @param {string} [sessionId]
   * @returns {{ consecutive: number, total: number, tripped: boolean }}
   */
  get(sessionId) {
    const key = sessionId || "default";
    let state = this.sessions.get(key);
    if (!state) {
      state = { consecutive: 0, total: 0, tripped: false };
      this.sessions.set(key, state);
    }
    return { ...state };
  }

  /**
   * Whether the breaker is currently tripped for this session.
   * @param {string} [sessionId]
   * @returns {boolean}
   */
  isTripped(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    return Boolean(state && state.tripped);
  }

  /**
   * Record a security denial. Returns true if this call tripped the breaker.
   * @param {string} [sessionId]
   * @returns {boolean}
   */
  countDeny(sessionId) {
    const key = sessionId || "default";
    let state = this.sessions.get(key);
    if (!state) {
      state = { consecutive: 0, total: 0, tripped: false };
      this.sessions.set(key, state);
    }
    state.consecutive += 1;
    state.total += 1;
    const wasTripped = state.tripped;
    if (state.consecutive >= this.maxConsecutive || state.total >= this.maxTotal) {
      state.tripped = true;
      return !wasTripped;
    }
    return false;
  }

  /**
   * Reset the consecutive counter on an allowed operation.
   * @param {string} [sessionId]
   */
  resetConsecutive(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    if (state) state.consecutive = 0;
  }

  /**
   * Fully resume auto-mode after human approval.
   * @param {string} [sessionId]
   */
  resume(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    if (state) {
      state.consecutive = 0;
      state.total = 0;
      state.tripped = false;
    }
  }

  /**
   * Clear all session tracking states.
   */
  clear() {
    this.sessions.clear();
  }
}
