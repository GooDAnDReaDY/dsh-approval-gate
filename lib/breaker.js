// lib/breaker.js
// Session-scoped Circuit Breaker for dsh-approval-gate with state transition events and history.
// Protects against agent thrashing / loops when blocked by security gates.

export const DEFAULT_MAX_CONSECUTIVE_DENIES = 3;
export const DEFAULT_MAX_TOTAL_DENIES = 20;
export const MAX_TRACKED_SESSIONS = 500;
export const MAX_SESSION_HISTORY = 100;

export const CIRCUIT_STATE_ACTIVE = "active";
export const CIRCUIT_STATE_TRIPPED = "tripped";
export const CIRCUIT_STATE_RESUMED = "resumed";

/**
 * @typedef {Object} CircuitTransitionEvent
 * @property {string} sessionId
 * @property {string} from
 * @property {string} to
 * @property {string} reason
 * @property {number} consecutive
 * @property {number} total
 * @property {number} timestamp
 */

export class CircuitBreaker {
  /**
   * @param {{
   *   maxConsecutive?: number,
   *   maxTotal?: number,
   *   logger?: { info?: (msg: string) => void, warn?: (msg: string) => void }
   * }} [options]
   */
  constructor(options = {}) {
    this.maxConsecutive = options.maxConsecutive || DEFAULT_MAX_CONSECUTIVE_DENIES;
    this.maxTotal = options.maxTotal || DEFAULT_MAX_TOTAL_DENIES;
    this.logger = options.logger || null;
    /** @type {Array<(event: CircuitTransitionEvent) => void>} */
    this.listeners = [];
    /** @type {Map<string, { consecutive: number, total: number, tripped: boolean, state: string, history: CircuitTransitionEvent[] }>} */
    this.sessions = new Map();
  }

  /**
   * Register a state change listener callback.
   * @param {(event: CircuitTransitionEvent) => void} fn
   * @returns {() => void} Unsubscribe function
   */
  onStateChange(fn) {
    if (typeof fn === "function") {
      this.listeners.push(fn);
    }
    return () => {
      const idx = this.listeners.indexOf(fn);
      if (idx !== -1) this.listeners.splice(idx, 1);
    };
  }

  /**
   * Emit a transition event to registered listeners and optional logger.
   * @private
   */
  _emitTransition(sessionState, sessionId, from, to, reason) {
    const event = {
      sessionId,
      from,
      to,
      reason,
      consecutive: sessionState.consecutive,
      total: sessionState.total,
      timestamp: Date.now(),
    };

    sessionState.state = to;
    sessionState.history.push(event);
    if (sessionState.history.length > MAX_SESSION_HISTORY) {
      sessionState.history.shift();
    }

    if (this.logger) {
      const logLine = `[dsh-approval-gate:breaker] session=${sessionId} state=${to} (was ${from}) reason=${reason} consecutive=${sessionState.consecutive} total=${sessionState.total}`;
      if (to === CIRCUIT_STATE_TRIPPED && typeof this.logger.warn === "function") {
        this.logger.warn(logLine);
      } else if (typeof this.logger.info === "function") {
        this.logger.info(logLine);
      }
    }

    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener error must not crash the breaker
      }
    }
  }

  /**
   * Internal session state fetch or initialize.
   * @private
   */
  _getOrCreate(sessionId) {
    const key = sessionId || "default";
    let state = this.sessions.get(key);
    if (!state) {
      if (this.sessions.size >= MAX_TRACKED_SESSIONS) {
        const oldestKey = this.sessions.keys().next().value;
        this.sessions.delete(oldestKey);
      }
      state = {
        consecutive: 0,
        total: 0,
        tripped: false,
        state: CIRCUIT_STATE_ACTIVE,
        history: [],
      };
      this.sessions.set(key, state);
    }
    return state;
  }

  /**
   * Get current state snapshot for a session (backward compatible).
   * @param {string} [sessionId]
   * @returns {{ consecutive: number, total: number, tripped: boolean }}
   */
  get(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    return state
      ? { consecutive: state.consecutive, total: state.total, tripped: state.tripped }
      : { consecutive: 0, total: 0, tripped: false };
  }

  /**
   * Get current lifecycle state string ("active" | "tripped" | "resumed").
   * @param {string} [sessionId]
   * @returns {string}
   */
  getState(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    return state ? state.state : CIRCUIT_STATE_ACTIVE;
  }

  /**
   * Retrieve state transition history for a session.
   * @param {string} [sessionId]
   * @returns {CircuitTransitionEvent[]}
   */
  getHistory(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    return state ? state.history.map((ev) => ({ ...ev })) : [];
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
    const state = this._getOrCreate(key);
    state.consecutive += 1;
    state.total += 1;

    const wasTripped = state.tripped;
    const isConsecutiveTrip = state.consecutive >= this.maxConsecutive;
    const isTotalTrip = state.total >= this.maxTotal;

    if ((isConsecutiveTrip || isTotalTrip) && !wasTripped) {
      state.tripped = true;
      const reason = isConsecutiveTrip
        ? `consecutive-threshold-exceeded (${state.consecutive}/${this.maxConsecutive})`
        : `total-threshold-exceeded (${state.total}/${this.maxTotal})`;
      this._emitTransition(state, key, CIRCUIT_STATE_ACTIVE, CIRCUIT_STATE_TRIPPED, reason);
      return true;
    }

    return false;
  }

  /**
   * Reset the consecutive counter on an allowed operation.
   * @param {string} [sessionId]
   */
  resetConsecutive(sessionId) {
    const key = sessionId || "default";
    const state = this._getOrCreate(key);
    if (state.consecutive > 0) {
      state.consecutive = 0;
    }
  }

  /**
   * Fully resume auto-mode after human approval or admin action.
   * @param {string} [sessionId]
   * @param {string} [reason="manual-human-resume"]
   */
  resume(sessionId, reason = "manual-human-resume") {
    const key = sessionId || "default";
    const state = this._getOrCreate(key);
    const wasTripped = state.tripped;
    const oldState = state.state;

    state.consecutive = 0;
    state.total = 0;
    state.tripped = false;

    if (wasTripped || oldState !== CIRCUIT_STATE_ACTIVE) {
      this._emitTransition(state, key, oldState, CIRCUIT_STATE_RESUMED, reason);
      this._emitTransition(state, key, CIRCUIT_STATE_RESUMED, CIRCUIT_STATE_ACTIVE, "session-reset-complete");
    }
  }

  /**
   * Clear all session tracking states.
   */
  clear() {
    this.sessions.clear();
  }
}

