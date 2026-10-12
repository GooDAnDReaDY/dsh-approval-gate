// lib/retry-exhaustion.js
// Anti-replay and Retry Exhaustion guard for dsh-approval-gate (#96).
// Blocks looping/thrashing agents attempting repeated bypasses after consecutive denials.

export const DEFAULT_MAX_RETRY_ATTEMPTS = 3;

/**
 * Extracts base command root from execution for grouping repeated bypass attempts.
 *
 * @param {any} execution
 * @returns {string}
 */
export function extractCommandRoot(execution) {
  if (!execution) return "";
  const tool = String(execution.name || execution.tool || "").trim().toLowerCase();
  const args = execution.arguments || {};
  if (tool === "bash" || tool === "sh" || tool === "shell") {
    const cmd = typeof args.command === "string" ? args.command.trim() : "";
    if (!cmd) return "bash";
    const parts = cmd.split(/[\s;&|]+/);
    for (const p of parts) {
      const clean = p.replace(/^['"]+|['"]+$/g, "").trim();
      if (!clean) continue;
      if (clean === "sudo" || clean === "env" || clean === "nohup") continue;
      return clean;
    }
    return "bash";
  }
  const path = args.path || args.file || args.target;
  if (typeof path === "string") return `${tool}:${path}`;
  return tool;
}

/**
 * @typedef {Object} RetrySessionState
 * @property {string} lastRoot
 * @property {number} rootRetries
 * @property {number} totalDenies
 * @property {boolean} exhausted
 * @property {number} trippedAt
 * @property {string[]} recentRoots
 */

export class RetryExhaustionGuard {
  /**
   * @param {{ maxAttempts?: number }} [options]
   */
  constructor(options = {}) {
    this.maxAttempts = options.maxAttempts || DEFAULT_MAX_RETRY_ATTEMPTS;
    /** @type {Map<string, RetrySessionState>} */
    this.sessions = new Map();
  }

  /**
   * @private
   */
  _getOrCreate(sessionId) {
    const key = sessionId || "default";
    let state = this.sessions.get(key);
    if (!state) {
      state = {
        lastRoot: "",
        rootRetries: 0,
        totalDenies: 0,
        exhausted: false,
        trippedAt: 0,
        recentRoots: [],
      };
      this.sessions.set(key, state);
    }
    return state;
  }

  /**
   * Check if session has exhausted retries.
   *
   * @param {string} [sessionId]
   * @returns {boolean}
   */
  isExhausted(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    return Boolean(state && state.exhausted);
  }

  /**
   * Get consecutive denials count for session.
   *
   * @param {string} [sessionId]
   * @returns {number}
   */
  getConsecutiveDenials(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    return state ? state.rootRetries : 0;
  }

  /**
   * Record a verdict for session and evaluate exhaustion threshold.
   *
   * @param {string} sessionId
   * @param {any} execution
   * @param {"allow" | "deny" | "ask"} verdict
   * @returns {boolean} True if this verdict caused exhaustion to trip
   */
  recordVerdict(sessionId, execution, verdict) {
    const state = this._getOrCreate(sessionId);
    const root = extractCommandRoot(execution);

    if (verdict === "deny") {
      state.totalDenies += 1;
      if (state.lastRoot === root) {
        state.rootRetries += 1;
      } else {
        state.lastRoot = root;
        state.rootRetries = 1;
      }

      state.recentRoots.push(root);
      if (state.recentRoots.length > 10) {
        state.recentRoots.shift();
      }

      if (state.rootRetries >= this.maxAttempts && !state.exhausted) {
        state.exhausted = true;
        state.trippedAt = Date.now();
        return true;
      }
    } else if (verdict === "allow") {
      state.rootRetries = 0;
      state.lastRoot = "";
    }

    return false;
  }

  /**
   * Reset consecutive denies without clearing total denies or exhaustion.
   *
   * @param {string} [sessionId]
   */
  resetConsecutive(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    if (state && state.rootRetries > 0) {
      state.rootRetries = 0;
      state.lastRoot = "";
    }
  }

  /**
   * Resume / reset a session to active state.
   *
   * @param {string} [sessionId]
   */
  reset(sessionId) {
    const key = sessionId || "default";
    const state = this.sessions.get(key);
    if (state) {
      state.lastRoot = "";
      state.rootRetries = 0;
      state.exhausted = false;
      state.trippedAt = 0;
      state.recentRoots = [];
    }
  }

  clear() {
    this.sessions.clear();
  }
}
