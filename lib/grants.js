// lib/grants.js
// Session-scoped temporary grants with TTL, usage limits, and automatic garbage collection.
// Fulfills level P1 (Session Grants) in SecurityEngine.

import { canonicalizeCall, hashCall } from "./canonical.js";

export const DEFAULT_GRANT_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const DEFAULT_GRANT_MAX_USES = 1;
export const DEFAULT_AUTO_PRUNE_OPS = 50;

/**
 * Checks if candidate string starts with prefix.
 * @param {any} val
 * @param {string} prefix
 * @returns {boolean}
 */
function matchesPrefix(val, prefix) {
  if (typeof val !== "string" || typeof prefix !== "string") return false;
  return val.startsWith(prefix);
}

/**
 * Evaluates whether arguments satisfy a grant's prefix / pattern requirements.
 *
 * @param {any} args
 * @param {Grant} grant
 * @returns {boolean}
 */
export function matchGrantCriteria(args, grant) {
  // 1. Specific command prefix
  if (grant.commandPrefix) {
    const cmd = args && typeof args.command === "string" ? args.command : "";
    if (!matchesPrefix(cmd, grant.commandPrefix)) return false;
  }

  // 2. Specific path prefix
  if (grant.pathPrefix) {
    const targetPath = args && (args.path || args.target || args.file || "");
    if (!matchesPrefix(targetPath, grant.pathPrefix)) return false;
  }

  // 3. Structured prefix match
  if (grant.prefix) {
    if (typeof grant.prefix === "string") {
      const cmd = args && typeof args.command === "string" ? args.command : "";
      if (!matchesPrefix(cmd, grant.prefix)) return false;
    } else if (typeof grant.prefix === "object" && grant.prefix !== null) {
      for (const [key, expectedPrefix] of Object.entries(grant.prefix)) {
        const val = args && args[key];
        if (!matchesPrefix(val, expectedPrefix)) return false;
      }
    }
  }

  // 4. Pattern matching (RegExp or predicate)
  if (grant.argsPattern) {
    if (typeof grant.argsPattern === "function") {
      if (!grant.argsPattern(args)) return false;
    } else if (typeof grant.argsPattern === "object" && grant.argsPattern !== null) {
      for (const [key, pattern] of Object.entries(grant.argsPattern)) {
        const val = args && args[key];
        if (pattern instanceof RegExp) {
          if (typeof val !== "string" || !pattern.test(val)) return false;
        } else if (typeof pattern === "string") {
          if (val !== pattern) return false;
        }
      }
    }
  }

  return true;
}

/**
 * @typedef {Object} Grant
 * @property {string} id
 * @property {string} sessionId
 * @property {string} tool
 * @property {number} createdAt
 * @property {number} expiresAt
 * @property {number} ttlMs
 * @property {number} maxUses
 * @property {number} uses
 * @property {string} [commandPrefix]
 * @property {string} [pathPrefix]
 * @property {string|Record<string, string>} [prefix]
 * @property {Record<string, RegExp|string>|Function} [argsPattern]
 * @property {any} [match]
 * @property {string} [callHash]
 */

export class SessionGrantStore {
  /**
   * @param {{
   *   defaultTtlMs?: number,
   *   defaultMaxUses?: number,
   *   autoPruneOps?: number
   * }} [options]
   */
  constructor(options = {}) {
    this.defaultTtlMs = options.defaultTtlMs || DEFAULT_GRANT_TTL_MS;
    this.defaultMaxUses = options.defaultMaxUses || DEFAULT_GRANT_MAX_USES;
    this.autoPruneOps = options.autoPruneOps || DEFAULT_AUTO_PRUNE_OPS;
    this._opCount = 0;
    this._pruneTimer = null;
    /** @type {Map<string, Grant[]>} */
    this.sessions = new Map();
  }

  /**
   * Check if a grant is expired at a given timestamp.
   * @param {Grant} grant
   * @param {number} [now]
   * @returns {boolean}
   */
  isExpired(grant, now = Date.now()) {
    return Number.isFinite(grant.expiresAt) && now > grant.expiresAt;
  }

  /**
   * Check if a grant has exhausted its allowed uses.
   * @param {Grant} grant
   * @returns {boolean}
   */
  isExhausted(grant) {
    return Number.isFinite(grant.maxUses) && grant.uses >= grant.maxUses;
  }

  /**
   * Trigger automatic counter-based pruning if threshold is reached.
   * @private
   */
  _maybeAutoPrune() {
    this._opCount += 1;
    if (this.autoPruneOps > 0 && this._opCount >= this.autoPruneOps) {
      this._opCount = 0;
      this.prune();
    }
  }

  /**
   * Issue a new temporary session grant.
   *
   * @param {{
   *   sessionId?: string,
   *   tool: string,
   *   ttlMs?: number,
   *   maxUses?: number,
   *   commandPrefix?: string,
   *   pathPrefix?: string,
   *   prefix?: string | Record<string, string>,
   *   argsPattern?: Record<string, RegExp|string> | Function,
   *   match?: any,
   *   callHash?: string,
   *   id?: string
   * }} options
   * @returns {Grant}
   */
  addGrant(options) {
    if (!options || typeof options.tool !== "string") {
      throw new TypeError("addGrant requires options.tool as string");
    }

    this._maybeAutoPrune();

    const sessionId = options.sessionId || "default";
    const now = Date.now();
    const ttlMs = options.ttlMs !== undefined ? options.ttlMs : this.defaultTtlMs;
    const maxUses = options.maxUses !== undefined ? options.maxUses : this.defaultMaxUses;
    const expiresAt = Number.isFinite(ttlMs) ? now + ttlMs : Infinity;
    const id = options.id || ("grant_" + now + "_" + Math.random().toString(36).slice(2, 9));

    const grant = {
      id,
      sessionId,
      tool: options.tool.trim(),
      createdAt: now,
      expiresAt,
      ttlMs,
      maxUses,
      uses: 0,
      commandPrefix: options.commandPrefix,
      pathPrefix: options.pathPrefix,
      prefix: options.prefix,
      argsPattern: options.argsPattern,
      match: options.match,
      callHash: options.callHash,
    };

    let list = this.sessions.get(sessionId);
    if (!list) {
      list = [];
      this.sessions.set(sessionId, list);
    }
    list.push(grant);

    return grant;
  }

  /**
   * Evaluates if a tool execution is authorized by an active session grant.
   * If a match is found, increments the grant usage counter and returns "allow".
   *
   * @param {string} toolName
   * @param {any} args
   * @param {{ sessionId?: string, now?: number }} [context]
   * @returns {"allow" | "no-match"}
   */
  decide(toolName, args, context = {}) {
    this._maybeAutoPrune();

    const sessionId = (context && context.sessionId) || "default";
    const now = (context && context.now) || Date.now();
    const list = this.sessions.get(sessionId);

    if (!list || list.length === 0) {
      return "no-match";
    }

    const incomingHash = hashCall(toolName, args);

    for (let i = 0; i < list.length; i++) {
      const grant = list[i];

      // Expiry & Exhaustion check
      if (this.isExpired(grant, now) || this.isExhausted(grant)) {
        continue;
      }

      // Tool match
      if (grant.tool !== "*" && grant.tool !== toolName) {
        continue;
      }

      // Hash match (if specific call was granted)
      if (grant.callHash && grant.callHash !== incomingHash) {
        continue;
      }

      // Prefix and pattern matching criteria
      if (!matchGrantCriteria(args, grant)) {
        continue;
      }

      // Generic match predicate if provided
      if (typeof grant.match === "function") {
        if (!grant.match(toolName, args)) {
          continue;
        }
      }

      // Valid grant found: increment usage and allow
      grant.uses += 1;
      return "allow";
    }

    return "no-match";
  }

  /**
   * Retrieves active, non-expired grants for a session.
   * @param {string} [sessionId]
   * @param {number} [now]
   * @returns {Grant[]}
   */
  getGrants(sessionId, now = Date.now()) {
    const key = sessionId || "default";
    const list = this.sessions.get(key) || [];
    return list
      .filter((g) => !this.isExpired(g, now) && !this.isExhausted(g))
      .map((g) => ({ ...g }));
  }

  /**
   * Revoke a specific grant by ID.
   * @param {string} grantId
   * @param {string} [sessionId]
   * @returns {boolean} True if grant was found and revoked
   */
  revokeGrant(grantId, sessionId) {
    if (sessionId) {
      const list = this.sessions.get(sessionId);
      if (!list) return false;
      const idx = list.findIndex((g) => g.id === grantId);
      if (idx !== -1) {
        list.splice(idx, 1);
        if (list.length === 0) this.sessions.delete(sessionId);
        return true;
      }
      return false;
    }

    // Search across all sessions if sessionId not specified
    for (const [sId, list] of this.sessions.entries()) {
      const idx = list.findIndex((g) => g.id === grantId);
      if (idx !== -1) {
        list.splice(idx, 1);
        if (list.length === 0) this.sessions.delete(sId);
        return true;
      }
    }
    return false;
  }

  /**
   * Garbage-collect expired and exhausted grants across sessions.
   * Cleans up empty session entries to prevent memory leaks.
   *
   * @param {{ now?: number, sessionId?: string }} [options]
   * @returns {{ removedCount: number, remainingCount: number, emptySessionsPruned: number }}
   */
  prune(options = {}) {
    const now = options.now || Date.now();
    let removedCount = 0;
    let remainingCount = 0;
    let emptySessionsPruned = 0;

    const targetSessions = options.sessionId
      ? [options.sessionId]
      : Array.from(this.sessions.keys());

    for (const sId of targetSessions) {
      const list = this.sessions.get(sId);
      if (!list) continue;

      const active = [];
      for (const grant of list) {
        if (this.isExpired(grant, now) || this.isExhausted(grant)) {
          removedCount += 1;
        } else {
          active.push(grant);
          remainingCount += 1;
        }
      }

      if (active.length === 0) {
        this.sessions.delete(sId);
        emptySessionsPruned += 1;
      } else {
        this.sessions.set(sId, active);
      }
    }

    return { removedCount, remainingCount, emptySessionsPruned };
  }

  /**
   * Start periodic timer-based background pruning.
   * @param {number} [intervalMs=60000]
   */
  startPeriodicPrune(intervalMs = 60000) {
    this.stopPeriodicPrune();
    this._pruneTimer = setInterval(() => {
      this.prune();
    }, intervalMs);
    if (this._pruneTimer && typeof this._pruneTimer.unref === "function") {
      this._pruneTimer.unref();
    }
  }

  /**
   * Stop periodic timer-based background pruning.
   */
  stopPeriodicPrune() {
    if (this._pruneTimer) {
      clearInterval(this._pruneTimer);
      this._pruneTimer = null;
    }
  }

  /**
   * Clear grants for a session or entirely.
   * @param {string} [sessionId]
   */
  clear(sessionId) {
    if (sessionId) {
      this.sessions.delete(sessionId);
    } else {
      this.sessions.clear();
    }
  }
}

