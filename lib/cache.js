// lib/cache.js
// Semantic LRU/TTL verdict cache for dsh-approval-gate (#63, #119).
// Caches deterministic security decisions by canonical operation fingerprint.

import { computeFingerprintHash } from "./fingerprint.js";

export const DEFAULT_CACHE_MAX_SIZE = 1000;
export const DEFAULT_CACHE_TTL_MS = 300_000; // 5 minutes

export class VerdictCache {
  /**
   * @param {{ maxSize?: number, defaultTtlMs?: number }} [options]
   */
  constructor(options = {}) {
    this.maxSize = options.maxSize || DEFAULT_CACHE_MAX_SIZE;
    this.defaultTtlMs = options.defaultTtlMs !== undefined ? options.defaultTtlMs : DEFAULT_CACHE_TTL_MS;
    /** @type {Map<string, { decision: any, expiresAt: number, sessionId?: string, timestamp: number }>} */
    this.entries = new Map();
  }

  /**
   * Generates a stable cache key for execution in a session context.
   *
   * @param {any} execution
   * @param {{ sessionId?: string, cwd?: string, sessionScoped?: boolean }} [context]
   * @returns {string}
   */
  makeKey(execution, context = {}) {
    const hash = computeFingerprintHash(execution, { cwd: context.cwd });
    if (context.sessionScoped && context.sessionId) {
      return `${context.sessionId}:${hash}`;
    }
    return hash;
  }

  /**
   * Retrieves a cached verdict if present and not expired.
   * Promotes the entry to most recently used.
   *
   * @param {string} key
   * @returns {any | undefined} Cached decision object or undefined
   */
  get(key) {
    if (!this.entries.has(key)) return undefined;
    const entry = this.entries.get(key);
    const now = Date.now();

    if (entry.expiresAt > 0 && now > entry.expiresAt) {
      this.entries.delete(key);
      return undefined;
    }

    // Refresh LRU order: delete and re-insert
    this.entries.delete(key);
    this.entries.set(key, entry);

    return { ...entry.decision, cached: true, cacheHitAt: now };
  }

  /**
   * Stores a decision in the cache.
   * Only caches deterministic verdicts ("allow" or "deny").
   *
   * @param {string} key
   * @param {any} decision
   * @param {{ ttlMs?: number, sessionId?: string }} [options]
   */
  set(key, decision, options = {}) {
    if (!key || !decision) return;
    // Do not cache transient or uncertain verdicts unless explicit
    if (decision.verdict !== "allow" && decision.verdict !== "deny") {
      return;
    }

    const ttl = options.ttlMs !== undefined ? options.ttlMs : this.defaultTtlMs;
    const now = Date.now();
    const expiresAt = ttl > 0 ? now + ttl : 0;

    // If key already exists, delete it first to ensure correct insertion order
    if (this.entries.has(key)) {
      this.entries.delete(key);
    } else if (this.entries.size >= this.maxSize) {
      // Evict oldest (first key in iteration)
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey !== undefined) {
        this.entries.delete(oldestKey);
      }
    }

    this.entries.set(key, {
      decision: {
        verdict: decision.verdict,
        stage: decision.stage,
        reason: decision.reason,
        detail: decision.detail,
        hit: decision.hit,
      },
      expiresAt,
      sessionId: options.sessionId,
      timestamp: now,
    });
  }

  has(key) {
    const entry = this.entries.get(key);
    if (!entry) return false;
    if (entry.expiresAt > 0 && Date.now() > entry.expiresAt) {
      this.entries.delete(key);
      return false;
    }
    return true;
  }

  delete(key) {
    return this.entries.delete(key);
  }

  clear() {
    this.entries.clear();
  }

  clearSession(sessionId) {
    if (!sessionId) return;
    for (const [key, entry] of this.entries.entries()) {
      if (entry.sessionId === sessionId || key.startsWith(`${sessionId}:`)) {
        this.entries.delete(key);
      }
    }
  }

  prune() {
    const now = Date.now();
    let count = 0;
    for (const [key, entry] of this.entries.entries()) {
      if (entry.expiresAt > 0 && now > entry.expiresAt) {
        this.entries.delete(key);
        count += 1;
      }
    }
    return count;
  }

  get size() {
    return this.entries.size;
  }
}
