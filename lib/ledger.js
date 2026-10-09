// lib/ledger.js
// Quality and Anomaly Ledger for dsh-approval-gate (#88).
// Tracks session health, consecutive denials, and execution anomalies.

export const MAX_LEDGER_EVENTS_PER_SESSION = 50;

/**
 * @typedef {Object} LedgerEvent
 * @property {number} timestamp
 * @property {string} type - "allow" | "deny" | "ask" | "exhaustion" | "breaker" | "error"
 * @property {string} reason
 * @property {string} [detail]
 * @property {string} [tool]
 */

/**
 * @typedef {Object} SessionLedger
 * @property {string} sessionId
 * @property {number} totalDecisions
 * @property {number} allowedCount
 * @property {number} deniedCount
 * @property {number} askCount
 * @property {number} anomalyCount
 * @property {number} consecutiveDenies
 * @property {boolean} breakerTripped
 * @property {boolean} retryExhausted
 * @property {LedgerEvent[]} recentEvents
 */

export class QualityLedger {
  constructor() {
    /** @type {Map<string, SessionLedger>} */
    this.sessions = new Map();
  }

  /**
   * @private
   */
  _getOrCreate(sessionId) {
    const key = sessionId || "default";
    let ledger = this.sessions.get(key);
    if (!ledger) {
      ledger = {
        sessionId: key,
        totalDecisions: 0,
        allowedCount: 0,
        deniedCount: 0,
        askCount: 0,
        anomalyCount: 0,
        consecutiveDenies: 0,
        breakerTripped: false,
        retryExhausted: false,
        recentEvents: [],
      };
      this.sessions.set(key, ledger);
    }
    return ledger;
  }

  /**
   * Record a decision or system event in the ledger.
   *
   * @param {string} sessionId
   * @param {string} type - "allow" | "deny" | "ask" | "exhaustion" | "breaker" | "error"
   * @param {{ reason?: string, detail?: string, tool?: string }} [details]
   */
  record(sessionId, type, details = {}) {
    const ledger = this._getOrCreate(sessionId);
    const now = Date.now();

    const event = {
      timestamp: now,
      type,
      reason: details.reason || "",
      detail: details.detail ? String(details.detail).slice(0, 200) : undefined,
      tool: details.tool || "",
    };

    ledger.recentEvents.push(event);
    if (ledger.recentEvents.length > MAX_LEDGER_EVENTS_PER_SESSION) {
      ledger.recentEvents.shift();
    }

    if (type === "allow") {
      ledger.totalDecisions += 1;
      ledger.allowedCount += 1;
      ledger.consecutiveDenies = 0;
    } else if (type === "deny") {
      ledger.totalDecisions += 1;
      ledger.deniedCount += 1;
      ledger.consecutiveDenies += 1;
      if (ledger.consecutiveDenies > 1) {
        ledger.anomalyCount += 1;
      }
    } else if (type === "ask") {
      ledger.totalDecisions += 1;
      ledger.askCount += 1;
    } else if (type === "exhaustion") {
      ledger.retryExhausted = true;
      ledger.anomalyCount += 1;
    } else if (type === "breaker") {
      ledger.breakerTripped = true;
      ledger.anomalyCount += 1;
    } else if (type === "error") {
      ledger.anomalyCount += 1;
    }
  }

  /**
   * Returns a quality summary for the session.
   *
   * @param {string} sessionId
   * @returns {{
   *   sessionId: string,
   *   totalDecisions: number,
   *   allowedCount: number,
   *   deniedCount: number,
   *   askCount: number,
   *   anomalyCount: number,
   *   consecutiveDenies: number,
   *   qualityScore: number,
   *   degradationWarning: boolean,
   *   recentEvents: LedgerEvent[]
   * }}
   */
  getSummary(sessionId) {
    const ledger = this._getOrCreate(sessionId);
    const total = ledger.totalDecisions;

    // Quality score: 1.0 down towards 0.0 based on denial & anomaly ratio
    let score = 1.0;
    if (total > 0) {
      const penalty = (ledger.deniedCount * 0.2 + ledger.anomalyCount * 0.3) / total;
      score = Math.max(0, Math.min(1.0, 1.0 - penalty));
    }

    const degradationWarning = ledger.consecutiveDenies >= 2 ||
      ledger.retryExhausted ||
      ledger.breakerTripped ||
      (total >= 3 && ledger.deniedCount / total >= 0.5);

    return {
      sessionId: ledger.sessionId,
      totalDecisions: ledger.totalDecisions,
      allowedCount: ledger.allowedCount,
      deniedCount: ledger.deniedCount,
      askCount: ledger.askCount,
      anomalyCount: ledger.anomalyCount,
      consecutiveDenies: ledger.consecutiveDenies,
      qualityScore: Number(score.toFixed(2)),
      degradationWarning,
      recentEvents: ledger.recentEvents.map((e) => ({ ...e })),
    };
  }

  reset(sessionId) {
    const key = sessionId || "default";
    this.sessions.delete(key);
  }

  clear() {
    this.sessions.clear();
  }
}
