// lib/ledger.js
// Quality and Anomaly Ledger for dsh-approval-gate (#88, #73).
// Tracks session health, consecutive denials, and execution anomalies with schema versioning.

export const MAX_LEDGER_EVENTS_PER_SESSION = 50;

export const CURRENT_SCHEMA_VERSION = 3;
export const SUPPORTED_SCHEMA_VERSIONS = Object.freeze([1, 2, 3]);

/**
 * Migrates a verdict record across schema versions (v1 -> v2 -> v3) (#73).
 * - v1: { id, verdict, ruleId, timestamp, riskBucket }
 * - v2: + { reviewDecision, bandVerdict, mitigation, auditSummary }
 * - v3: + { track, dossier, driftScore, driftWarning, schema_version: 3 }
 *
 * @param {Record<string, any>} record
 * @param {number} [targetVersion=CURRENT_SCHEMA_VERSION]
 * @returns {Record<string, any>}
 */
export function migrateVerdictRecord(record, targetVersion = CURRENT_SCHEMA_VERSION) {
  if (!record || typeof record !== "object") return record;

  let currentVersion = record.schema_version;
  if (!currentVersion) {
    // Infer version from fields
    if (record.reviewDecision !== undefined || record.bandVerdict !== undefined) {
      currentVersion = 2;
    } else {
      currentVersion = 1;
    }
  }

  let migrated = { ...record };

  // v1 -> v2 migration
  if (currentVersion < 2 && targetVersion >= 2) {
    migrated.reviewDecision = migrated.reviewDecision || migrated.verdict || "allow";
    migrated.bandVerdict = migrated.bandVerdict || migrated.verdict || "allow";
    migrated.mitigation = migrated.mitigation || null;
    migrated.auditSummary = migrated.auditSummary || null;
    migrated.schema_version = 2;
    currentVersion = 2;
  }

  // v2 -> v3 migration
  if (currentVersion < 3 && targetVersion >= 3) {
    migrated.track = migrated.track || "external";
    migrated.dossier = migrated.dossier || null;
    migrated.driftScore = typeof migrated.driftScore === "number" ? migrated.driftScore : 0;
    migrated.driftWarning = Boolean(migrated.driftWarning);
    migrated.schema_version = 3;
    currentVersion = 3;
  }

  migrated.schema_version = currentVersion;
  return migrated;
}

/**
 * @typedef {Object} LedgerEvent
 * @property {number} timestamp
 * @property {string} type - "allow" | "deny" | "ask" | "exhaustion" | "breaker" | "error"
 * @property {string} reason
 * @property {string} [detail]
 * @property {string} [tool]
 * @property {number} [schema_version]
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
   * @param {{ reason?: string, detail?: string, tool?: string, track?: string, dossier?: any }} [details]
   */
  record(sessionId, type, details = {}) {
    const ledger = this._getOrCreate(sessionId);
    const now = Date.now();

    const rawEvent = {
      timestamp: now,
      type,
      reason: details.reason || "",
      detail: details.detail ? String(details.detail).slice(0, 200) : undefined,
      tool: details.tool || "",
      track: details.track,
      dossier: details.dossier,
      schema_version: CURRENT_SCHEMA_VERSION,
    };

    const event = migrateVerdictRecord(rawEvent, CURRENT_SCHEMA_VERSION);

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

  /**
   * Serializes session ledger state with current schema version (#73).
   * @param {string} sessionId
   * @returns {Record<string, any>}
   */
  serializeSession(sessionId) {
    const ledger = this._getOrCreate(sessionId);
    return {
      schema_version: CURRENT_SCHEMA_VERSION,
      sessionId: ledger.sessionId,
      totalDecisions: ledger.totalDecisions,
      allowedCount: ledger.allowedCount,
      deniedCount: ledger.deniedCount,
      askCount: ledger.askCount,
      anomalyCount: ledger.anomalyCount,
      consecutiveDenies: ledger.consecutiveDenies,
      breakerTripped: ledger.breakerTripped,
      retryExhausted: ledger.retryExhausted,
      recentEvents: ledger.recentEvents.map((e) => migrateVerdictRecord(e, CURRENT_SCHEMA_VERSION)),
    };
  }

  /**
   * Restores session ledger state from serialized data with automatic migration (#73).
   * @param {Record<string, any>} data
   */
  deserializeSession(data) {
    if (!data || !data.sessionId) return;
    const ledger = this._getOrCreate(data.sessionId);
    ledger.totalDecisions = data.totalDecisions || 0;
    ledger.allowedCount = data.allowedCount || 0;
    ledger.deniedCount = data.deniedCount || 0;
    ledger.askCount = data.askCount || 0;
    ledger.anomalyCount = data.anomalyCount || 0;
    ledger.consecutiveDenies = data.consecutiveDenies || 0;
    ledger.breakerTripped = Boolean(data.breakerTripped);
    ledger.retryExhausted = Boolean(data.retryExhausted);
    ledger.recentEvents = Array.isArray(data.recentEvents)
      ? data.recentEvents.map((e) => migrateVerdictRecord(e, CURRENT_SCHEMA_VERSION))
      : [];
  }

  reset(sessionId) {
    const key = sessionId || "default";
    this.sessions.delete(key);
  }

  clear() {
    this.sessions.clear();
  }
}
