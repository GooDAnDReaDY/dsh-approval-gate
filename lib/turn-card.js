// lib/turn-card.js
// TurnCard Round Summary Engine for DSH Approval Gate (#86).
// Aggregates tool hits, blocked rules, asked confirmations, and builds a comprehensive summary per agent turn.

/**
 * @typedef {Object} TurnCallRecord
 * @property {string} [tool]
 * @property {string} [command]
 * @property {string} [snippet]
 * @property {'allow' | 'deny' | 'ask' | 'preempted'} verdict
 * @property {string} [reason]
 * @property {string} [rule]
 * @property {number} [durationMs]
 * @property {number} [timestamp]
 */

/**
 * @typedef {Object} RuleHitSummary
 * @property {string} rule
 * @property {number} count
 * @property {string[]} reasons
 */

/**
 * @typedef {Object} TurnCard
 * @property {string} sessionId
 * @property {string | number} turnId
 * @property {number} timestamp
 * @property {'clean' | 'warnings' | 'blocked'} status
 * @property {number} totalCalls
 * @property {number} allowedCalls
 * @property {number} blockedCalls
 * @property {number} askedCalls
 * @property {number} preemptedCalls
 * @property {RuleHitSummary[]} ruleHits
 * @property {TurnCallRecord[]} blockedDetails
 * @property {string} summaryText
 */

/**
 * Formats a localized or human-readable summary string for a TurnCard (#86).
 *
 * @param {TurnCard} card
 * @param {'en' | 'ru' | 'zh'} [lang='en']
 * @returns {string}
 */
export function formatTurnCardSummary(card, lang = "en") {
  if (!card) return "";
  const tid = card.turnId !== undefined && card.turnId !== null ? card.turnId : "current";

  if (lang === "ru") {
    if (card.status === "clean") {
      return `Раунд #${tid}: ${card.totalCalls} вызовов, все одобрены без замечаний.`;
    }
    const parts = [`Раунд #${tid}: ${card.totalCalls} вызовов`];
    if (card.blockedCalls > 0) parts.push(`заблокировано: ${card.blockedCalls}`);
    if (card.askedCalls > 0) parts.push(`запросов подтверждения: ${card.askedCalls}`);
    if (card.ruleHits && card.ruleHits.length > 0) {
      const rules = card.ruleHits.map((r) => `${r.rule} (${r.count})`).join(", ");
      parts.push(`сработавшие правила: [${rules}]`);
    }
    return parts.join("; ") + ".";
  }

  if (lang === "zh") {
    if (card.status === "clean") {
      return `轮次 #${tid}: 共 ${card.totalCalls} 次调用，全部安全通过。`;
    }
    const parts = [`轮次 #${tid}: 共 ${card.totalCalls} 次调用`];
    if (card.blockedCalls > 0) parts.push(`拦截: ${card.blockedCalls}`);
    if (card.askedCalls > 0) parts.push(`需人工确认: ${card.askedCalls}`);
    if (card.ruleHits && card.ruleHits.length > 0) {
      const rules = card.ruleHits.map((r) => `${r.rule} (${r.count})`).join(", ");
      parts.push(`命中规则: [${rules}]`);
    }
    return parts.join("；") + "。";
  }

  // Default English
  if (card.status === "clean") {
    return `Turn #${tid}: ${card.totalCalls} calls, all allowed cleanly.`;
  }
  const parts = [`Turn #${tid}: ${card.totalCalls} calls`];
  if (card.blockedCalls > 0) parts.push(`${card.blockedCalls} blocked`);
  if (card.askedCalls > 0) parts.push(`${card.askedCalls} confirmation prompts`);
  if (card.ruleHits && card.ruleHits.length > 0) {
    const rules = card.ruleHits.map((r) => `${r.rule} (${r.count})`).join(", ");
    parts.push(`rule hits: [${rules}]`);
  }
  return parts.join(", ") + ".";
}

/**
 * TurnCardTracker: tracks tool calls per agent turn and builds structured summaries (#86).
 */
export class TurnCardTracker {
  /**
   * @param {{ maxRetainedTurns?: number }} [options]
   */
  constructor(options = {}) {
    this.maxRetainedTurns = options.maxRetainedTurns || 50;
    /** @type {Map<string, Map<string | number, TurnCallRecord[]>>} */
    this._sessions = new Map();
    /** @type {Map<string, Map<string | number, TurnCard>>} */
    this._cards = new Map();
  }

  /**
   * Records a tool call within a specific session and turn.
   *
   * @param {string} sessionId
   * @param {string | number} turnId
   * @param {TurnCallRecord} record
   */
  recordCall(sessionId, turnId, record) {
    const sid = String(sessionId || "default");
    const tid = turnId !== undefined && turnId !== null ? turnId : "active";

    let sessionTurns = this._sessions.get(sid);
    if (!sessionTurns) {
      sessionTurns = new Map();
      this._sessions.set(sid, sessionTurns);
    }

    let calls = sessionTurns.get(tid);
    if (!calls) {
      calls = [];
      sessionTurns.set(tid, calls);
    }

    calls.push({
      tool: record.tool || "unknown",
      command: record.command || "",
      snippet: record.snippet || "",
      verdict: record.verdict || "allow",
      reason: record.reason || "",
      rule: record.rule || record.reason || "",
      durationMs: record.durationMs || 0,
      timestamp: record.timestamp || Date.now(),
    });

    // Invalidate cached card for this turn
    const sessionCards = this._cards.get(sid);
    if (sessionCards) {
      sessionCards.delete(tid);
    }
  }

  /**
   * Builds the TurnCard for a specific turn in a session (#86).
   *
   * @param {string} sessionId
   * @param {string | number} turnId
   * @param {Object} [options]
   * @param {'en' | 'ru' | 'zh'} [options.lang='en']
   * @returns {TurnCard}
   */
  buildTurnCard(sessionId, turnId, options = {}) {
    const sid = String(sessionId || "default");
    const tid = turnId !== undefined && turnId !== null ? turnId : "active";
    const lang = options.lang || "en";

    let sessionCards = this._cards.get(sid);
    if (!sessionCards) {
      sessionCards = new Map();
      this._cards.set(sid, sessionCards);
    }

    const cached = sessionCards.get(tid);
    if (cached) return cached;

    const sessionTurns = this._sessions.get(sid);
    const calls = (sessionTurns && sessionTurns.get(tid)) || [];

    let totalCalls = calls.length;
    let allowedCalls = 0;
    let blockedCalls = 0;
    let askedCalls = 0;
    let preemptedCalls = 0;
    /** @type {Map<string, { count: number, reasons: Set<string> }>} */
    const ruleHitMap = new Map();
    /** @type {TurnCallRecord[]} */
    const blockedDetails = [];

    for (const c of calls) {
      if (c.verdict === "deny") {
        blockedCalls++;
        blockedDetails.push(c);
      } else if (c.verdict === "ask") {
        askedCalls++;
      } else if (c.verdict === "preempted") {
        preemptedCalls++;
      } else {
        allowedCalls++;
      }

      if (c.rule && c.verdict !== "allow") {
        let entry = ruleHitMap.get(c.rule);
        if (!entry) {
          entry = { count: 0, reasons: new Set() };
          ruleHitMap.set(c.rule, entry);
        }
        entry.count++;
        if (c.reason) entry.reasons.add(c.reason);
      }
    }

    /** @type {RuleHitSummary[]} */
    const ruleHits = Array.from(ruleHitMap.entries()).map(([rule, data]) => ({
      rule,
      count: data.count,
      reasons: Array.from(data.reasons),
    }));

    /** @type {'clean' | 'warnings' | 'blocked'} */
    let status = "clean";
    if (blockedCalls > 0) {
      status = "blocked";
    } else if (askedCalls > 0) {
      status = "warnings";
    }

    /** @type {TurnCard} */
    const card = {
      sessionId: sid,
      turnId: tid,
      timestamp: Date.now(),
      status,
      totalCalls,
      allowedCalls,
      blockedCalls,
      askedCalls,
      preemptedCalls,
      ruleHits,
      blockedDetails,
      summaryText: "",
    };

    card.summaryText = formatTurnCardSummary(card, lang);
    sessionCards.set(tid, card);
    return card;
  }

  /**
   * Returns all TurnCards for a session.
   *
   * @param {string} sessionId
   * @returns {TurnCard[]}
   */
  getTurnCards(sessionId) {
    const sid = String(sessionId || "default");
    const sessionTurns = this._sessions.get(sid);
    if (!sessionTurns) return [];
    const list = [];
    for (const tid of sessionTurns.keys()) {
      list.push(this.buildTurnCard(sid, tid));
    }
    return list;
  }

  /**
   * Clears tracking for a given turn.
   *
   * @param {string} sessionId
   * @param {string | number} turnId
   */
  clearTurn(sessionId, turnId) {
    const sid = String(sessionId || "default");
    const tid = turnId !== undefined && turnId !== null ? turnId : "active";
    const st = this._sessions.get(sid);
    if (st) st.delete(tid);
    const sc = this._cards.get(sid);
    if (sc) sc.delete(tid);
  }

  /**
   * Clears tracking for an entire session.
   *
   * @param {string} sessionId
   */
  clearSession(sessionId) {
    const sid = String(sessionId || "default");
    this._sessions.delete(sid);
    this._cards.delete(sid);
  }
}
