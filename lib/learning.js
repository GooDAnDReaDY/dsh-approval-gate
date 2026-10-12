// lib/learning.js
// Confirmation Learning with Hard Critical Category Exclusion (#79, #81).
// Tracks manual user approvals and auto-promotes routine safe operations after N-1 confirmations.
// Strictly excludes destructive, secret, privilege-escalation, and system-level operations.

import { isCriticalOperation } from "./engine.js";

export const DEFAULT_MIN_CONFIRMATIONS = 2;
export const DEFAULT_MAX_LEARNED_RULES = 100;

export const EXCLUSION_REASONS = Object.freeze({
  CRITICAL_OPERATION: "critical-category-excluded",
  SECRETS_EXCLUDED: "secrets-category-excluded",
  DESTRUCTIVE_EXCLUDED: "destructive-category-excluded",
  SYSTEM_PATHS_EXCLUDED: "system-paths-category-excluded",
  PRIVILEGE_EXCLUDED: "privilege-category-excluded",
});

const SECRETS_PATTERNS = [
  /\.env\b/i,
  /[\\/]\.ssh[\\/]/i,
  /[\\/]\.aws[\\/]/i,
  /\/etc\/(?:shadow|gshadow|sudoers)/i,
  /\b(?:id_rsa|id_ed25519|id_ecdsa|private[._-]?key)\b/i,
];

const DESTRUCTIVE_PATTERNS = [
  /\b(?:rm|shred|wipefs)\b/i,
  /\btruncate\s+-s\s+0\b/i,
  />\s*\/dev\/(?:null|zero|sd[a-z]|nvme)/i,
];

const SYSTEM_PATH_PATTERNS = [
  /^\/(?:etc|boot|sys|proc|root|dev)\b/i,
  /[\\/](?:Windows[\\/]System32|Program Files)/i,
];

const PRIVILEGE_PATTERNS = [
  /\b(?:sudo|su|doas)\b/i,
  /\bchmod\s+(-[a-zA-Z]*\s+)?(?:777|666)\b/i,
  /\bchown\s+(-[a-zA-Z]*\s+)?root\b/i,
];

/**
 * Checks if an operation is strictly eligible for confirmation learning (#81).
 *
 * @param {string} [toolName]
 * @param {string} [command]
 * @param {Record<string, any>} [execution]
 * @returns {{ canLearn: boolean, reason?: string }}
 */
export function canLearnOperation(toolName, command, execution) {
  const args = execution?.arguments || execution || {};
  const cmd = String(command || args?.command || "").trim();
  const tool = String(toolName || execution?.name || "").trim();
  const target = String(
    args?.TargetFile ||
    args?.target_file ||
    args?.targetPath ||
    args?.path ||
    args?.file ||
    ""
  ).trim();

  // 1. Critical operations check (#52, #81)
  if (isCriticalOperation(tool, cmd, execution)) {
    return { canLearn: false, reason: EXCLUSION_REASONS.CRITICAL_OPERATION };
  }

  // 2. Destructive operations exclusion
  if (cmd && DESTRUCTIVE_PATTERNS.some((p) => p.test(cmd))) {
    return { canLearn: false, reason: EXCLUSION_REASONS.DESTRUCTIVE_EXCLUDED };
  }

  // 3. Secrets and credentials exclusion
  if ((cmd && SECRETS_PATTERNS.some((p) => p.test(cmd))) || (target && SECRETS_PATTERNS.some((p) => p.test(target)))) {
    return { canLearn: false, reason: EXCLUSION_REASONS.SECRETS_EXCLUDED };
  }

  // 4. System paths exclusion
  if ((cmd && SYSTEM_PATH_PATTERNS.some((p) => p.test(cmd))) || (target && SYSTEM_PATH_PATTERNS.some((p) => p.test(target)))) {
    return { canLearn: false, reason: EXCLUSION_REASONS.SYSTEM_PATHS_EXCLUDED };
  }

  // 5. Privilege escalation exclusion
  if (cmd && PRIVILEGE_PATTERNS.some((p) => p.test(cmd))) {
    return { canLearn: false, reason: EXCLUSION_REASONS.PRIVILEGE_EXCLUDED };
  }

  return { canLearn: true };
}

/**
 * Normalizes an execution to a stable cache/lookup key for learning.
 * @param {string} toolName
 * @param {string} command
 * @param {Record<string, any>} [args]
 * @returns {string}
 */
export function normalizeLearningKey(toolName, command, args = {}) {
  const tool = String(toolName || "").trim().toLowerCase();
  const cmd = String(command || args?.command || "").trim().replace(/\s+/g, " ");
  if (cmd) return `${tool}:${cmd}`;
  const target = String(args?.TargetFile || args?.path || args?.file || "").trim();
  return `${tool}:${target}`;
}

/**
 * Manages confirmation counts and learned rules (#79, #81).
 */
export class ConfirmationLearner {
  /**
   * @param {{ minConfirmations?: number, maxLearnedRules?: number }} [options]
   */
  constructor(options = {}) {
    this.minConfirmations = options.minConfirmations || DEFAULT_MIN_CONFIRMATIONS;
    this.maxLearnedRules = options.maxLearnedRules || DEFAULT_MAX_LEARNED_RULES;
    /** @type {Map<string, Map<string, { count: number, learned: boolean, command: string, tool: string, timestamp: number }>>} */
    this.sessions = new Map();
  }

  /**
   * @private
   */
  _getSessionMap(sessionId) {
    const key = sessionId || "default";
    let map = this.sessions.get(key);
    if (!map) {
      map = new Map();
      this.sessions.set(key, map);
    }
    return map;
  }

  /**
   * Records a manual human confirmation for an execution.
   *
   * @param {string} sessionId
   * @param {{ name: string, arguments?: any }} execution
   * @returns {{ learned: boolean, count: number, threshold: number, excluded?: boolean, reason?: string }}
   */
  recordConfirmation(sessionId, execution) {
    const toolName = execution?.name || "";
    const command = execution?.arguments?.command || "";

    const check = canLearnOperation(toolName, command, execution);
    if (!check.canLearn) {
      return { learned: false, count: 0, threshold: this.minConfirmations, excluded: true, reason: check.reason };
    }

    const sessionMap = this._getSessionMap(sessionId);
    const key = normalizeLearningKey(toolName, command, execution?.arguments);
    const existing = sessionMap.get(key) || { count: 0, learned: false, command, tool: toolName, timestamp: Date.now() };

    existing.count += 1;
    existing.timestamp = Date.now();

    if (existing.count >= this.minConfirmations) {
      existing.learned = true;
    }

    sessionMap.set(key, existing);

    // Enforce maxLearnedRules eviction (FIFO)
    if (sessionMap.size > this.maxLearnedRules) {
      const oldestKey = sessionMap.keys().next().value;
      if (oldestKey) sessionMap.delete(oldestKey);
    }

    return {
      learned: existing.learned,
      count: existing.count,
      threshold: this.minConfirmations,
      key,
    };
  }

  /**
   * Checks if an execution matches a learned rule in the session.
   *
   * @param {string} sessionId
   * @param {{ name: string, arguments?: any }} execution
   * @returns {{ learned: boolean, rule?: any }}
   */
  isLearned(sessionId, execution) {
    const toolName = execution?.name || "";
    const command = execution?.arguments?.command || "";

    // Double-check hard exclusion: critical items can NEVER be learned
    if (!canLearnOperation(toolName, command, execution).canLearn) {
      return { learned: false };
    }

    const sessionMap = this._getSessionMap(sessionId);
    const key = normalizeLearningKey(toolName, command, execution?.arguments);
    const entry = sessionMap.get(key);

    if (entry && entry.learned) {
      return { learned: true, rule: { ...entry, key } };
    }

    return { learned: false };
  }

  /**
   * Returns list of all learned rules for a session.
   * @param {string} sessionId
   * @returns {Array<any>}
   */
  getLearnedRules(sessionId) {
    const sessionMap = this._getSessionMap(sessionId);
    const rules = [];
    for (const [key, entry] of sessionMap.entries()) {
      if (entry.learned) {
        rules.push({ key, ...entry });
      }
    }
    return rules;
  }

  revoke(sessionId, key) {
    const sessionMap = this._getSessionMap(sessionId);
    return sessionMap.delete(key);
  }

  clearSession(sessionId) {
    const key = sessionId || "default";
    this.sessions.delete(key);
  }

  reset() {
    this.sessions.clear();
  }
}
