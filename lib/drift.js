// lib/drift.js
// Trajectory Drift Detection for dsh-approval-gate (#68).
// Detects when agent deviates from session goal into port scanning, credential hunting, or out-of-scope probing.

export const DRIFT_CATEGORIES = Object.freeze({
  NETWORK_RECON: "network-recon",
  CREDENTIAL_HUNT: "credential-hunt",
  SYSTEM_PROBING: "system-probing",
  OUT_OF_SCOPE: "out-of-scope",
});

const NETWORK_RECON_PATTERNS = [
  /\b(?:nmap|masscan|zmap)\b/i,
  /\bnetstat\s+-[antulp]+/i,
  /\bss\s+-[antulp]+/i,
  /\barp\s+-(?:a|n)\b/i,
  /\b(?:tcpdump|tshark|wireshark)\b/i,
  /\b(?:traceroute|tracepath)\b/i,
];

const NETWORK_GOAL_KEYWORDS = [
  "network", "port", "scan", "packet", "interface", "traceroute", "traffic", "firewall", "diagnose"
];

const CREDENTIAL_HUNT_PATTERNS = [
  /[\\/]\.ssh[\\/](?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)/i,
  /[\\/]\.aws[\\/]credentials/i,
  /\/etc\/(?:shadow|gshadow|sudoers)/i,
  /\bcat\s+[^\n]*(?:id_rsa|id_ed25519|\.ssh|\.aws\/credentials)/i,
  /\bfind\s+[^\n]*-(?:name|iname)\s+['"]?\*?\.(?:pem|key|pfx|pkcs12)['"]?/i,
];

const CREDENTIAL_GOAL_KEYWORDS = [
  "ssh", "key", "credential", "auth", "secret", "password", "token", "certificate", "cert", "deploy key"
];

const SYSTEM_PROBE_PATTERNS = [
  /\bfind\s+\/(?:\s|$)[^\n]*-perm\s+-[0-9]+/i,
  /\/proc\/(?:kallsyms|keys|sched_debug)/i,
  /\b(?:linpeas|winpeas|chkrootkit|rkhunter)\b/i,
  /\bls\s+-[la]*\s+\/root\b/i,
];

const SYSTEM_PROBE_GOAL_KEYWORDS = [
  "kernel", "root", "audit", "security audit", "permission audit", "probe", "privilege"
];

/**
 * Checks if text contains any of the given keywords.
 * @param {string} text
 * @param {string[]} keywords
 * @returns {boolean}
 */
function containsKeyword(text, keywords) {
  if (!text || typeof text !== "string") return false;
  const lower = text.toLowerCase();
  return keywords.some((kw) => lower.includes(kw));
}

/**
 * Detects trajectory drift for an execution against session goal (#68).
 *
 * @param {string} [sessionId]
 * @param {Record<string, any>} [execution]
 * @param {Record<string, any>} [context]
 * @param {{ goal?: string, allowedScopes?: string[] }} [goalInfo]
 * @returns {{
 *   hasDrift: boolean,
 *   driftScore: number,
 *   driftWarning: boolean,
 *   category?: string,
 *   reason?: string,
 *   detail?: string
 * }}
 */
export function detectTrajectoryDrift(sessionId, execution = {}, context = {}, goalInfo = {}) {
  const goal = String(
    goalInfo?.goal ||
    context?.goal ||
    context?.userPrompt ||
    context?.prompt ||
    ""
  ).trim();

  const command = String(
    execution?.arguments?.command ||
    execution?.command ||
    ""
  ).trim();

  const targetPath = String(
    execution?.arguments?.TargetFile ||
    execution?.arguments?.targetPath ||
    execution?.arguments?.path ||
    execution?.arguments?.file ||
    ""
  ).trim();

  const textToScan = `${command} ${targetPath}`.trim();
  if (!textToScan) {
    return { hasDrift: false, driftScore: 0, driftWarning: false };
  }

  // 1. Network reconnaissance check
  if (NETWORK_RECON_PATTERNS.some((p) => p.test(textToScan))) {
    if (!containsKeyword(goal, NETWORK_GOAL_KEYWORDS)) {
      return {
        hasDrift: true,
        driftScore: 0.85,
        driftWarning: true,
        category: DRIFT_CATEGORIES.NETWORK_RECON,
        reason: "trajectory-drift-detected",
        detail: `Operation matches network reconnaissance without matching session goal (${goal.slice(0, 50) || "none"})`,
      };
    }
  }

  // 2. Credential hunting check
  if (CREDENTIAL_HUNT_PATTERNS.some((p) => p.test(textToScan))) {
    if (!containsKeyword(goal, CREDENTIAL_GOAL_KEYWORDS)) {
      return {
        hasDrift: true,
        driftScore: 0.95,
        driftWarning: true,
        category: DRIFT_CATEGORIES.CREDENTIAL_HUNT,
        reason: "trajectory-drift-detected",
        detail: `Operation matches credential inspection without matching session goal (${goal.slice(0, 50) || "none"})`,
      };
    }
  }

  // 3. System probing check
  if (SYSTEM_PROBE_PATTERNS.some((p) => p.test(textToScan))) {
    if (!containsKeyword(goal, SYSTEM_PROBE_GOAL_KEYWORDS)) {
      return {
        hasDrift: true,
        driftScore: 0.9,
        driftWarning: true,
        category: DRIFT_CATEGORIES.SYSTEM_PROBING,
        reason: "trajectory-drift-detected",
        detail: `Operation matches system probing/privilege reconnaissance outside session goal`,
      };
    }
  }

  // 4. Allowed scopes check
  const allowedScopes = goalInfo?.allowedScopes || context?.allowedScopes;
  if (Array.isArray(allowedScopes) && allowedScopes.length > 0 && targetPath) {
    const normTarget = targetPath.replace(/\\/g, "/").toLowerCase();
    const isWithinScope = allowedScopes.some((scope) => {
      const normScope = String(scope).replace(/\\/g, "/").toLowerCase();
      return normTarget.startsWith(normScope);
    });
    if (!isWithinScope && (normTarget.startsWith("/etc") || normTarget.startsWith("/root") || normTarget.includes("/.ssh"))) {
      return {
        hasDrift: true,
        driftScore: 0.8,
        driftWarning: true,
        category: DRIFT_CATEGORIES.OUT_OF_SCOPE,
        reason: "trajectory-drift-detected",
        detail: `Access to ${targetPath} is outside declared session scopes`,
      };
    }
  }

  return { hasDrift: false, driftScore: 0, driftWarning: false };
}

/**
 * Trajectory Tracker for sessions (#68).
 */
export class TrajectoryTracker {
  constructor() {
    /** @type {Map<string, { goal: string, allowedScopes: string[], stepCount: number }>} */
    this.sessions = new Map();
  }

  setGoal(sessionId, goal, allowedScopes = []) {
    const key = sessionId || "default";
    this.sessions.set(key, {
      goal: String(goal || ""),
      allowedScopes: Array.isArray(allowedScopes) ? [...allowedScopes] : [],
      stepCount: 0,
    });
  }

  getGoal(sessionId) {
    const key = sessionId || "default";
    return this.sessions.get(key) || null;
  }

  recordStep(sessionId) {
    const key = sessionId || "default";
    const entry = this.sessions.get(key);
    if (entry) {
      entry.stepCount += 1;
    }
  }

  detect(sessionId, execution, context = {}) {
    const key = sessionId || "default";
    const goalInfo = this.sessions.get(key) || {};
    return detectTrajectoryDrift(key, execution, context, goalInfo);
  }

  clearSession(sessionId) {
    const key = sessionId || "default";
    this.sessions.delete(key);
  }

  reset() {
    this.sessions.clear();
  }
}
