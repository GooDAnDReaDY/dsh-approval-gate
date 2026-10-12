// lib/session-modes.js
// Session-level Gate Mode Switching (#61).
// Allows per-session mode switching between auto-approval, hybrid, manual, and strict modes.

export const GATE_MODES = Object.freeze({
  AUTO: "auto-approval",
  MANUAL: "manual",
  HYBRID: "hybrid",
  STRICT: "strict",
});

export const PRESET_MODE_MAP = Object.freeze({
  sandbox: GATE_MODES.AUTO,
  test: GATE_MODES.AUTO,
  auto: GATE_MODES.AUTO,
  "auto-approval": GATE_MODES.AUTO,
  prod: GATE_MODES.STRICT,
  production: GATE_MODES.STRICT,
  strict: GATE_MODES.STRICT,
  manual: GATE_MODES.MANUAL,
  dev: GATE_MODES.HYBRID,
  development: GATE_MODES.HYBRID,
  hybrid: GATE_MODES.HYBRID,
  standard: GATE_MODES.HYBRID,
});

/**
 * Resolves active gate mode for a session based on presets, context, or defaults.
 *
 * @param {string} [sessionId]
 * @param {string} [sessionPreset]
 * @param {Record<string, any>} [options]
 * @returns {string}
 */
export function resolveSessionGateMode(sessionId, sessionPreset, options = {}) {
  // 1. Explicit mode in options or context
  if (options.mode && Object.values(GATE_MODES).includes(options.mode)) {
    return options.mode;
  }
  if (options.sessionMode && Object.values(GATE_MODES).includes(options.sessionMode)) {
    return options.sessionMode;
  }

  // 2. Preset mapping
  const presetKey = String(sessionPreset || options.preset || "").toLowerCase().trim();
  if (presetKey && PRESET_MODE_MAP[presetKey]) {
    return PRESET_MODE_MAP[presetKey];
  }

  // 3. Fallback default
  return options.defaultMode || GATE_MODES.HYBRID;
}

/**
 * Applies session gate mode policy to a verdict decision (#61).
 *
 * @param {string} mode - Gate mode
 * @param {Record<string, any>} decision - Original verdict decision
 * @param {{ track?: string, riskBucket?: string, lockedAsk?: boolean, isRead?: boolean }} [meta]
 * @returns {Record<string, any>}
 */
export function applySessionModePolicy(mode, decision, meta = {}) {
  if (!decision) return decision;

  const currentMode = mode || GATE_MODES.HYBRID;
  const isLocked = Boolean(decision.lockedAsk || meta.lockedAsk);
  const track = meta.track || decision.track || "external";
  const riskBucket = meta.riskBucket || decision.riskBucket || "medium";

  // Auto-approval mode: relaxes low-risk or internal chores that would otherwise ask
  if (currentMode === GATE_MODES.AUTO && decision.verdict === "ask" && !isLocked) {
    const isInternal = track === "internal";
    const isLowRisk = riskBucket === "low" || riskBucket === "minimal";
    if (isInternal || isLowRisk) {
      return {
        ...decision,
        verdict: "allow",
        autoApproved: true,
        originalVerdict: "ask",
        sessionMode: currentMode,
        stage: "session-mode-auto",
        autoReason: isInternal ? "auto-approve-internal-track" : "auto-approve-low-risk",
      };
    }
  }

  // Manual or strict mode: requires manual confirmation for external mutations or higher risk
  if ((currentMode === GATE_MODES.MANUAL || currentMode === GATE_MODES.STRICT) && decision.verdict === "allow") {
    const isSafeRead = Boolean(meta.isRead);
    const isInternalSafe = track === "internal" && (riskBucket === "low" || riskBucket === "minimal");
    if (!isSafeRead && !isInternalSafe) {
      return {
        ...decision,
        verdict: "ask",
        manualRequired: true,
        originalVerdict: "allow",
        sessionMode: currentMode,
        stage: "session-mode-manual",
        manualReason: currentMode === GATE_MODES.STRICT ? "strict-mode-enforcement" : "manual-mode-enforcement",
      };
    }
  }

  return {
    ...decision,
    sessionMode: currentMode,
  };
}

/**
 * Registry for maintaining per-session gate modes (#61).
 */
export class SessionModeRegistry {
  constructor(defaultMode = GATE_MODES.HYBRID) {
    this.defaultMode = defaultMode;
    /** @type {Map<string, string>} */
    this.sessionModes = new Map();
  }

  setMode(sessionId, mode) {
    const key = sessionId || "default";
    const resolved = PRESET_MODE_MAP[String(mode).toLowerCase().trim()] || mode;
    if (Object.values(GATE_MODES).includes(resolved)) {
      this.sessionModes.set(key, resolved);
      return resolved;
    }
    return this.defaultMode;
  }

  getMode(sessionId, preset) {
    const key = sessionId || "default";
    if (this.sessionModes.has(key)) {
      return this.sessionModes.get(key);
    }
    return resolveSessionGateMode(sessionId, preset, { defaultMode: this.defaultMode });
  }

  clearSession(sessionId) {
    const key = sessionId || "default";
    this.sessionModes.delete(key);
  }

  reset() {
    this.sessionModes.clear();
  }
}
