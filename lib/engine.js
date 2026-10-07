// lib/engine.js
// 5-tier Security Decision Engine for dsh-approval-gate.
// Waterfall:
// P0: Hard Deny (Bands Band 0 + inspectExecution hard denials + protected files)
// P1: Session Grants (scoped temporary allowances)
// P2: Static Rules / Safe Allow (Bands Band 1 + safe read-only commands)
// P3: Optional Semantic Classifier
// P4: Human Ask Fallback (uncertain syntax / ambiguous commands / tripped breaker)

import { BandsEngine } from "./bands.js";
import { CircuitBreaker } from "./breaker.js";
import { SessionGrantStore } from "./grants.js";
import { inspectExecution } from "./inspect.js";

export class SecurityEngine {
  /**
   * @param {{
   *   bands?: BandsEngine,
   *   breaker?: CircuitBreaker,
   *   inspectConfig?: { toolName?: string, fileWriteTools?: string[] },
   *   classifier?: ((execution: any, context?: any) => { verdict: "allow"|"deny", reason?: string }),
   *   grantRegistry?: { decide: (tool: string, args: any, context?: any) => "allow"|"no-match" }
   * }} [options]
   */
  constructor(options = {}) {
    this.bands = options.bands || new BandsEngine(options);
    this.breaker = options.breaker || new CircuitBreaker(options);
    this.inspectConfig = options.inspectConfig || {};
    this.classifier = options.classifier || null;
    this.grantRegistry = options.grantRegistry || new SessionGrantStore(options);
    this.defaultVerdict = options.defaultVerdict || "allow";
  }

  /**
   * Evaluates an execution request through the P0-P4 waterfall.
   *
   * @param {{ name: string, arguments?: any }} execution - Tool call
   * @param {{ sessionId?: string, knobs?: any }} [context] - Context options
   * @returns {{ verdict: "allow" | "deny" | "ask", stage: "P0" | "P1" | "P2" | "P3" | "P4", reason: string, detail?: string, hit?: any }}
   */
  decide(execution, context = {}) {
    try {
      const sessionId = context.sessionId || "default";
    const toolName = execution && execution.name;
    const command = execution && execution.arguments && execution.arguments.command;

    // Fast-path Band 0 Hard Deny
    const bandVerdict = this.bands.evaluate(toolName, command);
    if (bandVerdict === "deny") {
      this.breaker.countDeny(sessionId);
      const hit = { deny: true, reason: "band-hard-deny", detail: command, snippet: command };
      return { verdict: "deny", stage: "P0", reason: "band-hard-deny", detail: command, hit };
    }

    // Inspect execution for hard denials and syntax checks
    const hit = inspectExecution(execution, this.inspectConfig);
    if (hit.deny) {
      this.breaker.countDeny(sessionId);
      return { verdict: "deny", stage: "P0", reason: hit.reason || "hard-deny", detail: hit.detail || hit.snippet, hit };
    }

    // P1: Session Grants
    if (this.grantRegistry && typeof this.grantRegistry.decide === "function") {
      const grantMatch = this.grantRegistry.decide(toolName, execution.arguments, context);
      if (grantMatch === "allow") {
        this.breaker.resetConsecutive(sessionId);
        return { verdict: "allow", stage: "P1", reason: "session-grant", hit };
      }
    }

    // If Circuit Breaker is tripped, suspend auto-mode and force P4 Human Ask
    if (this.breaker.isTripped(sessionId)) {
      const breakerHit = {
        ask: true,
        reason: "circuit-breaker-tripped",
        detail: "Circuit breaker tripped due to repeated security denials. Manual confirmation required.",
        snippet: command || toolName,
      };
      return {
        verdict: "ask",
        stage: "P4",
        reason: "circuit-breaker-tripped",
        detail: breakerHit.detail,
        hit: breakerHit,
      };
    }

    // P4: Human Ask if syntax is unparseable or uncertain
    if (hit.ask) {
      return { verdict: "ask", stage: "P4", reason: hit.reason || "uncertain-syntax", detail: hit.detail || hit.snippet, hit };
    }

    // P2: Static Rules / Safe Allow
    if (bandVerdict === "allow") {
      this.breaker.resetConsecutive(sessionId);
      return { verdict: "allow", stage: "P2", reason: "safe-allow", hit };
    }

    // P3: Optional Semantic Classifier
    if (this.classifier && typeof this.classifier === "function") {
      try {
        const cls = this.classifier(execution, context);
        if (cls && cls.verdict === "allow") {
          this.breaker.resetConsecutive(sessionId);
          return { verdict: "allow", stage: "P3", reason: cls.reason || "classifier-allow", hit };
        }
        if (cls && cls.verdict === "deny") {
          this.breaker.countDeny(sessionId);
          const clsHit = { deny: true, reason: cls.reason || "classifier-deny", snippet: command || toolName };
          return { verdict: "deny", stage: "P3", reason: cls.reason || "classifier-deny", detail: cls.reason, hit: clsHit };
        }
      } catch (err) {
        // Classifier error fails closed to P4 Ask
        return { verdict: "ask", stage: "P4", reason: "classifier-error", detail: String(err && err.message || err), hit: null };
      }
    }

    // Default verdict for unclassified commands (#163)
    if (this.defaultVerdict === "ask") {
      const askHit = { ask: true, reason: "unmatched-ask", snippet: command || toolName };
      return { verdict: "ask", stage: "P4", reason: "unmatched-ask", hit: askHit };
    }
    return { verdict: "allow", stage: "P2", reason: "unmatched-allow", hit };
    } catch (err) {
      return {
        verdict: "ask",
        stage: "P4",
        reason: "inspect-error",
        detail: String(err && err.message || err),
        hit: { ask: true, reason: "inspect-error", detail: String(err && err.message || err) },
      };
    }
  }

  addGrant(options) {
    if (this.grantRegistry && typeof this.grantRegistry.addGrant === "function") {
      return this.grantRegistry.addGrant(options);
    }
    return null;
  }

  getGrants(sessionId) {
    if (this.grantRegistry && typeof this.grantRegistry.getGrants === "function") {
      return this.grantRegistry.getGrants(sessionId);
    }
    return [];
  }

  resume(sessionId, reason) {
    return this.breaker.resume(sessionId, reason);
  }
}
