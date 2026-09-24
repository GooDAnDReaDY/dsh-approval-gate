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
import { inspectExecution } from "./inspect.js";

export class SecurityEngine {
  /**
   * @param {{
   *   bands?: BandsEngine,
   *   breaker?: CircuitBreaker,
   *   inspectConfig?: { toolName?: string, fileWriteTools?: string[] },
   *   classifier?: ((execution: any, context?: any) => { verdict: "allow"|"deny", reason?: string }),
   *   grantRegistry?: { decide: (tool: string, args: any) => "allow"|"no-match" }
   * }} [options]
   */
  constructor(options = {}) {
    this.bands = options.bands || new BandsEngine(options);
    this.breaker = options.breaker || new CircuitBreaker(options);
    this.inspectConfig = options.inspectConfig || {};
    this.classifier = options.classifier || null;
    this.grantRegistry = options.grantRegistry || null;
  }

  /**
   * Evaluates an execution request through the P0-P4 waterfall.
   *
   * @param {{ name: string, arguments?: any }} execution - Tool call
   * @param {{ sessionId?: string, knobs?: any }} [context] - Context options
   * @returns {{ verdict: "allow" | "deny" | "ask", stage: "P0" | "P1" | "P2" | "P3" | "P4", reason: string, detail?: string }}
   */
  decide(execution, context = {}) {
    const sessionId = context.sessionId || "default";
    const toolName = execution && execution.name;
    const command = execution && execution.arguments && execution.arguments.command;

    // Fast-path Band 0 Hard Deny
    const bandVerdict = this.bands.evaluate(toolName, command);
    if (bandVerdict === "deny") {
      this.breaker.countDeny(sessionId);
      return { verdict: "deny", stage: "P0", reason: "band-hard-deny", detail: command };
    }

    // Inspect execution for hard denials and syntax checks
    const hit = inspectExecution(execution, this.inspectConfig);
    if (hit.deny) {
      this.breaker.countDeny(sessionId);
      return { verdict: "deny", stage: "P0", reason: hit.reason || "hard-deny", detail: hit.detail || hit.snippet };
    }

    // P1: Session Grants
    if (this.grantRegistry && typeof this.grantRegistry.decide === "function") {
      const grantMatch = this.grantRegistry.decide(toolName, execution.arguments);
      if (grantMatch === "allow") {
        this.breaker.resetConsecutive(sessionId);
        return { verdict: "allow", stage: "P1", reason: "session-grant" };
      }
    }

    // If Circuit Breaker is tripped, suspend auto-mode and force P4 Human Ask
    if (this.breaker.isTripped(sessionId)) {
      return {
        verdict: "ask",
        stage: "P4",
        reason: "circuit-breaker-tripped",
        detail: "Circuit breaker tripped due to repeated security denials. Manual confirmation required."
      };
    }

    // P2: Static Rules / Safe Allow
    if (bandVerdict === "allow") {
      this.breaker.resetConsecutive(sessionId);
      return { verdict: "allow", stage: "P2", reason: "safe-allow" };
    }

    // P3: Optional Semantic Classifier
    if (this.classifier && typeof this.classifier === "function") {
      try {
        const cls = this.classifier(execution, context);
        if (cls && cls.verdict === "allow") {
          this.breaker.resetConsecutive(sessionId);
          return { verdict: "allow", stage: "P3", reason: cls.reason || "classifier-allow" };
        }
        if (cls && cls.verdict === "deny") {
          this.breaker.countDeny(sessionId);
          return { verdict: "deny", stage: "P3", reason: cls.reason || "classifier-deny" };
        }
      } catch (err) {
        // Classifier error fails closed to P4 Ask
      }
    }

    // P4: Human Ask (uncertain syntax or unlisted command)
    if (hit.ask) {
      return { verdict: "ask", stage: "P4", reason: hit.reason || "uncertain-syntax", detail: hit.detail || hit.snippet };
    }

    // Safe default for unclassified commands
    return { verdict: "allow", stage: "P2", reason: "unmatched-allow" };
  }
}
