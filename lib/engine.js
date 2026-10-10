// lib/engine.js
// 5-tier Security Decision Engine for dsh-approval-gate.
// Waterfall:
// P0: Hard Deny (Bands Band 0 + Declarative Rules Deny + inspectExecution hard denials + protected files + retry exhaustion)
// P1: Session Grants & Declarative Allow (scoped temporary allowances and whitelists)
// P2: Static Rules / Safe Allow (Bands Band 1 + safe read-only commands)
// P3: Optional Semantic Classifier
// P4: Human Ask Fallback (uncertain syntax / ambiguous commands / tripped breaker / declarative ask)

import { BandsEngine } from "./bands.js";
import { CircuitBreaker } from "./breaker.js";
import { SessionGrantStore } from "./grants.js";
import { inspectExecution } from "./inspect.js";
import { VerdictCache } from "./cache.js";
import { RetryExhaustionGuard } from "./retry-exhaustion.js";
import { QualityLedger } from "./ledger.js";
import { AuditLogger } from "./audit-log.js";
import { DeclarativeRulesEngine } from "./rules-loader.js";

export class SecurityEngine {
  /**
   * @param {{
   *   bands?: BandsEngine,
   *   breaker?: CircuitBreaker,
   *   cache?: VerdictCache,
   *   retryGuard?: RetryExhaustionGuard,
   *   ledger?: QualityLedger,
   *   auditLogger?: AuditLogger,
   *   declarativeRules?: DeclarativeRulesEngine,
   *   inspectConfig?: { toolName?: string, fileWriteTools?: string[], workspaceDir?: string },
   *   classifier?: ((execution: any, context?: any) => { verdict: "allow"|"deny", reason?: string }),
   *   grantRegistry?: { decide: (tool: string, args: any, context?: any) => "allow"|"no-match" },
   *   dryRun?: boolean,
   *   shadowMode?: boolean,
   *   defaultVerdict?: "allow" | "ask"
   * }} [options]
   */
  constructor(options = {}) {
    this.bands = options.bands || new BandsEngine(options);
    this.breaker = options.breaker || new CircuitBreaker(options);
    this.inspectConfig = options.inspectConfig || {};
    this.classifier = options.classifier || null;
    this.grantRegistry = options.grantRegistry || new SessionGrantStore(options);
    this.defaultVerdict = options.defaultVerdict || "allow";

    this.dryRun = Boolean(options.dryRun || options.shadowMode);
    this.cache = options.cache !== undefined ? options.cache : new VerdictCache();
    this.retryGuard = options.retryGuard !== undefined ? options.retryGuard : new RetryExhaustionGuard();
    this.ledger = options.ledger !== undefined ? options.ledger : new QualityLedger();
    this.auditLogger = options.auditLogger !== undefined ? options.auditLogger : new AuditLogger();
    this.declarativeRules = options.declarativeRules || new DeclarativeRulesEngine({
      workspaceDir: this.inspectConfig?.workspaceDir,
    });
  }

  /**
   * Evaluates an execution request through the P0-P4 waterfall.
   *
   * @param {{ name: string, arguments?: any }} execution - Tool call
   * @param {{ sessionId?: string, knobs?: any, cwd?: string }} [context] - Context options
   * @returns {{ verdict: "allow" | "deny" | "ask", stage: "P0" | "P1" | "P2" | "P3" | "P4", reason: string, detail?: string, hit?: any, dryRun?: boolean, cached?: boolean }}
   */
  decide(execution, context = {}) {
    try {
      const sessionId = context.sessionId || "default";
      const toolName = execution && execution.name;
      const command = execution && execution.arguments && execution.arguments.command;

      // Check Retry Exhaustion guard (#96)
      if (this.retryGuard && this.retryGuard.isExhausted(sessionId)) {
        const exhHit = {
          deny: true,
          reason: "retry-exhaustion",
          detail: "Retry exhaustion: consecutive blocked attempts exceeded threshold",
          snippet: command || toolName,
        };
        const exhDecision = { verdict: "deny", stage: "P0", reason: "retry-exhaustion", detail: exhHit.detail, hit: exhHit };
        if (this.ledger) this.ledger.record(sessionId, "exhaustion", { reason: "retry-exhaustion", tool: toolName });
        if (this.auditLogger) this.auditLogger.log({ sessionId, execution, decision: exhDecision, dryRun: this.dryRun });

        if (this.dryRun) {
          return { verdict: "allow", stage: "P0", dryRun: true, originalVerdict: "deny", reason: "retry-exhaustion", detail: exhHit.detail, hit: exhHit };
        }
        return exhDecision;
      }

      // Check Verdict Cache (#63, #119)
      const cacheKey = this.cache ? this.cache.makeKey(execution, context) : null;
      if (this.cache && cacheKey) {
        const cached = this.cache.get(cacheKey);
        if (cached) {
          if (this.dryRun && (cached.verdict === "deny" || cached.verdict === "ask")) {
            return {
              verdict: "allow",
              stage: cached.stage,
              dryRun: true,
              originalVerdict: cached.verdict,
              reason: cached.reason,
              detail: cached.detail,
              hit: cached.hit,
              cached: true,
            };
          }
          return cached;
        }
      }

      const decision = this._evaluateWaterfall(execution, context, sessionId, toolName, command);

      // Post-decision hooks: ledger, retryGuard, cache, audit
      if (decision.verdict === "deny") {
        if (this.retryGuard) this.retryGuard.recordVerdict(sessionId, execution, "deny");
        if (this.ledger) this.ledger.record(sessionId, "deny", { reason: decision.reason, detail: decision.detail, tool: toolName });
        if (this.cache && cacheKey) this.cache.set(cacheKey, decision, { sessionId });
      } else if (decision.verdict === "allow") {
        if (this.retryGuard) this.retryGuard.recordVerdict(sessionId, execution, "allow");
        if (this.ledger) this.ledger.record(sessionId, "allow", { reason: decision.reason, detail: decision.detail, tool: toolName });
        if (this.cache && cacheKey) this.cache.set(cacheKey, decision, { sessionId });
      } else if (decision.verdict === "ask") {
        if (this.ledger) this.ledger.record(sessionId, "ask", { reason: decision.reason, detail: decision.detail, tool: toolName });
      }

      if (this.auditLogger) {
        this.auditLogger.log({ sessionId, execution, decision, dryRun: this.dryRun });
      }

      // Shadow Mode (#128)
      if (this.dryRun && (decision.verdict === "deny" || decision.verdict === "ask")) {
        return {
          verdict: "allow",
          stage: decision.stage,
          dryRun: true,
          originalVerdict: decision.verdict,
          reason: decision.reason,
          detail: decision.detail,
          hit: decision.hit,
        };
      }

      return decision;
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

  /**
   * Internal evaluation of P0-P4 waterfall.
   * @private
   */
  _evaluateWaterfall(execution, context, sessionId, toolName, command) {
    // Fast-path Band 0 Hard Deny
    const bandVerdict = this.bands.evaluate(toolName, command);
    if (bandVerdict === "deny") {
      this.breaker.countDeny(sessionId);
      const hit = { deny: true, reason: "band-hard-deny", detail: command, snippet: command };
      return { verdict: "deny", stage: "P0", reason: "band-hard-deny", detail: command, hit };
    }

    // Declarative YAML Rules evaluation (#38, #45, #44)
    if (this.declarativeRules && command) {
      const decl = this.declarativeRules.evaluate(toolName, command, context);
      if (decl.match) {
        if (decl.verdict === "deny") {
          this.breaker.countDeny(sessionId);
          const hit = { deny: true, reason: decl.reason || "declarative-deny", detail: command, snippet: command, ruleId: decl.ruleId };
          return { verdict: "deny", stage: "P0", reason: decl.reason || "declarative-deny", detail: command, hit };
        }
        if (decl.verdict === "allow") {
          this.breaker.resetConsecutive(sessionId);
          return { verdict: "allow", stage: "P1", reason: decl.reason || "declarative-allow", hit: null };
        }
        if (decl.verdict === "ask") {
          const hit = { ask: true, reason: decl.reason || "declarative-ask", detail: command, snippet: command, ruleId: decl.ruleId };
          return { verdict: "ask", stage: "P4", reason: decl.reason || "declarative-ask", detail: command, hit };
        }
      }
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
      if (this.ledger) this.ledger.record(sessionId, "breaker", { reason: "circuit-breaker-tripped", tool: toolName });
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
        // Classifier error fails closed to P4 Ask (#111: does not trip breaker)
        if (this.ledger) this.ledger.record(sessionId, "error", { reason: "classifier-error", detail: String(err && err.message || err), tool: toolName });
        return { verdict: "ask", stage: "P4", reason: "classifier-error", detail: String(err && err.message || err), hit: null };
      }
    }

    // Default verdict for unclassified commands (#163)
    if (this.defaultVerdict === "ask") {
      const askHit = { ask: true, reason: "unmatched-ask", snippet: command || toolName };
      return { verdict: "ask", stage: "P4", reason: "unmatched-ask", hit: askHit };
    }
    return { verdict: "allow", stage: "P2", reason: "unmatched-allow", hit };
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

  getLedgerSummary(sessionId) {
    return this.ledger ? this.ledger.getSummary(sessionId) : null;
  }

  isRetryExhausted(sessionId) {
    return this.retryGuard ? this.retryGuard.isExhausted(sessionId) : false;
  }

  clearCache() {
    if (this.cache) this.cache.clear();
  }

  resume(sessionId, reason) {
    if (this.retryGuard) this.retryGuard.reset(sessionId);
    if (this.cache) this.cache.clearSession(sessionId);
    return this.breaker.resume(sessionId, reason);
  }
}
