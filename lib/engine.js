// lib/engine.js
// 5-tier Security Decision Engine for dsh-approval-gate (P0-P4 Waterfall).

import { BandsEngine } from "./bands.js";
import { CircuitBreaker } from "./breaker.js";
import { SessionGrantStore } from "./grants.js";
import { inspectExecution } from "./inspect.js";
import { VerdictCache } from "./cache.js";
import { RetryExhaustionGuard } from "./retry-exhaustion.js";
import { QualityLedger } from "./ledger.js";
import { AuditLogger } from "./audit-log.js";
import { DeclarativeRulesEngine } from "./rules-loader.js";
import { BlockCounters } from "./counters.js";
import { ContractGuard } from "./contract-guard.js";
import { OverengineeringGuard } from "./overengineering.js";
import { extractFilePath, DEFAULT_FILE_WRITE_TOOLS } from "./dispatcher.js";
import { categorizeRiskBucket, extractRiskTags } from "./risk.js";
import { ClassifierLatencyTracker } from "./latency.js";
import { ArtifactRegistry } from "./artifacts.js";
import { isRmCommand, extractRmTargets, suggestTrashAlternative } from "./trash.js";
import { VersionGuard } from "./version-guard.js";
import { loadAgentsRules, evaluateAgentsRules } from "./agents-parser.js";

/**
 * Determine whether an operation belongs to a critical risk category requiring lockedAsk (#52).
 * Locked ask operations can never be auto-approved by unattended timeouts or fallback heuristics.
 *
 * @param {string} [toolName]
 * @param {string} [command]
 * @param {any} [execution]
 * @returns {boolean}
 */
export function isCriticalOperation(toolName, command, execution) {
  const cmd = String(command || "").trim();
  const tool = String(toolName || "").trim();
  if (!cmd && !tool) return false;

  // 1. Root and privilege escalation
  if (/^(sudo|su|doas)\b/i.test(cmd)) return true;
  if (/\b(chmod\s+(-[a-zA-Z]*\s+)?777|chown\s+(-[a-zA-Z]*\s+)?root)\b/i.test(cmd)) return true;

  // 2. Recursive or bulk destructive deletion
  if (/\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+|--recursive\s+)/i.test(cmd)) return true;
  if (/\b(shred|wipefs)\b/i.test(cmd)) return true;

  // 3. Sensitive credentials and SSH access
  if (/(\.ssh\/(id_|authorized_keys|known_hosts)|\.gnupg\/|\/etc\/shadow)/i.test(cmd)) return true;

  // 4. Raw disk and filesystem manipulation
  if (/\b(mkfs|fdisk|parted)\b/i.test(cmd)) return true;
  if (/\bdd\s+.*of=\/dev\/(sd[a-z]|nvme|vd[a-z]|hd[a-z]|loop)/i.test(cmd)) return true;

  // 5. Remote shell piping and reverse shells
  if (/curl\s+.*\|\s*(bash|sh|python|perl)/i.test(cmd)) return true;
  if (/\b(nc|ncat|netcat)\s+.*-e\s+/i.test(cmd)) return true;
  if (/>&\s*\/dev\/tcp\//i.test(cmd)) return true;

  // 6. System halts and service shutdowns
  if (/\b(shutdown|reboot|poweroff|halt|init\s+0)\b/i.test(cmd)) return true;
  if (/systemctl\s+(stop|disable|mask)\s+(sshd|systemd|ufw|iptables)/i.test(cmd)) return true;

  // 7. Protected file writes via tools
  if (tool === "write_to_file" || tool === "edit" || tool === "replace_file_content" || tool === "str_replace_editor") {
    const target = execution && execution.arguments && (execution.arguments.TargetFile || execution.arguments.target_file || execution.arguments.path || "");
    if (typeof target === "string" && /(\/etc\/|\.ssh\/|\/boot\/|\/sys\/|\/proc\/)/i.test(target)) {
      return true;
    }
  }

  return false;
}

export class SecurityEngine {
  /** @param {Record<string, any>} [options] */
  constructor(options = {}) {
    this.bands = options.bands || new BandsEngine(options);
    this.breaker = options.breaker || new CircuitBreaker(options);
    this.inspectConfig = options.inspectConfig || {};
    this.classifier = options.classifier || null;
    this.timeoutPolicy = options.timeoutPolicy === "permissive" ? "permissive" : "strict";
    this.grantRegistry = options.grantRegistry || new SessionGrantStore(options);
    this.defaultVerdict = options.defaultVerdict || "allow";

    this.dryRun = Boolean(options.dryRun || options.shadowMode);
    this.auditFailClosed = options.auditFailClosed === true;
    this.cache = options.cache !== undefined ? options.cache : new VerdictCache();
    this.retryGuard = options.retryGuard !== undefined ? options.retryGuard : new RetryExhaustionGuard();
    this.ledger = options.ledger !== undefined ? options.ledger : new QualityLedger();
    this.counters = options.counters || new BlockCounters();
    this.auditLogger = options.auditLogger !== undefined ? options.auditLogger : new AuditLogger({
      failClosed: this.auditFailClosed,
    });
    if (this.auditFailClosed && this.auditLogger) {
      this.auditLogger.failClosed = true;
    }
    this.declarativeRules = options.declarativeRules || new DeclarativeRulesEngine({
      workspaceDir: this.inspectConfig?.workspaceDir,
    });
    this.contractGuard = options.contractGuard !== undefined
      ? options.contractGuard
      : (options.taskContract ? new ContractGuard(options.taskContract) : null);
    this.overengineeringGuard = options.overengineeringGuard !== undefined
      ? options.overengineeringGuard
      : (options.maxFilesPerSession !== undefined || options.maxCreatedFilesPerSession !== undefined
          ? new OverengineeringGuard(options)
          : null);
    this.latencyTracker = options.latencyTracker || new ClassifierLatencyTracker(options);
    this.artifactRegistry = options.artifactRegistry !== undefined
      ? options.artifactRegistry
      : new ArtifactRegistry({ workspaceDir: this.inspectConfig?.workspaceDir });
    this.versionGuard = options.versionGuard !== undefined
      ? options.versionGuard
      : new VersionGuard({ workspaceDir: this.inspectConfig?.workspaceDir });
    this.agentsRules = options.agentsRules !== undefined
      ? options.agentsRules
      : (loadAgentsRules(this.inspectConfig?.workspaceDir)?.rules || null);
  }

  /**
   * Evaluates an execution request through the P0-P4 waterfall.
   *
   * @param {{ name: string, arguments?: any }} execution - Tool call
   * @param {{ sessionId?: string, knobs?: any, cwd?: string }} [context] - Context options
   * @returns {{ verdict: "allow" | "deny" | "ask", stage: "P0" | "P1" | "P2" | "P3" | "P4", reason: string, detail?: string, hit?: any, dryRun?: boolean, cached?: boolean, lockedAsk?: boolean, lockedReason?: string, auditFailed?: boolean }}
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
        if (this.counters) this.counters.record(exhDecision, execution);
        if (this.auditLogger) this.auditLogger.appendAuditLine({ sessionId, execution, decision: exhDecision, dryRun: this.dryRun });

        if (this.dryRun) {
          return this._enrichDecision({ verdict: "allow", stage: "P0", dryRun: true, originalVerdict: "deny", reason: "retry-exhaustion", detail: exhHit.detail, hit: exhHit }, execution, context);
        }
        return this._enrichDecision(exhDecision, execution, context);
      }

      // Check Verdict Cache (#63, #119)
      const cacheKey = this.cache ? this.cache.makeKey(execution, context) : null;
      if (this.cache && cacheKey) {
        const cached = this.cache.get(cacheKey);
        if (cached) {
          if (this.dryRun && (cached.verdict === "deny" || cached.verdict === "ask")) {
            return this._enrichDecision({
              verdict: "allow",
              stage: cached.stage,
              dryRun: true,
              originalVerdict: cached.verdict,
              reason: cached.reason,
              detail: cached.detail,
              hit: cached.hit,
              cached: true,
            }, execution, context);
          }
          if (this.counters) this.counters.record(cached, execution);
          return this._enrichDecision(cached, execution, context);
        }
      }

      let decision = this._evaluateWaterfall(execution, context, sessionId, toolName, command);
      this._enrichDecision(decision, execution, context);

      // Post-decision hooks: ledger, retryGuard, cache
      if (decision.verdict === "deny") {
        if (this.retryGuard) this.retryGuard.recordVerdict(sessionId, execution, "deny");
        if (this.ledger) this.ledger.record(sessionId, "deny", { reason: decision.reason, detail: decision.detail, tool: toolName });
        if (this.cache && cacheKey) this.cache.set(cacheKey, decision, { sessionId });
      } else if (decision.verdict === "allow") {
        if (this.retryGuard) this.retryGuard.recordVerdict(sessionId, execution, "allow");
        if (this.ledger) this.ledger.record(sessionId, "allow", { reason: decision.reason, detail: decision.detail, tool: toolName });
        if (this.cache && cacheKey) this.cache.set(cacheKey, decision, { sessionId });
        if (this.artifactRegistry) {
          const targetPath = extractFilePath(execution && execution.arguments);
          if (targetPath) this.artifactRegistry.recordArtifact(sessionId, targetPath);
        }
      } else if (decision.verdict === "ask") {
        if (this.ledger) this.ledger.record(sessionId, "ask", { reason: decision.reason, detail: decision.detail, tool: toolName });
      }

      // Audit Logger (#56) with fail-closed audit verification (#53)
      if (this.auditLogger) {
        const auditOk = this.auditLogger.appendAuditLine({ sessionId, execution, decision, dryRun: this.dryRun });
        if (!auditOk && this.auditFailClosed && !this.dryRun) {
          const auditDenyHit = {
            deny: true,
            reason: "fail-closed-audit",
            detail: "Audit log write failed. Execution blocked by fail-closed audit policy (#53).",
            snippet: command || toolName,
          };
          decision = {
            verdict: "deny",
            stage: "P0",
            reason: "fail-closed-audit",
            detail: auditDenyHit.detail,
            hit: auditDenyHit,
            auditFailed: true,
          };
          this._enrichDecision(decision, execution, context);
        }
      }

      // Record block counters (#48)
      if (this.counters) {
        this.counters.record(decision, execution);
      }

      // Shadow Mode (#128)
      if (this.dryRun && (decision.verdict === "deny" || decision.verdict === "ask")) {
        return this._enrichDecision({
          verdict: "allow",
          stage: decision.stage,
          dryRun: true,
          originalVerdict: decision.verdict,
          reason: decision.reason,
          detail: decision.detail,
          hit: decision.hit,
          lockedAsk: decision.lockedAsk,
        }, execution, context);
      }

      return decision;
    } catch (err) {
      const errDecision = {
        verdict: "ask",
        stage: "P4",
        reason: "inspect-error",
        detail: String(err && err.message || err),
        hit: { ask: true, reason: "inspect-error", detail: String(err && err.message || err) },
      };
      if (this.counters) this.counters.record(errDecision, execution);
      return this._enrichDecision(errDecision, execution, context);
    }
  }

  /**
   * Asynchronous evaluation supporting async classifiers and latency SLA tracking (#129, #118, #57).
   *
   * @param {{ name: string, arguments?: any }} execution
   * @param {{ sessionId?: string, knobs?: any, cwd?: string }} [context]
   * @returns {Promise<any>}
   */
  async decideAsync(execution, context = {}) {
    if (this.classifier) {
      let resolvedVerdict = null;
      let caughtError = null;

      if (this.latencyTracker && this.latencyTracker.isDegraded()) {
        resolvedVerdict = {
          verdict: "ask",
          reason: "classifier-sla-fallback",
          detail: `Classifier latency p95 (${this.latencyTracker.getP95()}ms) exceeded SLA (${this.latencyTracker.slaMs}ms) (#57)`,
        };
      } else {
        const start = Date.now();
        try {
          if (typeof this.classifier.classify === "function") {
            resolvedVerdict = await this.classifier.classify(execution, context);
          } else if (typeof this.classifier === "function") {
            const res = this.classifier(execution, context);
            resolvedVerdict = res && typeof res.then === "function" ? await res : res;
          }
          if (this.latencyTracker) {
            this.latencyTracker.recordSample(Date.now() - start);
          }
        } catch (err) {
          caughtError = err;
          if (this.latencyTracker) {
            this.latencyTracker.recordSample(Date.now() - start);
          }
        }
      }

      const originalClassifier = this.classifier;
      if (caughtError) {
        this.classifier = () => { throw caughtError; };
      } else {
        this.classifier = () => resolvedVerdict;
      }
      try {
        return this.decide(execution, context);
      } finally {
        this.classifier = originalClassifier;
      }
    }
    return this.decide(execution, context);
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
          return { verdict: "allow", stage: "P1", reason: decl.reason || "declarative-allow", hit: null, ruleId: decl.ruleId };
        }
        if (decl.verdict === "ask") {
          const hit = { ask: true, reason: decl.reason || "declarative-ask", detail: command, snippet: command, ruleId: decl.ruleId };
          const res = { verdict: "ask", stage: "P4", reason: decl.reason || "declarative-ask", detail: command, hit, ruleId: decl.ruleId };
          this._applyLockedAskIfCritical(res, toolName, command, execution);
          return res;
        }
      }
    }

    // AGENTS.md rules (#91)
    if (this.agentsRules) {
      const ag = evaluateAgentsRules(this.agentsRules, execution, extractFilePath(execution && execution.arguments));
      if (ag.match) {
        this.breaker.countDeny(sessionId);
        const agHit = { deny: true, reason: ag.reason, detail: ag.rule?.text, snippet: command || toolName };
        return { verdict: "deny", stage: "P0", reason: ag.reason, detail: ag.rule?.text, hit: agHit };
      }
    }

    // Inspect execution for hard denials and syntax checks
    const hit = inspectExecution(execution, this.inspectConfig);
    if (hit.deny) {
      this.breaker.countDeny(sessionId);
      return { verdict: "deny", stage: "P0", reason: hit.reason || "hard-deny", detail: hit.detail || hit.snippet, hit };
    }

    // Task Contract Guard (#87)
    if (this.contractGuard) {
      const cg = this.contractGuard.check(toolName, command, execution);
      if (!cg.allowed) {
        const cgHit = {
          ask: true,
          reason: cg.reason || "contract-violation",
          detail: cg.detail,
          snippet: cg.snippet || command || toolName,
        };
        const res = { verdict: "ask", stage: "P4", reason: cg.reason || "contract-violation", detail: cg.detail, hit: cgHit };
        this._applyLockedAskIfCritical(res, toolName, command, execution);
        return res;
      }
    }

    // Overengineering Guard (#89)
    const fileTools = new Set(this.inspectConfig?.fileWriteTools || DEFAULT_FILE_WRITE_TOOLS);
    if (this.overengineeringGuard && typeof toolName === "string" && fileTools.has(toolName)) {
      const targetPath = extractFilePath(execution ? execution.arguments : undefined);
      if (targetPath) {
        const og = this.overengineeringGuard.checkAndRecord(sessionId, targetPath);
        if (!og.allowed) {
          const ogHit = {
            ask: true,
            reason: og.reason || "overengineering-file-limit",
            detail: og.detail,
            snippet: targetPath,
          };
          const res = { verdict: "ask", stage: "P4", reason: og.reason || "overengineering-file-limit", detail: og.detail, hit: ogHit };
          this._applyLockedAskIfCritical(res, toolName, command, execution);
          return res;
        }
      }
    }

    // VersionGuard: major version bump control (#95)
    if (this.versionGuard && typeof toolName === "string" && fileTools.has(toolName)) {
      const targetPath = extractFilePath(execution ? execution.arguments : undefined);
      const content = execution?.arguments?.content || execution?.arguments?.code || execution?.arguments?.CodeContent || execution?.arguments?.text;
      if (targetPath && content) {
        const vg = this.versionGuard.inspectWrite(targetPath, content);
        if (vg.majorBump) {
          const vgHit = { ask: true, reason: "major-version-bump", detail: vg.detail, snippet: targetPath };
          const res = { verdict: "ask", stage: "P4", reason: "major-version-bump", detail: vg.detail, hit: vgHit };
          this._applyLockedAskIfCritical(res, toolName, command, execution);
          return res;
        }
      }
    }

    // P1: Session Artifact Cleanup Whitelist (#100)
    if (command && isRmCommand(command)) {
      const targets = extractRmTargets(command);
      if (targets.length > 0 && this.artifactRegistry && this.artifactRegistry.areAllSessionArtifacts(sessionId, targets)) {
        this.breaker.resetConsecutive(sessionId);
        const artHit = { allow: true, reason: "session-artifact-cleanup", snippet: command };
        return { verdict: "allow", stage: "P1", reason: "session-artifact-cleanup", hit: artHit };
      }
    }

    // P1: Session Grants
    if (this.grantRegistry && typeof this.grantRegistry.decide === "function") {
      const grantMatch = this.grantRegistry.decide(toolName, execution.arguments, context);
      if (grantMatch === "allow") {
        this.breaker.resetConsecutive(sessionId);
        return { verdict: "allow", stage: "P1", reason: "session-grant", hit };
      }
    }

    // If Circuit Breaker is tripped, force P4 Human Ask
    if (this.breaker.isTripped(sessionId)) {
      if (this.ledger) this.ledger.record(sessionId, "breaker", { reason: "circuit-breaker-tripped", tool: toolName });
      const breakerHit = {
        ask: true,
        reason: "circuit-breaker-tripped",
        detail: "Circuit breaker tripped due to repeated security denials. Manual confirmation required.",
        snippet: command || toolName,
      };
      const res = {
        verdict: "ask",
        stage: "P4",
        reason: "circuit-breaker-tripped",
        detail: breakerHit.detail,
        hit: breakerHit,
      };
      this._applyLockedAskIfCritical(res, toolName, command, execution);
      return res;
    }

    // P4: Human Ask if syntax is unparseable or uncertain
    if (hit.ask) {
      const res = { verdict: "ask", stage: "P4", reason: hit.reason || "uncertain-syntax", detail: hit.detail || hit.snippet, hit };
      this._applyLockedAskIfCritical(res, toolName, command, execution);
      return res;
    }

    // P2: Static Rules / Safe Allow
    if (bandVerdict === "allow") {
      this.breaker.resetConsecutive(sessionId);
      return { verdict: "allow", stage: "P2", reason: "safe-allow", hit };
    }

    // P3: Optional Semantic Classifier
    if (this.classifier) {
      try {
        const cls = typeof this.classifier === "function"
          ? this.classifier(execution, context)
          : (typeof this.classifier.classify === "function" ? this.classifier.classify(execution, context) : null);
        if (cls && cls.verdict === "allow") {
          this.breaker.resetConsecutive(sessionId);
          return { verdict: "allow", stage: "P3", reason: cls.reason || "classifier-allow", hit };
        }
        if (cls && cls.verdict === "deny") {
          this.breaker.countDeny(sessionId);
          const clsHit = { deny: true, reason: cls.reason || "classifier-deny", snippet: command || toolName };
          return { verdict: "deny", stage: "P3", reason: cls.reason || "classifier-deny", detail: cls.reason, hit: clsHit };
        }
        if (cls && cls.verdict === "ask") {
          const res = { verdict: "ask", stage: "P4", reason: cls.reason || "classifier-ask", detail: cls.detail || cls.reason, hit: null };
          this._applyLockedAskIfCritical(res, toolName, command, execution);
          return res;
        }
      } catch (err) {
        // Classifier error fails closed to P4 Ask or handles timeoutPolicy (#118, #111)
        if (this.ledger) this.ledger.record(sessionId, "error", { reason: "classifier-error", detail: String(err && err.message || err), tool: toolName });
        const isTimeout = CircuitBreaker.isFaultOrTimeout(err) || Boolean(err && (err.isTimeout || err.timeout));
        if (isTimeout && this.timeoutPolicy === "permissive") {
          const critical = isCriticalOperation(toolName, command, execution);
          if (!critical && bandVerdict !== "deny") {
            return { verdict: "allow", stage: "P3", reason: "classifier-timeout-fallback-permissive", hit: null };
          }
          const res = { verdict: "ask", stage: "P4", reason: "classifier-timeout-fallback-strict", detail: String(err && err.message || err), hit: null };
          this._applyLockedAskIfCritical(res, toolName, command, execution);
          return res;
        }
        const reason = isTimeout ? "classifier-timeout-strict" : "classifier-error";
        const res = { verdict: "ask", stage: "P4", reason, detail: String(err && err.message || err), hit: null };
        this._applyLockedAskIfCritical(res, toolName, command, execution);
        return res;
      }
    }

    // Default verdict for unclassified commands (#163)
    if (this.defaultVerdict === "ask") {
      const askHit = { ask: true, reason: "unmatched-ask", snippet: command || toolName };
      const res = { verdict: "ask", stage: "P4", reason: "unmatched-ask", hit: askHit };
      this._applyLockedAskIfCritical(res, toolName, command, execution);
      return res;
    }
    return { verdict: "allow", stage: "P2", reason: "unmatched-allow", hit };
  }

  /**
   * Helper to check and mark lockedAsk for critical operations (#52).
   * @private
   */
  _applyLockedAskIfCritical(decision, toolName, command, execution) {
    if (decision && decision.verdict === "ask" && isCriticalOperation(toolName, command, execution)) {
      decision.lockedAsk = true;
      decision.lockedReason = "critical-operation";
      if (decision.hit) {
        decision.hit.lockedAsk = true;
      }
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

  getLedgerSummary(sessionId) {
    return this.ledger ? this.ledger.getSummary(sessionId) : null;
  }

  isRetryExhausted(sessionId) {
    return this.retryGuard ? this.retryGuard.isExhausted(sessionId) : false;
  }

  clearCache() {
    if (this.cache) this.cache.clear();
  }

  getCounters() {
    return this.counters ? this.counters.getSnapshot() : null;
  }

  resetCounters() {
    if (this.counters) this.counters.reset();
  }

  resume(sessionId, reason) {
    if (this.retryGuard) this.retryGuard.reset(sessionId);
    if (this.overengineeringGuard) this.overengineeringGuard.reset(sessionId);
    if (this.cache) this.cache.clearSession(sessionId);
    return this.breaker.resume(sessionId, reason);
  }

  /**
   * Enriches decision with risk bucket (#58) and operational risk tags (#70).
   * @private
   */
  _enrichDecision(decision, execution, context) {
    if (!decision) return decision;
    if (!decision.riskBucket) decision.riskBucket = categorizeRiskBucket(execution, context);
    if (!decision.riskTags || !Array.isArray(decision.riskTags)) decision.riskTags = extractRiskTags(execution, context);
    const command = execution && execution.arguments && execution.arguments.command;
    if (command && isRmCommand(command)) {
      decision.trashAlternative = suggestTrashAlternative(command, this.inspectConfig?.workspaceDir, context?.sessionId);
    }
    return decision;
  }

  getArtifacts(sessionId) {
    return this.artifactRegistry ? this.artifactRegistry.getArtifacts(sessionId) : [];
  }

  clearArtifacts(sessionId) {
    if (this.artifactRegistry) this.artifactRegistry.clearSession(sessionId);
  }

  getLatencyMetrics() {
    return this.latencyTracker ? this.latencyTracker.getMetrics() : null;
  }

  resetLatencyTracker() {
    if (this.latencyTracker) this.latencyTracker.reset();
  }
}


