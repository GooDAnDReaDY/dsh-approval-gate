// lib/counters.js
// In-memory block counters and rule hit frequency metrics for dsh-approval-gate (#48).
// Tracks total evaluated decisions, verdicts, pipeline stages, top rules, and risk categories.

/**
 * Categorize a decision reason into a high-level risk category.
 * @param {string} [reason]
 * @returns {string}
 */
export function categorizeReason(reason) {
  const r = String(reason || "").toLowerCase();
  if (r.includes("band") || r.includes("hard-deny") || r.includes("rm") || r.includes("destructive") || r.includes("delete") || r.includes("drop") || r.includes("truncate") || r.includes("wipe") || r.includes("clean")) {
    return "destructive";
  }
  if (r.includes("privilege") || r.includes("sudo") || r.includes("systemctl") || r.includes("reboot") || r.includes("service") || r.includes("kill") || r.includes("chmod") || r.includes("chown")) {
    return "system";
  }
  if (r.includes("network") || r.includes("egress") || r.includes("curl") || r.includes("wget") || r.includes("ssh") || r.includes("socket") || r.includes("connect")) {
    return "network";
  }
  if (r.includes("secret") || r.includes("env") || r.includes("token") || r.includes("key") || r.includes("credential") || r.includes("password")) {
    return "secrets";
  }
  if (r.includes("persist") || r.includes("crontab") || r.includes("profile") || r.includes("bashrc") || r.includes("startup")) {
    return "persistence";
  }
  if (r.includes("syntax") || r.includes("parser") || r.includes("subshell") || r.includes("uncertain")) {
    return "syntax";
  }
  return "other";
}

export class BlockCounters {
  constructor() {
    this.reset();
  }

  /**
   * Reset all counters to zero.
   */
  reset() {
    this.totalEvaluated = 0;
    this.byVerdict = {
      allow: 0,
      deny: 0,
      ask: 0,
    };
    this.byStage = {
      P0: 0,
      P1: 0,
      P2: 0,
      P3: 0,
      P4: 0,
    };
    this.byCategory = {
      destructive: 0,
      system: 0,
      network: 0,
      secrets: 0,
      persistence: 0,
      syntax: 0,
      other: 0,
    };
    /** @type {Map<string, { hits: number, lastHitAt: number, lastVerdict: string, category: string }>} */
    this.byRule = new Map();
  }

  /**
   * Record a decision event.
   * @param {{ verdict: string, stage?: string, reason?: string, ruleId?: string }} decision
   * @param {any} [execution]
   */
  record(decision, execution) {
    if (!decision || typeof decision !== "object") return;

    this.totalEvaluated++;

    const v = decision.verdict;
    if (v === "allow" || v === "deny" || v === "ask") {
      this.byVerdict[v] = (this.byVerdict[v] || 0) + 1;
    }

    const st = decision.stage;
    if (st && this.byStage[st] !== undefined) {
      this.byStage[st] = (this.byStage[st] || 0) + 1;
    }

    const ruleKey = String(decision.ruleId || decision.reason || "unspecified").trim();
    const category = categorizeReason(decision.reason);

    this.byCategory[category] = (this.byCategory[category] || 0) + 1;

    const existing = this.byRule.get(ruleKey);
    const now = Date.now();
    if (existing) {
      existing.hits++;
      existing.lastHitAt = now;
      existing.lastVerdict = decision.verdict;
      existing.category = category;
    } else {
      this.byRule.set(ruleKey, {
        hits: 1,
        lastHitAt: now,
        lastVerdict: decision.verdict,
        category,
      });
    }
  }

  /**
   * Get stats for a specific rule.
   * @param {string} ruleId
   * @returns {{ rule: string, hits: number, lastHitAt: number, lastVerdict: string, category: string } | null}
   */
  getRuleStats(ruleId) {
    const s = this.byRule.get(String(ruleId || "").trim());
    if (!s) return null;
    return { rule: ruleId, ...s };
  }

  /**
   * Get complete snapshot of all counters for settings UI / API.
   * @returns {{
   *   total: number,
   *   byVerdict: { allow: number, deny: number, ask: number },
   *   byStage: { P0: number, P1: number, P2: number, P3: number, P4: number },
   *   byCategory: Record<string, number>,
   *   rules: Array<{ rule: string, hits: number, lastHitAt: number, lastVerdict: string, category: string }>
   * }}
   */
  getSnapshot() {
    const rulesList = Array.from(this.byRule.entries())
      .map(([rule, data]) => ({ rule, ...data }))
      .sort((a, b) => b.hits - a.hits);

    return {
      total: this.totalEvaluated,
      byVerdict: { ...this.byVerdict },
      byStage: { ...this.byStage },
      byCategory: { ...this.byCategory },
      rules: rulesList,
    };
  }
}
