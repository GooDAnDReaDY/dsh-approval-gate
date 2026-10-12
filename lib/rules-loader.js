// lib/rules-loader.js
// Cascading declarative YAML rules loader and evaluator for dsh-approval-gate (#38, #45, #44, #93).
// Evaluates rules cascading from workspace (.dsh/rules.yaml), user (~/.dsh/rules.yaml) and builtin threats.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseYaml } from "./yaml-parser.js";
import { evaluateWhen } from "./when-matcher.js";
import { HotwordsMatcher } from "./hotwords.js";

export const BUILTIN_RULES_FILE = path.join("rules", "builtin-high-risk.yaml");
export const WORKSPACE_RULES_REL = path.join(".dsh", "rules.yaml");
export const USER_RULES_REL = path.join(".dsh", "rules.yaml");

/**
 * @typedef {Object} CompiledRule
 * @property {string} id
 * @property {string} [tool]
 * @property {RegExp} regex
 * @property {"allow" | "deny" | "ask"} verdict
 * @property {string} reason
 * @property {string} [description]
 * @property {Record<string, any>} [when]
 * @property {string} source - "workspace" | "user" | "builtin"
 */

export class DeclarativeRulesEngine {
  /**
   * @param {{
   *   workspaceDir?: string,
   *   userHomeDir?: string,
   *   builtinCatalogPath?: string,
   *   customRules?: any[],
   *   hotwords?: HotwordsMatcher
   * }} [options]
   */
  constructor(options = {}) {
    this.workspaceDir = options.workspaceDir || "";
    this.userHomeDir = options.userHomeDir || (os.homedir ? os.homedir() : (process.env.HOME || process.env.USERPROFILE || ""));
    this.builtinCatalogPath = options.builtinCatalogPath || "";
    this.hotwords = options.hotwords || new HotwordsMatcher();

    /** @type {CompiledRule[]} */
    this.rules = [];
    this.load(options);
  }

  /**
   * Loads and merges all rule sources (workspace -> user -> builtin).
   *
   * @param {{ customRules?: any[] }} [options]
   */
  load(options = {}) {
    this.rules = [];
    const rawList = [];

    // 1. Workspace local rules (.dsh/rules.yaml)
    if (this.workspaceDir) {
      const wsPath = path.isAbsolute(this.workspaceDir)
        ? path.join(this.workspaceDir, WORKSPACE_RULES_REL)
        : path.resolve(this.workspaceDir, WORKSPACE_RULES_REL);
      const wsRules = this._loadFile(wsPath, "workspace");
      rawList.push(...wsRules);
    }

    // 2. User global rules (~/.dsh/rules.yaml)
    if (this.userHomeDir) {
      const userPath = path.join(this.userHomeDir, USER_RULES_REL);
      const userRules = this._loadFile(userPath, "user");
      rawList.push(...userRules);
    }

    // 3. Builtin threat catalog
    const builtinPath = this.builtinCatalogPath || path.resolve(process.cwd(), BUILTIN_RULES_FILE);
    const builtinRules = this._loadFile(builtinPath, "builtin");
    rawList.push(...builtinRules);

    // 4. In-memory / custom rules passed via options
    if (Array.isArray(options.customRules)) {
      rawList.unshift(...options.customRules.map((r) => ({ ...r, source: "custom" })));
    }

    // Compile and deduplicate by rule ID (first defined wins!)
    const seenIds = new Set();
    for (const r of rawList) {
      if (!r || !r.id || !r.verdict) continue;
      if (seenIds.has(r.id)) continue;
      seenIds.add(r.id);

      const patternStr = r.pattern || r.regex || r.command;
      if (!patternStr) continue;

      try {
        const regex = patternStr instanceof RegExp ? patternStr : new RegExp(patternStr, r.flags || "");
        this.rules.push({
          id: String(r.id),
          tool: r.tool ? String(r.tool).toLowerCase() : undefined,
          regex,
          verdict: r.verdict,
          reason: r.reason || r.id,
          description: r.description,
          when: r.when,
          source: r.source || "custom",
        });
      } catch {
        // Invalid regex in user file must not crash the loader
      }
    }
  }

  /**
   * Safely reads and parses a rules file.
   * @private
   */
  _loadFile(filePath, source) {
    if (!filePath || !fs.existsSync(filePath)) return [];
    try {
      const text = fs.readFileSync(filePath, "utf8");
      const doc = parseYaml(text);
      const rules = Array.isArray(doc) ? doc : (doc && Array.isArray(doc.rules) ? doc.rules : []);
      return rules.map((r) => ({ ...r, source }));
    } catch {
      return [];
    }
  }

  /**
   * Evaluates a command against the declarative rule chain.
   *
   * @param {string} toolName
   * @param {string} command
   * @param {{ os?: string, branch?: string, env?: Record<string, string>, cwd?: string }} [context]
   * @returns {{ match: boolean, ruleId?: string, verdict?: "allow"|"deny"|"ask", reason?: string, source?: string }}
   */
  evaluate(toolName, command, context = {}) {
    if (!command || typeof command !== "string") {
      return { match: false };
    }

    const normTool = String(toolName || "").toLowerCase();
    const envContext = { ...context, tool: normTool };

    for (let i = 0; i < this.rules.length; i += 1) {
      const rule = this.rules[i];

      // Tool filter
      if (rule.tool && rule.tool !== normTool) {
        continue;
      }

      // Context predicate (when) filter
      if (rule.when && !evaluateWhen(rule.when, envContext)) {
        continue;
      }

      // Pattern match
      if (rule.regex.test(command)) {
        return {
          match: true,
          ruleId: rule.id,
          verdict: rule.verdict,
          reason: rule.reason,
          source: rule.source,
        };
      }
    }

    return { match: false };
  }

  get ruleCount() {
    return this.rules.length;
  }
}
