// lib/bands.js
// Two-band deterministic filtering engine for dsh-approval-gate.
// Band 0: Hard Deny (fast regexes for exfiltration, fork-bombs, disk wipes)
// Band 1: Safe Allow (prefix globs & curated safe read-only inspection commands and tools)

export const DEFAULT_DENY_PATTERNS = Object.freeze([
  /\b(?:nc|ncat|netcat)\s+.*-e\s+/i,
  /\/dev\/tcp\/\d+\.\d+\.\d+\.\d+\/\d+/i,
  /\/dev\/udp\/\d+\.\d+\.\d+\.\d+\/\d+/i,
  /\bmkfs(?:\.[a-z0-9]+)?\s+/i,
  /\bdd\s+.*of=\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|loop|mapper)/i,
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
  /\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\s+\/(?!tmp)/i,
  /\bchown\s+(?:-R\s+)?root\b/i,
  /\b(?:shutdown|reboot|poweroff|halt)\s*(?:-|$)/i,
]);

export const DEFAULT_ALLOW_GLOBS = Object.freeze([
  // Git inspection commands
  "git status*",
  "git diff*",
  "git log*",
  "git branch*",
  "git show*",
  "git remote*",
  "git tag*",
  "git rev-parse*",

  // File viewing & analysis
  "cat *",
  "head *",
  "tail *",
  "more *",
  "less *",
  "wc *",
  "file *",
  "stat *",
  "diff *",

  // Search & finding
  "grep *",
  "fgrep *",
  "egrep *",
  "rg *",
  "ag *",
  "find *",

  // Directory listing & environment info
  "ls*",
  "dir*",
  "pwd*",
  "which *",
  "whereis *",
  "whoami*",
  "hostname*",
  "uname*",
  "date*",
  "uptime*",
  "echo *",
  "printf *",

  // Language / runtime versions & test runners
  "node --version*",
  "node -v*",
  "npm test*",
  "npm --version*",
  "npm -v*",
  "pnpm test*",
  "pnpm --version*",
  "pnpm -v*",
  "yarn test*",
  "cargo test*",
  "cargo check*",
  "cargo --version*",
  "pytest*",
  "python --version*",
  "python3 --version*",
]);

export const DEFAULT_READ_ONLY_TOOLS = Object.freeze([
  "read",
  "read_file",
  "readFile",
  "read_file_content",
  "view_file",
  "view",
  "show",
  "glob",
  "grep",
  "find_files",
  "find_by_name",
  "search_code",
  "file_search",
  "list_dir",
  "list_directory",
  "directory_list",
  "tree",
  "read_url_content",
  "fetch_web_page",
  "web_search",
  "search_web",
  "list_resources",
  "read_resource",
]);

/**
 * Compile a prefix-glob into an anchored RegExp.
 * @param {string} pattern
 * @returns {RegExp}
 */
export function compileGlob(pattern) {
  let source = "";
  for (const ch of pattern) {
    if (ch === "*") source += ".*";
    else if (ch === "?") source += ".";
    else source += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${source}$`, "i");
}

export class BandsEngine {
  /**
   * @param {{
   *   denyPatterns?: Array<RegExp|string>,
   *   allowGlobs?: Array<RegExp|string>,
   *   readOnlyTools?: Array<string>
   * }} [options]
   */
  constructor(options = {}) {
    this.denyPatterns = (options.denyPatterns || DEFAULT_DENY_PATTERNS).map((p) =>
      typeof p === "string" ? new RegExp(p, "i") : p
    );
    this.allowGlobs = (options.allowGlobs || DEFAULT_ALLOW_GLOBS).map((g) =>
      typeof g === "string" ? compileGlob(g) : g
    );
    this.readOnlyTools = new Set(options.readOnlyTools || DEFAULT_READ_ONLY_TOOLS);
  }

  /**
   * Check if a tool is configured as an unconditional read-only tool.
   * @param {string} tool
   * @returns {boolean}
   */
  isReadOnlyTool(tool) {
    return typeof tool === "string" && this.readOnlyTools.has(tool.trim());
  }

  /**
   * Check if a command matches safe inspection patterns.
   * @param {string} command
   * @returns {boolean}
   */
  isSafeInspectionCommand(command) {
    if (typeof command !== "string" || command.trim() === "") return false;
    const text = command.trim();
    // Chained commands, subshells, substitutions, and redirections cannot match whole-string safe-allow
    if (/[\n;&|`<>]|\$\([\s\S]*\)|\$\{[\s\S]*\}/.test(text)) {
      return false;
    }
    for (const pattern of this.denyPatterns) {
      if (pattern.test(text)) return false;
    }
    for (const glob of this.allowGlobs) {
      if (glob.test(text)) return true;
    }
    return false;
  }

  /**
   * Register an additional read-only tool name.
   * @param {string} tool
   */
  addReadOnlyTool(tool) {
    if (typeof tool === "string" && tool.trim()) {
      this.readOnlyTools.add(tool.trim());
    }
  }

  /**
   * Register an additional allow-glob pattern.
   * @param {string} globPattern
   */
  addAllowGlob(globPattern) {
    if (typeof globPattern === "string" && globPattern.trim()) {
      this.allowGlobs.push(compileGlob(globPattern.trim()));
    }
  }

  /**
   * Evaluates an execution request through Band 0 and Band 1.
   * @param {string} tool - Tool name
   * @param {string} [command] - Normalized command text (for bash)
   * @returns {"deny" | "allow" | "unmatched"}
   */
  evaluate(tool, command) {
    if (this.isReadOnlyTool(tool)) {
      return "allow";
    }

    if (typeof command === "string" && command.trim().length > 0) {
      const text = command.trim();

      // Band 0: Hard Deny
      for (const pattern of this.denyPatterns) {
        if (pattern.test(text)) {
          return "deny";
        }
      }

      // Band 1: Safe Allow (applies strictly to single commands without chaining, subshells or redirects)
      if (!/[\n;&|`<>]|\$\([\s\S]*\)|\$\{[\s\S]*\}/.test(text)) {
        for (const glob of this.allowGlobs) {
          if (glob.test(text)) {
            return "allow";
          }
        }
      }
    }

    return "unmatched";
  }
}

