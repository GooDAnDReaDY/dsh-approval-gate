// lib/bands.js
// Two-band deterministic filtering engine for dsh-approval-gate.
// Band 0: Hard Deny (fast regexes for exfiltration, fork-bombs, disk wipes)
// Band 1: Safe Allow (prefix globs & curated safe inspection commands)

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
  "git status*",
  "git diff*",
  "git log*",
  "git branch*",
  "git show*",
  "ls*",
  "pwd*",
  "cat *",
  "head *",
  "tail *",
  "wc *",
  "which *",
  "whereis *",
  "whoami*",
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
  "echo *",
]);

export const DEFAULT_READ_ONLY_TOOLS = Object.freeze([
  "read",
  "read_file",
  "readFile",
  "view_file",
  "glob",
  "grep",
  "find_files",
  "search_code",
  "file_search",
  "list_dir",
  "list_directory",
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
   * @param {{ denyPatterns?: Array<RegExp|string>, allowGlobs?: Array<RegExp|string>, readOnlyTools?: Array<string> }} [options]
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
   * Evaluates an execution request through Band 0 and Band 1.
   * @param {string} tool - Tool name
   * @param {string} [command] - Normalized command text (for bash)
   * @returns {"deny" | "allow" | "unmatched"}
   */
  evaluate(tool, command) {
    if (this.readOnlyTools.has(tool)) {
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

      // Band 1: Safe Allow
      for (const glob of this.allowGlobs) {
        if (glob.test(text)) {
          return "allow";
        }
      }
    }

    return "unmatched";
  }
}
