// lib/agents-parser.js
// Parser and enforcement for local project safety rules from AGENTS.md / CLAUDE.md (#91).

import fs from "node:fs";
import path from "node:path";

const AGENTS_FILENAMES = ["AGENTS.md", ".dsh/AGENTS.md", "CLAUDE.md"];

const SECURITY_HEADING_REGEX = /^(?:#{1,3})\s*(?:security|safety|rules|constraints|prohibited|forbidden|restrictions|do\s+not|never)\b/i;

const FORBIDDEN_DIRECTIVE_REGEX = /(?:(?:never|do\s+not|don't|prohibit(?:ed)?|forbid(?:den)?|cannot|must\s+not)\s+(?:run|execute|use|modify|delete|touch|access|call|write)|forbidden:\s*|prohibited:\s*)/i;

/**
 * Parses markdown text of AGENTS.md and extracts active security constraints (#91).
 *
 * @param {string} content - Markdown document text
 * @returns {{
 *   rules: Array<{ type: "command" | "path" | "keyword" | "directive", pattern: string, text: string }>,
 *   rawDirectives: string[]
 * }}
 */
export function parseAgentsSecurityRules(content) {
  if (typeof content !== "string" || !content.trim()) {
    return { rules: [], rawDirectives: [] };
  }

  const lines = content.split(/\r?\n/);
  const rules = [];
  const rawDirectives = [];

  let inSecuritySection = false;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    // Check headings
    if (trimmed.startsWith("#")) {
      inSecuritySection = SECURITY_HEADING_REGEX.test(trimmed);
      continue;
    }

    if (!trimmed) continue;

    // Check bullet points or bold directives in security section or explicit global directives
    const isBullet = /^[-*+]\s+/.test(trimmed) || /^\d+\.\s+/.test(trimmed);
    const cleanText = trimmed.replace(/^[-*+]\s+/, "").replace(/^\d+\.\s+/, "").trim();

    if ((inSecuritySection && isBullet) || FORBIDDEN_DIRECTIVE_REGEX.test(cleanText)) {
      rawDirectives.push(cleanText);

      // 1. Check for command / tool restriction: e.g. `Never run rm -rf`, `Do not execute curl`
      const cmdMatch = /(?:run|execute|use|call)\s+(?:`([^`]+)`|"([^"]+)"|([a-zA-Z0-9_\-\.\/]+(?:\s+[a-zA-Z0-9_\-\.\/]+)?))/i.exec(cleanText);
      if (cmdMatch) {
        const cmdPattern = (cmdMatch[1] || cmdMatch[2] || cmdMatch[3]).trim();
        if (cmdPattern && !["to", "the", "a", "an", "any", "this"].includes(cmdPattern.toLowerCase())) {
          rules.push({
            type: "command",
            pattern: cmdPattern,
            text: cleanText,
          });
          continue;
        }
      }

      // 2. Check for path restriction: e.g. `Do not modify package.json`, `Do not touch .env`
      const pathMatch = /(?:modify|edit|delete|write|overwrite|touch)\s+(?:`([^`]+)`|"([^"]+)"|([a-zA-Z0-9_\-\.\/\*]+))/i.exec(cleanText);
      if (pathMatch) {
        const pathPattern = (pathMatch[1] || pathMatch[2] || pathMatch[3]).trim();
        if (pathPattern && !["to", "the", "a", "an", "any", "this"].includes(pathPattern.toLowerCase())) {
          rules.push({
            type: "path",
            pattern: pathPattern,
            text: cleanText,
          });
          continue;
        }
      }

      // 3. Fallback general directive
      rules.push({
        type: "directive",
        pattern: cleanText,
        text: cleanText,
      });
    }
  }

  return { rules, rawDirectives };
}

/**
 * Loads and parses AGENTS.md rules from a workspace directory (#91).
 *
 * @param {string} [workspaceDir]
 * @returns {{ rules: Array<any>, rawDirectives: string[], filePath?: string } | null}
 */
export function loadAgentsRules(workspaceDir) {
  const ws = workspaceDir && typeof workspaceDir === "string" ? workspaceDir : process.cwd();

  for (const rel of AGENTS_FILENAMES) {
    const fullPath = path.resolve(ws, rel);
    try {
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, "utf-8");
        const parsed = parseAgentsSecurityRules(content);
        return {
          rules: parsed.rules,
          rawDirectives: parsed.rawDirectives,
          filePath: fullPath,
        };
      }
    } catch {
      // ignore read faults
    }
  }

  return null;
}

/**
 * Evaluates an execution against active AGENTS.md rules (#91).
 *
 * @param {Array<any>} rules - Parsed rules from parseAgentsSecurityRules
 * @param {{ name?: string, arguments?: any }} execution
 * @param {string} [targetPath]
 * @returns {{ match: boolean, reason?: string, rule?: any }}
 */
export function evaluateAgentsRules(rules, execution, targetPath) {
  if (!Array.isArray(rules) || rules.length === 0) {
    return { match: false };
  }

  const args = execution && execution.arguments;
  const command = (args && typeof args === "object" && typeof args.command === "string")
    ? args.command.trim()
    : (typeof args === "string" ? args.trim() : "");
  const toolName = String((execution && execution.name) || "").trim();
  const pathToCheck = String(targetPath || (args && (args.path || args.file || args.TargetFile)) || "").trim();

  for (const rule of rules) {
    if (rule.type === "command") {
      const pat = rule.pattern.toLowerCase();
      if (command && command.toLowerCase().includes(pat)) {
        return {
          match: true,
          reason: "agents-md-prohibited-command",
          rule,
        };
      }
      if (toolName && toolName.toLowerCase() === pat) {
        return {
          match: true,
          reason: "agents-md-prohibited-command",
          rule,
        };
      }
    }

    if (rule.type === "path" && pathToCheck) {
      const pat = rule.pattern.replace(/\\/g, "/");
      const normPath = pathToCheck.replace(/\\/g, "/");
      if (pat.endsWith("*")) {
        const prefix = pat.slice(0, -1);
        if (normPath.startsWith(prefix) || normPath.includes(prefix)) {
          return {
            match: true,
            reason: "agents-md-prohibited-path",
            rule,
          };
        }
      } else if (normPath.endsWith(pat) || normPath === pat) {
        return {
          match: true,
          reason: "agents-md-prohibited-path",
          rule,
        };
      }
    }
  }

  return { match: false };
}
