// lib/similarity.js
// Semantic Command Similarity & Fast Validation (#85).
// Normalizes and validates syntactic variations of commands (e.g. pnpm test vs npm run test vs npm test).
// Provides canonical command normalization and optional fast Flash-model validator with deterministic fallback.

const PKG_MGR_REGEX = /^(?:pnpm|npm|yarn|bun)\b/;

/**
 * Normalizes common command variants into canonical representation (#85).
 *
 * @param {string} command
 * @returns {string}
 */
export function canonicalizeCommand(command) {
  if (!command || typeof command !== "string") return "";
  let cmd = command.trim().replace(/\s+/g, " ");

  // 1. Package manager scripts normalization
  // pnpm test / npm run test / yarn test / bun test -> npm test
  if (/^(?:pnpm|npm\s+run|yarn|bun)\s+test\b/.test(cmd)) {
    return cmd.replace(/^(?:pnpm|npm\s+run|yarn|bun)\s+test/, "npm test");
  }
  // pnpm run <script> / yarn <script> / bun run <script> -> npm run <script>
  if (/^(?:pnpm\s+run|yarn\s+run|bun\s+run)\s+([a-zA-Z0-9_:.-]+)/.test(cmd)) {
    return cmd.replace(/^(?:pnpm\s+run|yarn\s+run|bun\s+run)/, "npm run");
  }
  if (/^(?:pnpm|yarn|bun)\s+(build|lint|check|start|dev)\b/.test(cmd)) {
    return cmd.replace(/^(?:pnpm|yarn|bun)\s+/, "npm run ");
  }

  // 2. Python testing tools
  // python -m pytest / python3 -m pytest -> pytest
  if (/^python[23]?\s+-m\s+pytest\b/.test(cmd)) {
    return cmd.replace(/^python[23]?\s+-m\s+pytest/, "pytest");
  }

  // 3. Git status / diff flags
  if (/^git\s+status\s+(?:-s|--short)\b/.test(cmd)) {
    return "git status";
  }
  if (/^git\s+diff\s+HEAD\b/.test(cmd)) {
    return "git diff";
  }

  return cmd;
}

/**
 * Checks whether two commands are semantically equivalent (#85).
 *
 * @param {string} cmdA
 * @param {string} cmdB
 * @returns {{ equivalent: boolean, confidence: number, method: string }}
 */
export function isSemanticallyEquivalent(cmdA, cmdB) {
  if (!cmdA || !cmdB) return { equivalent: false, confidence: 0, method: "none" };
  const a = String(cmdA).trim();
  const b = String(cmdB).trim();
  if (a === b) {
    return { equivalent: true, confidence: 1.0, method: "exact" };
  }

  const normA = canonicalizeCommand(a);
  const normB = canonicalizeCommand(b);

  if (normA && normA === normB) {
    return { equivalent: true, confidence: 0.98, method: "canonical" };
  }

  return { equivalent: false, confidence: 0, method: "mismatch" };
}

/**
 * Searches a list of learned rules for a semantically equivalent match (#85).
 *
 * @param {string} command
 * @param {Array<{ command?: string, key?: string }>} learnedRules
 * @returns {{ matched: boolean, matchedRule?: any, method?: string }}
 */
export function findSemanticallyEquivalentRule(command, learnedRules = []) {
  if (!command || !Array.isArray(learnedRules) || learnedRules.length === 0) {
    return { matched: false };
  }

  for (const rule of learnedRules) {
    const ruleCmd = rule.command || (rule.key && rule.key.includes(":") ? rule.key.slice(rule.key.indexOf(":") + 1) : "");
    if (!ruleCmd) continue;

    const check = isSemanticallyEquivalent(command, ruleCmd);
    if (check.equivalent) {
      return { matched: true, matchedRule: rule, method: check.method };
    }
  }

  return { matched: false };
}

/**
 * Validates semantic similarity with optional Flash-model LLM client (#85).
 * Falls back safely to deterministic canonical matching on error or absence.
 *
 * @param {string} cmdA
 * @param {string} cmdB
 * @param {{ classify?: Function, model?: string }} [llmClient]
 * @returns {Promise<{ equivalent: boolean, confidence: number, method: string }>}
 */
export async function validateSemanticSimilarity(cmdA, cmdB, llmClient = null) {
  // 1. Fast deterministic check
  const det = isSemanticallyEquivalent(cmdA, cmdB);
  if (det.equivalent) {
    return det;
  }

  // 2. If no LLM client, return deterministic result
  if (!llmClient || typeof llmClient.classify !== "function") {
    return det;
  }

  try {
    const prompt = `Are these two terminal commands semantically equivalent in purpose and safety?\nCommand 1: ${cmdA}\nCommand 2: ${cmdB}\nRespond with JSON: {"equivalent": true|false, "confidence": number}`;
    const res = await llmClient.classify({ name: "semantic_check", prompt });
    if (res && typeof res.equivalent === "boolean") {
      return {
        equivalent: res.equivalent,
        confidence: typeof res.confidence === "number" ? res.confidence : 0.9,
        method: "flash-model",
      };
    }
  } catch (_err) {
    // Fail closed to deterministic fallback
  }

  return det;
}
