// lib/when-matcher.js
// Conditional predicates (when) evaluator for dsh-approval-gate rules (#44).
// Evaluates OS, git branch, environment variables, and tool context.

/**
 * Checks a string or regex value against a target with negation support.
 *
 * @param {string | RegExp} expected
 * @param {string} actual
 * @returns {boolean}
 */
export function matchConditionValue(expected, actual) {
  if (expected === undefined || expected === null) return true;
  const actualStr = String(actual || "");

  if (typeof expected === "string") {
    const trimmed = expected.trim();
    if (trimmed.startsWith("!")) {
      const negated = trimmed.slice(1).trim();
      return actualStr !== negated;
    }
    return actualStr === trimmed;
  }

  if (expected instanceof RegExp) {
    return expected.test(actualStr);
  }

  return expected === actual;
}

/**
 * Evaluates a rule's `when` section against runtime facts.
 *
 * @param {Record<string, any>} [when] - When clause from rule
 * @param {{
 *   os?: string,
 *   branch?: string,
 *   tool?: string,
 *   env?: Record<string, string | undefined>
 * }} [context] - Environmental context
 * @returns {boolean}
 */
export function evaluateWhen(when, context = {}) {
  if (!when || typeof when !== "object" || Object.keys(when).length === 0) {
    return true;
  }

  const currentOs = context.os || process.platform;
  const currentBranch = context.branch || "";
  const currentTool = (context.tool || "").toLowerCase();
  const currentEnv = context.env || process.env || {};

  // 1. OS check
  if (when.os !== undefined) {
    if (!matchConditionValue(when.os, currentOs)) {
      return false;
    }
  }

  // 2. Branch check
  if (when.branch !== undefined) {
    if (!matchConditionValue(when.branch, currentBranch)) {
      return false;
    }
  }

  // 3. Tool check
  if (when.tool !== undefined) {
    if (!matchConditionValue(String(when.tool).toLowerCase(), currentTool)) {
      return false;
    }
  }

  // 4. Environment variables check
  if (when.env && typeof when.env === "object") {
    for (const [varName, expectedVal] of Object.entries(when.env)) {
      const actualVal = currentEnv[varName];
      if (typeof expectedVal === "boolean") {
        const isPresent = actualVal !== undefined && actualVal !== "" && actualVal !== "0" && actualVal !== "false";
        if (isPresent !== expectedVal) return false;
      } else if (!matchConditionValue(expectedVal, actualVal)) {
        return false;
      }
    }
  }

  return true;
}
