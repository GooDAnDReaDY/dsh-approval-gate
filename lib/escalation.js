// lib/escalation.js
// Redundant sandbox recovery (#101) and privilege escalation justification (#107).
// Prevents unnecessary danger-full-access requests and enforces accountable escalation justifications.

import { isSystemLevelExecution } from "./measure-kinds.js";

export const REDUNDANT_SANDBOX_REASON = "redundant-sandbox-privilege";
export const MISSING_JUSTIFICATION_REASON = "missing-escalation-justification";
export const INSUFFICIENT_JUSTIFICATION_REASON = "insufficient-escalation-justification";

const PLACEHOLDER_JUSTIFICATIONS = new Set([
  "none",
  "n/a",
  "na",
  "test",
  "testing",
  "sudo",
  "fix",
  "run",
  "escalate",
  "please",
  "bypass",
  "temp",
]);

const INTERNAL_SAFE_COMMAND_REGEX = /^(?:git\s+(?:status|diff|log|branch|show)|npm\s+(?:test|run\s+test|run\s+lint)|pnpm\s+(?:test|run\s+test)|node\s+[\w\-./]+\.m?[jt]s|cat\s+|head\s+|tail\s+|grep\s+|find\s+|ls\b|pwd\b|echo\b)/i;

/**
 * Checks whether an elevated sandbox request is redundant for a safe internal command (#101).
 *
 * @param {string} [command]
 * @param {string} [requestedMode]
 * @param {{ toolName?: string, args?: any }} [options]
 * @returns {boolean}
 */
export function isRedundantSandboxRequest(command, requestedMode, options = {}) {
  const mode = String(requestedMode || options.sandboxMode || "").toLowerCase();
  const isElevated = mode === "danger-full-access" || mode === "full-access" || mode === "danger" || mode === "unrestricted";
  if (!isElevated) return false;

  const cmd = String(command || "").trim();
  if (!cmd) return false;

  // If command is system-level, escalation might be genuine (not redundant)
  if (isSystemLevelExecution(cmd, options.toolName, options.args)) {
    return false;
  }

  // If command contains explicit dangerous tokens, it's not a redundant request
  if (/\b(?:sudo|docker|systemctl|service|apt|apt-get|apk|dnf|pacman|chown|chmod\s+-R)\b/i.test(cmd)) {
    return false;
  }

  // Safe internal commands: reading, status, unit testing
  return INTERNAL_SAFE_COMMAND_REGEX.test(cmd);
}

/**
 * Builds actionable remediation advice for redundant sandbox requests (#101).
 *
 * @param {string} command
 * @param {"en" | "ru" | "zh"} [lang="en"]
 * @returns {string}
 */
export function buildRedundantSandboxRemediation(command, lang = "en") {
  const cmd = String(command || "").trim();
  if (lang === "ru") {
    return `Избыточный запрос привилегий песочницы: команда '${cmd}' является безопасной внутрипроектной операцией. Повторите вызов в стандартном режиме песочницы без 'danger-full-access'.`;
  }
  if (lang === "zh") {
    return `请求了冗余的沙箱提权：命令 '${cmd}' 为工作区内部安全操作。请以普通沙箱模式重新执行，无需 'danger-full-access'。`;
  }
  return `Redundant sandbox elevation requested: command '${cmd}' is workspace-internal and safe. Repeat the command in standard sandbox mode without 'danger-full-access'.`;
}

/**
 * Checks whether privilege escalation requires justification and whether provided justification is valid (#107).
 *
 * @param {string} [command]
 * @param {string} [toolName]
 * @param {any} [args]
 * @param {{
 *   justification?: string,
 *   context?: any,
 *   requireJustification?: boolean,
 *   lang?: "en" | "ru" | "zh"
 * }} [options]
 * @returns {{
 *   required: boolean,
 *   valid: boolean,
 *   reason?: string,
 *   detail?: string,
 *   advice?: string
 * }}
 */
export function checkEscalationJustification(command, toolName, args, options = {}) {
  const cmd = String(command || "").trim();
  const execObj = { name: toolName || "bash", arguments: { ...(args || {}), command: cmd } };
  const isSystem = isSystemLevelExecution(execObj, options.context);
  const explicitRequire = options.requireJustification === true || options.context?.requireJustification === true;
  const isEscalatedSandbox = Boolean(options.context?.sandboxMode && options.context.sandboxMode !== "sandboxed");

  // Escalation justification is required when explicitly required OR when escalated sandbox mode is requested for system operations
  const escalationRequired = explicitRequire || (isEscalatedSandbox && isSystem);
  if (!escalationRequired) {
    return { required: false, valid: true };
  }

  const rawJustification =
    (typeof options.justification === "string" && options.justification) ||
    (typeof args?.justification === "string" && args.justification) ||
    (typeof options.context?.justification === "string" && options.context.justification) ||
    "";

  const justification = rawJustification.trim();
  const lang = options.lang || "en";

  if (!justification) {
    return {
      required: true,
      valid: false,
      reason: MISSING_JUSTIFICATION_REASON,
      detail: `Privilege escalation for '${cmd || toolName}' requires an explicit justification.`,
      advice: lang === "ru"
        ? "Укажите поле 'justification' с объяснением необходимости системных привилегий."
        : lang === "zh"
        ? "执行系统级操作必须提供 'justification' 理由说明。"
        : "Provide a 'justification' field explaining why elevated privileges are necessary.",
    };
  }

  if (justification.length < 10 || PLACEHOLDER_JUSTIFICATIONS.has(justification.toLowerCase())) {
    return {
      required: true,
      valid: false,
      reason: INSUFFICIENT_JUSTIFICATION_REASON,
      detail: `Justification '${justification}' is too short or generic (minimum 10 non-placeholder characters required).`,
      advice: lang === "ru"
        ? "Обоснование слишком короткое или шаблонное. Опишите конкретную причину эскалации."
        : lang === "zh"
        ? "理由说明过短或为占位符。请详细描述提权的实际原因（至少10个字符）。"
        : "Justification is too brief or placeholder. Describe the specific reason for privilege escalation.",
    };
  }

  return {
    required: true,
    valid: true,
    justification,
  };
}
