export const LOCALE_NS = "dsh-approval-gate";

export const MESSAGES = Object.freeze({
  en: {
    blockedPrefix: "Blocked by dsh-approval-gate rule",
    detectedLabel: "Detected",
    commandLabel: "Command",
    parseReasonLabel: "Parse reason",
    detailProcessSubstitution: "process substitution needs confirmation",
    detailUnclosedProcessSubstitution: "unclosed process substitution",
    detailUnclosedCommandSubstitution: "unclosed command substitution",
    detailUnclosedBacktick: "unclosed backtick substitution",
    detailUnclosedParameterExpansion: "unclosed parameter expansion",
    detailUnclosedSingleQuote: "unclosed single quote",
    detailUnclosedDoubleQuote: "unclosed double quote",
    detailDanglingEscape: "unfinished escape",
    detailInvalidHeredoc: "invalid here-document delimiter",
    detailUnterminatedHeredoc: "here-document terminator was not found",
    detailUnsupportedGrouping: "shell grouping syntax is not supported by the analyzer",
    detailUnsupported: "unsupported shell syntax",
    approvalRequired: "Approval required",
    askUnknown: "The command could not be fully inspected; review it before allowing",
    askUnparseable: "Shell syntax could not be fully inspected; review it before allowing",
    askUnknownFormat: "The tool call format could not be inspected; review it before allowing",
    askUnknownWriteTarget: "The file write target could not be identified; review it before allowing",
    askDynamicCommand: "The expanded command name cannot be verified; review it before allowing",
    askDynamicArguments: "Expanded arguments to a sensitive command cannot be verified; review it before allowing",
    askDynamicRedirect: "The expanded redirect target cannot be verified; review it before allowing",
    askScriptFile: "The script file contents are not available to the guard; review it before allowing",
    askShellStdin: "Shell input is not fully available to the guard; review it before allowing",
    askInterpreterPayload: "Interpreter side effects are not fully analyzed; review it before allowing",
    askCredentialInArgv: "Expanded authorization values become process arguments; use a credential-safe API helper or review before allowing",
    ruleUnknown: "A blocking safety rule matched",
    ruleRecursiveRm: "Recursive file deletion",
    ruleProcessSignal: "Process termination",
    ruleServiceControl: "Service state change",
    ruleGitClean: "Destructive git clean",
    ruleGitResetHard: "Destructive git reset --hard",
    ruleFindDelete: "find -delete",
    ruleDestructiveSql: "Destructive SQL",
    ruleSecretWrite: "Write to a protected secret file",
    ruleDeviceWrite: "Write to a device or protected file",
    ruleMkfsDevice: "Filesystem formatting",
    ruleCurlPipe: "Downloaded content piped to a shell",
    ruleEval: "Dynamic shell evaluation",
    ruleNestedShell: "Nested shell depth limit",
    ruleInterpreterPayload: "Unsafe interpreter payload",
  },
  zh: {
    blockedPrefix: "dsh-approval-gate 规则已阻止",
    detectedLabel: "检测到",
    commandLabel: "命令",
    parseReasonLabel: "解析原因",
    detailProcessSubstitution: "进程替换需要确认",
    detailUnclosedProcessSubstitution: "进程替换未闭合",
    detailUnclosedCommandSubstitution: "命令替换未闭合",
    detailUnclosedBacktick: "反引号命令替换未闭合",
    detailUnclosedParameterExpansion: "参数展开未闭合",
    detailUnclosedSingleQuote: "单引号未闭合",
    detailUnclosedDoubleQuote: "双引号未闭合",
    detailDanglingEscape: "转义符不完整",
    detailInvalidHeredoc: "here-document 定界符无效",
    detailUnterminatedHeredoc: "未找到 here-document 结束标记",
    detailUnsupportedGrouping: "分析器不支持此 shell 分组语法",
    detailUnsupported: "不支持的 shell 语法",
    approvalRequired: "需要审批",
    askUnknown: "无法完整检查此命令；允许前请先检查",
    askUnparseable: "无法完整检查 shell 语法；允许前请先检查",
    askUnknownFormat: "无法检查此工具调用格式；允许前请先检查",
    askUnknownWriteTarget: "无法识别文件写入目标；允许前请先检查",
    askDynamicCommand: "无法验证展开后的命令名称；允许前请先检查",
    askDynamicArguments: "无法验证敏感命令展开后的参数；允许前请先检查",
    askDynamicRedirect: "无法验证展开后的重定向目标；允许前请先检查",
    askScriptFile: "守卫无法读取脚本内容；允许前请先检查",
    askShellStdin: "守卫无法完整检查 shell 输入；允许前请先检查",
    askInterpreterPayload: "未能完整分析解释器的副作用；允许前请先检查",
    askCredentialInArgv: "展开后的授权凭据会成为进程参数；请使用安全的凭据 API 帮助程序或在允许前检查",
    ruleUnknown: "命中安全阻止规则",
    ruleRecursiveRm: "递归删除文件",
    ruleProcessSignal: "终止进程",
    ruleServiceControl: "更改服务状态",
    ruleGitClean: "破坏性 git clean",
    ruleGitResetHard: "破坏性 git reset --hard",
    ruleFindDelete: "find -delete",
    ruleDestructiveSql: "破坏性 SQL",
    ruleSecretWrite: "写入受保护的敏感文件",
    ruleDeviceWrite: "写入设备或受保护文件",
    ruleMkfsDevice: "格式化文件系统",
    ruleCurlPipe: "将下载内容传递给 shell",
    ruleEval: "动态 shell 求值",
    ruleNestedShell: "嵌套 shell 超出检查深度",
    ruleInterpreterPayload: "不安全的解释器代码",
  },
  ru: {
    blockedPrefix: "Заблокировано правилом dsh-approval-gate",
    detectedLabel: "Обнаружено",
    commandLabel: "Команда",
    parseReasonLabel: "Причина синтаксического анализа",
    detailProcessSubstitution: "процессная подстановка требует подтверждения",
    detailUnclosedProcessSubstitution: "незакрытая процессная подстановка",
    detailUnclosedCommandSubstitution: "незакрытая подстановка команды",
    detailUnclosedBacktick: "незакрытая подстановка команды в обратных кавычках",
    detailUnclosedParameterExpansion: "незакрытое расширение параметров",
    detailUnclosedSingleQuote: "незакрытая одинарная кавычка",
    detailUnclosedDoubleQuote: "незакрытая двойная кавычка",
    detailDanglingEscape: "незавершённое экранирование",
    detailInvalidHeredoc: "неверный разделитель here-document",
    detailUnterminatedHeredoc: "завершитель here-document не найден",
    detailUnsupportedGrouping: "группировка шелла не поддерживается анализатором",
    detailUnsupported: "неподдерживаемый синтаксис шелла",
    approvalRequired: "Требуется подтверждение",
    askUnknown: "Команда не может быть проверена полностью; проверьте её перед подтверждением",
    askUnparseable: "Синтаксис шелла не может быть проверен полностью; проверьте его перед подтверждением",
    askUnknownFormat: "Формат вызова инструмента не может быть проверен; проверьте его перед подтверждением",
    askUnknownWriteTarget: "Целевой файл для записи не определён; проверьте его перед подтверждением",
    askDynamicCommand: "Развёрнутое имя команды не может быть проверено; проверьте его перед подтверждением",
    askDynamicArguments: "Развёрнутые аргументы чувствительной команды не могут быть проверены; проверьте их перед подтверждением",
    askDynamicRedirect: "Развёрнутая цель перенаправления не может быть проверена; проверьте её перед подтверждением",
    askScriptFile: "Содержимое файла скрипта недоступно для гейта; проверьте его перед подтверждением",
    askShellStdin: "Ввод шелла недоступен для гейта в полном объёме; проверьте его перед подтверждением",
    askInterpreterPayload: "Побочные эффекты интерпретатора не могут быть полностью проанализированы; проверьте их перед подтверждением",
    askCredentialInArgv: "Развёрнутые учётные данные передаются как аргументы процесса; используйте безопасный API или проверьте перед подтверждением",
    ruleUnknown: "Сработало защитное правило блокировки",
    ruleRecursiveRm: "Рекурсивное удаление файлов",
    ruleProcessSignal: "Завершение процесса",
    ruleServiceControl: "Изменение состояния службы",
    ruleGitClean: "Разрушительный git clean",
    ruleGitResetHard: "Разрушительный git reset --hard",
    ruleFindDelete: "find -delete",
    ruleDestructiveSql: "Разрушительный SQL",
    ruleSecretWrite: "Запись в защищённый файл с секретами",
    ruleDeviceWrite: "Запись в системное устройство или защищённый файл",
    ruleMkfsDevice: "Форматирование файловой системы",
    ruleCurlPipe: "Передача скачанного содержимого в шелл",
    ruleEval: "Динамическое выполнение шелла (eval)",
    ruleNestedShell: "Превышен лимит вложенности шелла",
    ruleInterpreterPayload: "Небезопасный исполняемый код интерпретатора",
  },
});

export function sessionTag(execution) {
  const agent = execution && execution.agent;
  if (typeof agent === "string") return " (session " + agent + ")";
  if (agent && agent.session) return " (session " + String(agent.session) + ")";
  return "";
}

function safeSnippet(value) {
  return String(value || "")
    .replace(/[\r\n\t\u0000-\u001f]+/g, " ")
    .replace(/(authorization\s*:\s*(?:bearer|token)\s+)\S+/gi, "$1[redacted]")
    .replace(/((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;]+/gi, "$1[redacted]")
    .slice(0, 120);
}

function translated(translate, key, logger) {
  if (typeof translate === "function") {
    try {
      const value = translate(key);
      if (value && value !== key) return value;
    } catch {
      if (logger && typeof logger.warn === "function") {
        logger.warn("[dsh-approval-gate] localization lookup failed; using English fallback");
      }
    }
  }
  return MESSAGES.en[key] || key;
}

const RULE_KEYS = Object.freeze({
  "recursive-rm": "ruleRecursiveRm",
  "process-signal": "ruleProcessSignal",
  "service-control": "ruleServiceControl",
  "git-clean": "ruleGitClean",
  "git-reset-hard": "ruleGitResetHard",
  "find-delete": "ruleFindDelete",
  "destructive-sql": "ruleDestructiveSql",
  "secret-write": "ruleSecretWrite",
  "device-write": "ruleDeviceWrite",
  "mkfs-device": "ruleMkfsDevice",
  "curl-pipe": "ruleCurlPipe",
  "eval": "ruleEval",
  "nested-shell": "ruleNestedShell",
  "interpreter-payload": "ruleInterpreterPayload",
  "env-dump-leak": "ruleEnvDumpLeak",
});

const ASK_KEYS = Object.freeze({
  unparseable: "askUnparseable",
  "unknown-format": "askUnknownFormat",
  "unknown-write-target": "askUnknownWriteTarget",
  "dynamic-command": "askDynamicCommand",
  "dynamic-arguments": "askDynamicArguments",
  "dynamic-redirect": "askDynamicRedirect",
  "script-file": "askScriptFile",
  "shell-stdin": "askShellStdin",
  "interpreter-payload": "askInterpreterPayload",
  "credential-in-argv": "askCredentialInArgv",
});

const DETAIL_KEYS = Object.freeze({
  "process-substitution": "detailProcessSubstitution",
  "unclosed-process-substitution": "detailUnclosedProcessSubstitution",
  "unclosed-command-substitution": "detailUnclosedCommandSubstitution",
  "unclosed-backtick-substitution": "detailUnclosedBacktick",
  "unclosed-parameter-expansion": "detailUnclosedParameterExpansion",
  "unclosed-single-quote": "detailUnclosedSingleQuote",
  "unclosed-double-quote": "detailUnclosedDoubleQuote",
  "dangling-backslash": "detailDanglingEscape",
  "invalid-heredoc-delimiter": "detailInvalidHeredoc",
  "unterminated-heredoc": "detailUnterminatedHeredoc",
  "unsupported-shell-grouping": "detailUnsupportedGrouping",
});

export function denyMessage(hit, who, translate, logger) {
  const key = RULE_KEYS[hit && hit.reason] || "ruleUnknown";
  const snippet = safeSnippet(hit && hit.snippet);
  const parts = [translated(translate, "blockedPrefix", logger), translated(translate, key, logger)];
  if (snippet) parts.push(translated(translate, "detectedLabel", logger) + ": " + snippet);
  if (who) parts.push(who.trim());
  return parts.join(" — ") + ".";
}

export function askMessage(hit, who, translate, logger) {
  const key = ASK_KEYS[hit && hit.reason] || "askUnknown";
  const snippet = safeSnippet(hit && hit.snippet);
  const parts = [translated(translate, "approvalRequired", logger), translated(translate, key, logger)];
  if (hit && hit.reason === "unparseable") {
    const detailKey = DETAIL_KEYS[hit.detail] || "detailUnsupported";
    parts.push(translated(translate, "parseReasonLabel", logger) + ": " + translated(translate, detailKey, logger));
  }
  if (snippet) parts.push(translated(translate, "commandLabel", logger) + ": " + snippet);
  if (who) parts.push(who.trim());
  return parts.join(" — ") + ".";
}
