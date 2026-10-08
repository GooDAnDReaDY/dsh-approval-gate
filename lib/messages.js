import { redactCredentials } from "./redact.js";
export const LOCALE_NS = "dsh-approval-gate";

export const MESSAGES = Object.freeze({
  en: {
    blockedPrefix: "Blocked by dsh-approval-gate rule",
    detectedLabel: "Detected",
    commandLabel: "Command",
    parseReasonLabel: "Parse reason",
    hintPrefix: "Hint",
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
    askGitRemotePush: "Publishing commits to a remote repository via git push requires confirmation",
    askSilentErrorMasked: "The command suppresses errors or masks non-zero exit codes; review before allowing",
    ruleUnknown: "A blocking safety rule matched",
    ruleRecursiveRm: "Recursive file deletion",
    ruleProcessSignal: "Process termination",
    ruleServiceControl: "Service state change",
    ruleGitClean: "Destructive git clean",
    ruleGitResetHard: "Destructive git reset --hard",
    ruleGitForcePush: "Forceful git push",
    ruleGitBranchForceDelete: "Forceful git branch deletion",
    ruleGitCheckoutForce: "Forceful checkout discarding local modifications",
    ruleGitRestoreWorktree: "Restoring working tree files discarding modifications",
    ruleFindDelete: "find -delete",
    ruleDestructiveSql: "Destructive SQL",
    ruleSecretWrite: "Write to a protected secret file",
    ruleDeviceWrite: "Write to a device or protected file",
    ruleMkfsDevice: "Filesystem formatting",
    ruleCurlPipe: "Downloaded content piped to a shell",
    ruleEval: "Dynamic shell evaluation",
    ruleNestedShell: "Nested shell depth limit",
    ruleInterpreterPayload: "Unsafe interpreter payload",
    ruleEnvDumpLeak: "Process environment or credential exfiltration",
    rulePathTraversal: "Directory traversal attack detected",
    ruleBandHardDeny: "Command matched Band 0 critical security blocklist",
    ruleCircuitBreakerTripped: "Circuit breaker tripped due to repeated security denials",
    ruleSilentErrorMasked: "Suppression of command failure or error stream",
    ruleChmodChown: "Permission or ownership mutation",
    ruleReviewerReadOnly: "Reviewer agent is strictly isolated in read-only mode",
    hintRecursiveRm: "Specify exact target files instead of recursive deletion",
    hintPathTraversal: "Keep operations strictly within the project directory",
    hintSecretWrite: "Modify configuration via settings or environment variables, not raw file overwrite",
    hintEnvDumpLeak: "Query specific non-secret environment variables individually",
    hintCircuitBreakerTripped: "Request manual operator approval before attempting new system commands",
    hintDestructiveSql: "Use migrations or execute non-destructive database operations",
    hintCurlPipe: "Download the script, inspect its content, and execute locally",
    hintGitForcePush: "Push branch without force or check with remote administrator",
    hintGitRemotePush: "Confirm remote target branch and repository before pushing",
    hintSilentErrorMasked: "Allow standard error output to be captured and handle non-zero exit codes explicitly",
    hintChmodChown: "Avoid modifying file permissions or system directory ownership directly",
    hintReviewerReadOnly: "Reviewer agents may only read repository files, not run commands or modify files",
  },
  zh: {
    blockedPrefix: "dsh-approval-gate 规则已阻止",
    detectedLabel: "检测到",
    commandLabel: "命令",
    parseReasonLabel: "解析原因",
    hintPrefix: "建议",
    detailProcessSubstitution: "进程替换需要确认",
    detailUnclosedProcessSubstitution: "进程替换未闭合",
    detailUnclosedCommandSubstitution: "命令替换未闭合",
    detailUnclosedBacktick: "反引号命令替换未闭合",
    detailUnclosedParameterExpansion: "参数展开未闭合",
    detailUnclosedSingleQuote: "单引号未闭合",
    detailUnclosedDoubleQuote: "双引号未闭合",
    detailDanglingEscape: "未完成的转义符",
    detailInvalidHeredoc: "无效的 heredoc 定界符",
    detailUnterminatedHeredoc: "未找到 heredoc 结束符",
    detailUnsupportedGrouping: "分析器不支持该 shell 分组语法",
    detailUnsupported: "不支持的 shell 语法",
    approvalRequired: "需要批准",
    askUnknown: "命令无法完整检查；请在允许前进行审查",
    askUnparseable: "Shell 语法无法完整检查；请在允许前进行审查",
    askUnknownFormat: "工具调用格式无法检查；请在允许前进行审查",
    askUnknownWriteTarget: "无法识别文件写入目标；请在允许前进行审查",
    askDynamicCommand: "无法验证展开后的命令名；请在允许前进行审查",
    askDynamicArguments: "敏感命令的展开参数无法验证；请在允许前进行审查",
    askDynamicRedirect: "展开后的重定向目标无法验证；请在允许前进行审查",
    askScriptFile: "卫兵无法获取脚本文件内容；请在允许前进行审查",
    askShellStdin: "卫兵无法完整获取 Shell 输入；请在允许前进行审查",
    askInterpreterPayload: "解释器副作用未完全分析；请在允许前进行审查",
    askCredentialInArgv: "展开后的授权凭据作为进程参数传递；请使用凭据安全的 API 辅助工具，或在允许前进行审查",
    askGitRemotePush: "通过 git push 向远程仓库发布代码需要确认",
    askSilentErrorMasked: "命令屏蔽了错误输出或强制将退出码设为 0；请在允许前审查",
    ruleUnknown: "命中阻止性安全规则",
    ruleRecursiveRm: "递归删除文件",
    ruleProcessSignal: "终止进程",
    ruleServiceControl: "更改服务状态",
    ruleGitClean: "破坏性 git clean",
    ruleGitResetHard: "破坏性 git reset --hard",
    ruleGitForcePush: "强制 git push",
    ruleGitBranchForceDelete: "强制删除 git 分支",
    ruleGitCheckoutForce: "强制 checkout 丢弃本地修改",
    ruleGitRestoreWorktree: "还原工作区文件并丢弃修改",
    ruleFindDelete: "find -delete",
    ruleDestructiveSql: "破坏性 SQL",
    ruleSecretWrite: "写入受保护的敏感文件",
    ruleDeviceWrite: "写入系统设备或受保护文件",
    ruleMkfsDevice: "格式化文件系统",
    ruleCurlPipe: "将下载内容通过管道传入 shell",
    ruleEval: "动态 shell 执行 (eval)",
    ruleNestedShell: "超出嵌套 shell 深度限制",
    ruleInterpreterPayload: "不安全的解释器执行代码",
    ruleEnvDumpLeak: "尝试泄露环境变量与敏感凭据",
    rulePathTraversal: "检测到路径穿越攻击",
    ruleBandHardDeny: "命令匹配 Band 0 关键安全黑名单",
    ruleCircuitBreakerTripped: "因连续多次安全拒绝，断路熔断器已触发",
    ruleSilentErrorMasked: "屏蔽错误输出或强制忽略退出码",
    ruleChmodChown: "修改权限或所有权",
    ruleReviewerReadOnly: "审查者代理处于只读隔离模式",
    hintRecursiveRm: "请指定具体目标文件，避免递归删除",
    hintPathTraversal: "请将操作限制在项目根目录内",
    hintSecretWrite: "请通过设置或环境变量修改配置，不要直接覆盖敏感配置文件",
    hintEnvDumpLeak: "请单独查询非敏感环境变量，避免全量导出",
    hintCircuitBreakerTripped: "请在尝试新的系统命令前请求操作员人工授权",
    hintDestructiveSql: "请使用版本化数据库迁移，或执行非破坏性查询",
    hintCurlPipe: "先将脚本下载到本地检查内容，再安全执行",
    hintGitForcePush: "请勿使用 force 参数推送分支，或与远程仓库管理员确认",
    hintGitRemotePush: "推送前请核对目标分支与远程仓库地址",
    hintSilentErrorMasked: "请保留标准错误输出，并明确处理非零退出码",
    hintChmodChown: "避免直接修改系统目录所有权或文件权限",
    hintReviewerReadOnly: "审查者代理仅可读取项目文件，禁止执行命令或修改文件",
  },
});

export function sessionTag(execution) {
  const agent = execution && execution.agent;
  if (typeof agent === "string") return " (session " + agent + ")";
  if (agent && agent.session) {
    const s = agent.session;
    const sid = typeof s === "string" ? s : (s.id || s.name || s.sessionId || s.sessionKey);
    return sid ? " (session " + String(sid) + ")" : "";
  }
  return "";
}

function safeSnippet(value) {
  const flattened = String(value || "").replace(/[\r\n\t\u0000-\u001f]+/g, " ");
  return redactCredentials(flattened).slice(0, 120);
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
  "git-force-push": "ruleGitForcePush",
  "git-branch-force-delete": "ruleGitBranchForceDelete",
  "git-checkout-force": "ruleGitCheckoutForce",
  "git-restore-worktree": "ruleGitRestoreWorktree",
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
  "path-traversal": "rulePathTraversal",
  "band-hard-deny": "ruleBandHardDeny",
  "circuit-breaker-tripped": "ruleCircuitBreakerTripped",
  "silent-error-masked": "ruleSilentErrorMasked",
  "chmod-chown": "ruleChmodChown",
  "reviewer-read-only": "ruleReviewerReadOnly",
});

const HINT_KEYS = Object.freeze({
  "recursive-rm": "hintRecursiveRm",
  "path-traversal": "hintPathTraversal",
  "secret-write": "hintSecretWrite",
  "env-dump-leak": "hintEnvDumpLeak",
  "circuit-breaker-tripped": "hintCircuitBreakerTripped",
  "destructive-sql": "hintDestructiveSql",
  "curl-pipe": "hintCurlPipe",
  "git-force-push": "hintGitForcePush",
  "git-remote-push": "hintGitRemotePush",
  "silent-error-masked": "hintSilentErrorMasked",
  "chmod-chown": "hintChmodChown",
  "reviewer-read-only": "hintReviewerReadOnly",
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
  "git-remote-push": "askGitRemotePush",
  "silent-error-masked": "askSilentErrorMasked",
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
  const reason = hit && hit.reason;
  const key = RULE_KEYS[reason] || "ruleUnknown";
  const snippet = safeSnippet(hit && hit.snippet);
  const parts = [translated(translate, "blockedPrefix", logger), translated(translate, key, logger)];
  if (snippet) parts.push(translated(translate, "detectedLabel", logger) + ": " + snippet);
  const hintKey = HINT_KEYS[reason];
  if (hintKey) {
    parts.push(translated(translate, "hintPrefix", logger) + ": " + translated(translate, hintKey, logger));
  }
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