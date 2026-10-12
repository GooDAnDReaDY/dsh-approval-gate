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
    ruleRetryExhaustion: "Exhausted repeated attempts to bypass safety gate",
    ruleFailClosedAudit: "Audit log write failure blocked by fail-closed policy",
    ruleLockedAskUnattended: "Critical operation requires human confirmation and cannot be bypassed in unattended mode",
    ruleClassifierTimeoutStrict: "Semantic classifier timed out under strict confirmation policy",
    ruleClassifierTimeoutPermissive: "Semantic classifier timed out; allowed by low-risk fallback policy",
    askClassifierTimeout: "Semantic classifier request timed out; human confirmation required",
    askClassifierError: "Semantic classifier error; human confirmation required",
    askClassifierSlaFallback: "Semantic classifier exceeded SLA latency threshold; manual review required",
    askMalformedClassifierResponse: "Semantic classifier returned malformed or unverified decision; manual review required",
    askPayloadTooLarge: "Command arguments exceed maximum payload size limit; review before allowing",
    ruleReviewerInjectionAttempt: "Prompt instruction injection detected in tool arguments",
    askContractViolation: "Operation falls outside task contract boundaries; review before allowing",
    ruleContractViolation: "Execution violated task contract boundaries",
    askUnisolatedTempPath: "Target path uses global /tmp instead of isolated project temp directory; review before allowing",
    ruleUnisolatedTempPath: "Target path uses unisolated global temp directory",
    askOverengineeringLimit: "Session file creation limit exceeded; potential overengineering requires review before allowing",
    ruleOverengineeringLimit: "Session exceeded maximum allowed created files limit",
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
    hintRetryExhaustion: "Repeated denials detected; manual operator intervention required",
    hintFailClosedAudit: "Ensure the audit log directory is writable and disk space is available",
    hintLockedAskUnattended: "Switch to an interactive session or request explicit human confirmation",
    hintClassifierTimeout: "Check external LLM connectivity or review timeout policy settings",
    hintClassifierSlaFallback: "Check external LLM classifier load or increase classifierSlaMs",
    hintMalformedClassifierResponse: "Verify model JSON output format or check response schema compatibility",
    hintPayloadTooLarge: "Reduce input payload size or chunk data into smaller batches",
    hintReviewerInjectionAttempt: "Remove adversarial prompt override directives from input",
    hintContractViolation: "Confine operations to permitted task tools and project scope",
    hintUnisolatedTempPath: "Use workspace-isolated temporary directory (<workspace>/.dsh/tmp)",
    hintOverengineeringLimit: "Reuse existing files and avoid creating redundant abstractions or boilerplate",
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
    askScriptFile: "脚本文件内容不可见；请在允许前进行审查",
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
    ruleRetryExhaustion: "多次尝试绕过安全网关已达上限",
    ruleFailClosedAudit: "审计日志写入失败，受安全失败策略阻止",
    ruleLockedAskUnattended: "关键操作需要人工确认，无法在无人值守模式下自动批准",
    ruleClassifierTimeoutStrict: "语义分类器在严格策略下超时",
    ruleClassifierTimeoutPermissive: "语义分类器超时；根据低风险容错策略放行",
    askClassifierTimeout: "语义分类器请求超时；需要人工审查",
    askClassifierError: "语义分类器发生异常；需要人工审查",
    askClassifierSlaFallback: "语义分类器延迟超出 SLA 阈值；需要人工审查",
    askMalformedClassifierResponse: "语义分类器返回非预期或未通过校验的判定；需要人工审查",
    askPayloadTooLarge: "命令参数超过最大负载大小限制；请在允许前进行审查",
    ruleReviewerInjectionAttempt: "在工具参数中检测到提示词指令注入尝试",
    askContractViolation: "操作超出任务契约范围；请在允许前进行审查",
    ruleContractViolation: "执行违反了任务契约边界",
    askUnisolatedTempPath: "目标路径使用全局 /tmp 而非隔离的项目临时目录；请在允许前进行审查",
    ruleUnisolatedTempPath: "目标路径使用未隔离的全局临时目录",
    askOverengineeringLimit: "会话创建文件数超过限制；潜在的过度工程需要人工审查",
    ruleOverengineeringLimit: "会话超出最大允许创建文件数限制",
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
    hintRetryExhaustion: "检测到重复拒绝；需要操作员手动介入",
    hintFailClosedAudit: "请确保审计日志目录可写且磁盘空间充足",
    hintLockedAskUnattended: "请切换到交互式会话或请求人工显式确认",
    hintClassifierTimeout: "请检查外部 LLM 服务连通性或调整分类器超时容错策略",
    hintClassifierSlaFallback: "请检查外部 LLM 分类器负载或调高 classifierSlaMs 阈值",
    hintMalformedClassifierResponse: "请检查模型 JSON 输出格式或验证返回模式兼容性",
    hintPayloadTooLarge: "减小输入参数大小或分批传输数据",
    hintReviewerInjectionAttempt: "从输入中移除对抗性指令覆盖指令",
    hintContractViolation: "将操作限制在允许的任务工具和项目范围内",
    hintUnisolatedTempPath: "使用工作区隔离的临时目录 (<workspace>/.dsh/tmp)",
    hintOverengineeringLimit: "复用现有文件，避免创建多余的抽象或样板代码",
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
  "retry-exhaustion": "ruleRetryExhaustion",
  "fail-closed-audit": "ruleFailClosedAudit",
  "locked-ask-unattended-denied": "ruleLockedAskUnattended",
  "classifier-timeout-strict": "ruleClassifierTimeoutStrict",
  "classifier-timeout-fallback-strict": "ruleClassifierTimeoutStrict",
  "classifier-timeout-fallback-permissive": "ruleClassifierTimeoutPermissive",
  "classifier-sla-fallback": "askClassifierSlaFallback",
  "malformed-classifier-response": "askMalformedClassifierResponse",
  "reviewer-injection-attempt": "ruleReviewerInjectionAttempt",
  "contract-violation": "ruleContractViolation",
  "unisolated-temp-path": "ruleUnisolatedTempPath",
  "overengineering-file-limit": "ruleOverengineeringLimit",
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
  "retry-exhaustion": "hintRetryExhaustion",
  "fail-closed-audit": "hintFailClosedAudit",
  "locked-ask-unattended-denied": "hintLockedAskUnattended",
  "classifier-timeout-strict": "hintClassifierTimeout",
  "classifier-timeout-fallback-strict": "hintClassifierTimeout",
  "classifier-sla-fallback": "hintClassifierSlaFallback",
  "malformed-classifier-response": "hintMalformedClassifierResponse",
  "payload-too-large": "hintPayloadTooLarge",
  "reviewer-injection-attempt": "hintReviewerInjectionAttempt",
  "contract-violation": "hintContractViolation",
  "unisolated-temp-path": "hintUnisolatedTempPath",
  "overengineering-file-limit": "hintOverengineeringLimit",
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
  "classifier-timeout-strict": "askClassifierTimeout",
  "classifier-timeout-fallback-strict": "askClassifierTimeout",
  "classifier-error": "askClassifierError",
  "classifier-sla-fallback": "askClassifierSlaFallback",
  "malformed-classifier-response": "askMalformedClassifierResponse",
  "payload-too-large": "askPayloadTooLarge",
  "contract-violation": "askContractViolation",
  "unisolated-temp-path": "askUnisolatedTempPath",
  "overengineering-file-limit": "askOverengineeringLimit",
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
