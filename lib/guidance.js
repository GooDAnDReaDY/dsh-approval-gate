// lib/guidance.js
// Dynamic security guidance for system prompts (AUTO_MODE_AGENT_GUIDANCE) (#99).
// Injects structured execution expectations and gate constraints directly into agent context.

export const GUIDANCE_MARKER = "<!-- dsh-approval-gate:guidance -->";

/**
 * Generates structured agent safety guidance.
 *
 * @param {{
 *   language?: "en" | "ru" | "zh",
 *   failClosed?: boolean,
 *   trashEnabled?: boolean,
 *   snapshotsEnabled?: boolean,
 *   justificationRequired?: boolean,
 *   redundantSandboxRecovery?: boolean,
 *   workspaceDir?: string
 * }} [options]
 * @returns {string}
 */
export function generateAgentGuidance(options = {}) {
  const lang = options.language || "en";
  const failClosed = options.failClosed !== false;
  const trash = options.trashEnabled !== false;
  const snapshots = options.snapshotsEnabled !== false;
  const justification = options.justificationRequired !== false;

  if (lang === "ru") {
    return [
      GUIDANCE_MARKER,
      "### Инструкции безопасности среды выполнения (dsh-approval-gate)",
      failClosed
        ? "- **Режим выполнения**: Включен строгий контроль (fail-closed). Нераспознанные шелл-команды требуют ручного подтверждения."
        : "- **Режим выполнения**: Стандартный контроль команд.",
      snapshots
        ? "- **Снимки файлов**: Перед изменением файлов автоматически создаются pre-execution снимки. Избегайте слепой перезаписи."
        : "",
      trash
        ? "- **Удаление файлов**: Запрещено безусловное `rm -rf`. Используйте перемещение в сессионную корзину `.dsh/trash/<session>/` или очистку сессионных артефактов."
        : "- **Удаление файлов**: Удаляйте файлы строго в границах текущего рабочего каталога.",
      "- **Песочница**: Не запрашивайте `danger-full-access` или выход из песочницы для стандартных задач внутри проекта.",
      justification
        ? "- **Эскалация привилегий**: Любая системная операция (apt, systemctl, сетевые вызовы) требует обязательного поля `justification` с обоснованием."
        : "",
      "- **Безопасные команды**: Чтение файлов, `git status`, `git diff`, `npm test` выполняются быстро и без запроса подтверждения.",
    ].filter(Boolean).join("\n");
  }

  if (lang === "zh") {
    return [
      GUIDANCE_MARKER,
      "### 执行环境安全指引 (dsh-approval-gate)",
      failClosed
        ? "- **执行模式**: 已启用严格安全保护 (fail-closed)。未识别的命令需人工确认。"
        : "- **执行模式**: 标准命令控制。",
      snapshots
        ? "- **文件快照**: 修改文件前会自动生成执行前快照。请避免盲目覆盖文件。"
        : "",
      trash
        ? "- **文件删除**: 禁止盲目运行 `rm -rf`。优先移动至会话回收站 `.dsh/trash/<session>/`。"
        : "- **文件删除**: 请确保仅在项目工作区内删除文件。",
      "- **沙箱权限**: 请勿对常规项目任务请求 `danger-full-access` 或沙箱提升。",
      justification
        ? "- **权限提升**: 任何系统级操作或跨目录访问必须附带明确的 `justification` 说明。"
        : "",
      "- **安全检查**: `git status`、`git diff`、`npm test` 等检查操作自动放行。",
    ].filter(Boolean).join("\n");
  }

  // Default: English
  return [
    GUIDANCE_MARKER,
    "### Security & Execution Guidance (dsh-approval-gate)",
    failClosed
      ? "- **Execution Mode**: Strict fail-closed policy is active. Unrecognized shell commands require human approval."
      : "- **Execution Mode**: Standard execution controls active.",
    snapshots
      ? "- **File Mutations**: Pre-execution snapshots are captured automatically before writes. Avoid blind destructive overwrites."
      : "",
    trash
      ? "- **Deletion Policy**: Do NOT run unconditional `rm -rf`. Prefer moving to session trash `.dsh/trash/<session>/` or safe artifact cleanup."
      : "- **Deletion Policy**: Keep all deletions strictly within the workspace boundary.",
    "- **Sandbox Boundaries**: Do NOT request `danger-full-access` or sandbox elevation for standard internal project tasks.",
    justification
      ? "- **Privilege Escalation**: Any system-level command or out-of-workspace access requires an explicit `justification` explanation."
      : "",
    "- **Safe Inspection**: Inspection commands (`git status`, `git diff`, `npm test`, `cat`, `ls`) are fast-tracked and safe.",
  ].filter(Boolean).join("\n");
}

/**
 * Injects guidance into system prompt idempotently.
 *
 * @param {string} systemPrompt
 * @param {Parameters<typeof generateAgentGuidance>[0]} [options]
 * @returns {string}
 */
export function injectAgentGuidance(systemPrompt, options = {}) {
  if (typeof systemPrompt !== "string") {
    return generateAgentGuidance(options);
  }
  if (systemPrompt.includes(GUIDANCE_MARKER)) {
    return systemPrompt;
  }
  const guidance = generateAgentGuidance(options);
  return `${systemPrompt.trimEnd()}\n\n${guidance}`;
}

/**
 * Extracts injected guidance block from prompt if present.
 * @param {string} prompt
 * @returns {string|null}
 */
export function extractGuidance(prompt) {
  if (typeof prompt !== "string") return null;
  const idx = prompt.indexOf(GUIDANCE_MARKER);
  if (idx === -1) return null;
  return prompt.slice(idx);
}
