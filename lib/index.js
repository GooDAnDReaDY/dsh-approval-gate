// dsh-approval-gate — «делай» gate for DeepSeek Harness.
//
// Registers a `tools.guard(...)` on the tool runtime and denies DANGEROUS bash
// commands (rm -rf, kill, service stop/restart, restart dsh-web, destructive
// DB statements, writes to .env/secrets) EVEN when the current sandbox mode
// would allow them. A guard return value (non-undefined) denies execution, so
// the dangerous command never runs on its own — it needs an explicit user
// "делай".
//
// Only the agent's tool calls pass through the guard (cron/systemd scripts do
// not), so legitimate unattended operations are unaffected.
import Schema from '@deepseek-ai/schemastery';

export const name = 'dsh-approval-gate';
export const inject = ['tools'];

export const Config = Schema.object({
  /** Name of the tool whose `command` arg is inspected (the DSH bash tool). */
  toolName: Schema.string().default('bash'),
});

const DANGEROUS_PATTERNS = [
  // rm -rf / rm -r / rm -fr <path> — recursive forced delete
  /\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\S+/i,
  // kill / pkill / killall
  /\b(?:kill|pkill|killall)\b/i,
  // service control: stop/restart/disable/enable/mask/reboot/shutdown
  /\bsystemctl\s+(?:stop|restart|disable|enable|mask|unmask|reboot|halt|poweroff|shutdown)\b/i,
  /\bservice\s+\S+\s+(?:stop|restart|force-stop|force-reload)\b/i,
  // (state queries like `systemctl is-active dsh-web` are reads and pass)
  // destructive database statements
  /\b(?:sqlite3|mysql|psql|pg_restore|mongo|mongosh|redis-cli|clickhouse-client)\b.*\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i,
  // writes to .env or secret-ish files via redirect/tee/sed -i
  /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*\.env\b/i,
  /(?:\s(?:>>|>)\s|\|\s*tee\s+|\bsed\s+-i\b).*(?:secret|token|credential|api[_-]?key|passwd)\S*/i,
];

function findDangerous(command) {
  for (const pattern of DANGEROUS_PATTERNS) {
    const match = pattern.exec(command);
    if (match) return match[0];
  }
  return undefined;
}

export function apply(ctx, config = {}) {
  const cfg = Config(config) ?? {};
  const toolName = cfg.toolName ?? 'bash';

  return ctx.tools.guard((execution) => {
    if (execution.name !== toolName) return undefined;
    const args = execution.arguments;
    const command = typeof args === 'object' && args !== null ? args.command : undefined;
    if (typeof command !== 'string' || command.trim() === '') return undefined;
    const hit = findDangerous(command);
    if (!hit) return undefined;
    const who = typeof execution.agent === 'string'
      ? ` (session ${execution.agent})`
      : (execution.agent?.session ? ` (session ${String(execution.agent.session)})` : '');
    console.warn(`[dsh-approval-gate] blocked dangerous command${who}: ${String(hit).slice(0, 140)}`);
    return `⛔ [dsh-approval-gate] Команда заблокирована: \`${String(hit).slice(0, 160)}\`${who ? ` ${who}` : ''}. Опасная операция (rm -rf / kill / перезапуск сервиса / изменение БД / запись в секреты или .env). Для выполнения нужно явное \`делай\` от Вадима — либо переформулируй команду безопаснее.`;
  });
}
