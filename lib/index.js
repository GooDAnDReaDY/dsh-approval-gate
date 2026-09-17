// dsh-approval-gate - approval gate for DeepSeek Harness.
//
// Registers tools.guard on the tool runtime and denies dangerous bash
// commands and writes to secret files even when sandbox mode would allow
// them. A guard return value (non-undefined) denies execution, so the
// dangerous call never runs on its own - it needs an explicit owner
// Approval is handled by DSH's native flow; no separate word is implemented.
//
// Only the agent tool calls pass through the guard (cron/systemd scripts
// do not), so legitimate unattended operations are unaffected.
import Schema from "@deepseek-ai/schemastery";
import {
  DEFAULT_BASH_TOOL,
  DEFAULT_FILE_WRITE_TOOLS,
  askMessage,
  denyMessage,
  inspectExecution,
  sessionTag,
} from "./inspect.js";
import { LOCALE_NS, MESSAGES } from "./messages.js";

export const name = "dsh-approval-gate";
export const inject = ["tools"];

export const Config = Schema.object({
  /** Name of the tool whose `command` arg is inspected (the DSH bash tool). */
  toolName: Schema.string().default(DEFAULT_BASH_TOOL),
  /** Extra tool names treated as file writes; paths are matched against secret files. */
  fileWriteTools: Schema.array(Schema.string()).default(DEFAULT_FILE_WRITE_TOOLS.slice()),
});

function logBlocked(ctx, hit, who) {
  const line = "[dsh-approval-gate] blocked rule=" + (hit.reason || "unknown") + who;
  if (ctx && ctx.logger && typeof ctx.logger.warn === "function") ctx.logger.warn(line);
}

export function apply(ctx, config) {
  const cfg = Config(config || {}) || {};
  const toolName = cfg.toolName || DEFAULT_BASH_TOOL;
  const fileWriteTools = cfg.fileWriteTools || DEFAULT_FILE_WRITE_TOOLS.slice();
  const getLocale = function () {
    if (ctx && typeof ctx.get === "function") return ctx.get("locale");
    return ctx && ctx.locale;
  };
  const registerLocale = function () {
    const locale = getLocale();
    if (locale && typeof locale.register === "function") return locale.register(LOCALE_NS, MESSAGES);
  };
  if (ctx && typeof ctx.effect === "function") ctx.effect(registerLocale, "dsh-approval-gate: dictionaries");
  else registerLocale();

  const translate = function (key) {
    const locale = getLocale();
    if (locale && typeof locale.bind === "function") return locale.bind(LOCALE_NS)(key);
    return key;
  };
  const hasPreExecute = ctx && typeof ctx.on === "function";
  if (hasPreExecute) {
    ctx.on("tools/pre-execute", function (execution, next) {
      const hit = inspectExecution(execution, { toolName: toolName, fileWriteTools: fileWriteTools });
      if (hit.ask) return { kind: "ask", reason: askMessage(hit, sessionTag(execution), translate, ctx && ctx.logger) };
      return next();
    });
  }

  const guard = function (execution) {
    const hit = inspectExecution(execution, { toolName: toolName, fileWriteTools: fileWriteTools });
    if (!hit.deny && !(hit.ask && !hasPreExecute)) return undefined;
    const who = sessionTag(execution);
    logBlocked(ctx, hit, who);
    return denyMessage(hit, who, translate, ctx && ctx.logger);
  };

  const mount = function () {
    return ctx.tools.guard(guard);
  };
  if (ctx && typeof ctx.effect === "function") {
    ctx.effect(mount, "dsh-approval-gate: tools guard");
    return;
  }
  return mount();
}
