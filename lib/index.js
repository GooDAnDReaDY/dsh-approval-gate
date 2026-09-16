// dsh-approval-gate - approval gate for DeepSeek Harness.
//
// Registers tools.guard on the tool runtime and denies dangerous bash
// commands and writes to secret files even when sandbox mode would allow
// them. A guard return value (non-undefined) denies execution, so the
// dangerous call never runs on its own - it needs an explicit owner
// approval word "делай".
//
// Only the agent tool calls pass through the guard (cron/systemd scripts
// do not), so legitimate unattended operations are unaffected.
import Schema from "@deepseek-ai/schemastery";
import {
  DEFAULT_BASH_TOOL,
  DEFAULT_FILE_WRITE_TOOLS,
  denyMessage,
  inspectExecution,
  sessionTag,
} from "./inspect.js";

export const name = "dsh-approval-gate";
export const inject = ["tools"];

export const Config = Schema.object({
  /** Name of the tool whose `command` arg is inspected (the DSH bash tool). */
  toolName: Schema.string().default(DEFAULT_BASH_TOOL),
  /** Extra tool names treated as file writes; paths are matched against secret files. */
  fileWriteTools: Schema.array(Schema.string()).default(DEFAULT_FILE_WRITE_TOOLS.slice()),
});

function logBlocked(ctx, hit, who) {
  const line = "[dsh-approval-gate] blocked " + (hit.reason || "dangerous") + who + ": " + String(hit.snippet || "").slice(0, 140);
  if (ctx && ctx.logger && typeof ctx.logger.warn === "function") ctx.logger.warn(line);
}

export function apply(ctx, config) {
  const cfg = Config(config || {}) || {};
  const toolName = cfg.toolName || DEFAULT_BASH_TOOL;
  const fileWriteTools = cfg.fileWriteTools || DEFAULT_FILE_WRITE_TOOLS.slice();

  const guard = function (execution) {
    const hit = inspectExecution(execution, { toolName: toolName, fileWriteTools: fileWriteTools });
    if (!hit.deny) return undefined;
    const who = sessionTag(execution);
    logBlocked(ctx, hit, who);
    return denyMessage(hit, who);
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
