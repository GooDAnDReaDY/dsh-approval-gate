// dsh-approval-gate - approval gate for DeepSeek Harness.
//
// Registers tools.guard on the tool runtime and denies dangerous bash
// commands and writes to secret files even when sandbox mode would allow
// them. A guard return value (non-undefined) denies execution, so the
// dangerous call never runs on its own - it needs an explicit owner
// Approval is handled by DSH's native flow; no separate word is implemented. When the
// effective approval policy cannot be answered ("never", i.e. the full-access preset),
// the gate does not raise an ask at all: an allowed command proceeds instead of dying as
// a rejection nobody could consent to. Denials never depend on the policy.
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

/** Policies under which a prompt cannot be answered, so raising one is a silent denial. */
export const DEFAULT_UNATTENDED_POLICIES = ["never"];

/**
 * Whether a raised ask would be answerable in this session.
 *
 * `policy` comes from the approval service (`ctx.approval.config.policy`); an empty value
 * means the knob is unknown and the gate keeps asking, which is the safe direction.
 * @param {{policy?: string, unattendedPolicies?: string[]}} knobs
 * @returns {boolean}
 */
export function isUnattended(knobs) {
  const policy = knobs && knobs.policy;
  const policies = (knobs && knobs.unattendedPolicies) || DEFAULT_UNATTENDED_POLICIES;
  if (typeof policy !== "string" || policy === "") return false;
  return policies.includes(policy);
}

/** Effective permission knobs, as the harness exposes them. */
function readKnobs(ctx) {
  const read = (name) => {
    try {
      return ctx && typeof ctx.get === "function" ? ctx.get(name) : undefined;
    } catch {
      return undefined;
    }
  };
  const approval = read("approval");
  const shell = read("shell");
  return {
    policy: (approval && approval.config && approval.config.policy) || "",
    sandbox: (shell && shell.sandboxMode) || "",
  };
}

export const Config = Schema.object({
  /** Name of the tool whose `command` arg is inspected (the DSH bash tool). */
  toolName: Schema.string().default(DEFAULT_BASH_TOOL),
  /** Extra tool names treated as file writes; paths are matched against secret files. */
  fileWriteTools: Schema.array(Schema.string()).default(DEFAULT_FILE_WRITE_TOOLS.slice()),
  /** Approval policies under which an ask could not be answered, so it is not raised. */
  unattendedPolicies: Schema.array(Schema.string()).default(DEFAULT_UNATTENDED_POLICIES.slice()),
  /** Force unattended behaviour where the approval policy is not visible. */
  unattended: Schema.boolean().default(false),
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
  const unattendedPolicies = cfg.unattendedPolicies || DEFAULT_UNATTENDED_POLICIES.slice();
  const forcedUnattended = cfg.unattended === true;
  const hasPreExecute = ctx && typeof ctx.on === "function";
  if (hasPreExecute) {
    ctx.on("tools/pre-execute", function (execution, next) {
      const hit = inspectExecution(execution, { toolName: toolName, fileWriteTools: fileWriteTools });
      if (!hit.ask) return next();
      const knobs = readKnobs(ctx);
      if (forcedUnattended || isUnattended({ policy: knobs.policy, unattendedPolicies })) {
        // No one can answer here: an allowed command proceeds. Denials are the guard's job
        // and do not depend on this decision.
        return next();
      }
      return { kind: "ask", reason: askMessage(hit, sessionTag(execution), translate, ctx && ctx.logger) };
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

export { SecurityEngine } from "./engine.js";
export { BandsEngine } from "./bands.js";
export { CircuitBreaker } from "./breaker.js";
export { expandHome } from "./paths.js";
export { splitSubcommands } from "./tokenizer.js";
