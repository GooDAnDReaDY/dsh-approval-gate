import { SecurityEngine } from "./engine.js";
import { BandsEngine } from "./bands.js";
import Schema from "@deepseek-ai/schemastery";

if (typeof Schema.prototype?.volatile !== "function") {
  if (Schema.prototype) {
    Schema.prototype.volatile = function volatile() {
      if (this.meta && this.meta.volatile) return this;
      return typeof this.extra === "function" ? this.extra("volatile", true) : this;
    };
  }
}

function isVolatileRef(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && typeof value.get === "function";
}

export function plainConfig(value) {
  if (isVolatileRef(value)) return plainConfig(value.get());
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(plainConfig);
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plainConfig(v)]));
}
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
export const provide = ["approvalGate"];

/** Policies under which a prompt cannot be answered, so raising one is a silent denial. */
export const DEFAULT_UNATTENDED_POLICIES = ["never"];

/**
 * Whether a raised ask would be answerable in this session.
 *
 * Checks explicit unattended policies, as well as preset and sandbox modes.
 * In 'danger-full-access' mode, approval prompts are disabled by host design.
 * @param {{policy?: string, preset?: string, sandbox?: string, unattendedPolicies?: string[]}} knobs
 * @returns {boolean}
 */
export function isUnattended(knobs) {
  if (!knobs) return false;
  if (knobs.preset === "danger-full-access" || knobs.sandbox === "danger-full-access") return true;
  const policy = knobs.policy;
  const policies = (knobs && knobs.unattendedPolicies) || DEFAULT_UNATTENDED_POLICIES;
  if (typeof policy !== "string" || policy === "") return false;
  return policies.includes(policy);
}

/**
 * Extracts a clean string session identifier from an execution object.
 * @param {any} execution
 * @returns {string}
 */
export function resolveSessionId(execution) {
  const agent = execution && execution.agent;
  const session = agent && agent.session;
  if (session) {
    if (typeof session === "string") return session;
    if (typeof session.id === "string") return session.id;
    if (typeof session.sessionId === "string") return session.sessionId;
    if (typeof session.sessionKey === "string") return session.sessionKey;
  }
  if (agent) {
    if (typeof agent === "string") return agent;
    if (typeof agent.id === "string") return agent.id;
  }
  return "default";
}

/**
 * Effective permission knobs, as the harness exposes them.
 * Resolves session-level approval policy, preset, and sandbox mode.
 *
 * @param {any} ctx - Cordis context
 * @param {any} [execution] - Optional tool execution carrying agent/session
 * @returns {{ policy: string, sandbox: string, preset: string }}
 */
export function readKnobs(ctx, execution) {
  const read = (name) => {
    try {
      return ctx && typeof ctx.get === "function" ? ctx.get(name) : undefined;
    } catch {
      return undefined;
    }
  };
  const approval = read("approval");
  const shell = read("shell");

  const agent = execution && execution.agent;
  const session = agent && (agent.session || (typeof agent === "object" && typeof agent.eventAt === "function" ? agent : undefined));

  let policy = "";
  let preset = "";
  let sessionSandbox = "";

  // 1. Inspect session events backwards (bounded to last 100 events) with sequence caching
  if (session && typeof session.eventAt === "function" && typeof session.seq === "number") {
    if (session._gateCachedSeq === session.seq && session._gateCachedPolicy !== undefined) {
      policy = session._gateCachedPolicy;
      preset = session._gateCachedPreset || "";
      sessionSandbox = session._gateCachedSandbox || "";
    } else {
      try {
        const minSeq = Math.max(0, session.seq - 100);
        for (let seq = session.seq - 1; seq >= minSeq; seq -= 1) {
          const event = session.eventAt(seq);
          if (!policy && event && event.type === "approval/policy" && event.data && event.data.policy) {
            policy = event.data.policy;
          }
          if (!preset && event && event.type === "permission/preset" && event.data && event.data.preset) {
            preset = event.data.preset;
          }
          if (!sessionSandbox && event && event.type === "sandbox/mode" && event.data && event.data.mode) {
            sessionSandbox = event.data.mode;
          }
          if (policy && preset && sessionSandbox) break;
        }
        session._gateCachedSeq = session.seq;
        session._gateCachedPolicy = policy || "";
        session._gateCachedPreset = preset || "";
        session._gateCachedSandbox = sessionSandbox || "";
      } catch {
        // ignore
      }
    }
  }

  // 2. In-memory session.events array fallback (common in mocks / tests)
  if (session && Array.isArray(session.events)) {
    try {
      const minIdx = Math.max(0, session.events.length - 100);
      for (let i = session.events.length - 1; i >= minIdx; i -= 1) {
        const event = session.events[i];
        if (!policy && event && event.type === "approval/policy" && event.data && event.data.policy) {
          policy = event.data.policy;
        }
        if (!preset && event && event.type === "permission/preset" && event.data && event.data.preset) {
          preset = event.data.preset;
        }
        if (!sessionSandbox && event && event.type === "sandbox/mode" && event.data && event.data.mode) {
          sessionSandbox = event.data.mode;
        }
        if (policy && preset && sessionSandbox) break;
      }
    } catch {
      // ignore
    }
  }

  // 3. Preset / sandbox direct values: danger-full-access implies "never" approval
  if (preset === "danger-full-access" || sessionSandbox === "danger-full-access") {
    policy = "never";
  }

  // 4. Direct session property fallback
  if (!policy && session && typeof session.approvalPolicy === "string") {
    policy = session.approvalPolicy;
  }

  // 5. Live approval service effectivePolicy(session)
  if (!policy && approval && session && typeof approval.effectivePolicy === "function") {
    try {
      policy = approval.effectivePolicy(session) || "";
    } catch {
      // ignore
    }
  }

  // 6. Global static fallback from approval service config
  if (!policy && approval && approval.config && approval.config.policy) {
    policy = approval.config.policy;
  }

  const sandbox = sessionSandbox || (shell && shell.sandboxMode) || "";
  if (sandbox === "danger-full-access" && !policy) {
    policy = "never";
  }

  return {
    policy: policy || "",
    sandbox: sandbox || "",
    preset: preset || "",
  };
}

export const Config = Schema.object({
  /** Name of the tool whose `command` arg is inspected (the DSH bash tool). */
  toolName: Schema.string().default(DEFAULT_BASH_TOOL).volatile(),
  /** Extra tool names treated as file writes; paths are matched against secret files. */
  fileWriteTools: Schema.array(Schema.string()).default(DEFAULT_FILE_WRITE_TOOLS.slice()).volatile(),
  /** Approval policies under which an ask could not be answered, so it is not raised. */
  unattendedPolicies: Schema.array(Schema.string()).default(DEFAULT_UNATTENDED_POLICIES.slice()).volatile(),
  /** Force unattended behaviour where the approval policy is not visible. */
  unattended: Schema.boolean().default(false).volatile(),
  /** Workspace directory for path traversal boundary checks. */
  workspaceDir: Schema.string().default("").volatile(),
  /** Default verdict for unclassified commands: 'allow' (default) or 'ask' (fail-closed) (#163). */
  defaultVerdict: Schema.union(["allow", "ask"]).default("allow").volatile(),
  /** Security engine instance (internal/testing). */
  engine: Schema.any().hidden(),
});

function logBlocked(ctx, hit, who) {
  const line = "[dsh-approval-gate] blocked rule=" + (hit.reason || "unknown") + who;
  if (ctx && ctx.logger && typeof ctx.logger.warn === "function") ctx.logger.warn(line);
}

export function apply(ctx, config) {
  const cfg = plainConfig(Config(plainConfig(config) || {}) || {});
  const toolName = cfg.toolName || DEFAULT_BASH_TOOL;
  const fileWriteTools = cfg.fileWriteTools || DEFAULT_FILE_WRITE_TOOLS.slice();
  const getLocale = function () {
    if (ctx && typeof ctx.get === "function") return ctx.get("locale");
    return ctx && ctx.locale;
  };
  const registerLocale = function () {
    const locale = getLocale();
    if (locale && typeof locale.register === "function") {
      try {
        return locale.register(LOCALE_NS, MESSAGES);
      } catch (err) {
        if (ctx && ctx.logger && typeof ctx.logger.warn === "function") {
          ctx.logger.warn("[dsh-approval-gate] locale registration skipped: " + (err && err.message || err));
        }
      }
    }
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
  const engine = (config && config.engine) || cfg.engine || new SecurityEngine({
    inspectConfig: { toolName: toolName, fileWriteTools: fileWriteTools, workspaceDir: cfg.workspaceDir || "" },
    bands: new BandsEngine({ toolRegistry: ctx && ctx.tools }),
    defaultVerdict: cfg.defaultVerdict || "allow",
  });

  const gateService = {
    engine,
    addGrant: (options) => engine.addGrant(options),
    resume: (sessionId, reason) => engine.resume(sessionId, reason),
  };
  if (ctx && typeof ctx === "object") {
    if (typeof ctx.provide === "function") {
      ctx.provide("approvalGate", gateService);
    } else {
      ctx.approvalGate = gateService;
    }
  }

  const hasPreExecute = ctx && typeof ctx.on === "function";
  if (hasPreExecute) {
    ctx.on("tools/pre-execute", function (execution, next) {
      const knobs = readKnobs(ctx, execution);
      const who = sessionTag(execution);
      const sessionId = resolveSessionId(execution);
      let decision;
      try {
        decision = engine.decide(execution, { sessionId, knobs });
      } catch (err) {
        const hit = {
          ask: true,
          reason: "inspect-error",
          detail: String(err && err.message || err),
          snippet: (execution && execution.arguments && execution.arguments.command) || execution.name,
        };
        return { kind: "ask", reason: askMessage(hit, who, translate, ctx && ctx.logger) };
      }

      if (decision.verdict === "ask") {
        if (decision.reason === "circuit-breaker-tripped") {
          const hit = decision.hit || {
            deny: true,
            reason: "circuit-breaker-tripped",
            detail: decision.detail,
            snippet: (execution && execution.arguments && execution.arguments.command) || execution.name,
          };
          logBlocked(ctx, hit, who);
          return denyMessage(hit, who, translate, ctx && ctx.logger);
        }
        if (forcedUnattended || isUnattended({ policy: knobs.policy, preset: knobs.preset, sandbox: knobs.sandbox, unattendedPolicies })) {
          return next();
        }
        const hit = decision.hit || {
          ask: true,
          reason: decision.reason,
          detail: decision.detail,
          snippet: decision.detail || (execution && execution.arguments && execution.arguments.command),
        };
        return { kind: "ask", reason: askMessage(hit, who, translate, ctx && ctx.logger) };
      }
      return next();
    });
  }

  const guard = function (execution) {
    const who = sessionTag(execution);
    const sessionId = resolveSessionId(execution);
    let decision;
    try {
      decision = engine.decide(execution, { sessionId });
    } catch (err) {
      const hit = {
        deny: true,
        reason: "inspect-error",
        detail: String(err && err.message || err),
        snippet: (execution && execution.arguments && execution.arguments.command) || execution.name,
      };
      logBlocked(ctx, hit, who);
      return denyMessage(hit, who, translate, ctx && ctx.logger);
    }

    if (decision.verdict === "deny" || (decision.verdict === "ask" && !hasPreExecute)) {
      const hit = decision.hit || {
        deny: true,
        reason: decision.reason,
        snippet: decision.detail || (execution && execution.arguments && execution.arguments.command) || execution.name,
      };
      logBlocked(ctx, hit, who);
      return denyMessage(hit, who, translate, ctx && ctx.logger);
    }
    return undefined;
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
export {
  CircuitBreaker,
  CIRCUIT_STATE_ACTIVE,
  CIRCUIT_STATE_TRIPPED,
  CIRCUIT_STATE_RESUMED,
} from "./breaker.js";
export {
  SessionGrantStore,
  DEFAULT_GRANT_TTL_MS,
  DEFAULT_GRANT_MAX_USES,
  matchGrantCriteria,
} from "./grants.js";
export {
  canonicalizeCall,
  canonicalString,
  hashCall,
  sortKeys,
} from "./canonical.js";
export { expandHome, resolveSafePath, isPathTraversal, canonicalizeFsPath } from "./paths.js";
export { splitSubcommands } from "./tokenizer.js";
export { redactCredentials, redactUrl } from "./redact.js";
