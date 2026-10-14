// lib/compat.js
// Host compatibility checks and polyfills across DeepSeek Harness minor versions (#106, #184).

/**
 * Detects available runtime capabilities and services in the Cordis host context (#106, #184).
 * Safely accesses properties via ctx.get() and guarded property lookup to avoid
 * throwing in strict Cordis contexts where uninjected property access is forbidden.
 *
 * @param {any} ctx - Cordis / DSH host context
 * @returns {{
 *   hasContext: boolean,
 *   hasToolsService: boolean,
 *   hasPreExecuteHook: boolean,
 *   hasProvideApi: boolean,
 *   hasLocaleService: boolean,
 *   harnessVersion: string
 * }}
 */
export function detectHarnessCapabilities(ctx) {
  if (!ctx || typeof ctx !== "object") {
    return {
      hasContext: false,
      hasToolsService: false,
      hasPreExecuteHook: false,
      hasProvideApi: false,
      hasLocaleService: false,
      harnessVersion: "unknown",
    };
  }

  const safeGet = (name) => {
    try {
      if (typeof ctx.get === "function") return ctx.get(name);
    } catch {
      // ignore
    }
    try {
      return ctx[name];
    } catch {
      return undefined;
    }
  };

  const tools = safeGet("tools");
  const locale = safeGet("locale");
  const onFn = safeGet("on");
  const provideFn = safeGet("provide");

  const rawVersion = safeGet("version");

  const harnessVersion =
    (typeof rawVersion === "string" && rawVersion.trim()) ||
    (rawVersion && typeof rawVersion === "object" && typeof rawVersion.version === "string" && rawVersion.version.trim()) ||
    (typeof process.env.DSH_VERSION === "string" && process.env.DSH_VERSION.trim()) ||
    "unknown";

  return {
    hasContext: true,
    hasToolsService: Boolean(tools),
    hasPreExecuteHook: typeof onFn === "function",
    hasProvideApi: typeof provideFn === "function",
    hasLocaleService: Boolean(locale && typeof locale.register === "function"),
    harnessVersion,
  };
}

/**
 * Asserts host compatibility and identifies missing optional or required features (#106, #184).
 *
 * @param {any} ctx
 * @param {{ requireTools?: boolean }} [options]
 * @returns {{ compatible: boolean, issues: string[], capabilities: ReturnType<typeof detectHarnessCapabilities> }}
 */
export function assertHarnessCompatibility(ctx, options = {}) {
  const caps = detectHarnessCapabilities(ctx);
  const issues = [];

  if (!caps.hasContext) {
    issues.push("Invalid or missing Cordis context object");
  }

  if (options.requireTools && !caps.hasToolsService) {
    issues.push("Missing tools service in host context");
  }

  return {
    compatible: issues.length === 0,
    issues,
    capabilities: caps,
  };
}

/**
 * Safely provides a service to the host context with backward-compatible polyfill (#106, #184).
 *
 * @param {any} ctx
 * @param {string} serviceName
 * @param {any} serviceInstance
 * @returns {boolean} True if successfully registered
 */
export function provideServicePolyfill(ctx, serviceName, serviceInstance) {
  if (!ctx || typeof ctx !== "object" || !serviceName) return false;

  let provideFn = undefined;
  try {
    provideFn = ctx.provide;
  } catch {
    // ignore
  }

  if (typeof provideFn === "function") {
    try {
      provideFn.call(ctx, serviceName, serviceInstance);
      return true;
    } catch {
      // fallback to property assignment below
    }
  }

  try {
    ctx[serviceName] = serviceInstance;
    return true;
  } catch {
    return false;
  }
}

/**
 * Safely attaches an event hook to the host context with error boundary (#106, #184).
 *
 * @param {any} ctx
 * @param {string} event
 * @param {(...args: any[]) => any} handler
 * @returns {(() => void) | null} Unsubscribe dispose function or null
 */
export function registerHookPolyfill(ctx, event, handler) {
  if (!ctx || typeof ctx !== "object" || typeof handler !== "function") {
    return null;
  }

  let onFn = undefined;
  try {
    onFn = ctx.on;
  } catch {
    // ignore
  }

  if (typeof onFn !== "function") {
    return null;
  }

  try {
    return onFn.call(ctx, event, handler);
  } catch {
    return null;
  }
}
