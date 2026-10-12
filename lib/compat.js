// lib/compat.js
// Host compatibility checks and polyfills across DeepSeek Harness minor versions (#106).

/**
 * Detects available runtime capabilities and services in the Cordis host context (#106).
 *
 * @param {any} ctx - Cordis / DSH host context
 * @returns {{
 *   hasContext: boolean,
 *   hasToolsService: boolean,
 *   hasPreExecuteHook: boolean,
 *   hasProvideApi: boolean,
 *   hasLocaleService: boolean,
 *   harnessVersion: string | null
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
      harnessVersion: null,
    };
  }

  const getService = (name) => {
    try {
      if (typeof ctx.get === "function") return ctx.get(name);
    } catch {
      // ignore
    }
    return ctx[name];
  };

  const tools = getService("tools");
  const locale = getService("locale");

  const harnessVersion =
    (typeof ctx.version === "string" && ctx.version) ||
    (typeof process.env.DSH_VERSION === "string" && process.env.DSH_VERSION) ||
    null;

  return {
    hasContext: true,
    hasToolsService: Boolean(tools),
    hasPreExecuteHook: typeof ctx.on === "function",
    hasProvideApi: typeof ctx.provide === "function",
    hasLocaleService: Boolean(locale && typeof locale.register === "function"),
    harnessVersion,
  };
}

/**
 * Asserts host compatibility and identifies missing optional or required features (#106).
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
 * Safely provides a service to the host context with backward-compatible polyfill (#106).
 *
 * @param {any} ctx
 * @param {string} serviceName
 * @param {any} serviceInstance
 * @returns {boolean} True if successfully registered
 */
export function provideServicePolyfill(ctx, serviceName, serviceInstance) {
  if (!ctx || typeof ctx !== "object" || !serviceName) return false;

  if (typeof ctx.provide === "function") {
    try {
      ctx.provide(serviceName, serviceInstance);
      return true;
    } catch {
      // fallback to property assignment below
    }
  }

  ctx[serviceName] = serviceInstance;
  return true;
}

/**
 * Safely attaches an event hook to the host context with error boundary (#106).
 *
 * @param {any} ctx
 * @param {string} event
 * @param {(...args: any[]) => any} handler
 * @returns {(() => void) | null} Unsubscribe dispose function or null
 */
export function registerHookPolyfill(ctx, event, handler) {
  if (!ctx || typeof ctx.on !== "function" || typeof handler !== "function") {
    return null;
  }

  try {
    return ctx.on(event, handler);
  } catch {
    return null;
  }
}
