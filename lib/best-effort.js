// lib/best-effort.js
// Explicit fail-open / service-lookup wrappers with structured warning logging (#195).

/**
 * Executes a non-critical operation and logs any failure via logger.warn instead of
 * silently swallowing exceptions in an empty catch block (#195).
 *
 * @template T
 * @param {string} label
 * @param {() => T} fn
 * @param {any} [logger]
 * @param {T} [fallback]
 * @returns {T | undefined}
 */
export function bestEffort(label, fn, logger, fallback = undefined) {
  try {
    return fn();
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    if (logger && typeof logger.warn === "function") {
      logger.warn(`[dsh-approval-gate] ${label}: ${msg}`);
    }
    return fallback;
  }
}

/**
 * Resolves an optional Cordis service via ctx.get(name) with direct property fallback (#184, #195).
 * Returns null without crashing when strict Cordis Proxy contexts deny unregistered injection.
 *
 * @param {any} ctx
 * @param {string} serviceName
 * @param {any} [logger]
 * @returns {any}
 */
export function resolveService(ctx, serviceName, logger) {
  if (!ctx || !serviceName) return null;
  let svc = bestEffort(`resolveService.get(${serviceName})`, () => {
    return typeof ctx.get === "function" ? ctx.get(serviceName) : null;
  }, logger, null);
  if (!svc) {
    svc = bestEffort(`resolveService.prop(${serviceName})`, () => ctx[serviceName] || null, logger, null);
  }
  return svc || null;
}
