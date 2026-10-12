// lib/network-sandbox.js
// Mapping Network Egress Policies to DSH Sandbox Modes (#41).
// Controls outbound socket and HTTP connections based on shell.sandboxMode.

import { isLoopbackHost } from "./loopback.js";

export const NETWORK_POLICIES = Object.freeze({
  DENY_ALL: "deny-all",
  WHITELIST_ONLY: "whitelist-only",
  ALLOW_ALL: "allow-all",
});

export const SANDBOX_NETWORK_MAP = Object.freeze({
  "read-only": NETWORK_POLICIES.DENY_ALL,
  readonly: NETWORK_POLICIES.DENY_ALL,
  isolated: NETWORK_POLICIES.DENY_ALL,
  "workspace-write": NETWORK_POLICIES.WHITELIST_ONLY,
  standard: NETWORK_POLICIES.WHITELIST_ONLY,
  hybrid: NETWORK_POLICIES.WHITELIST_ONLY,
  "danger-full-access": NETWORK_POLICIES.ALLOW_ALL,
  full: NETWORK_POLICIES.ALLOW_ALL,
});

/**
 * Resolves network egress policy from DSH sandbox mode (#41).
 *
 * @param {string} [sandboxMode]
 * @param {Record<string, any>} [options]
 * @returns {"deny-all" | "whitelist-only" | "allow-all"}
 */
export function resolveNetworkPolicy(sandboxMode, options = {}) {
  if (options.policy && Object.values(NETWORK_POLICIES).includes(options.policy)) {
    return options.policy;
  }
  const mode = String(sandboxMode || "").toLowerCase().trim();
  return SANDBOX_NETWORK_MAP[mode] || options.defaultPolicy || NETWORK_POLICIES.WHITELIST_ONLY;
}

/**
 * Normalizes a destination host / URL to hostname and port.
 * @param {string} destination
 * @returns {{ hostname: string, port: number }}
 */
export function parseDestination(destination) {
  if (!destination || typeof destination !== "string") {
    return { hostname: "", port: 80 };
  }
  const clean = destination.trim();
  try {
    if (clean.includes("://")) {
      const u = new URL(clean);
      return { hostname: u.hostname.toLowerCase(), port: Number(u.port) || (u.protocol === "https:" ? 443 : 80) };
    }
  } catch (_e) {}

  // host:port format
  if (clean.includes(":")) {
    const [h, p] = clean.split(":");
    return { hostname: h.toLowerCase(), port: Number(p) || 80 };
  }

  return { hostname: clean.toLowerCase(), port: 80 };
}

/**
 * Checks whether outbound network access to destination is allowed (#41).
 *
 * @param {string} destination - Host, host:port, or full URL
 * @param {string} [sandboxMode] - Active DSH sandbox mode
 * @param {{
 *   whitelist?: string[],
 *   allowLoopback?: boolean,
 *   policy?: string,
 * }} [options]
 * @returns {{
 *   allowed: boolean,
 *   policy: string,
 *   destination: string,
 *   hostname: string,
 *   reason?: string
 * }}
 */
export function checkNetworkAccess(destination, sandboxMode, options = {}) {
  const policy = resolveNetworkPolicy(sandboxMode, options);
  const { hostname } = parseDestination(destination);

  // 1. Loopback check (allowed by default for internal services unless explicitly blocked)
  const isLoopback = isLoopbackHost(hostname);
  if (isLoopback && options.allowLoopback !== false) {
    return {
      allowed: true,
      policy,
      destination,
      hostname,
      reason: "loopback-allowed",
    };
  }

  // 2. Deny-all policy (read-only sandbox mode)
  if (policy === NETWORK_POLICIES.DENY_ALL) {
    return {
      allowed: false,
      policy,
      destination,
      hostname,
      reason: "sandbox-read-only-network-denied",
    };
  }

  // 3. Allow-all policy (danger-full-access sandbox mode)
  if (policy === NETWORK_POLICIES.ALLOW_ALL) {
    return {
      allowed: true,
      policy,
      destination,
      hostname,
      reason: "danger-full-access-unrestricted",
    };
  }

  // 4. Whitelist-only policy (workspace-write / standard sandbox mode)
  const whitelist = Array.isArray(options.whitelist) ? options.whitelist : [];
  const isWhitelisted = whitelist.some((entry) => {
    const entryHost = String(entry).toLowerCase().trim();
    if (entryHost === hostname) return true;
    if (entryHost.startsWith("*.") && hostname.endsWith(entryHost.slice(1))) return true;
    return false;
  });

  if (isWhitelisted) {
    return {
      allowed: true,
      policy,
      destination,
      hostname,
      reason: "whitelist-allowed",
    };
  }

  return {
    allowed: false,
    policy,
    destination,
    hostname,
    reason: "not-in-network-whitelist",
  };
}
