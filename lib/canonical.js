// lib/canonical.js
// Deterministic canonicalization and hashing for tool execution requests.
// Ensures identical tool calls with different key ordering produce identical hashes.

import { createHash } from "node:crypto";

/**
 * Recursively sort object keys alphabetically and normalize values.
 *
 * @param {any} value
 * @returns {any}
 */
export function sortKeys(value) {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  const sorted = {};
  const keys = Object.keys(value).sort();
  for (const k of keys) {
    sorted[k] = sortKeys(value[k]);
  }
  return sorted;
}

/**
 * Canonicalizes a tool call into a stable structure { tool: string, arguments: any }.
 *
 * @param {{ name?: string, tool?: string, arguments?: any } | string} executionOrTool
 * @param {any} [args]
 * @returns {{ tool: string, arguments: any }}
 */
export function canonicalizeCall(executionOrTool, args) {
  let tool = "";
  let rawArgs = {};

  if (typeof executionOrTool === "string") {
    tool = executionOrTool.trim();
    rawArgs = args || {};
  } else if (executionOrTool && typeof executionOrTool === "object") {
    tool = String(executionOrTool.name || executionOrTool.tool || "").trim();
    rawArgs = executionOrTool.arguments !== undefined ? executionOrTool.arguments : (args || {});
  }

  // If rawArgs is a JSON string, try to parse it
  if (typeof rawArgs === "string") {
    try {
      rawArgs = JSON.parse(rawArgs);
    } catch {
      // Keep as string if not valid JSON
    }
  }

  const normalizedArgs = rawArgs && typeof rawArgs === "object"
    ? sortKeys(rawArgs)
    : (rawArgs ?? {});

  return {
    tool,
    arguments: normalizedArgs,
  };
}

/**
 * Converts a tool call to a deterministic canonical JSON string.
 *
 * @param {{ name?: string, tool?: string, arguments?: any } | string} executionOrTool
 * @param {any} [args]
 * @returns {string}
 */
export function canonicalString(executionOrTool, args) {
  return JSON.stringify(canonicalizeCall(executionOrTool, args));
}

/**
 * Computes a cryptographic hash of the canonicalized tool call.
 *
 * @param {{ name?: string, tool?: string, arguments?: any } | string} executionOrTool
 * @param {any} [args]
 * @param {string} [algorithm="sha256"]
 * @returns {string}
 */
export function hashCall(executionOrTool, args, algorithm = "sha256") {
  const str = canonicalString(executionOrTool, args);
  return createHash(algorithm).update(str, "utf8").digest("hex");
}
