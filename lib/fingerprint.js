// lib/fingerprint.js
// Canonical operation fingerprint generator for dsh-approval-gate (#80).
// Format: tool:normalize(cmd):target_path
// Strict: flag or argument variations produce distinct fingerprints.

import { createHash } from "node:crypto";
import { extractFilePath } from "./dispatcher.js";
import { canonicalizeFsPath, normalizeSeparators } from "./paths.js";

/**
 * Normalizes command whitespace while preserving quotes.
 *
 * @param {string} cmd
 * @returns {string}
 */
export function normalizeCommandString(cmd) {
  if (typeof cmd !== "string") return "";
  const trimmed = cmd.trim();
  if (!trimmed) return "";

  let result = "";
  let inSingle = false;
  let inDouble = false;
  let lastWasSpace = false;

  for (let i = 0; i < trimmed.length; i += 1) {
    const ch = trimmed[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      result += ch;
      lastWasSpace = false;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      result += ch;
      lastWasSpace = false;
    } else if (/\s/.test(ch) && !inSingle && !inDouble) {
      if (!lastWasSpace) {
        result += " ";
        lastWasSpace = true;
      }
    } else {
      result += ch;
      lastWasSpace = false;
    }
  }

  return result.trim();
}

/**
 * Generates a canonical fingerprint for an operation.
 * Format: tool:normalized_cmd:target_path
 *
 * @param {{ name?: string, tool?: string, arguments?: any } | string} execution
 * @param {{ cwd?: string }} [options]
 * @returns {string}
 */
export function computeFingerprint(execution, options = {}) {
  let tool = "";
  let args = {};

  if (typeof execution === "string") {
    tool = execution.trim().toLowerCase();
  } else if (execution && typeof execution === "object") {
    tool = String(execution.name || execution.tool || "").trim().toLowerCase();
    args = execution.arguments || {};
    if (typeof args === "string") {
      try {
        args = JSON.parse(args);
      } catch {
        args = { raw: args };
      }
    }
  }

  const rawCmd = args && typeof args.command === "string" ? args.command : "";
  const normalizedCmd = normalizeCommandString(rawCmd);

  let targetPath = (args && (args.cwd || extractFilePath(args))) || options.cwd || "";
  if (typeof targetPath === "string" && targetPath.trim()) {
    targetPath = canonicalizeFsPath(normalizeSeparators(targetPath.trim()));
  } else {
    targetPath = "";
  }

  return `${tool}:${normalizedCmd}:${targetPath}`;
}

/**
 * Computes sha256 hash of the canonical operation fingerprint.
 *
 * @param {{ name?: string, tool?: string, arguments?: any } | string} execution
 * @param {{ cwd?: string, algorithm?: string }} [options]
 * @returns {string}
 */
export function computeFingerprintHash(execution, options = {}) {
  const fp = computeFingerprint(execution, options);
  const algo = options.algorithm || "sha256";
  return createHash(algo).update(fp, "utf8").digest("hex");
}
