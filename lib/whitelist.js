// lib/whitelist.js
// Safe P1 path whitelist normalization and matching helpers (#199).

import path from "node:path";
import { expandHome, normalizeSeparators } from "./paths.js";

/**
 * Normalizes a whitelist entry array, dropping blank entries or dangerous global wildcards.
 *
 * @param {unknown} rawPaths
 * @returns {string[]}
 */
export function normalizeWhitelistPaths(rawPaths) {
  if (!Array.isArray(rawPaths)) return [];
  const out = [];
  const seen = new Set();
  for (const item of rawPaths) {
    if (typeof item !== "string") continue;
    const trimmed = item.trim();
    if (!trimmed) continue;
    if (trimmed === "/" || trimmed === "*" || trimmed === "**" || trimmed === "/*") continue;
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      out.push(trimmed);
    }
  }
  return out;
}

function resolveCandidate(rawPath, workspaceDir) {
  const expanded = expandHome(String(rawPath || "").trim());
  const ws = workspaceDir ? expandHome(String(workspaceDir)) : process.cwd();
  const abs = path.isAbsolute(expanded) ? path.resolve(expanded) : path.resolve(ws, expanded);
  return normalizeSeparators(abs).replace(/\/+$/, "") || "/";
}

/**
 * Checks whether a target file path falls within any configured whitelist prefix/path.
 * Invoked only in P1 after P0 hard-deny rules so protected credentials/system files stay blocked.
 *
 * @param {string} targetPath
 * @param {string[]} whitelistPaths
 * @param {string} [workspaceDir]
 * @returns {boolean}
 */
export function matchesWhitelistPath(targetPath, whitelistPaths, workspaceDir) {
  if (!targetPath || typeof targetPath !== "string") return false;
  if (!Array.isArray(whitelistPaths) || whitelistPaths.length === 0) return false;
  const target = resolveCandidate(targetPath, workspaceDir);
  for (const rawEntry of whitelistPaths) {
    if (typeof rawEntry !== "string") continue;
    const entryText = rawEntry.trim();
    if (!entryText || entryText === "/" || entryText === "*" || entryText === "**" || entryText === "/*") continue;
    const cleanPattern = entryText.endsWith("/**") ? entryText.slice(0, -3) : entryText.endsWith("/*") ? entryText.slice(0, -2) : entryText;
    const entry = resolveCandidate(cleanPattern, workspaceDir);
    if (target === entry || target.startsWith(entry + "/")) {
      return true;
    }
  }
  return false;
}
