// lib/dualtrack.js
// Dual-Track Markers for separating internal agent chores from external project mutations (#92).
// Provides classification and predicates to differentiate internal sandbox actions from project changes.

export const TRACK_TYPES = Object.freeze({
  INTERNAL: "internal",
  EXTERNAL: "external",
});

const INTERNAL_TOOL_NAMES = new Set([
  "read_url_content",
  "search_web",
  "web_search",
  "view_file",
  "read_file",
  "view",
  "inspect_file",
]);

const INTERNAL_PATH_PATTERNS = [
  /[\\/]\.dsh[\\/](?:tmp|trash|cache|sessions)[\\/]/i,
  /[\\/]\.gemini[\\/]/i,
  /[\\/]scratch[\\/]/i,
  /[\\/]\.cache[\\/]/i,
  /[\\/]tmp[\\/]/i,
];

const INTERNAL_COMMAND_REGEX = /^(?:git\s+(?:status|diff|rev-parse|branch|log)|npm\s+(?:view|help)|node\s+--version|echo\b|cat\s+[^\n]*\.(?:dsh|tmp|cache)|ls\s+-[la]*\s*(?:\.|$))/i;

/**
 * Classifies an operation into internal or external track (#92).
 *
 * @param {string} [toolName]
 * @param {string} [command]
 * @param {Record<string, any>} [args]
 * @param {Record<string, any>} [context]
 * @returns {'internal' | 'external'}
 */
export function classifyTrack(toolName, command, args = {}, context = {}) {
  // Explicit overrides in context or args
  if (context.track === TRACK_TYPES.INTERNAL || args?.track === TRACK_TYPES.INTERNAL || context.internal === true || args?.internal === true) {
    return TRACK_TYPES.INTERNAL;
  }
  if (context.track === TRACK_TYPES.EXTERNAL || args?.track === TRACK_TYPES.EXTERNAL || context.external === true || args?.external === true) {
    return TRACK_TYPES.EXTERNAL;
  }

  const tool = String(toolName || "").trim();
  const cmd = String(command || (args && args.command) || "").trim();
  const target = String((args && (args.TargetFile || args.targetPath || args.path || args.file)) || "").trim();

  // Operations targeting internal scratch/temp paths are internal
  if (target && INTERNAL_PATH_PATTERNS.some((p) => p.test(target))) {
    return TRACK_TYPES.INTERNAL;
  }

  // Pure read-only knowledge tools are internal
  if (INTERNAL_TOOL_NAMES.has(tool)) {
    return TRACK_TYPES.INTERNAL;
  }

  // File mutations on project files are external
  if (tool === "write_to_file" || tool === "replace_file_content" || tool === "create_file") {
    return TRACK_TYPES.EXTERNAL;
  }

  // Shell command classification
  if (cmd) {
    if (INTERNAL_PATH_PATTERNS.some((p) => p.test(cmd))) {
      return TRACK_TYPES.INTERNAL;
    }
    if (INTERNAL_COMMAND_REGEX.test(cmd)) {
      return TRACK_TYPES.INTERNAL;
    }
  }

  // Default for non-read commands or mutations
  return TRACK_TYPES.EXTERNAL;
}

/**
 * Checks whether track or decision is marked as internal.
 * @param {string | { track?: string }} [trackOrDecision]
 * @returns {boolean}
 */
export function isInternalTrack(trackOrDecision) {
  if (!trackOrDecision) return false;
  if (typeof trackOrDecision === "string") return trackOrDecision === TRACK_TYPES.INTERNAL;
  return trackOrDecision.track === TRACK_TYPES.INTERNAL;
}

/**
 * Checks whether track or decision is marked as external.
 * @param {string | { track?: string }} [trackOrDecision]
 * @returns {boolean}
 */
export function isExternalTrack(trackOrDecision) {
  if (!trackOrDecision) return false;
  if (typeof trackOrDecision === "string") return trackOrDecision === TRACK_TYPES.EXTERNAL;
  return trackOrDecision.track === TRACK_TYPES.EXTERNAL;
}
