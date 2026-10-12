// lib/trash.js
// Reversible Trash Move: safe alternative to destructive rm commands (#104).

import path from "node:path";

const RM_COMMAND_PATTERN = /^\s*rm\b/i;
const RM_FLAGS_PATTERN = /^-[a-zA-Z0-9_\-]+$/;

/**
 * Resolves the isolated trash directory for a workspace and session (#104).
 * Default path: <workspaceDir>/.dsh/trash/<sessionId>
 *
 * @param {string} [workspaceDir]
 * @param {string} [sessionId]
 * @returns {string}
 */
export function resolveTrashDir(workspaceDir, sessionId = "default") {
  const base = workspaceDir && typeof workspaceDir === "string" ? workspaceDir : ".";
  const session = String(sessionId || "default").replace(/[^a-zA-Z0-9_\-]/g, "_");
  return path.join(base, ".dsh", "trash", session);
}

/**
 * Checks if a shell command is an rm command (#104).
 *
 * @param {string} command
 * @returns {boolean}
 */
export function isRmCommand(command) {
  if (typeof command !== "string") return false;
  return RM_COMMAND_PATTERN.test(command.trim());
}

/**
 * Extracts target file and directory paths from an rm command string (#104).
 *
 * @param {string} command
 * @returns {string[]}
 */
export function extractRmTargets(command) {
  if (typeof command !== "string") return [];
  const trimmed = command.trim();
  if (!RM_COMMAND_PATTERN.test(trimmed)) return [];

  const parts = trimmed.split(/\s+/);
  const targets = [];

  // Skip leading "rm" and any option flags (-r, -f, -rf, --recursive, etc.)
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    if (part.startsWith("-")) {
      continue;
    }
    // Stop if shell control operators occur
    if (/[;&|]/.test(part)) {
      break;
    }
    targets.push(part);
  }

  return targets;
}

/**
 * Builds a reversible trash move command replacing destructive rm (#104).
 *
 * @param {string[]} targetPaths
 * @param {string} trashDir
 * @returns {string}
 */
export function buildTrashCommand(targetPaths, trashDir) {
  if (!Array.isArray(targetPaths) || targetPaths.length === 0) {
    return "";
  }
  const cleanTargets = targetPaths
    .map((t) => String(t || "").trim())
    .filter((t) => t.length > 0 && !t.startsWith("-"));

  if (cleanTargets.length === 0) {
    return "";
  }

  const quotedTargets = cleanTargets.map((t) => (t.includes(" ") ? `"${t}"` : t)).join(" ");
  const normalizedTrash = String(trashDir || ".dsh/trash").trim();
  const quotedTrash = normalizedTrash.includes(" ") ? `"${normalizedTrash}"` : normalizedTrash;

  return `mkdir -p ${quotedTrash} && mv ${quotedTargets} ${quotedTrash}/`;
}

/**
 * Suggests a safe trash alternative for an rm execution (#104).
 *
 * @param {string} command
 * @param {string} [workspaceDir]
 * @param {string} [sessionId]
 * @returns {{ isRm: boolean, targets: string[], trashDir: string, suggestedCommand: string | null }}
 */
export function suggestTrashAlternative(command, workspaceDir, sessionId) {
  const isRm = isRmCommand(command);
  if (!isRm) {
    return {
      isRm: false,
      targets: [],
      trashDir: "",
      suggestedCommand: null,
    };
  }

  const targets = extractRmTargets(command);
  const trashDir = resolveTrashDir(workspaceDir, sessionId);
  const suggestedCommand = targets.length > 0 ? buildTrashCommand(targets, trashDir) : null;

  return {
    isRm: true,
    targets,
    trashDir,
    suggestedCommand,
  };
}
