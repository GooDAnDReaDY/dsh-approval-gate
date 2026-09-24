// lib/paths.js
// Home path expansion and path boundary helpers for dsh-approval-gate.

/**
 * Expand `~`, `${HOME}`, `$HOME`, and `%USERPROFILE%` at the start of or within a path.
 *
 * @param {string} p - Path or string containing path references
 * @param {Record<string, string|undefined>} [env] - Environment dictionary (defaults to process.env)
 * @returns {string} Normalized path with home expanded
 */
export function expandHome(p, env = process.env) {
  if (typeof p !== "string" || p.trim() === "") return p;
  const home = (env && (env.HOME || env.USERPROFILE)) || "";
  if (!home) return p;
  const cleanHome = home.replace(/[/\\]+$/, "");

  let res = p;
  // Expand leading ~ or ~/ or ~\
  res = res.replace(/^~(?=$|[/\\])/, cleanHome);
  // Expand ${HOME} and $HOME
  res = res.replace(/\$\{HOME\}|\$HOME/g, cleanHome);
  // Expand %USERPROFILE% (Windows)
  res = res.replace(/%USERPROFILE%/gi, cleanHome);
  return res;
}
