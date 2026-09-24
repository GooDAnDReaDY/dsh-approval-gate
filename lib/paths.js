// lib/paths.js
// Cross-platform path normalization, home expansion, and path boundary helpers for dsh-approval-gate.

/**
 * Normalizes Windows and POSIX path separators to uniform forward slashes.
 * Collapses redundant slashes and standardizes Windows drive letters.
 *
 * @param {string} p
 * @returns {string}
 */
export function normalizeSeparators(p) {
  if (typeof p !== "string") return "";
  let s = p.trim();
  if (s === "") return "";

  // Check UNC network share (e.g. \\server\share or //server/share)
  const isUnc = /^([\\/]{2})([^\\/]+)/.test(s);

  // Convert all backslashes to forward slashes
  s = s.replace(/\\/g, "/");

  // Collapse multiple consecutive slashes
  if (isUnc) {
    s = "//" + s.slice(2).replace(/\/+/g, "/");
  } else {
    s = s.replace(/\/+/g, "/");
  }

  // Normalize Windows drive letter: c:/ -> C:/
  s = s.replace(/^([a-zA-Z]):(\/|$)/, (_, drive, rest) => `${drive.toUpperCase()}:${rest}`);

  // Strip trailing slash unless root / or C:/
  if (s.length > 1 && s.endsWith("/")) {
    if (!/^(?:\/|[A-Za-z]:\/)$/.test(s)) {
      s = s.slice(0, -1);
    }
  }

  return s;
}

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

