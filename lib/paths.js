// lib/paths.js
// Cross-platform path normalization, home expansion, canonicalization, and path boundary traversal protection for dsh-approval-gate.

const PROTECTED_BASENAMES = new Set([
  ".bashrc",
  ".bash_profile",
  ".bash_login",
  ".profile",
  ".zshrc",
  ".zprofile",
  ".zshenv",
  ".cshrc",
  "cordis.patch.yml",
]);

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

/**
 * Canonicalizes a path resolving dot and dot-dot segments without disk I/O.
 *
 * @param {string} p
 * @param {{ env?: Record<string, string|undefined> }} [options]
 * @returns {string}
 */
export function canonicalizeFsPath(p, options = {}) {
  if (typeof p !== "string") return "";
  let s = expandHome(p, options.env);
  s = normalizeSeparators(s);
  if (!s) return "";

  // Check prefix: / (root), C:/ (Windows root), //server/share (UNC), or relative
  let prefix = "";
  if (s.startsWith("//")) {
    const m = s.match(/^(\/\/[^/]+\/[^/]+)(?:\/|$)/);
    if (m) {
      prefix = m[1];
      s = s.slice(prefix.length);
    }
  } else if (/^[A-Za-z]:\//.test(s)) {
    prefix = s.slice(0, 3);
    s = s.slice(3);
  } else if (s.startsWith("/")) {
    prefix = "/";
    s = s.slice(1);
  }

  const rawSegments = s.split("/");
  const stack = [];

  for (const seg of rawSegments) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (stack.length > 0 && stack[stack.length - 1] !== "..") {
        stack.pop();
      } else if (!prefix) {
        stack.push("..");
      }
      // If there is an absolute prefix (e.g. / or C:/), .. at root cannot escape above root
    } else {
      stack.push(seg);
    }
  }

  const resolvedBody = stack.join("/");
  if (!prefix) {
    return resolvedBody || ".";
  }
  if (!resolvedBody) {
    return prefix;
  }
  return prefix.endsWith("/") ? `${prefix}${resolvedBody}` : `${prefix}/${resolvedBody}`;
}

/**
 * Checks whether a path contains directory traversal sequences attempting to escape baseDir.
 *
 * @param {string} p
 * @param {string} [baseDir]
 * @returns {boolean}
 */
export function isPathTraversal(p, baseDir = "/workspace") {
  if (typeof p !== "string" || p.trim() === "") return false;

  // Detect null byte injection
  if (p.includes("\0") || /%00/i.test(p)) return true;

  // Detect encoded traversal sequences
  if (/(?:%2e|%2f|%5c|\.\.)(?:%2e|%2f|%5c|\.\.)/i.test(p)) return true;

  const normBase = canonicalizeFsPath(baseDir);
  const isAbsolute = /^(?:\/|[A-Za-z]:\/|\/\/)/.test(normalizeSeparators(p));

  let candidate = "";
  if (isAbsolute) {
    candidate = canonicalizeFsPath(p);
  } else {
    candidate = canonicalizeFsPath(`${normBase}/${p}`);
  }

  if (candidate === normBase) return false;
  return !(candidate.startsWith(normBase.endsWith("/") ? normBase : `${normBase}/`));
}

/**
 * Safely resolves a path relative to a base directory, verifying boundaries.
 *
 * @param {string} p
 * @param {string} [baseDir]
 * @returns {{ safe: boolean, path: string, canonical: string, reason?: string }}
 */
export function resolveSafePath(p, baseDir = "/workspace") {
  if (isPathTraversal(p, baseDir)) {
    return {
      safe: false,
      reason: "path-traversal-escape",
      path: p,
      canonical: canonicalizeFsPath(p),
    };
  }
  const normBase = canonicalizeFsPath(baseDir);
  const isAbsolute = /^(?:\/|[A-Za-z]:\/|\/\/)/.test(normalizeSeparators(p));
  const resolved = isAbsolute ? canonicalizeFsPath(p) : canonicalizeFsPath(`${normBase}/${p}`);
  return {
    safe: true,
    path: p,
    canonical: resolved,
  };
}

/**
 * Checks whether a path targets protected system, git, ssh, or secret configuration.
 *
 * @param {string} p
 * @param {Record<string, string|undefined>} [env]
 * @returns {boolean}
 */
export function isProtectedConfigPath(p, env = process.env) {
  if (typeof p !== "string" || p.trim() === "") return false;

  const expanded = expandHome(p, env);
  const normalized = canonicalizeFsPath(expanded);
  const lower = normalized.toLowerCase();

  // 1. .git internal tree
  if (
    lower === ".git" ||
    lower.startsWith(".git/") ||
    lower.endsWith("/.git") ||
    lower.includes("/.git/")
  ) {
    return true;
  }

  // 2. .ssh directory and key files
  if (
    lower === ".ssh" ||
    lower.startsWith(".ssh/") ||
    lower.endsWith("/.ssh") ||
    lower.includes("/.ssh/")
  ) {
    return true;
  }

  // 3. System auth and security files
  if (
    lower === "/etc/sudoers" ||
    lower.includes("/etc/sudoers.d/") ||
    lower === "/etc/shadow" ||
    lower === "/etc/gshadow" ||
    lower.includes("/etc/pam.d/")
  ) {
    return true;
  }

  // 4. Shell startup files
  const parts = normalized.split("/");
  const base = parts[parts.length - 1];
  const baseLower = base.toLowerCase();

  if (PROTECTED_BASENAMES.has(baseLower)) {
    return true;
  }

  // 5. Env files (.env, .env.local, .env.prod)
  if (baseLower === ".env" || baseLower.startsWith(".env.")) {
    return true;
  }

  // 6. Credentials and settings
  if (/^credentials\.ya?ml$/i.test(base) || /^settings\.ya?ml$/i.test(base)) {
    return true;
  }

  // 7. Certificates and keys
  if (/\.(pem|key|crt|p12|pfx)$/i.test(base)) {
    return true;
  }

  // 8. SSH key filenames anywhere
  if (/^(id_rsa|id_ed25519|id_ecdsa|authorized_keys2?)$/i.test(base)) {
    return true;
  }

  // 9. Generic secrets / tokens / passwords
  if (/(?:^|[._-])(?:secret|token|credential|passwd|api[_-]?key)(?:$|[._-])/i.test(baseLower)) {
    return true;
  }

  return false;
}

