import fs from "node:fs";
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
  res = res.replace(/\$\{HOME\}|\$HOME(?=\$|[\/\\])/g, cleanHome);
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

    const norm = normalizeSeparators(p);
  if (/^\/dev\/(?:null|zero|stdout|stderr|fd\/\d+)$/.test(norm)) {
    return false;
  }

  const isAbsolute = /^(?:\/|[A-Za-z]:\/|\/\/)/.test(norm);

  const normBase = canonicalizeFsPath(baseDir);
  if (isAbsolute) {
    // For absolute path, it is a traversal only if caller specifies a strict baseDir and candidate is outside
    const candidate = canonicalizeFsPath(p);
    if (baseDir && baseDir !== "/" && normBase !== "/") {
      if (candidate === normBase) return false;
      return !candidate.startsWith(normBase.endsWith("/") ? normBase : `${normBase}/`);
    }
    return false;
  }

  // Relative path traversal checking
  const candidate = canonicalizeFsPath(`${normBase}/${p}`);
  if (candidate === normBase) return false;
  return !candidate.startsWith(normBase.endsWith("/") ? normBase : `${normBase}/`);
}

/**
 * Safely resolves a path relative to a base directory, verifying boundaries.
 *
 * @param {string} p
 * @param {string} [baseDir]
 * @returns {{ safe: boolean, path: string, canonical: string, reason?: string }}
 */
export function resolveSafePath(p, baseDir = "/workspace") {
  if (typeof p !== "string" || p.trim() === "") {
    return { safe: false, reason: "empty-path", path: p, canonical: "" };
  }

  const normBase = canonicalizeFsPath(baseDir);

  if (isPathTraversal(p, baseDir)) {
    return {
      safe: false,
      reason: "path-traversal-escape",
      path: p,
      canonical: canonicalizeFsPath(p),
    };
  }

  const isAbsolute = /^(?:\/|[A-Za-z]:\/|\/\/)/.test(normalizeSeparators(p));
  const resolved = isAbsolute ? canonicalizeFsPath(p) : canonicalizeFsPath(`${normBase}/${p}`);

  if (isAbsolute && baseDir && normBase !== "/" && !resolved.startsWith(normBase.endsWith("/") ? normBase : `${normBase}/`) && resolved !== normBase) {
    return {
      safe: false,
      reason: "path-traversal-escape",
      path: p,
      canonical: resolved,
    };
  }

  // Inspect filesystem symlinks if the target file or its parent directory exists
  try {
    if (fs.existsSync(resolved)) {
      const real = fs.realpathSync(resolved);
      const normReal = canonicalizeFsPath(real);
      if (!normReal.startsWith(normBase.endsWith("/") ? normBase : `${normBase}/`) && normReal !== normBase) {
        return {
          safe: false,
          reason: "symlink-traversal-escape",
          path: p,
          canonical: normReal,
        };
      }
      return {
        safe: true,
        path: p,
        canonical: normReal,
      };
    }
  } catch {
    // Non-filesystem paths or missing directories fall back safely to lexical canonical
  }

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
export function isProtectedConfigPath(p, env = process.env, options = {}) {
  if (typeof p !== "string" || p.trim() === "") return false;
  const allowConfigEdits = Boolean(options && options.allowConfigEdits);

  const expanded = expandHome(p, env);
  const normalized = canonicalizeFsPath(expanded);
  const lower = normalized.toLowerCase();

  // Custom protected paths if specified (#192)
  if (options && Array.isArray(options.protectedPaths) && options.protectedPaths.length > 0) {
    for (const pat of options.protectedPaths) {
      if (typeof pat === "string" && pat.trim()) {
        const pLower = pat.trim().toLowerCase();
        if (lower === pLower || lower.endsWith("/" + pLower) || lower.includes("/" + pLower + "/")) {
          return true;
        }
      }
    }
  }

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

  // 4. Shell startup files & cordis.patch.yml
  const parts = normalized.split("/");
  const base = parts[parts.length - 1];
  const baseLower = base.toLowerCase();

  if (baseLower === "cordis.patch.yml") {
    return !allowConfigEdits;
  }

  if (PROTECTED_BASENAMES.has(baseLower)) {
    return true;
  }

  // 5. Env files (.env, .env.local, .env.prod)
  if (baseLower === ".env" || baseLower.startsWith(".env.")) {
    return true;
  }

  // 6. Credentials and settings (#192 allowConfigEdits)
  if (/^credentials\.ya?ml$/i.test(base)) {
    return true;
  }
  if (/^settings\.ya?ml$/i.test(base)) {
    return !allowConfigEdits;
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

/**
 * Resolves the isolated project-specific temporary root directory (#102).
 *
 * @param {string} [workspaceDir]
 * @returns {string}
 */
export function resolveTempRoot(workspaceDir) {
  const ws = normalizeSeparators(workspaceDir || process.cwd());
  return `${ws}/.dsh/tmp`;
}

/**
 * Checks if a path targets global host temporary directories (#102).
 *
 * @param {string} p
 * @returns {boolean}
 */
export function isGlobalTempPath(p) {
  if (typeof p !== "string") return false;
  const s = normalizeSeparators(p);
  const lower = s.toLowerCase();
  return (
    lower === "/tmp" ||
    lower.startsWith("/tmp/") ||
    lower === "/var/tmp" ||
    lower.startsWith("/var/tmp/") ||
    lower === "/dev/shm" ||
    lower.startsWith("/dev/shm/") ||
    /^[a-z]:\/windows\/temp(\/|$)/i.test(s)
  );
}

/**
 * Checks whether a file write target complies with project tempRoots isolation (#102).
 *
 * @param {string} targetPath
 * @param {string} [workspaceDir]
 * @returns {{ isolated: boolean, suggestedPath?: string, reason?: string }}
 */
export function checkTempIsolation(targetPath, workspaceDir) {
  if (!isGlobalTempPath(targetPath)) {
    return { isolated: true };
  }
  const ws = workspaceDir || process.cwd();
  const tempRoot = resolveTempRoot(ws);
  const norm = normalizeSeparators(targetPath);
  if (norm.startsWith(tempRoot)) {
    return { isolated: true };
  }
  const parts = norm.split("/").filter(Boolean);
  const filename = parts.pop() || "tempfile";
  return {
    isolated: false,
    suggestedPath: `${tempRoot}/${filename}`,
    reason: `Target path ${targetPath} targets global /tmp; should use project tempRoot: ${tempRoot}`,
  };
}

/**
 * Resolves the effective default workspace directory (#189).
 * Checks process.env.DSH_WORKSPACE, process.env.WORKSPACE_DIR, then process.cwd().
 * @returns {string}
 */
export function getDefaultWorkspaceDir() {
  const envDir = (process.env.DSH_WORKSPACE || process.env.WORKSPACE_DIR || "").trim();
  if (envDir) return canonicalizeFsPath(envDir);
  try {
    return canonicalizeFsPath(process.cwd());
  } catch {
    return "/workspace";
  }
}


