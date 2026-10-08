// lib/parsers/shell-cmds.js
// Specialized shell AST parser for redirections, subshells, pipelines, and error masking.
// Resolves: #126, #90

import { REDIR_OPS, SPLIT_OPS } from "../tokenizer.js";
import { isProtectedConfigPath, isPathTraversal, normalizeSeparators } from "../paths.js";

const SHELLS = new Set(["bash", "sh", "dash", "zsh", "ksh", "ash"]);
const INTERPRETERS = new Set(["python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php"]);
const DB_CLIENTS = new Set([
  "sqlite3", "mysql", "psql", "pg_restore", "mongo", "mongosh", "redis-cli", "clickhouse-client",
]);
const DESTRUCTIVE_SQL = /\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i;
const WRAPPERS = new Set(["sudo", "command", "builtin", "nohup", "time", "nice", "ionice", "stdbuf", "timeout", "exec"]);

const SILENT_STDERR_PATTERN = /(?:2\s*>\s*\/dev\/null|&>\s*\/dev\/null|2>&1\s*>\s*\/dev\/null|>\s*\/dev\/null\s*2>&1)/i;
const SILENT_EXIT_ZERO_PATTERN = /\|\|\s*(?:true|:|exit\s+0)\b/i;
const SET_PLUS_E_PATTERN = /\bset\s+(?:\+[eE]|\+o\s+errexit)\b/i;

/**
 * Checks whether a path represents a raw physical or virtual disk device.
 *
 * @param {string} path
 * @returns {boolean}
 */
export function isDevicePath(path) {
  if (typeof path !== "string" || !path.startsWith("/dev/")) return false;
  const device = path.slice(5);
  if (["null", "zero", "full", "random", "urandom", "stdin", "stdout", "stderr", "tty"].includes(device)) {
    return false;
  }
  if (/^(?:sd[a-z]+\d*|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|loop\d+)$/i.test(device)) {
    return true;
  }
  return device.startsWith("mapper/") || device.startsWith("disk/by-id/") || device.startsWith("disk/by-uuid/");
}

/**
 * Extracts redirection operators and their target paths from segment tokens.
 *
 * @param {Array<{ kind: string, value: string, dynamic?: boolean }>} seg
 * @returns {Array<{ operator: string, path: string, dynamic: boolean }>}
 */
export function extractRedirects(seg) {
  if (!Array.isArray(seg)) return [];
  const redirects = [];
  for (let i = 0; i < seg.length; i += 1) {
    const t = seg[i];
    if (t.kind === "op" && REDIR_OPS.has(t.value)) {
      const next = seg[i + 1];
      if (next && next.kind === "word") {
        redirects.push({
          operator: t.value,
          path: next.value,
          dynamic: Boolean(next.dynamic),
        });
      }
    }
  }
  return redirects;
}

/**
 * Evaluates security of extracted redirections (device writes, secret writes, path traversals).
 *
 * @param {Array<{ operator: string, path: string, dynamic: boolean }>} redirects
 * @param {{ workspaceDir?: string, env?: Record<string, string> }} [options]
 * @returns {{ deny?: boolean, ask?: boolean, reason?: string, detail?: string, path?: string } | null}
 */
export function inspectRedirectSecurity(redirects, options = {}) {
  const workspaceDir = options.workspaceDir || process.cwd();
  const env = options.env || process.env;

  for (const redir of redirects) {
    if (redir.dynamic) {
      return {
        ask: true,
        reason: "dynamic-redirect",
        detail: "The expanded redirect target cannot be verified; review before allowing",
        path: redir.path,
      };
    }

    const norm = normalizeSeparators(redir.path);

    // Block device redirection
    if (isDevicePath(norm)) {
      return {
        deny: true,
        reason: "device-write",
        detail: `Redirection targets block device ${norm}`,
        path: redir.path,
      };
    }

    // Block protected secrets redirection
    if (isProtectedConfigPath(norm, env)) {
      return {
        deny: true,
        reason: "secret-write",
        detail: `Redirection targets protected configuration or credentials file ${norm}`,
        path: redir.path,
      };
    }

    // Block path traversal outside workspace
    const isRel = !/^(?:\/|[A-Za-z]:\/|\/\/)/.test(norm);
    const isExempt = !isRel && (
      /^\/dev\/(?:null|zero|stdout|stderr|fd\/\d+)$/.test(norm) ||
      /^(?:\/tmp|\/var\/tmp)(?:\/|$)/i.test(norm)
    );

    if (!isExempt && isPathTraversal(redir.path, workspaceDir)) {
      return {
        deny: true,
        reason: "path-traversal",
        detail: `Redirection escapes workspace boundary: ${redir.path}`,
        path: redir.path,
      };
    }
  }

  return null;
}

/**
 * Detects error masking and suppressed failures in shell commands.
 * Resolves: #90 (SilentErrorGuard).
 *
 * @param {string} command - Raw command line
 * @param {string[]} [argv] - Optional parsed argv
 * @returns {{
 *   masked: boolean,
 *   kind?: "stderr-suppressed" | "exit-zero-forced" | "errexit-disabled",
 *   pattern?: string,
 *   reason?: string,
 *   detail?: string
 * }}
 */
export function inspectSilentErrors(command, argv = []) {
  if (typeof command !== "string" || !command.trim()) {
    return { masked: false };
  }

  // 1. Check stderr suppression to /dev/null
  if (SILENT_STDERR_PATTERN.test(command)) {
    return {
      masked: true,
      kind: "stderr-suppressed",
      pattern: "2>/dev/null",
      reason: "silent-error-masked",
      detail: "Command suppresses error output via stderr redirection to /dev/null",
    };
  }

  // 2. Check forced success masking (|| true, || :)
  if (SILENT_EXIT_ZERO_PATTERN.test(command)) {
    return {
      masked: true,
      kind: "exit-zero-forced",
      pattern: "|| true",
      reason: "silent-error-masked",
      detail: "Command forces a success exit code via logical OR fallback (|| true or || :)",
    };
  }

  // 3. Check shell errexit unsetting (set +e)
  if (SET_PLUS_E_PATTERN.test(command)) {
    return {
      masked: true,
      kind: "errexit-disabled",
      pattern: "set +e",
      reason: "silent-error-masked",
      detail: "Command disables shell error-exit checking (set +e)",
    };
  }

  return { masked: false };
}

function unwrapExecutableFromSegment(seg) {
  const words = seg.filter((t) => t.kind === "word").map((t) => t.value);
  const takesValue = new Set(["-u", "--user", "-g", "--group", "-p", "-s", "--signal", "-k", "--kill-after", "-o", "-e", "-i"]);
  let i = 0;
  while (i < words.length) {
    const val = words[i];
    if (val === "then" || val === "do" || val === "{" || val === "!" || val === "}") {
      i += 1;
      continue;
    }
    if (val === "env") {
      i += 1;
      while (i < words.length && words[i].includes("=") && !words[i].startsWith("-")) i += 1;
      continue;
    }
    if (val.includes("=") && !val.startsWith("-")) {
      i += 1;
      continue;
    }
    if (!WRAPPERS.has(val)) {
      const parts = val.replace(/\\/g, "/").split("/");
      return parts[parts.length - 1] || "";
    }
    i += 1;
    while (i < words.length && words[i].startsWith("-")) {
      const flag = words[i];
      if (flag === "--") { i += 1; break; }
      if (takesValue.has(flag)) i += 2;
      else i += 1;
    }
    if (val === "timeout" && i < words.length) i += 1;
    if (val === "nice" && i < words.length && /^[0-9-]+$/.test(words[i])) i += 1;
  }
  return "";
}

/**
 * Scans tokens for dangerous downloader-to-shell or destructive SQL pipelines.
 *
 * @param {Array<{ kind: string, value: string }>} tokens
 * @returns {{ dangerousPipeline: boolean, kind?: "curl-pipe" | "destructive-sql", reason?: string }}
 */
export function inspectPipelines(tokens) {
  if (!Array.isArray(tokens)) return { dangerousPipeline: false };

  let segment = [];
  let pipelineHasDownloader = false;
  let pipelineHasDestructiveSql = false;
  let inPipeline = false;

  for (const token of tokens) {
    if (token.kind === "op" && SPLIT_OPS.has(token.value)) {
      const cmd = unwrapExecutableFromSegment(segment);
      if (inPipeline && (SHELLS.has(cmd) || INTERPRETERS.has(cmd)) && pipelineHasDownloader) {
        return { dangerousPipeline: true, kind: "curl-pipe", reason: "curl-pipe" };
      }
      if (inPipeline && DB_CLIENTS.has(cmd) && pipelineHasDestructiveSql) {
        return { dangerousPipeline: true, kind: "destructive-sql", reason: "destructive-sql" };
      }

      const continues = token.value === "|" || token.value === "|&";
      if (continues) {
        pipelineHasDownloader = pipelineHasDownloader || cmd === "curl" || cmd === "wget";
        const segText = segment.filter((t) => t.kind === "word").map((t) => t.value).join(" ");
        pipelineHasDestructiveSql = pipelineHasDestructiveSql || DESTRUCTIVE_SQL.test(segText);
        inPipeline = true;
      } else {
        pipelineHasDownloader = false;
        pipelineHasDestructiveSql = false;
        inPipeline = false;
      }
      segment = [];
      continue;
    }
    segment.push(token);
  }

  const finalCmd = unwrapExecutableFromSegment(segment);
  if (inPipeline && (SHELLS.has(finalCmd) || INTERPRETERS.has(finalCmd)) && pipelineHasDownloader) {
    return { dangerousPipeline: true, kind: "curl-pipe", reason: "curl-pipe" };
  }
  if (inPipeline && DB_CLIENTS.has(finalCmd) && pipelineHasDestructiveSql) {
    return { dangerousPipeline: true, kind: "destructive-sql", reason: "destructive-sql" };
  }

  return { dangerousPipeline: false };
}