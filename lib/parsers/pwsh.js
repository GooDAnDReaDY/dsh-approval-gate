// lib/parsers/pwsh.js
// Specialized PowerShell parser and security inspector for dsh-approval-gate (#192).
// Inspects PowerShell cmdlets, aliases, parameters, pipelines, and script blocks.

import { isProtectedConfigPath, resolveSafePath, normalizeSeparators } from "../paths.js";

/** Set of destructive cmdlets or aliases that delete files/directories */
const RM_CMDLETS = new Set([
  "remove-item",
  "rm",
  "rmdir",
  "del",
  "erase",
  "rd",
  "ri",
]);

/** Set of service manipulation cmdlets */
const SERVICE_CMDLETS = new Set([
  "stop-service",
  "spsv",
  "restart-service",
  "set-service",
  "suspend-service",
]);

/** Set of disk/volume destruction cmdlets */
const DISK_CMDLETS = new Set([
  "format-volume",
  "clear-disk",
  "initialize-disk",
  "remove-partition",
  "clear-partition",
  "format-hex",
]);

/** Set of file writing / mutation cmdlets */
const WRITE_CMDLETS = new Set([
  "set-content",
  "sc",
  "add-content",
  "ac",
  "out-file",
  "export-clixml",
  "export-csv",
]);

/** Known safe read-only inspection cmdlets */
const SAFE_READ_CMDLETS = new Set([
  "get-childitem", "dir", "ls", "gci",
  "get-content", "cat", "type", "gc",
  "get-location", "pwd", "gl",
  "get-process", "ps", "gps",
  "get-service", "gsv",
  "get-command", "gcm",
  "get-help",
  "get-date",
  "get-host",
  "get-random",
  "test-path",
  "select-string", "sls",
  "write-output", "echo",
  "write-host",
  "set-location", "cd", "chdir", "sl",
]);

/** Safe external CLI tools */
const SAFE_CLI_TOOLS = new Set([
  "git", "npm", "pnpm", "node", "yarn", "python", "python3", "pytest", "cargo", "go",
  "which", "where", "whoami", "hostname", "date",
]);

/**
 * Splits PowerShell pipeline into individual pipeline stages.
 * Handles single/double quotes and backtick escapes.
 * @param {string} commandLine
 * @returns {string[]}
 */
export function splitPwshPipeline(commandLine) {
  if (typeof commandLine !== "string") return [];
  const stages = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < commandLine.length; i++) {
    const ch = commandLine[i];
    if (ch === "`" && !inSingle) {
      current += ch;
      if (i + 1 < commandLine.length) {
        current += commandLine[++i];
      }
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
      continue;
    }
    if (ch === "|" && !inSingle && !inDouble) {
      if (current.trim()) stages.push(current.trim());
      current = "";
      continue;
    }
    if ((ch === ";" || ch === "\n" || (ch === "&" && commandLine[i + 1] === "&")) && !inSingle && !inDouble) {
      if (current.trim()) stages.push(current.trim());
      current = "";
      if (ch === "&") i++; // skip second &
      continue;
    }
    current += ch;
  }
  if (current.trim()) stages.push(current.trim());
  return stages;
}

/**
 * Tokenizes a single PowerShell command segment into argv tokens.
 * @param {string} segment
 * @returns {string[]}
 */
export function tokenizePwshSegment(segment) {
  const tokens = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (ch === "`" && !inSingle) {
      if (i + 1 < segment.length) current += segment[++i];
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (/\s/.test(ch) && !inSingle && !inDouble) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

/**
 * Checks whether a target path targets Windows system root or drive root.
 * @param {string} target
 * @returns {boolean}
 */
function isWindowsRootOrSystemTarget(target) {
  if (!target || typeof target !== "string") return false;
  const t = normalizeSeparators(target).trim();
  if (t === "/" || t === "\\" || /^[a-zA-Z]:(?:\/|\\)?$/.test(t)) return true;
  const lower = t.toLowerCase();
  if (lower === "c:/windows" || lower.startsWith("c:/windows/") || lower === "c:/winnt") return true;
  if (lower.startsWith("$env:windir") || lower.startsWith("$env:systemroot") || lower.startsWith("$env:userprofile")) return true;
  return false;
}

/**
 * Evaluates a single PowerShell tokenized command.
 * @param {string[]} tokens
 * @param {Record<string, any>} config
 * @returns {{ allow?: boolean, deny?: boolean, ask?: boolean, reason?: string, detail?: string, snippet?: string }}
 */
export function inspectPwshTokens(tokens, config = {}) {
  if (!tokens || tokens.length === 0) return { allow: true, deny: false, ask: false };
  const cmd = tokens[0].toLowerCase();
  const rest = tokens.slice(1);

  // 1. Disk / Partition wiping
  if (DISK_CMDLETS.has(cmd)) {
    return { deny: true, reason: "disk-wipe", detail: `Command ${tokens[0]} wipes or partitions disks (#192)`, snippet: tokens.join(" ") };
  }

  // 2. Service stopping / modification
  if (SERVICE_CMDLETS.has(cmd)) {
    return { deny: true, reason: "service-control", detail: `Command ${tokens[0]} manipulates system services (#192)`, snippet: tokens.join(" ") };
  }

  // 3. Dynamic code execution (Invoke-Expression / iex) (#192)
  if (cmd === "invoke-expression" || cmd === "iex") {
    return { deny: true, reason: "powershell-iex", detail: "Dynamic PowerShell script execution via Invoke-Expression/iex is prohibited (#192)", snippet: tokens.join(" ") };
  }

  // 3b. Execution policy bypass
  if (cmd === "set-executionpolicy") {
    const hasBypass = rest.some((a) => /^(?:bypass|unrestricted)$/i.test(a));
    if (hasBypass || rest.some((a) => /^-f(?:orce)?$/i.test(a))) {
      return { deny: true, reason: "execution-policy", detail: "Bypassing PowerShell ExecutionPolicy is prohibited (#192)", snippet: tokens.join(" ") };
    }
  }

  // 4. Destructive File Deletion (Remove-Item / rm / del / rmdir)
  if (RM_CMDLETS.has(cmd)) {
    const isRecursive = rest.some((a) => /^(?:-r|-recurse)$/i.test(a));
    const isForce = rest.some((a) => /^(?:-f|-force)$/i.test(a));
    const pathArgs = rest.filter((a) => a[0] !== "-");

    if (isRecursive) {
      return { deny: true, reason: "recursive-rm", detail: `Recursive deletion via ${tokens[0]} (#192)`, snippet: tokens.join(" ") };
    }

    // Check root deletion or protected path
    for (const p of pathArgs) {
      if (isWindowsRootOrSystemTarget(p)) {
        return { deny: true, reason: "destructive-command", detail: `Root deletion via ${tokens[0]} ${p} (#192)`, snippet: tokens.join(" ") };
      }
      if (isProtectedConfigPath(p, process.env, config)) {
        return { deny: true, reason: "secret-write", detail: `Deletion of protected file: ${p}`, snippet: tokens.join(" ") };
      }
    }

    // Single item removal inside workspace
    if (config.uncertainPolicy === "allow") {
      return { allow: true, deny: false, ask: false, reason: "uncertain-allow", snippet: tokens.join(" ") };
    }
    return { ask: true, deny: false, allow: false, reason: "file-remove", detail: `File removal via ${tokens[0]}`, snippet: tokens.join(" ") };
  }

  // 5. File writing cmdlets (Set-Content, Out-File, Add-Content)
  if (WRITE_CMDLETS.has(cmd)) {
    const pathArgs = rest.filter((a) => a[0] !== "-");
    for (const p of pathArgs) {
      if (isProtectedConfigPath(p, process.env, config)) {
        return { deny: true, reason: "secret-write", detail: `Modification of protected file: ${p}`, snippet: tokens.join(" ") };
      }
      if (config.workspaceDir) {
        const safe = resolveSafePath(p, config.workspaceDir);
        if (!safe.safe) {
          return { deny: true, reason: "path-traversal", detail: `File write outside workspace: ${p}`, snippet: tokens.join(" ") };
        }
      }
    }
  }

  // 6. Stop-Process (kill)
  if (cmd === "stop-process" || cmd === "kill" || cmd === "spps") {
    const criticalProcs = ["csrss", "lsass", "services", "explorer", "smss", "winlogon", "system"];
    for (const a of rest) {
      const lower = a.toLowerCase();
      if (criticalProcs.some((p) => lower.includes(p))) {
        return { deny: true, reason: "process-kill", detail: `Terminating critical system process: ${a}`, snippet: tokens.join(" ") };
      }
    }
  }

  // 7. Safe read-only cmdlets and CLI tools
  if (SAFE_READ_CMDLETS.has(cmd) || SAFE_CLI_TOOLS.has(cmd)) {
    return { allow: true, deny: false, ask: false, reason: "safe-allow", snippet: tokens.join(" ") };
  }

  // 8. Fallback based on uncertainPolicy
  if (config.uncertainPolicy === "allow") {
    return { allow: true, deny: false, ask: false, reason: "uncertain-allow", snippet: tokens.join(" ") };
  }

  return { ask: true, deny: false, allow: false, reason: "uncertain-syntax", detail: `PowerShell command requires confirmation: ${tokens[0]}`, snippet: tokens.join(" ") };
}

/**
 * Inspects a complete PowerShell command string (including pipelines and chains).
 * @param {string} commandLine
 * @param {number} [depth=0]
 * @param {Record<string, any>} [config={}]
 * @returns {{ allow?: boolean, deny?: boolean, ask?: boolean, reason?: string, detail?: string, snippet?: string }}
 */
export function inspectPwshCommand(commandLine, depth = 0, config = {}) {
  if (typeof commandLine !== "string" || !commandLine.trim()) {
    return { allow: true, deny: false, ask: false };
  }

  const stages = splitPwshPipeline(commandLine);
  if (stages.length === 0) return { allow: true, deny: false, ask: false };

  let hasAsk = null;
  let lastAllowReason = "safe-allow";

  for (const stage of stages) {
    const tokens = tokenizePwshSegment(stage);
    if (tokens.length === 0) continue;
    const hit = inspectPwshTokens(tokens, config);
    if (hit.deny) return hit; // Hard deny immediately aborts
    if (hit.ask && !hasAsk) hasAsk = hit;
    if (hit.reason) lastAllowReason = hit.reason;
  }

  if (hasAsk) return hasAsk;
  return { allow: true, deny: false, ask: false, reason: lastAllowReason };
}
