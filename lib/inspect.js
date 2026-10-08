// lib/inspect.js
// Pure command and path inspector for dsh-approval-gate.
// Resolves: #133, #125, #126, #103, #90, #65, #40
// No Cordis imports: unit tests run this without the harness.

import { checkEnvExfiltration } from "./inspect-env.js";
export { checkEnvExfiltration } from "./inspect-env.js";
import { DYNAMIC_MARKER, SPLIT_OPS, tokenize, readCommandSubstitution, readBacktick, readParameterExpansion } from "./tokenizer.js";
import { expandHome, isProtectedConfigPath, resolveSafePath, isPathTraversal, canonicalizeFsPath, normalizeSeparators } from "./paths.js";
import { askMessage, denyMessage, sessionTag } from "./messages.js";
import { inspectGitCommand } from "./parsers/git.js";
import { extractRedirects, inspectRedirectSecurity, inspectSilentErrors, inspectPipelines, isDevicePath } from "./parsers/shell-cmds.js";
import { isLoopbackCommand } from "./loopback.js";
import { isReviewerAgent, extractFilePath, DEFAULT_BASH_TOOL, DEFAULT_FILE_WRITE_TOOLS } from "./dispatcher.js";

export { DYNAMIC_MARKER, tokenize, splitSubcommands } from "./tokenizer.js";
export { askMessage, denyMessage, sessionTag } from "./messages.js";
export { expandHome, isProtectedConfigPath, resolveSafePath, isPathTraversal, canonicalizeFsPath, normalizeSeparators } from "./paths.js";
export { DEFAULT_BASH_TOOL, DEFAULT_FILE_WRITE_TOOLS } from "./dispatcher.js";

const PREFIXES = new Set(["then", "do", "{", "}", "!"]);
const SHELLS = new Set(["bash", "sh", "dash", "zsh", "ksh", "ash"]);
const INTERPRETERS = new Set(["python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php"]);
const DB_CLIENTS = new Set([
  "sqlite3", "mysql", "psql", "pg_restore", "mongo", "mongosh", "redis-cli", "clickhouse-client",
]);
const DESTRUCTIVE_SQL = /\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i;
const KILL_CMDS = new Set(["kill", "pkill", "killall"]);
const SYSTEMCTL_DENY = new Set([
  "stop", "restart", "disable", "enable", "mask", "unmask",
  "reboot", "halt", "poweroff", "shutdown", "kill",
]);
const SERVICE_DENY = new Set(["stop", "restart", "force-stop", "force-reload"]);

const DESTRUCTIVE_CMDS = new Set([
  "rm", "chmod", "chown", "kill", "pkill", "systemctl", "service",
  "git", "dd", "mkfs", "tee", "install", "mv", "cp", "sed",
]);

export function basename(path) {
  const parts = String(path).replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || "";
}

export function isProtectedPath(path, env = process.env) {
  if (typeof path !== "string" || path.trim() === "") return false;
  return isProtectedConfigPath(path, env);
}

function wordsOf(seg) {
  return seg.filter((t) => t.kind === "word").map((t) => t.value);
}

function wordTokensOf(seg) {
  return seg.filter((t) => t.kind === "word");
}

function splitSegments(tokens) {
  const segs = [];
  let cur = [];
  for (const t of tokens) {
    if (t.kind === "op" && SPLIT_OPS.has(t.value)) {
      segs.push(cur);
      cur = [];
      continue;
    }
    cur.push(t);
  }
  segs.push(cur);
  return segs;
}

function stripPrefixes(argv) {
  const out = argv.filter((a) => a !== "}" && a !== ";");
  while (out.length) {
    const head = out[0];
    if (PREFIXES.has(head)) { out.shift(); continue; }
    if (head === "env") {
      out.shift();
      while (out.length && out[0].includes("=") && out[0][0] !== "-") out.shift();
      continue;
    }
    if (head.includes("=") && head[0] !== "-") { out.shift(); continue; }
    break;
  }
  return out;
}

function hasLetterFlag(argv, letter) {
  for (const a of argv) {
    if (a === "--") break;
    if (a.length > 1 && a[0] === "-" && a[1] !== "-" && a.indexOf(letter) !== -1) return true;
  }
  return false;
}

function deny(reason, snippet) {
  return { deny: true, ask: false, reason, detail: reason, snippet: String(snippet || reason).slice(0, 160) };
}

function allow() {
  return { deny: false, ask: false };
}

function ask(reason, detail, snippet) {
  return { deny: false, ask: true, reason, detail: detail || reason, snippet: String(snippet || "").slice(0, 160) };
}

function scriptAfterDashC(rest) {
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "-c") return rest[i + 1];
    if (a[0] === "-" && a[1] !== "-" && a.indexOf("c") !== -1) return rest[i + 1];
  }
  return undefined;
}

function skipWrapper(rest, arity) {
  let i = 0;
  while (i < rest.length && rest[i][0] === "-") {
    const a = rest[i];
    if (a === "--") { i += 1; break; }
    if (arity.has(a)) i += 2;
    else i += 1;
  }
  return rest.slice(i);
}

function inspectInterpreterPayload(cmd, payload) {
  const code = String(payload || "");
  const executesProcess = /(?:\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(|\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(|\b(?:exec|spawn)\s*\()/i.test(code);
  const writesFile = /\b(?:write_text|write_bytes|unlink|rmdir|remove|chmod|chown|truncate)\s*\(|\bopen\s*\([^)]*,\s*["'][wax+]/i.test(code);
  if (executesProcess) {
    if (/\brm\s+(?:-[a-z]*r[a-z]*|--recursive)\s+|\b(?:kill|pkill|killall)\b|\bsystemctl\s+(?:stop|restart|disable|mask)\b|\bservice\s+\S+\s+(?:stop|restart)\b|\bgit\s+reset\s+--hard\b|\b(?:curl|wget)\b[^|]*\|\s*(?:bash|sh)\b|\bmkfs(?:\.|\s)|\bdd\b[^\n]{0,160}\bof=\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|loop|mapper)/i.test(code)) {
      return deny("interpreter-payload", code);
    }
    return ask("interpreter-payload", "interpreter process execution is not fully analyzed", code);
  }
  if (writesFile) {
    if (/(?:\.env(?:\.[A-Za-z0-9_.-]+)?|credentials\.ya?ml|settings\.ya?ml|cordis\.patch\.yml|id_(?:rsa|ed25519|ecdsa)|[A-Za-z0-9_.-]+\.key)\b/i.test(code)) return deny("secret-write", code);
    return ask("interpreter-payload", "interpreter file writes are not fully analyzed", code);
  }
  return allow();
}

function inspectArgv(argv, depth, hasHeredoc, config = {}) {
  if (!argv.length) return allow();
  const cmd = basename(argv[0]);
  const rest = argv.slice(1);

  const envHit = checkEnvExfiltration(argv, argv.join(" "));
  if (envHit.deny) {
    return deny("env-dump-leak", envHit.detail || argv.join(" "));
  }

  if (cmd === "env") {
    const sub = rest.filter((a) => !a.startsWith("-") && !a.includes("="));
    if (sub.length > 0) {
      return inspectArgv(sub, depth, hasHeredoc, config);
    }
  }

  if (cmd === "sudo" || cmd === "command" || cmd === "builtin" || cmd === "nohup" || cmd === "time" || cmd === "nice" || cmd === "ionice" || cmd === "stdbuf" || cmd === "timeout") {
    const arity = new Set(["-u", "--user", "-g", "--group", "-p", "-s", "--signal", "-k", "--kill-after", "-o", "-e", "-i"]);
    let next = skipWrapper(rest, arity);
    if (cmd === "timeout" && next.length) next = next.slice(1);
    if (cmd === "nice" && next.length && /^[0-9-]+$/.test(next[0])) next = next.slice(1);
    return inspectArgv(next, depth, hasHeredoc, config);
  }

  if (cmd === "eval") return deny("eval", argv.join(" "));
  if (KILL_CMDS.has(cmd)) return deny("process-signal", argv.join(" "));
  if (cmd === "rm" && (hasLetterFlag(argv, "r") || hasLetterFlag(argv, "R") || rest.includes("--recursive"))) {
    return deny("recursive-rm", argv.join(" "));
  }
  if (cmd === "systemctl") {
    const verb = rest.find((a) => a[0] !== "-");
    if (verb && SYSTEMCTL_DENY.has(verb)) return deny("service-control", argv.join(" "));
  }
  if (cmd === "service") {
    const verb = rest.length >= 2 ? rest[1] : "";
    if (SERVICE_DENY.has(verb)) return deny("service-control", argv.join(" "));
  }

  // Network commands & loopback bypass (#40)
  if (cmd === "curl" || cmd === "wget") {
    const loopback = isLoopbackCommand(argv);
    if (!loopback.isLoopback && rest.some((a) => a.includes(DYNAMIC_MARKER) && /\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|token)\s+/i.test(a))) {
      return ask("credential-in-argv", "expanded authorization values become curl process arguments", argv.join(" "));
    }
  }

  // Git inspection via specialized parser (#125, #103)
  if (cmd === "git") {
    const git = inspectGitCommand(argv);
    if (git.isDestructive) {
      return deny(git.reason, argv.join(" "));
    }
    if (git.verb === "push") {
      return ask("git-remote-push", git.detail || "Publishing commits to a remote repository via git push requires confirmation", argv.join(" "));
    }
  }

  if (cmd === "find" && rest.includes("-delete")) return deny("find-delete", argv.join(" "));
  if (DB_CLIENTS.has(cmd) && DESTRUCTIVE_SQL.test(rest.join(" "))) {
    return deny("destructive-sql", argv.join(" "));
  }
  if (/^mkfs(?:\.|$)/i.test(cmd)) return deny("mkfs-device", argv.join(" "));
  if (cmd === "dd") {
    for (const a of rest) {
      if (a.startsWith("of=") && (isDevicePath(a.slice(3)) || isProtectedPath(a.slice(3)))) return deny("device-write", a);
    }
  }

  // File mutations & chmod/chown protection (#65)
  if (cmd === "tee" || cmd === "install" || cmd === "cp" || cmd === "mv" || cmd === "truncate" || cmd === "chmod" || cmd === "chown") {
    for (const a of rest) {
      if (a[0] !== "-" && isProtectedPath(a)) return deny("secret-write", argv.join(" "));
    }
    if (cmd === "chmod" || cmd === "chown") {
      const isRecursive = hasLetterFlag(argv, "R") || hasLetterFlag(argv, "r") || rest.includes("--recursive");
      if (isRecursive) {
        for (const a of rest) {
          if (a === "/" || a === "/etc" || a === "/var" || a === "/usr" || a === "/root" || a === "/boot") {
            return deny("device-write", argv.join(" "));
          }
        }
        return deny("chmod-chown", argv.join(" "));
      }
    }
  }

  if (cmd === "sed" && (hasLetterFlag(argv, "i") || rest.some((a) => a === "--in-place" || a.startsWith("--in-place=")))) {
    for (const a of rest) {
      if (a[0] !== "-" && isProtectedPath(a)) return deny("secret-write", argv.join(" "));
    }
  }

  if (SHELLS.has(cmd) || cmd === "source" || cmd === ".") {
    const script = scriptAfterDashC(rest);
    if (typeof script === "string") {
      if (depth > 4) return deny("nested-shell", script);
      return inspectBashCommand(script, depth + 1, config);
    }
    const scriptFile = rest.find((a) => a && a[0] !== "-");
    if (scriptFile) return ask("script-file", "shell script contents are not available to the guard", scriptFile);
    if (!hasHeredoc) return ask("shell-stdin", "shell input is not fully available to the guard", argv.join(" "));
  }

  if (INTERPRETERS.has(cmd) && rest.some((a) => a === "-c" || a === "-e")) {
    const idx = rest.findIndex((a) => a === "-c" || a === "-e");
    return inspectInterpreterPayload(cmd, rest[idx + 1] || "");
  }

  if (/\.sh$/i.test(cmd) || (cmd.includes("/") && /\.(?:bash|zsh|ksh)$/i.test(cmd))) {
    return ask("script-file", "script contents are not available to the guard", argv[0]);
  }

  return allow();
}

function executableTokenOf(seg) {
  const words = wordTokensOf(seg);
  const wrappers = new Set(["sudo", "command", "builtin", "nohup", "time", "nice", "ionice", "stdbuf", "timeout", "exec"]);
  const takesValue = new Set(["-u", "--user", "-g", "--group", "-p", "-s", "--signal", "-k", "--kill-after", "-o", "-e", "-i"]);
  let i = 0;
  while (i < words.length) {
    const value = words[i].value;
    if (PREFIXES.has(value)) { i += 1; continue; }
    if (value === "env") {
      i += 1;
      while (i < words.length && words[i].value.includes("=") && !words[i].value.startsWith("-")) i += 1;
      continue;
    }
    if (value.includes("=") && !value.startsWith("-")) { i += 1; continue; }
    if (!wrappers.has(value)) return words[i];
    i += 1;
    while (i < words.length && words[i].value.startsWith("-")) {
      const flag = words[i].value;
      if (flag === "--") { i += 1; break; }
      if (takesValue.has(flag)) i += 2;
      else i += 1;
    }
    if (value === "timeout" && i < words.length) i += 1;
    if (value === "nice" && i < words.length && /^[0-9-]+$/.test(words[i].value)) i += 1;
  }
  return undefined;
}

function commandNameFromSegment(seg) {
  const token = executableTokenOf(seg);
  return token ? basename(token.value) : "";
}

function inspectEmbeddedExpansions(source, depth, config = {}) {
  if (depth > 8) return ask("unparseable", "nesting-depth", source);
  for (let i = 0; i < source.length; i += 1) {
    if (source[i] === "\\") { i += 1; continue; }
    if (source.startsWith("$" + "(", i) || source[i] === String.fromCharCode(96)) {
      const sub = source.startsWith("$" + "(", i)
        ? readCommandSubstitution(source, i)
        : readBacktick(source, i);
      if (!sub) return ask("unparseable", "unclosed-command-substitution", source.slice(i));
      const nested = inspectBashCommand(sub.script, depth + 1, config);
      if (nested.deny || nested.ask) return nested;
      i = sub.end - 1;
      continue;
    }
    if (source.startsWith("$" + "{", i)) {
      const expansion = readParameterExpansion(source, i);
      if (!expansion) return ask("unparseable", "unclosed-parameter-expansion", source.slice(i));
      if (expansion.body !== undefined) {
        const nested = inspectEmbeddedExpansions(expansion.body, depth + 1, config);
        if (nested.deny || nested.ask) return nested;
      }
      i = expansion.end - 1;
    }
  }
  return allow();
}

function inspectPipelineHeredocs(tokens, depth, config = {}) {
  let group = [];
  let segment = [];
  function finishGroup() {
    if (segment.length) group.push(segment);
    const hasShell = group.some((part) => SHELLS.has(commandNameFromSegment(part)));
    if (hasShell) {
      for (const part of group) {
        for (const heredoc of part.filter((t) => t.kind === "heredoc")) {
          const nested = inspectBashCommand(heredoc.body, depth + 1, config);
          if (nested.deny || nested.ask) return nested;
        }
      }
    }
    group = [];
    segment = [];
    return allow();
  }
  for (const token of tokens) {
    if (token.kind === "op" && SPLIT_OPS.has(token.value)) {
      group.push(segment);
      segment = [];
      if (token.value !== "|" && token.value !== "|&") {
        const result = finishGroup();
        if (result.deny || result.ask) return result;
      }
    } else {
      segment.push(token);
    }
  }
  group.push(segment);
  return finishGroup();
}

function inspectUnparsedDanger(command) {
  const checks = [
    ["curl-pipe", /\b(?:curl|wget)\b[^\n]{0,240}\|\s*(?:sudo\s+)?(?:bash|sh)\b/i],
    ["recursive-rm", /\brm\s+(?:-[^\s]*r[^\s]*|--recursive)(?:\s|$)/i],
    ["process-signal", /\b(?:kill|pkill|killall)\b/i],
    ["service-control", /\bsystemctl\s+(?:stop|restart|disable|enable|mask|unmask|reboot|halt|poweroff|shutdown|kill)\b|\bservice\s+\S+\s+(?:stop|restart|force-stop|force-reload)\b/i],
    ["git-reset-hard", /\bgit\b[^\n;|&]{0,120}\breset\b[^\n;|&]{0,80}--hard\b/i],
    ["git-clean", /\bgit\b[^\n;|&]{0,120}\bclean\b[^\n;|&]{0,80}(?:--force|(?:^|\s)-[^\s]*f[^\s]*)/i],
    ["find-delete", /\bfind\b[^\n;|&]{0,200}\s-delete\b/i],
    ["mkfs-device", /\bmkfs(?:\.[A-Za-z0-9_-]+)?\b/i],
    ["device-write", /\bdd\b[^\n;|&]{0,200}\bof=\/dev\/(?:sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|loop\d+|mapper\/\S+)/i],
    ["destructive-sql", /\b(?:sqlite3|mysql|psql|mongo|mongosh|clickhouse-client)\b[^\n;|&]{0,200}\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|CREATE\s+(?:TABLE|DATABASE|INDEX))\b/i],
    ["secret-write", /(?:>|&>|\b(?:tee|install|mv|truncate|chmod|chown)\b|\bsed\b[^\n;|&]{0,160}(?:-i|--in-place))[^\n;|&]{0,240}(?:\.env(?:\.[\w.-]+)?|credentials\.ya?ml|settings\.ya?ml|cordis\.patch\.yml|[\w.-]*(?:secret|token|credential|api[_-]?key)[\w.-]*|id_(?:rsa|ed25519|ecdsa)|[\w.-]+\.key)\b/i],
  ];
  for (const [reason, pattern] of checks) {
    if (pattern.test(command)) return deny(reason, command);
  }
  return null;
}

export function inspectBashCommand(command, depth = 0, config = {}) {
  if (depth === undefined) depth = 0;
  if (depth > 8) return ask("unparseable", "nesting-depth", String(command || ""));
  if (typeof command !== "string") return ask("unknown-format", "command is not a string", "non-string command");
  if (command.trim() === "") return allow();

  const tok = tokenize(command);
  const tokens = tok.tokens || [];

  if (!tok.ok) {
    const knownDanger = inspectUnparsedDanger(command);
    if (knownDanger) return knownDanger;
  }

  // Pipeline inspection (#126)
  const pipeCheck = inspectPipelines(tokens);
  if (pipeCheck.dangerousPipeline) {
    return deny(pipeCheck.reason, command);
  }

  const pipelineHeredocHit = inspectPipelineHeredocs(tokens, depth, config);
  if (pipelineHeredocHit.deny || pipelineHeredocHit.ask) return pipelineHeredocHit;

  // Silent error guard check (#90)
  const silentHit = inspectSilentErrors(command);

  const segs = splitSegments(tokens);
  for (const seg of segs) {
    const rawWords = wordsOf(seg);
    const envHit = checkEnvExfiltration(rawWords, command);
    if (envHit.deny) {
      return deny("env-dump-leak", envHit.detail || command);
    }
    const wordTokens = wordTokensOf(seg);
    const heredocs = seg.filter((t) => t.kind === "heredoc");
    const argv = stripPrefixes(wordsOf(seg));
    const commandToken = executableTokenOf(seg);
    const commandName = commandNameFromSegment(seg);

    // Silent error guard triggered on mutating system commands (#90)
    if (silentHit.masked && (config.silentErrorGuard || DESTRUCTIVE_CMDS.has(commandName))) {
      return ask("silent-error-masked", silentHit.detail, command);
    }

    for (const token of wordTokens) {
      for (const substitution of token.substitutions || []) {
        const nested = substitution.kind === "parameter-expansion"
          ? inspectEmbeddedExpansions(substitution.script, depth + 1, config)
          : inspectBashCommand(substitution.script, depth + 1, config);
        if (nested.deny || nested.ask) return nested;
      }
    }

    // Redirects security inspection (#126)
    const redirects = extractRedirects(seg);
    const redirectHit = inspectRedirectSecurity(redirects, {
      workspaceDir: config.workspaceDir,
      env: config.env,
    });
    if (redirectHit) {
      return redirectHit.deny ? deny(redirectHit.reason, redirectHit.path) : ask(redirectHit.reason, redirectHit.detail, redirectHit.path);
    }

    if (commandToken && commandToken.dynamic && !commandToken.value.includes("=")) {
      return ask("dynamic-command", "expanded command name cannot be verified", commandToken.value);
    }

    const dynamicArgs = wordTokens.some((t) => (
      t.dynamic && (!commandToken || t !== commandToken) && !t.value.includes("=")
    ));
    if (dynamicArgs && ["rm", "find", "git", "systemctl", "service", "tee", "install", "cp", "mv", "truncate", "sed", "dd"].includes(commandName)) {
      return ask("dynamic-arguments", "expanded command arguments cannot be verified", commandName);
    }

    if (heredocs.length) {
      for (const heredoc of heredocs) {
        if (!heredoc.quoted) {
          const expansionHit = inspectEmbeddedExpansions(heredoc.body, depth, config);
          if (expansionHit.deny || expansionHit.ask) return expansionHit;
        }
      }
      if (SHELLS.has(commandName)) {
        for (const heredoc of heredocs) {
          const nested = inspectBashCommand(heredoc.body, depth + 1, config);
          if (nested.deny || nested.ask) return nested;
        }
      } else if (INTERPRETERS.has(commandName)) {
        for (const heredoc of heredocs) {
          const nested = inspectInterpreterPayload(commandName, heredoc.body);
          if (nested.deny || nested.ask) return nested;
        }
      } else if (DB_CLIENTS.has(commandName)) {
        for (const heredoc of heredocs) {
          if (DESTRUCTIVE_SQL.test(heredoc.body)) {
            return deny("destructive-sql", heredoc.body);
          }
        }
      }
    }

    const hit = inspectArgv(argv, depth, heredocs.length > 0, config);
    if (hit.deny || hit.ask) return hit;
  }

  if (!tok.ok) return ask("unparseable", tok.reason || "unsupported shell syntax", tok.snippet || command);
  return allow();
}

export function inspectExecution(execution, config) {
  if (!config) config = {};
  const toolName = config.toolName || DEFAULT_BASH_TOOL;
  const fileTools = new Set(config.fileWriteTools || DEFAULT_FILE_WRITE_TOOLS);
  const name = execution && execution.name;
  const args = execution ? execution.arguments : undefined;

  // Reviewer agent read-only mode isolation (#65)
  if (isReviewerAgent(execution, config)) {
    if (name === toolName || fileTools.has(name)) {
      return deny("reviewer-read-only", `Reviewer agent is strictly isolated in read-only mode; tool ${name} is prohibited`);
    }
  }

  if (name === toolName) {
    const command = args && typeof args === "object" ? args.command : undefined;
    if (command === undefined || command === null || command === "") return allow();
    if (typeof command !== "string") return ask("unknown-format", "command is not a string", "non-string command");
    return inspectBashCommand(command, 0, config);
  }

  if (typeof name === "string" && fileTools.has(name)) {
    const path = extractFilePath(args);
    if (!path) return ask("unknown-write-target", "file write target could not be identified", name);
    if (config.workspaceDir) {
      const safeCheck = resolveSafePath(path, config.workspaceDir);
      if (!safeCheck.safe) return deny("path-traversal", safeCheck.reason || "path-traversal-escape", path);
      if (isProtectedPath(safeCheck.canonical || path)) return deny("secret-write", path);
    } else {
      if (isPathTraversal(path, process.cwd())) {
        return deny("path-traversal", "path-traversal-escape", path);
      }
      if (isProtectedPath(path)) return deny("secret-write", path);
    }
  }

  return allow();
}