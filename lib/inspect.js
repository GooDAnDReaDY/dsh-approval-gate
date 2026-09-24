import { MESSAGES } from "./messages.js";

// Pure command/path inspector for dsh-approval-gate.
// No Cordis imports: unit tests run this without the harness.

export const DEFAULT_BASH_TOOL = "bash";
export const DEFAULT_FILE_WRITE_TOOLS = Object.freeze([
  "write",
  "edit",
  "Write",
  "Edit",
  "str_replace",
  "apply_patch",
]);

const SPLIT_OPS = new Set(["|", "|&", "||", "&&", ";", "&"]);
const REDIR_OPS = new Set([">", ">>", ">|", "<>", "2>", "2>>", "&>", "&>>"]);
const HEREDOC_OPS = new Set(["<<", "<<-"]);
const DYNAMIC_MARKER = "__shell_dynamic__";
const PREFIXES = new Set(["then", "do"]);
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

export function basename(path) {
  const parts = String(path).replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || "";
}

export function isProtectedPath(path) {
  if (typeof path !== "string" || path.trim() === "") return false;
  const base = basename(path);
  if (base === ".env" || base.startsWith(".env.")) return true;
  if (/^credentials\.ya?ml$/i.test(base)) return true;
  if (/^settings\.ya?ml$/i.test(base)) return true;
  if (base === "cordis.patch.yml") return true;
  if (/\.(pem|key|crt|p12|pfx)$/i.test(base)) return true;
  if (/^(id_rsa|id_ed25519|id_ecdsa)$/.test(base)) return true;
  if (/(?:^|[._-])(?:secret|token|credential|passwd|api[_-]?key)(?:$|[._-])/i.test(base)) return true;
  return false;
}

function fail(reason, snippet) {
  return { ok: false, reason: reason, snippet: snippet };
}

function opAt(s, i) {
  const rest = s.slice(i);
  if (rest.startsWith("<(") || rest.startsWith(">(")) return null;
  const candidates = ["2>&", "2>>", "&>>", "<<<", "<<-", "2>", ">>", ">|", "|&", "&&", "||", "&>", ">&", "<&", "<>", "<<", ">", "<", "|", ";", "&"];
  for (const op of candidates) {
    if (rest.startsWith(op)) return op;
  }
  return null;
}

function readCommandSubstitution(src, start) {
  let depth = 1;
  let quote = "";
  let escaped = false;
  for (let i = start + 2; i < src.length; i += 1) {
    const c = src[i];
    if (escaped) { escaped = false; continue; }
    if (c === "\\") { escaped = true; continue; }
    if (quote) {
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === String.fromCharCode(96)) {
      const end = readBacktick(src, i);
      if (!end) return null;
      i = end.end;
      continue;
    }
    if (src.startsWith("$(", i)) { depth += 1; i += 1; continue; }
    if (c === "(") { depth += 1; continue; }
    if (c === ")") {
      depth -= 1;
      if (depth === 0) return { script: src.slice(start + 2, i), end: i + 1 };
    }
  }
  return null;
}

function readBacktick(src, start) {
  let escaped = false;
  for (let i = start + 1; i < src.length; i += 1) {
    if (escaped) { escaped = false; continue; }
    if (src[i] === "\\") { escaped = true; continue; }
    if (src[i] === String.fromCharCode(96)) return { script: src.slice(start + 1, i), end: i + 1 };
  }
  return null;
}

function readParameterExpansion(src, start) {
  if (src[start + 1] !== "{") {
    let i = start + 1;
    if (/[A-Za-z_]/.test(src[i] || "")) {
      i += 1;
      while (i < src.length && /[A-Za-z0-9_]/.test(src[i])) i += 1;
    } else if (i < src.length) i += 1;
    return { end: i };
  }
  let depth = 1;
  let quote = "";
  for (let i = start + 2; i < src.length; i += 1) {
    const c = src[i];
    if (c === "\\") { i += 1; continue; }
    if (quote) {
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === String.fromCharCode(96)) {
      const nested = readBacktick(src, i);
      if (!nested) return null;
      i = nested.end - 1;
      continue;
    }
    if (src.startsWith("$" + "(", i)) {
      const nested = readCommandSubstitution(src, i);
      if (!nested) return null;
      i = nested.end - 1;
      continue;
    }
    if (src.startsWith("$" + "{", i)) {
      const nested = readParameterExpansion(src, i);
      if (!nested) return null;
      i = nested.end - 1;
      continue;
    }
    if (c === "{") depth += 1;
    if (c === "}") {
      depth -= 1;
      if (depth === 0) return { end: i + 1, body: src.slice(start + 2, i) };
    }
  }
  return null;
}

function lexFail(src, index, reason, tokens) {
  return { ok: false, reason: reason, snippet: src.slice(Math.max(0, index - 32), index + 96), tokens: tokens };
}

function readHeredocDelimiter(src, index) {
  let i = index;
  while (i < src.length && (src[i] === " " || src[i] === "\t")) i += 1;
  if (i >= src.length || src[i] === "\n" || src[i] === "\r") return null;
  let delimiter = "";
  let quote = "";
  let started = false;
  let quoted = false;
  while (i < src.length && !/\s/.test(src[i]) && !opAt(src, i)) {
    const c = src[i];
    if (c === "'" || c === '"') {
      if (!quote) { quote = c; quoted = true; started = true; i += 1; continue; }
      if (quote === c) { quote = ""; i += 1; continue; }
    }
    if (c === "\\") {
      if (i + 1 >= src.length) return null;
      quoted = true;
      delimiter += src[i + 1];
      started = true;
      i += 2;
      continue;
    }
    delimiter += c;
    started = true;
    i += 1;
  }
  if (quote || !started || !delimiter) return null;
  return { delimiter: delimiter, end: i, quoted: quoted };
}

export function tokenize(src) {
  if (typeof src !== "string") return { ok: false, reason: "not-a-string", snippet: "", tokens: [] };
  const tokens = [];
  const pendingHeredocs = [];
  let i = 0;
  const n = src.length;

  function flushWord(value, started, dynamic, substitutions) {
    if (started) tokens.push({ kind: "word", value: value, dynamic: dynamic, substitutions: substitutions });
  }

  while (i < n) {
    if (src.startsWith("\\\n", i)) { i += 2; continue; }
    if (src[i] === "\r" || src[i] === "\n") {
      if (src[i] === "\r" && src[i + 1] === "\n") i += 2;
      else i += 1;
      if (pendingHeredocs.length) {
        for (const heredoc of pendingHeredocs) {
          let body = "";
          let found = false;
          while (i <= n) {
            const lineEnd = src.indexOf("\n", i);
            const hasNewline = lineEnd !== -1;
            let line = src.slice(i, hasNewline ? lineEnd : n);
            if (line.endsWith("\r")) line = line.slice(0, -1);
            const compare = heredoc.stripTabs ? line.replace(/^\t+/, "") : line;
            if (compare === heredoc.delimiter) {
              i = hasNewline ? lineEnd + 1 : n;
              found = true;
              break;
            }
            body += (heredoc.stripTabs ? line.replace(/^\t+/, "") : line) + (hasNewline ? "\n" : "");
            if (!hasNewline) { i = n; break; }
            i = lineEnd + 1;
          }
          if (!found) return lexFail(src, i, "unterminated-heredoc", tokens);
          tokens.push({ kind: "heredoc", body: body, quoted: heredoc.quoted });
        }
        pendingHeredocs.length = 0;
        tokens.push({ kind: "op", value: ";" });
      } else {
        tokens.push({ kind: "op", value: ";" });
      }
      continue;
    }
    if (/\s/.test(src[i])) { i += 1; continue; }
    if (src[i] === "#" && (tokens.length === 0 || tokens[tokens.length - 1].kind === "op")) {
      while (i < n && src[i] !== "\n") i += 1;
      continue;
    }

    const op = opAt(src, i);
    if (op) {
      tokens.push({ kind: "op", value: op });
      i += op.length;
      if (HEREDOC_OPS.has(op)) {
        const parsed = readHeredocDelimiter(src, i);
        if (!parsed) return lexFail(src, i, "invalid-heredoc-delimiter", tokens);
        tokens.push({ kind: "heredoc-delimiter", value: parsed.delimiter });
        pendingHeredocs.push({ delimiter: parsed.delimiter, stripTabs: op === "<<-", quoted: parsed.quoted });
        i = parsed.end;
      }
      continue;
    }

    let word = "";
    let started = false;
    let dynamic = false;
    const substitutions = [];
    while (i < n && !/\s/.test(src[i]) && !opAt(src, i)) {
      const c = src[i];
      if (src.startsWith("<(", i) || src.startsWith(">(", i)) {
        const sub = readCommandSubstitution(src, i);
        if (!sub) return lexFail(src, i, "unclosed-process-substitution", tokens);
        substitutions.push({ kind: "process-substitution", script: sub.script });
        word += DYNAMIC_MARKER;
        dynamic = true;
        started = true;
        i = sub.end;
        continue;
      }
      if (c === "(" || c === ")") return lexFail(src, i, "unsupported-shell-grouping", tokens);
      if (c === "\\") {
        if (i + 1 >= n) return lexFail(src, i, "dangling-backslash", tokens);
        word += src[i + 1];
        started = true;
        i += 2;
        continue;
      }
      if (c === "'") {
        const j = src.indexOf("'", i + 1);
        if (j < 0) return lexFail(src, i, "unclosed-single-quote", tokens);
        word += src.slice(i + 1, j);
        started = true;
        i = j + 1;
        continue;
      }
      if (c === '"') {
        started = true;
        i += 1;
        let closed = false;
        while (i < n) {
          if (src[i] === '"') { i += 1; closed = true; break; }
          if (src[i] === "\\") {
            if (i + 1 >= n) return lexFail(src, i, "dangling-backslash", tokens);
            word += src[i + 1];
            i += 2;
            continue;
          }
          if (src.startsWith("$(", i)) {
            const sub = readCommandSubstitution(src, i);
            if (!sub) return lexFail(src, i, "unclosed-command-substitution", tokens);
            substitutions.push({ kind: "command-substitution", script: sub.script });
            word += DYNAMIC_MARKER;
            dynamic = true;
            i = sub.end;
            continue;
          }
          if (src[i] === String.fromCharCode(96)) {
            const sub = readBacktick(src, i);
            if (!sub) return lexFail(src, i, "unclosed-backtick-substitution", tokens);
            substitutions.push({ kind: "backtick-substitution", script: sub.script });
            word += DYNAMIC_MARKER;
            dynamic = true;
            i = sub.end;
            continue;
          }
          if (src[i] === "$") {
            const expansion = readParameterExpansion(src, i);
            if (!expansion) return lexFail(src, i, "unclosed-parameter-expansion", tokens);
            word += DYNAMIC_MARKER;
            dynamic = true;
            if (expansion.body !== undefined) substitutions.push({ kind: "parameter-expansion", script: expansion.body });
            i = expansion.end;
            continue;
          }
          word += src[i];
          i += 1;
        }
        if (!closed) return lexFail(src, i, "unclosed-double-quote", tokens);
        continue;
      }
      if (src.startsWith("$(", i)) {
        const sub = readCommandSubstitution(src, i);
        if (!sub) return lexFail(src, i, "unclosed-command-substitution", tokens);
        substitutions.push({ kind: "command-substitution", script: sub.script });
        word += DYNAMIC_MARKER;
        dynamic = true;
        started = true;
        i = sub.end;
        continue;
      }
      if (c === String.fromCharCode(96)) {
        const sub = readBacktick(src, i);
        if (!sub) return lexFail(src, i, "unclosed-backtick-substitution", tokens);
        substitutions.push({ kind: "backtick-substitution", script: sub.script });
        word += DYNAMIC_MARKER;
        dynamic = true;
        started = true;
        i = sub.end;
        continue;
      }
      if (c === "$") {
        const expansion = readParameterExpansion(src, i);
        if (!expansion) return lexFail(src, i, "unclosed-parameter-expansion", tokens);
        word += DYNAMIC_MARKER;
        dynamic = true;
        started = true;
        if (expansion.body !== undefined) substitutions.push({ kind: "parameter-expansion", script: expansion.body });
        i = expansion.end;
        continue;
      }
      if (c === "*" || c === "?") dynamic = true;
      word += c;
      started = true;
      i += 1;
    }
    flushWord(word, started, dynamic, substitutions);
  }
  if (pendingHeredocs.length) return lexFail(src, n, "unterminated-heredoc", tokens);
  return { ok: true, tokens: tokens };
}

function wordsOf(seg) {
  return seg.filter(function (t) { return t.kind === "word"; }).map(function (t) { return t.value; });
}

function wordTokensOf(seg) {
  return seg.filter(function (t) { return t.kind === "word"; });
}

function redirectsOf(seg) {
  const paths = [];
  for (let i = 0; i < seg.length; i += 1) {
    const t = seg[i];
    if (t.kind === "op" && REDIR_OPS.has(t.value)) {
      const next = seg[i + 1];
      if (next && next.kind === "word") paths.push({ path: next.value, dynamic: Boolean(next.dynamic), operator: t.value });
    }
  }
  return paths;
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
  const out = argv.slice();
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
  return { deny: true, ask: false, reason: reason, detail: reason, snippet: String(snippet || reason).slice(0, 160) };
}

function allow() {
  return { deny: false, ask: false };
}

function ask(reason, detail, snippet) {
  return { deny: false, ask: true, reason: reason, detail: detail || reason, snippet: String(snippet || "").slice(0, 160) };
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

function gitOperation(rest) {
  const takesValue = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace"]);
  let i = 0;
  while (i < rest.length && rest[i].startsWith("-")) {
    const flag = rest[i];
    if (flag === "--") { i += 1; break; }
    if (takesValue.has(flag)) i += 2;
    else if (flag.startsWith("--") && flag.includes("=")) i += 1;
    else if (flag.length > 2 && flag[1] !== "-") i += 1;
    else i += 1;
  }
  return { verb: rest[i], args: rest.slice(i + 1) };
}

function isDevicePath(path) {
  if (typeof path !== "string" || !path.startsWith("/dev/")) return false;
  const device = path.slice(5);
  if (["null", "zero", "full", "random", "urandom", "stdin", "stdout", "stderr", "tty"].includes(device)) return false;
  if (/^(?:sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|loop\d+)$/i.test(device)) return true;
  return device.startsWith("mapper/") || device.startsWith("disk/by-id/") || device.startsWith("disk/by-uuid/");
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

function inspectArgv(argv, depth, hasHeredoc) {
  if (!argv.length) return allow();
  const cmd = basename(argv[0]);
  const rest = argv.slice(1);

  if (cmd === "sudo" || cmd === "command" || cmd === "builtin" || cmd === "nohup" || cmd === "time" || cmd === "nice" || cmd === "ionice" || cmd === "stdbuf" || cmd === "timeout") {
    const arity = new Set(["-u", "--user", "-g", "--group", "-p", "-s", "--signal", "-k", "--kill-after", "-o", "-e", "-i"]);
    let next = skipWrapper(rest, arity);
    if (cmd === "timeout" && next.length) next = next.slice(1);
    if (cmd === "nice" && next.length && /^[0-9-]+$/.test(next[0])) next = next.slice(1);
    return inspectArgv(next, depth, hasHeredoc);
  }

  if (cmd === "eval") return deny("eval", argv.join(" "));
  if (KILL_CMDS.has(cmd)) return deny("process-signal", argv.join(" "));
  if (cmd === "rm" && (hasLetterFlag(argv, "r") || hasLetterFlag(argv, "R") || rest.indexOf("--recursive") !== -1)) {
    return deny("recursive-rm", argv.join(" "));
  }
  if (cmd === "systemctl") {
    const verb = rest.find(function (a) { return a[0] !== "-"; });
    if (verb && SYSTEMCTL_DENY.has(verb)) return deny("service-control", argv.join(" "));
  }
  if (cmd === "service") {
    const verb = rest.length >= 2 ? rest[1] : "";
    if (SERVICE_DENY.has(verb)) return deny("service-control", argv.join(" "));
  }
  if (cmd === "curl" && rest.some(function (a) {
    return a.includes(DYNAMIC_MARKER) && /\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|token)\s+/i.test(a);
  })) {
    return ask("credential-in-argv", "expanded authorization values become curl process arguments", argv.join(" "));
  }
  if (cmd === "git") {
    const operation = gitOperation(rest);
    if (operation.verb === "clean" && operation.args.some(function (a) {
      return a === "-f" || a === "--force" || (a[0] === "-" && a[1] !== "-" && a.indexOf("f") !== -1);
    })) return deny("git-clean", argv.join(" "));
    if (operation.verb === "reset" && operation.args.indexOf("--hard") !== -1) return deny("git-reset-hard", argv.join(" "));
  }
  if (cmd === "find" && rest.indexOf("-delete") !== -1) return deny("find-delete", argv.join(" "));
  if (DB_CLIENTS.has(cmd) && DESTRUCTIVE_SQL.test(rest.join(" "))) {
    return deny("destructive-sql", argv.join(" "));
  }
  if (/^mkfs(?:\.|$)/i.test(cmd)) return deny("mkfs-device", argv.join(" "));
  if (cmd === "dd") {
    for (const a of rest) {
      if (a.startsWith("of=") && (isDevicePath(a.slice(3)) || isProtectedPath(a.slice(3)))) return deny("device-write", a);
    }
  }
  if (cmd === "tee" || cmd === "install" || cmd === "cp" || cmd === "mv" || cmd === "truncate") {
    for (const a of rest) {
      if (a[0] !== "-" && isProtectedPath(a)) return deny("secret-write", argv.join(" "));
    }
  }
  if (cmd === "sed" && (hasLetterFlag(argv, "i") || rest.indexOf("--in-place") !== -1)) {
    for (const a of rest) {
      if (a[0] !== "-" && isProtectedPath(a)) return deny("secret-write", argv.join(" "));
    }
  }
  if (SHELLS.has(cmd)) {
    const script = scriptAfterDashC(rest);
    if (typeof script === "string") {
      if (depth > 4) return deny("nested-shell", script);
      return inspectBashCommand(script, depth + 1);
    }
    const scriptFile = rest.find(function (a) { return a && a[0] !== "-"; });
    if (scriptFile) return ask("script-file", "shell script contents are not available to the guard", scriptFile);
    if (!hasHeredoc) return ask("shell-stdin", "shell input is not fully available to the guard", argv.join(" "));
  }
  if (INTERPRETERS.has(cmd) && rest.some(function (a) { return a === "-c" || a === "-e"; })) {
    const idx = rest.findIndex(function (a) { return a === "-c" || a === "-e"; });
    return inspectInterpreterPayload(cmd, rest[idx + 1] || "");
  }
  if (/\.sh$/i.test(cmd) || (cmd.includes("/") && /\.(?:bash|zsh|ksh)$/i.test(cmd))) {
    return ask("script-file", "script contents are not available to the guard", argv[0]);
  }
  return allow();
}

function hasDangerousPipeline(tokens) {
  let segment = [];
  let pipelineHasDownloader = false;
  let inPipeline = false;
  function inspectSegment() {
    return commandNameFromSegment(segment);
  }
  for (const token of tokens) {
    if (token.kind === "op" && SPLIT_OPS.has(token.value)) {
      const cmd = inspectSegment();
      if (inPipeline && SHELLS.has(cmd) && pipelineHasDownloader) return true;
      const continues = token.value === "|" || token.value === "|&";
      if (continues) {
        pipelineHasDownloader = pipelineHasDownloader || cmd === "curl" || cmd === "wget";
        inPipeline = true;
      } else {
        pipelineHasDownloader = false;
        inPipeline = false;
      }
      segment = [];
      continue;
    }
    segment.push(token);
  }
  const cmd = inspectSegment();
  return inPipeline && pipelineHasDownloader && SHELLS.has(cmd);
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

function inspectEmbeddedExpansions(source, depth) {
  if (depth > 8) return ask("unparseable", "nesting-depth", source);
  for (let i = 0; i < source.length; i += 1) {
    if (source[i] === "\\") { i += 1; continue; }
    if (source.startsWith("$" + "(", i) || source[i] === String.fromCharCode(96)) {
      const sub = source.startsWith("$" + "(", i)
        ? readCommandSubstitution(source, i)
        : readBacktick(source, i);
      if (!sub) return ask("unparseable", "unclosed-command-substitution", source.slice(i));
      const nested = inspectBashCommand(sub.script, depth + 1);
      if (nested.deny || nested.ask) return nested;
      i = sub.end - 1;
      continue;
    }
    if (source.startsWith("$" + "{", i)) {
      const expansion = readParameterExpansion(source, i);
      if (!expansion) return ask("unparseable", "unclosed-parameter-expansion", source.slice(i));
      if (expansion.body !== undefined) {
        const nested = inspectEmbeddedExpansions(expansion.body, depth + 1);
        if (nested.deny || nested.ask) return nested;
      }
      i = expansion.end - 1;
    }
  }
  return allow();
}

function inspectPipelineHeredocs(tokens, depth) {
  let group = [];
  let segment = [];
  function finishGroup() {
    if (segment.length) group.push(segment);
    const hasShell = group.some(function (part) { return SHELLS.has(commandNameFromSegment(part)); });
    if (hasShell) {
      for (const part of group) {
        for (const heredoc of part.filter(function (t) { return t.kind === "heredoc"; })) {
          const nested = inspectBashCommand(heredoc.body, depth + 1);
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

export function inspectBashCommand(command, depth) {
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
  if (hasDangerousPipeline(tokens)) return deny("curl-pipe", command);
  const pipelineHeredocHit = inspectPipelineHeredocs(tokens, depth);
  if (pipelineHeredocHit.deny || pipelineHeredocHit.ask) return pipelineHeredocHit;

  const segs = splitSegments(tokens);
  for (const seg of segs) {
    const wordTokens = wordTokensOf(seg);
    const heredocs = seg.filter(function (t) { return t.kind === "heredoc"; });
    const argv = stripPrefixes(wordsOf(seg));
    const commandToken = executableTokenOf(seg);
    const commandName = commandNameFromSegment(seg);

    for (const token of wordTokens) {
      for (const substitution of token.substitutions || []) {
        const nested = substitution.kind === "parameter-expansion"
          ? inspectEmbeddedExpansions(substitution.script, depth + 1)
          : inspectBashCommand(substitution.script, depth + 1);
        if (nested.deny || nested.ask) return nested;
      }
    }

    for (const redirect of redirectsOf(seg)) {
      if (redirect.dynamic) return ask("dynamic-redirect", "expanded redirect target cannot be verified", redirect.path);
      if (isProtectedPath(redirect.path)) return deny("secret-write", redirect.path);
    }

    if (commandToken && commandToken.dynamic && !commandToken.value.includes("=")) {
      return ask("dynamic-command", "expanded command name cannot be verified", commandToken.value);
    }

    const dynamicArgs = wordTokens.some(function (t) {
      return t.dynamic && (!commandToken || t !== commandToken) && !t.value.includes("=");
    });
    if (dynamicArgs && ["rm", "find", "git", "systemctl", "service", "tee", "install", "cp", "mv", "truncate", "sed", "dd"].includes(commandName)) {
      return ask("dynamic-arguments", "expanded command arguments cannot be verified", commandName);
    }

    if (heredocs.length) {
      for (const heredoc of heredocs) {
        if (!heredoc.quoted) {
          const expansionHit = inspectEmbeddedExpansions(heredoc.body, depth);
          if (expansionHit.deny || expansionHit.ask) return expansionHit;
        }
      }
      if (SHELLS.has(commandName)) {
        for (const heredoc of heredocs) {
          const nested = inspectBashCommand(heredoc.body, depth + 1);
          if (nested.deny || nested.ask) return nested;
        }
      } else if (INTERPRETERS.has(commandName)) {
        for (const heredoc of heredocs) {
          const nested = inspectInterpreterPayload(commandName, heredoc.body);
          if (nested.deny || nested.ask) return nested;
        }
      }
    }

    const hit = inspectArgv(argv, depth, heredocs.length > 0);
    if (hit.deny || hit.ask) return hit;
  }

  if (!tok.ok) return ask("unparseable", tok.reason || "unsupported shell syntax", tok.snippet || command);
  return allow();
}

function pathFromArgs(args) {
  if (typeof args === "string") return args;
  if (!args || typeof args !== "object") return null;
  const keys = ["path", "file_path", "filePath", "file", "filename", "target", "to"];
  for (const k of keys) {
    if (typeof args[k] === "string") return args[k];
  }
  return null;
}

export function inspectExecution(execution, config) {
  if (!config) config = {};
  const toolName = config.toolName || DEFAULT_BASH_TOOL;
  const fileTools = new Set(config.fileWriteTools || DEFAULT_FILE_WRITE_TOOLS);
  const name = execution && execution.name;
  const args = execution ? execution.arguments : undefined;

  if (name === toolName) {
    const command = args && typeof args === "object" ? args.command : undefined;
    if (command === undefined || command === null || command === "") return allow();
    if (typeof command !== "string") return ask("unknown-format", "command is not a string", "non-string command");
    return inspectBashCommand(command);
  }
  if (typeof name === "string" && fileTools.has(name)) {
    const path = pathFromArgs(args);
    if (!path) return ask("unknown-write-target", "file write target could not be identified", name);
    if (isProtectedPath(path)) return deny("secret-write", path);
  }
  return allow();
}

export function sessionTag(execution) {
  const agent = execution && execution.agent;
  if (typeof agent === "string") return " (session " + agent + ")";
  if (agent && agent.session) return " (session " + String(agent.session) + ")";
  return "";
}

function safeSnippet(value) {
  return String(value || "")
    .replace(/[\r\n\t\u0000-\u001f]+/g, " ")
    .replace(/(authorization\s*:\s*(?:bearer|token)\s+)\S+/gi, "$1[redacted]")
    .replace(/((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;]+/gi, "$1[redacted]")
    .slice(0, 120);
}

function translated(translate, key, logger) {
  if (typeof translate === "function") {
    try {
      const value = translate(key);
      if (value && value !== key) return value;
    } catch {
      if (logger && typeof logger.warn === "function") {
        logger.warn("[dsh-approval-gate] localization lookup failed; using English fallback");
      }
    }
  }
  return MESSAGES.en[key] || key;
}

const RULE_KEYS = Object.freeze({
  "recursive-rm": "ruleRecursiveRm",
  "process-signal": "ruleProcessSignal",
  "service-control": "ruleServiceControl",
  "git-clean": "ruleGitClean",
  "git-reset-hard": "ruleGitResetHard",
  "find-delete": "ruleFindDelete",
  "destructive-sql": "ruleDestructiveSql",
  "secret-write": "ruleSecretWrite",
  "device-write": "ruleDeviceWrite",
  "mkfs-device": "ruleMkfsDevice",
  "curl-pipe": "ruleCurlPipe",
  "eval": "ruleEval",
  "nested-shell": "ruleNestedShell",
  "interpreter-payload": "ruleInterpreterPayload",
});

const ASK_KEYS = Object.freeze({
  unparseable: "askUnparseable",
  "unknown-format": "askUnknownFormat",
  "unknown-write-target": "askUnknownWriteTarget",
  "dynamic-command": "askDynamicCommand",
  "dynamic-arguments": "askDynamicArguments",
  "dynamic-redirect": "askDynamicRedirect",
  "script-file": "askScriptFile",
  "shell-stdin": "askShellStdin",
  "interpreter-payload": "askInterpreterPayload",
  "credential-in-argv": "askCredentialInArgv",
});

const DETAIL_KEYS = Object.freeze({
  "process-substitution": "detailProcessSubstitution",
  "unclosed-process-substitution": "detailUnclosedProcessSubstitution",
  "unclosed-command-substitution": "detailUnclosedCommandSubstitution",
  "unclosed-backtick-substitution": "detailUnclosedBacktick",
  "unclosed-parameter-expansion": "detailUnclosedParameterExpansion",
  "unclosed-single-quote": "detailUnclosedSingleQuote",
  "unclosed-double-quote": "detailUnclosedDoubleQuote",
  "dangling-backslash": "detailDanglingEscape",
  "invalid-heredoc-delimiter": "detailInvalidHeredoc",
  "unterminated-heredoc": "detailUnterminatedHeredoc",
  "unsupported-shell-grouping": "detailUnsupportedGrouping",
});

export function denyMessage(hit, who, translate, logger) {
  const key = RULE_KEYS[hit && hit.reason] || "ruleUnknown";
  const snippet = safeSnippet(hit && hit.snippet);
  const parts = [translated(translate, "blockedPrefix", logger), translated(translate, key, logger)];
  if (snippet) parts.push(translated(translate, "detectedLabel", logger) + ": " + snippet);
  if (who) parts.push(who.trim());
  return parts.join(" — ") + ".";
}

export function askMessage(hit, who, translate, logger) {
  const key = ASK_KEYS[hit && hit.reason] || "askUnknown";
  const snippet = safeSnippet(hit && hit.snippet);
  const parts = [translated(translate, "approvalRequired", logger), translated(translate, key, logger)];
  if (hit && hit.reason === "unparseable") {
    const detailKey = DETAIL_KEYS[hit.detail] || "detailUnsupported";
    parts.push(translated(translate, "parseReasonLabel", logger) + ": " + translated(translate, detailKey, logger));
  }
  if (snippet) parts.push(translated(translate, "commandLabel", logger) + ": " + snippet);
  if (who) parts.push(who.trim());
  return parts.join(" — ") + ".";
}
