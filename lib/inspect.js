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

const SPLIT_OPS = new Set(["|", "||", "&&", ";", "&"]);
const REDIR_OPS = new Set([">", ">>", ">|", "<>", "2>", "2>>", "&>", ">&"]);
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
  const candidates = ["2>>", "2>", ">>", ">|", "<<", "&&", "||", "&>", ">&", "<>", ">", "<", "|", ";", "&"];
  for (const op of candidates) {
    if (rest.startsWith(op)) return op;
  }
  return null;
}

export function tokenize(src) {
  if (typeof src !== "string") return fail("not-a-string", "");
  const tokens = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    if (/\s/.test(src[i])) { i += 1; continue; }
    const op = opAt(src, i);
    if (op) {
      if (op === "<<") return fail("heredoc", src.slice(i, i + 80));
      tokens.push({ kind: "op", value: op });
      i += op.length;
      continue;
    }
    if (src[i] === "`" || src.startsWith("$(", i) || src.startsWith("<(", i) || src.startsWith(">(", i)) {
      return fail("command-substitution", src.slice(i, i + 80));
    }
    let word = "";
    while (i < n && !/\s/.test(src[i]) && !opAt(src, i)) {
      const c = src[i];
      if (c === "`") return fail("command-substitution", src.slice(i, i + 80));
      if (src.startsWith("$(", i) || src.startsWith("${IFS}", i) || src.startsWith("$IFS", i)) {
        return fail("ifs-or-subst", src.slice(i, i + 80));
      }
      if (c === "\\") {
        if (i + 1 >= n) return fail("dangling-backslash", src.slice(Math.max(0, i - 20)));
        word += src[i + 1];
        i += 2;
        continue;
      }
      if (c === "'") {
        const j = src.indexOf("'", i + 1);
        if (j < 0) return fail("unclosed-single-quote", src.slice(i, i + 80));
        word += src.slice(i + 1, j);
        i = j + 1;
        continue;
      }
      if (c === '"') {
        i += 1;
        while (i < n && src[i] !== '"') {
          if (src[i] === "`") return fail("command-substitution", src.slice(i, i + 80));
          if (src.startsWith("$(", i) || src.startsWith("${IFS}", i) || src.startsWith("$IFS", i)) {
            return fail("ifs-or-subst", src.slice(i, i + 80));
          }
          if (src[i] === "\\" && i + 1 < n) { word += src[i + 1]; i += 2; continue; }
          word += src[i];
          i += 1;
        }
        if (i >= n) return fail("unclosed-double-quote", src.slice(Math.max(0, n - 40)));
        i += 1;
        continue;
      }
      word += c;
      i += 1;
    }
    if (word !== "") tokens.push({ kind: "word", value: word });
  }
  return { ok: true, tokens: tokens };
}

function wordsOf(seg) {
  return seg.filter(function (t) { return t.kind === "word"; }).map(function (t) { return t.value; });
}

function redirectsOf(seg) {
  const paths = [];
  for (let i = 0; i < seg.length; i += 1) {
    const t = seg[i];
    if (t.kind === "op" && REDIR_OPS.has(t.value)) {
      const next = seg[i + 1];
      if (next && next.kind === "word") paths.push(next.value);
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
  return { deny: true, reason: reason, snippet: String(snippet || reason).slice(0, 160) };
}

function allow() {
  return { deny: false };
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

function inspectArgv(argv, depth) {
  if (!argv.length) return allow();
  const cmd = basename(argv[0]);
  const rest = argv.slice(1);

  if (cmd === "sudo" || cmd === "command" || cmd === "builtin" || cmd === "nohup" || cmd === "time" || cmd === "nice" || cmd === "ionice" || cmd === "stdbuf" || cmd === "timeout") {
    const arity = new Set(["-u", "--user", "-g", "--group", "-p", "-s", "--signal", "-k", "--kill-after", "-o", "-e", "-i"]);
    let next = skipWrapper(rest, arity);
    if (cmd === "timeout" && next.length) next = next.slice(1);
    if (cmd === "nice" && next.length && /^[0-9-]+$/.test(next[0])) next = next.slice(1);
    return inspectArgv(next, depth);
  }

  if (cmd === "eval") return deny("eval", argv.join(" "));
  if (KILL_CMDS.has(cmd)) return deny("process-signal", argv.join(" "));
  if (cmd === "rm" && (hasLetterFlag(argv, "r") || rest.indexOf("--recursive") !== -1)) {
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
  if (cmd === "git" && rest[0] === "clean" && rest.some(function (a) {
    return a === "-f" || a === "--force" || (a[0] === "-" && a[1] !== "-" && a.indexOf("f") !== -1);
  })) {
    return deny("git-clean", argv.join(" "));
  }
  if (cmd === "find" && rest.indexOf("-delete") !== -1) return deny("find-delete", argv.join(" "));
  if (DB_CLIENTS.has(cmd) && DESTRUCTIVE_SQL.test(rest.join(" "))) {
    return deny("destructive-sql", argv.join(" "));
  }
  if (cmd === "dd") {
    for (const a of rest) {
      if (a.slice(0, 3) === "of=" && isProtectedPath(a.slice(3))) return deny("secret-write", a);
    }
  }
  if (cmd === "tee" || cmd === "install" || cmd === "cp" || cmd === "mv" || cmd === "truncate") {
    for (const p of rest) {
      if (p[0] !== "-" && isProtectedPath(p)) return deny("secret-write", argv.join(" "));
    }
  }
  if (cmd === "sed" && (hasLetterFlag(argv, "i") || rest.indexOf("--in-place") !== -1)) {
    for (const p of rest) {
      if (p[0] !== "-" && isProtectedPath(p)) return deny("secret-write", argv.join(" "));
    }
  }
  if (SHELLS.has(cmd)) {
    const script = scriptAfterDashC(rest);
    if (typeof script === "string") {
      if (depth > 4) return deny("nested-shell", script);
      const inner = inspectBashCommand(script, depth + 1);
      if (inner.deny) return inner;
    }
  }
  if (INTERPRETERS.has(cmd) && rest.some(function (a) { return a === "-c" || a === "-e"; })) {
    const idx = rest.findIndex(function (a) { return a === "-c" || a === "-e"; });
    const payload = rest[idx + 1] || "";
    const inner = inspectBashCommand(payload, depth + 1);
    if (inner.deny && inner.reason !== "unparseable") return deny("interpreter-payload", payload.slice(0, 160));
  }
  return allow();
}

export function inspectBashCommand(command, depth) {
  if (depth === undefined) depth = 0;
  if (typeof command !== "string") return deny("unknown-format", "non-string command");
  if (command.trim() === "") return allow();
  const tok = tokenize(command);
  if (!tok.ok) return deny("unparseable", tok.snippet || tok.reason);
  const segs = splitSegments(tok.tokens);
  for (const seg of segs) {
    const redirs = redirectsOf(seg);
    for (const p of redirs) {
      if (isProtectedPath(p)) return deny("secret-write", p);
    }
    const argv = stripPrefixes(wordsOf(seg));
    const hit = inspectArgv(argv, depth);
    if (hit.deny) return hit;
  }
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
    if (typeof command !== "string") {
      if (command === undefined || command === null) return allow();
      return deny("unknown-format", "command is not a string");
    }
    if (command.trim() === "") return allow();
    return inspectBashCommand(command);
  }
  if (typeof name === "string" && fileTools.has(name)) {
    const path = pathFromArgs(args);
    if (path && isProtectedPath(path)) return deny("secret-write", path);
  }
  return allow();
}

export function sessionTag(execution) {
  const agent = execution && execution.agent;
  if (typeof agent === "string") return " (session " + agent + ")";
  if (agent && agent.session) return " (session " + String(agent.session) + ")";
  return "";
}

export function denyMessage(hit, who) {
  const snippet = (hit && hit.snippet) ? hit.snippet : ((hit && hit.reason) || "blocked");
  return (
    "⛔ [dsh-approval-gate] Команда заблокирована: `" +
    String(snippet).slice(0, 160) +
    "`" +
    (who || "") +
    ". Опасная операция (rm -rf / kill / перезапуск сервиса / изменение БД / запись в секреты или .env). Для выполнения нужно явное `делай` от владельца — либо переформулируй команду безопаснее."
  );
}
