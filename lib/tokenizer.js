// Pure bash lexer and tokenizer for dsh-approval-gate.

export const SPLIT_OPS = new Set(["|", "|&", "||", "&&", ";", "&"]);
export const REDIR_OPS = new Set([">", ">>", ">|", "<>", "2>", "2>>", "&>", "&>>"]);
export const HEREDOC_OPS = new Set(["<<", "<<-"]);
export const DYNAMIC_MARKER = "__shell_dynamic__";

function opAt(s, i) {
  const rest = s.slice(i);
  if (rest.startsWith("<(") || rest.startsWith(">(")) return null;
  const candidates = ["2>&", "2>>", "&>>", "<<<", "<<-", "2>", ">>", ">|", "|&", "&&", "||", "&>", ">&", "<&", "<>", "<<", ">", "<", "|", ";", "&"];
  for (const op of candidates) {
    if (rest.startsWith(op)) return op;
  }
  return null;
}

export function readCommandSubstitution(src, start) {
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

export function readBacktick(src, start) {
  let escaped = false;
  for (let i = start + 1; i < src.length; i += 1) {
    if (escaped) { escaped = false; continue; }
    if (src[i] === "\\") { escaped = true; continue; }
    if (src[i] === String.fromCharCode(96)) return { script: src.slice(start + 1, i), end: i + 1 };
  }
  return null;
}

export function readParameterExpansion(src, start) {
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

