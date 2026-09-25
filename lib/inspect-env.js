// lib/inspect-env.js
// Inspection of environment exfiltration, memory dumps, and bare env commands.

export function basename(path) {
  const parts = String(path).replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || "";
}

/**
 * Inspects argv and command strings for process environment leaks and credential dumping.
 *
 * @param {string[]} words - Command words
 * @param {string} [fullCommand] - Full unparsed command string
 * @returns {{ deny: boolean, reason?: string, detail?: string }}
 */
export function checkEnvExfiltration(words, fullCommand = "") {
  if (!Array.isArray(words) || words.length === 0) return { deny: false };
  const cmd = basename(words[0]);

  // 1. Reading /proc/*/environ
  if (fullCommand && /\/proc\/(?:self|\$\$|\d+)\/environ\b/i.test(fullCommand)) {
    return { deny: true, reason: "env-dump-leak", detail: "Attempted read of process environ file" };
  }

  // 2. Bare env
  if (cmd === "env") {
    if (words.length === 1) {
      return { deny: true, reason: "env-dump-leak", detail: "Bare env command dumps all process secrets" };
    }
    const nonEnvWords = words.slice(1).filter((w) => !w.startsWith("-"));
    const onlyAssignments = nonEnvWords.length > 0 && nonEnvWords.every((w) => w.includes("="));
    if (nonEnvWords.length === 0 || onlyAssignments) {
      return { deny: true, reason: "env-dump-leak", detail: "env invocation without command dumps environment" };
    }
  }

  // 3. Bare printenv or sensitive key read
  if (cmd === "printenv") {
    if (words.length === 1) {
      return { deny: true, reason: "env-dump-leak", detail: "Bare printenv command dumps all process secrets" };
    }
    for (const w of words.slice(1)) {
      if (/(?:secret|token|key|password|credential|auth|dsh_)/i.test(w)) {
        return { deny: true, reason: "env-dump-leak", detail: "printenv querying sensitive variable" };
      }
    }
  }

  // 4. export without assignment
  if (cmd === "export") {
    if (words.length === 1 || (words.length === 2 && words[1] === "-p")) {
      return { deny: true, reason: "env-dump-leak", detail: "export without assignment dumps environment" };
    }
  }

  return { deny: false };
}
