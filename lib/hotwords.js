// lib/hotwords.js
// High-speed keyword pre-filter (Hotwords / Lexicon Matcher) for dsh-approval-gate (#93).
// Provides sub-microsecond pre-check to bypass heavy AST/regex parsing for clean commands.

export const DEFAULT_HOTWORDS = Object.freeze([
  "rm",
  "mkfs",
  "fdisk",
  "parted",
  "dd",
  "shadow",
  "sudoers",
  "passwd",
  "kill",
  "pkill",
  "killall",
  "systemctl",
  "service",
  "curl",
  "wget",
  "bash",
  "sh",
  "zsh",
  "nc",
  "netcat",
  "ncat",
  "socat",
  "chmod",
  "chown",
  "eval",
  "printenv",
  "drop",
  "truncate",
  "format",
  "sudo",
  "su",
  "ssh",
]);

/**
 * Splits text into normalized lowercase word tokens.
 *
 * @param {string} text
 * @returns {string[]}
 */
export function extractWords(text) {
  if (typeof text !== "string") return [];
  // Split on whitespace and common shell operators/delimiters
  const tokens = text.toLowerCase().split(/[^a-z0-9_-]+/);
  return tokens.filter((t) => t.length > 0);
}

export class HotwordsMatcher {
  /**
   * @param {string[]} [customHotwords]
   */
  constructor(customHotwords) {
    /** @type {Set<string>} */
    this.lexicon = new Set();
    const words = Array.isArray(customHotwords) && customHotwords.length > 0
      ? customHotwords
      : DEFAULT_HOTWORDS;

    for (const w of words) {
      if (typeof w === "string" && w.trim()) {
        this.lexicon.add(w.trim().toLowerCase());
      }
    }
  }

  /**
   * Add new words to lexicon.
   * @param {string | string[]} words
   */
  add(words) {
    const list = Array.isArray(words) ? words : [words];
    for (const w of list) {
      if (typeof w === "string" && w.trim()) {
        this.lexicon.add(w.trim().toLowerCase());
      }
    }
  }

  /**
   * Checks if text contains any word present in the hotwords lexicon.
   *
   * @param {string} text
   * @returns {boolean} True if any high-risk keyword matched
   */
  hasMatch(text) {
    if (!text || typeof text !== "string") return false;
    const words = extractWords(text);
    for (let i = 0; i < words.length; i += 1) {
      if (this.lexicon.has(words[i])) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns list of matching hotwords found in text.
   *
   * @param {string} text
   * @returns {string[]}
   */
  findMatches(text) {
    if (!text || typeof text !== "string") return [];
    const words = extractWords(text);
    const matches = [];
    for (let i = 0; i < words.length; i += 1) {
      if (this.lexicon.has(words[i]) && !matches.includes(words[i])) {
        matches.push(words[i]);
      }
    }
    return matches;
  }

  get size() {
    return this.lexicon.size;
  }
}
