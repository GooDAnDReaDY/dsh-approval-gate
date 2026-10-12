// lib/diff-viewer.js
// Unified Diff Generator and Hunk Folding Engine for DSH Approval Gate (#74, #75).
// Zero-dependency pure JavaScript Myers-style line diffing with folding support.

/**
 * @typedef {Object} DiffLine
 * @property {'eq' | 'add' | 'del'} type
 * @property {string} text
 * @property {number | null} oldLine
 * @property {number | null} newLine
 */

/**
 * @typedef {Object} FoldItem
 * @property {'fold'} type
 * @property {number} count
 * @property {number} startOldLine
 * @property {number} startNewLine
 * @property {DiffLine[]} foldedLines
 * @property {boolean} expanded
 */

/**
 * @typedef {Object} Hunk
 * @property {number} oldStart
 * @property {number} oldCount
 * @property {number} newStart
 * @property {number} newCount
 * @property {string} header
 * @property {(DiffLine | FoldItem)[]} items
 */

/**
 * Splits text into lines preserving empty lines.
 *
 * @param {string} text
 * @returns {string[]}
 */
export function splitLines(text) {
  if (typeof text !== "string") return [];
  const lines = text.split(/\r?\n/);
  if (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

/**
 * Computes Longest Common Subsequence matrix for two arrays of lines.
 *
 * @param {string[]} a
 * @param {string[]} b
 * @returns {number[][]}
 */
function lcsMatrix(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = 0; i < m; i++) {
    for (let j = 0; j < n; j++) {
      if (a[i] === b[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }
  return dp;
}

/**
 * Generates raw diff lines between old and new text.
 *
 * @param {string} oldText
 * @param {string} newText
 * @returns {DiffLine[]}
 */
export function generateDiffLines(oldText, newText) {
  const a = splitLines(oldText);
  const b = splitLines(newText);
  const dp = lcsMatrix(a, b);

  let i = a.length;
  let j = b.length;
  /** @type {DiffLine[]} */
  const reversed = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      reversed.push({ type: "eq", text: a[i - 1], oldLine: i, newLine: j });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      reversed.push({ type: "add", text: b[j - 1], oldLine: null, newLine: j });
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      reversed.push({ type: "del", text: a[i - 1], oldLine: i, newLine: null });
      i--;
    }
  }

  return reversed.reverse();
}

/**
 * Groups diff lines into hunks with context and hunk folding (#75).
 *
 * @param {DiffLine[]} lines
 * @param {Object} [options]
 * @param {number} [options.contextLines=3]
 * @param {number} [options.minFoldLines=4]
 * @returns {Hunk[]}
 */
export function groupHunks(lines, options = {}) {
  const ctx = typeof options.contextLines === "number" ? options.contextLines : 3;
  const minFold = typeof options.minFoldLines === "number" ? options.minFoldLines : 4;
  if (!lines || lines.length === 0) return [];

  // Find all modified indices
  const isChanged = lines.map((l) => l.type !== "eq");
  const anyChange = isChanged.some(Boolean);
  if (!anyChange) {
    return [];
  }

  // Group changed clusters with context
  const ranges = [];
  let curStart = null;
  let curEnd = null;

  for (let k = 0; k < lines.length; k++) {
    if (isChanged[k]) {
      const start = Math.max(0, k - ctx);
      const end = Math.min(lines.length - 1, k + ctx);
      if (curStart === null) {
        curStart = start;
        curEnd = end;
      } else if (start <= curEnd + 1) {
        curEnd = Math.max(curEnd, end);
      } else {
        ranges.push({ start: curStart, end: curEnd });
        curStart = start;
        curEnd = end;
      }
    }
  }
  if (curStart !== null) {
    ranges.push({ start: curStart, end: curEnd });
  }

  /** @type {Hunk[]} */
  const hunks = [];
  let lastRangeEnd = -1;

  for (let idx = 0; idx < ranges.length; idx++) {
    const r = ranges[idx];
    const prevEnd = lastRangeEnd;
    const hunkLines = lines.slice(r.start, r.end + 1);

    let oldStart = 0;
    let oldCount = 0;
    let newStart = 0;
    let newCount = 0;

    for (const l of hunkLines) {
      if (l.type === "eq" || l.type === "del") {
        oldCount++;
        if (!oldStart && l.oldLine) oldStart = l.oldLine;
      }
      if (l.type === "eq" || l.type === "add") {
        newCount++;
        if (!newStart && l.newLine) newStart = l.newLine;
      }
    }

    /** @type {(DiffLine | FoldItem)[]} */
    const items = [];

    // Leading fold if there are unchanged lines before this range (#75)
    if (r.start > prevEnd + 1) {
      const leadingLines = lines.slice(prevEnd + 1, r.start);
      if (leadingLines.length >= minFold) {
        items.push({
          type: "fold",
          count: leadingLines.length,
          startOldLine: leadingLines[0].oldLine,
          startNewLine: leadingLines[0].newLine,
          foldedLines: leadingLines,
          expanded: false,
        });
      } else {
        items.push(...leadingLines);
      }
    }

    // Inside range: check for fold streaks
    let eqStreak = [];
    const flushStreak = () => {
      if (eqStreak.length >= minFold) {
        items.push({
          type: "fold",
          count: eqStreak.length,
          startOldLine: eqStreak[0].oldLine,
          startNewLine: eqStreak[0].newLine,
          foldedLines: eqStreak.slice(),
          expanded: false,
        });
      } else {
        items.push(...eqStreak);
      }
      eqStreak = [];
    };

    for (const l of hunkLines) {
      if (l.type === "eq") {
        eqStreak.push(l);
      } else {
        if (eqStreak.length > 0) flushStreak();
        items.push(l);
      }
    }
    if (eqStreak.length > 0) flushStreak();

    // Trailing fold if this is the last range and there are remaining lines
    if (idx === ranges.length - 1 && r.end < lines.length - 1) {
      const trailingLines = lines.slice(r.end + 1);
      if (trailingLines.length >= minFold) {
        items.push({
          type: "fold",
          count: trailingLines.length,
          startOldLine: trailingLines[0].oldLine,
          startNewLine: trailingLines[0].newLine,
          foldedLines: trailingLines,
          expanded: false,
        });
      } else {
        items.push(...trailingLines);
      }
    }

    const header = `@@ -${oldStart || 1},${oldCount} +${newStart || 1},${newCount} @@`;
    hunks.push({
      oldStart: oldStart || 1,
      oldCount,
      newStart: newStart || 1,
      newCount,
      header,
      items,
    });
    lastRangeEnd = r.end;
  }

  return hunks;
}

/**
 * Formats hunks as standard Unified Diff string (#74).
 *
 * @param {Hunk[]} hunks
 * @param {Object} [options]
 * @param {string} [options.oldFile='a/file']
 * @param {string} [options.newFile='b/file']
 * @returns {string}
 */
export function formatUnifiedDiff(hunks, options = {}) {
  const oldFile = options.oldFile || "a/file";
  const newFile = options.newFile || "b/file";
  if (!hunks || hunks.length === 0) return "";

  const out = [`--- ${oldFile}`, `+++ ${newFile}`];

  for (const h of hunks) {
    out.push(h.header);
    for (const item of h.items) {
      if (item.type === "fold") {
        out.push(`@@ ... [${item.count} unchanged lines folded] ... @@`);
        if (item.expanded) {
          for (const fl of item.foldedLines) {
            out.push(` ${fl.text}`);
          }
        }
      } else if (item.type === "eq") {
        out.push(` ${item.text}`);
      } else if (item.type === "add") {
        out.push(`+${item.text}`);
      } else if (item.type === "del") {
        out.push(`-${item.text}`);
      }
    }
  }

  return out.join("\n");
}

/**
 * Parses a unified diff string into hunks and lines.
 *
 * @param {string} diffText
 * @returns {Hunk[]}
 */
export function parseUnifiedDiff(diffText) {
  if (typeof diffText !== "string" || !diffText.trim()) return [];
  const lines = splitLines(diffText);
  /** @type {Hunk[]} */
  const hunks = [];
  let curHunk = null;
  let curOldLine = 1;
  let curNewLine = 1;

  for (const l of lines) {
    if (l.startsWith("---") || l.startsWith("+++")) {
      continue;
    }
    const hMatch = l.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (hMatch) {
      if (curHunk) hunks.push(curHunk);
      curOldLine = parseInt(hMatch[1], 10);
      curNewLine = parseInt(hMatch[3], 10);
      curHunk = {
        oldStart: curOldLine,
        oldCount: hMatch[2] !== undefined ? parseInt(hMatch[2], 10) : 1,
        newStart: curNewLine,
        newCount: hMatch[4] !== undefined ? parseInt(hMatch[4], 10) : 1,
        header: l,
        items: [],
      };
      continue;
    }
    if (!curHunk) continue;

    if (l.startsWith("+")) {
      curHunk.items.push({ type: "add", text: l.slice(1), oldLine: null, newLine: curNewLine++ });
    } else if (l.startsWith("-")) {
      curHunk.items.push({ type: "del", text: l.slice(1), oldLine: curOldLine++, newLine: null });
    } else if (l.startsWith(" ")) {
      curHunk.items.push({ type: "eq", text: l.slice(1), oldLine: curOldLine++, newLine: curNewLine++ });
    } else if (l.startsWith("@@ ...")) {
      const fMatch = l.match(/\[(\d+) unchanged lines folded\]/);
      const count = fMatch ? parseInt(fMatch[1], 10) : 0;
      curHunk.items.push({
        type: "fold",
        count,
        startOldLine: curOldLine,
        startNewLine: curNewLine,
        foldedLines: [],
        expanded: false,
      });
      curOldLine += count;
      curNewLine += count;
    }
  }
  if (curHunk) hunks.push(curHunk);
  return hunks;
}

/**
 * Toggles fold expansion in a hunk item (#75).
 *
 * @param {Hunk} hunk
 * @param {number} itemIndex
 * @returns {boolean}
 */
export function toggleFold(hunk, itemIndex) {
  if (!hunk || !Array.isArray(hunk.items)) return false;
  const it = hunk.items[itemIndex];
  if (it && it.type === "fold") {
    it.expanded = !it.expanded;
    return true;
  }
  return false;
}
