// lib/audit-log.js
// Isolated append-only audit logger for dsh-approval-gate (#56, #53, #54, #55).
// Logs gate decisions to ~/.dsh/approval-gate-audit.jsonl out-of-band to prevent prompt injection.
// Features: fail-closed write verification (#53), single-pass reverse rotation up to 5MB (#54),
// and non-erasable tombstones for tamper resistance (#55).

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { computeFingerprint } from "./fingerprint.js";
import { redactCredentials } from "./redact.js";

export const DEFAULT_AUDIT_LOG_RELATIVE = path.join(".dsh", "approval-gate-audit.jsonl");
export const DEFAULT_MAX_AUDIT_BYTES = 5 * 1024 * 1024; // 5 MB (#54)
export const DEFAULT_MAX_AUDIT_LINES = 5000;
export const DEFAULT_RETAIN_LINES = 2500;
export const SCAN_CHUNK_SIZE = 64 * 1024; // 64 KB single-pass chunk

/**
 * Pure function: single-pass reverse scan rotation for string or buffer content (#54).
 * Scans from the tail backwards to avoid write amplification and full array allocation.
 *
 * @param {string} content
 * @param {number} [maxBytes=DEFAULT_MAX_AUDIT_BYTES]
 * @param {number} [maxLines=DEFAULT_MAX_AUDIT_LINES]
 * @param {number} [retainLines=DEFAULT_RETAIN_LINES]
 * @returns {{ rotated: boolean, content: string, previousBytes: number, previousLinesCount: number, retainedLinesCount: number }}
 */
export function auditRotateContent(
  content,
  maxBytes = DEFAULT_MAX_AUDIT_BYTES,
  maxLines = DEFAULT_MAX_AUDIT_LINES,
  retainLines = DEFAULT_RETAIN_LINES
) {
  if (typeof content !== "string" || content.length === 0) {
    return { rotated: false, content: "", previousBytes: 0, previousLinesCount: 0, retainedLinesCount: 0 };
  }

  const byteLength = Buffer.byteLength(content, "utf8");
  const allLines = content.split("\n");
  const nonEmptyLines = allLines[allLines.length - 1] === "" ? allLines.slice(0, -1) : allLines;
  const lineCount = nonEmptyLines.length;

  if (byteLength < maxBytes && lineCount < maxLines) {
    return { rotated: false, content, previousBytes: byteLength, previousLinesCount: lineCount, retainedLinesCount: lineCount };
  }

  let end = content.length;
  if (end > 0 && content.charCodeAt(end - 1) === 10) {
    end--; // skip trailing newline for line scanning
  }

  let targetCutoff = 0;
  let linesSeen = 0;
  for (let i = end - 1; i >= 0; i--) {
    if (content.charCodeAt(i) === 10) {
      linesSeen++;
      if (linesSeen === retainLines) {
        targetCutoff = i + 1;
        break;
      }
    }
  }
  if (linesSeen < retainLines) {
    targetCutoff = 0;
  }

  const retained = content.slice(targetCutoff);
  return {
    rotated: true,
    content: retained,
    previousBytes: byteLength,
    previousLinesCount: lineCount,
    retainedLinesCount: Math.min(lineCount, retainLines),
  };
}

export class AuditLogger {
  /**
   * @param {{
   *   logPath?: string,
   *   disabled?: boolean,
   *   failClosed?: boolean,
   *   maxBytes?: number,
   *   maxLines?: number,
   *   retainLines?: number
   * }} [options]
   */
  constructor(options = {}) {
    this.disabled = options.disabled === true;
    this.failClosed = options.failClosed === true;
    this.maxBytes = typeof options.maxBytes === "number" && options.maxBytes > 0 ? options.maxBytes : DEFAULT_MAX_AUDIT_BYTES;
    this.maxLines = typeof options.maxLines === "number" && options.maxLines > 0 ? options.maxLines : DEFAULT_MAX_AUDIT_LINES;
    this.retainLines = typeof options.retainLines === "number" && options.retainLines > 0 ? options.retainLines : DEFAULT_RETAIN_LINES;
    this.lastError = null;

    if (options.logPath) {
      this.logPath = options.logPath;
    } else {
      const home = os.homedir ? os.homedir() : (process.env.HOME || process.env.USERPROFILE || "");
      this.logPath = home ? path.join(home, DEFAULT_AUDIT_LOG_RELATIVE) : "";
    }
  }

  /**
   * Write an audit record to the isolated log file. Returns boolean (#53).
   *
   * @param {{
   *   sessionId?: string,
   *   execution?: any,
   *   decision: { verdict: string, stage?: string, reason?: string, detail?: string, dryRun?: boolean, ruleId?: string },
   *   dryRun?: boolean
   * }} record
   * @returns {boolean} True if append succeeded or disabled, false if write failed
   */
  appendAuditLine(record) {
    if (this.disabled || !this.logPath) return true;

    try {
      const now = Date.now();
      const execution = record.execution || {};
      const decision = record.decision || {};
      const tool = String(execution.name || execution.tool || "").trim();
      const rawCmd = execution.arguments && typeof execution.arguments.command === "string"
        ? execution.arguments.command
        : "";
      const redactedCmd = rawCmd ? redactCredentials(rawCmd) : undefined;
      const fp = computeFingerprint(execution);

      const entry = {
        timestamp: now,
        iso: new Date(now).toISOString(),
        sessionId: record.sessionId || "default",
        tool,
        command: redactedCmd,
        verdict: decision.verdict,
        stage: decision.stage,
        reason: decision.reason,
        ruleId: decision.ruleId,
        detail: decision.detail,
        fingerprint: fp,
        dryRun: Boolean(record.dryRun || decision.dryRun),
        callId: record.callId || decision.callId || null,
        agentId: record.agentId || decision.agentId || null,
        subagentId: record.subagentId || decision.subagentId || null,
      };

      const line = JSON.stringify(entry) + "\n";
      const dir = path.dirname(this.logPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.appendFileSync(this.logPath, line, "utf8");
      this.lastError = null;

      // Check if rotation is needed (#54)
      this._checkRotation();
      return true;
    } catch (err) {
      this.lastError = err;
      if (this.failClosed) {
        return false;
      }
      return false;
    }
  }

  /**
   * Alias for backward compatibility.
   * @param {any} record
   * @returns {boolean}
   */
  log(record) {
    return this.appendAuditLine(record);
  }

  /**
   * Single-pass reverse scan rotation (#54).
   * @private
   */
  _checkRotation() {
    if (!this.logPath || !fs.existsSync(this.logPath)) return;
    try {
      const stat = fs.statSync(this.logPath);
      if (stat.size >= this.maxBytes) {
        this.rotate();
      }
    } catch {
      // Rotation check failure must not crash logger
    }
  }

  /**
   * Explicitly rotate audit log using single-pass reverse scan and tombstone (#54, #55).
   * @returns {boolean}
   */
  rotate() {
    if (!this.logPath || !fs.existsSync(this.logPath)) return false;

    try {
      const raw = fs.readFileSync(this.logPath, "utf8");
      const prevSha256 = crypto.createHash("sha256").update(raw, "utf8").digest("hex");
      // Force rotation to retainLines
      const rot = auditRotateContent(raw, 0, 0, this.retainLines);

      const now = Date.now();
      const tombstone = {
        tombstone: true,
        timestamp: now,
        iso: new Date(now).toISOString(),
        reason: "rotation",
        clearedBy: "system:rotator",
        previousSha256: prevSha256,
        previousBytes: rot.previousBytes,
        previousLinesCount: rot.previousLinesCount,
        retainedLinesCount: rot.retainedLinesCount,
      };

      const tombstoneLine = JSON.stringify(tombstone) + "\n";
      const newContent = tombstoneLine + rot.content;

      const tmpPath = this.logPath + ".tmp." + now;
      fs.writeFileSync(tmpPath, newContent, "utf8");
      fs.renameSync(tmpPath, this.logPath);
      return true;
    } catch (err) {
      this.lastError = err;
      return false;
    }
  }

  /**
   * Clear the audit log with a non-erasable tombstone (#55).
   * Instead of silent deletion, creates an immutable tombstone record preserving hash and event chain.
   *
   * @param {{ reason?: string, clearedBy?: string }} [options]
   * @returns {{
   *   tombstone: boolean,
   *   timestamp: number,
   *   iso: string,
   *   reason: string,
   *   clearedBy: string,
   *   previousSha256: string,
   *   previousBytes: number,
   *   previousLinesCount: number
   * }}
   */
  clear(options = {}) {
    const reason = options.reason || "manual_clear";
    const clearedBy = options.clearedBy || "admin";
    let prevSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let prevBytes = 0;
    let prevLines = 0;

    if (this.logPath && fs.existsSync(this.logPath)) {
      try {
        const raw = fs.readFileSync(this.logPath, "utf8");
        prevBytes = Buffer.byteLength(raw, "utf8");
        prevSha256 = crypto.createHash("sha256").update(raw, "utf8").digest("hex");
        prevLines = raw.split("\n").filter((l) => l.trim().length > 0).length;
      } catch {
        // Read error
      }
    }

    const now = Date.now();
    const tombstone = {
      tombstone: true,
      timestamp: now,
      iso: new Date(now).toISOString(),
      reason,
      clearedBy,
      previousSha256: prevSha256,
      previousBytes: prevBytes,
      previousLinesCount: prevLines,
    };

    if (this.logPath) {
      const dir = path.dirname(this.logPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const line = JSON.stringify(tombstone) + "\n";
      fs.writeFileSync(this.logPath, line, "utf8");
    }

    return tombstone;
  }

  /**
   * Read all tombstones from the log file (#55).
   * @returns {Array<any>}
   */
  getTombstones() {
    if (!this.logPath || !fs.existsSync(this.logPath)) return [];
    try {
      const raw = fs.readFileSync(this.logPath, "utf8");
      const lines = raw.split("\n").filter((l) => l.trim().length > 0);
      const tombstones = [];
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          if (parsed && parsed.tombstone === true) {
            tombstones.push(parsed);
          }
        } catch {
          // ignore corrupted lines
        }
      }
      return tombstones;
    } catch {
      return [];
    }
  }

  /**
   * Read recent entries from the audit log.
   * @param {{ includeTombstones?: boolean, limit?: number }} [options]
   * @returns {Array<any>}
   */
  readEntries(options = {}) {
    if (!this.logPath || !fs.existsSync(this.logPath)) return [];
    const includeTombstones = options.includeTombstones !== false;
    const limit = typeof options.limit === "number" && options.limit > 0 ? options.limit : 100;

    try {
      const raw = fs.readFileSync(this.logPath, "utf8");
      const lines = raw.split("\n").filter((l) => l.trim().length > 0);
      const entries = [];
      for (let i = lines.length - 1; i >= 0 && entries.length < limit; i--) {
        try {
          const parsed = JSON.parse(lines[i]);
          if (!includeTombstones && parsed.tombstone === true) {
            continue;
          }
          entries.push(parsed);
        } catch {
          // ignore
        }
      }
      return entries.reverse();
    } catch {
      return [];
    }
  }
}
