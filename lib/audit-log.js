// lib/audit-log.js
// Isolated append-only audit logger for dsh-approval-gate (#56).
// Logs gate decisions to ~/.dsh/approval-gate-audit.jsonl out-of-band to prevent prompt injection.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { computeFingerprint } from "./fingerprint.js";
import { redactCredentials } from "./redact.js";

export const DEFAULT_AUDIT_LOG_RELATIVE = path.join(".dsh", "approval-gate-audit.jsonl");

export class AuditLogger {
  /**
   * @param {{ logPath?: string, disabled?: boolean }} [options]
   */
  constructor(options = {}) {
    this.disabled = options.disabled === true;
    if (options.logPath) {
      this.logPath = options.logPath;
    } else {
      const home = os.homedir ? os.homedir() : (process.env.HOME || process.env.USERPROFILE || "");
      this.logPath = home ? path.join(home, DEFAULT_AUDIT_LOG_RELATIVE) : "";
    }
  }

  /**
   * Write an audit record to the isolated log file.
   *
   * @param {{
   *   sessionId?: string,
   *   execution?: any,
   *   decision: { verdict: string, stage?: string, reason?: string, detail?: string, dryRun?: boolean },
   *   dryRun?: boolean
   * }} record
   */
  log(record) {
    if (this.disabled || !this.logPath) return;

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
        detail: decision.detail,
        fingerprint: fp,
        dryRun: Boolean(record.dryRun || decision.dryRun),
      };

      const line = JSON.stringify(entry) + "\n";
      const dir = path.dirname(this.logPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.appendFileSync(this.logPath, line, "utf8");
    } catch {
      // Security audit failures fail open to prevent DoS,
      // but never leak errors into agent prompt.
    }
  }
}
