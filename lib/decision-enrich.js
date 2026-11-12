// lib/decision-enrich.js
// Decision telemetry, risk tagging, track classification, and evidence dossier attachment.

import { isRmCommand, suggestTrashAlternative } from "./trash.js";
import { classifyTrack } from "./dualtrack.js";
import { buildEvidenceDossier } from "./dossier.js";
import { categorizeRiskBucket, extractRiskTags } from "./risk.js";
import { classifyMeasureKind } from "./measure-kinds.js";

/**
 * Attaches track classification, dossier, risk metadata, and trace IDs to a decision.
 *
 * @param {any} decision
 * @param {any} execution
 * @param {any} context
 * @param {string} [workspaceDir]
 * @returns {any}
 */
export function enrichDecision(decision, execution, context, workspaceDir) {
  if (!decision) return decision;
  const command = execution && execution.arguments && execution.arguments.command;
  if (!decision.track) decision.track = classifyTrack(execution?.name, command, execution?.arguments, context);
  if (!decision.dossier) decision.dossier = buildEvidenceDossier({ execution, decision, context, toolName: execution?.name, command });
  if (!decision.riskBucket) decision.riskBucket = categorizeRiskBucket(execution, context);
  if (!decision.riskTags || !Array.isArray(decision.riskTags)) decision.riskTags = extractRiskTags(execution, context);
  if (!decision.measureKind) decision.measureKind = classifyMeasureKind(execution, context);
  if (command && isRmCommand(command)) decision.trashAlternative = suggestTrashAlternative(command, workspaceDir, context?.sessionId);
  const callId = context?.callId || execution?.callId || execution?.id || context?.execution?.id;
  const agentId = context?.agentId || context?.agent?.id || context?.session?.agentId || execution?.agentId;
  const subagentId = context?.subagentId || context?.session?.subagentId || execution?.subagentId;
  if (callId) decision.callId = callId;
  if (agentId) decision.agentId = agentId;
  if (subagentId) decision.subagentId = subagentId;
  return decision;
}

/**
 * Determine whether an operation belongs to a critical risk category requiring lockedAsk (#52).
 * Locked ask operations can never be auto-approved by unattended timeouts or fallback heuristics.
 *
 * @param {string} [toolName]
 * @param {string} [command]
 * @param {any} [execution]
 * @returns {boolean}
 */
export function isCriticalOperation(toolName, command, execution) {
  const cmd = String(command || "").trim();
  const tool = String(toolName || "").trim();
  if (!cmd && !tool) return false;

  if (/^(sudo|su|doas)\b/i.test(cmd) || /\b(chmod\s+(-[a-zA-Z]*\s+)?777|chown\s+(-[a-zA-Z]*\s+)?root)\b/i.test(cmd)) return true;
  if (/\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+|--recursive\s+)/i.test(cmd) || /\b(shred|wipefs)\b/i.test(cmd)) return true;
  if (/(\.ssh\/(id_|authorized_keys|known_hosts)|\.gnupg\/|\/etc\/shadow)/i.test(cmd)) return true;
  if (/\b(mkfs|fdisk|parted)\b/i.test(cmd) || /\bdd\s+.*of=\/dev\/(sd[a-z]|nvme|vd[a-z]|hd[a-z]|loop)/i.test(cmd)) return true;
  if (/curl\s+.*\|\s*(bash|sh|python|perl)/i.test(cmd) || /\b(nc|ncat|netcat)\s+.*-e\s+/i.test(cmd) || />&\s*\/dev\/tcp\//i.test(cmd)) return true;
  if (/\b(shutdown|reboot|poweroff|halt|init\s+0)\b/i.test(cmd) || /systemctl\s+(stop|disable|mask)\s+(sshd|systemd|ufw|iptables)/i.test(cmd)) return true;

  if (tool === "write_to_file" || tool === "edit" || tool === "replace_file_content" || tool === "str_replace_editor") {
    const target = execution && execution.arguments && (execution.arguments.TargetFile || execution.arguments.target_file || execution.arguments.path || "");
    if (typeof target === "string" && /(\/etc\/|\.ssh\/|\/boot\/|\/sys\/|\/proc\/)/i.test(target)) {
      return true;
    }
  }
  return false;
}
