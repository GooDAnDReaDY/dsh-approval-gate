// lib/dossier.js
// Evidence Dossier Gathering (#64).
// Assembles compact evidence packets for tool calls, diffs, terminal output, and user prompts.

export const MAX_PROMPT_CHARS = 200;
export const MAX_DIFF_CHARS = 400;
export const MAX_OUTPUT_CHARS = 300;

/**
 * Truncates a string safely with ellipsis.
 * @param {any} str
 * @param {number} max
 * @returns {string}
 */
function truncate(str, max) {
  if (typeof str !== "string") return "";
  const trimmed = str.trim();
  if (trimmed.length <= max) return trimmed;
  return trimmed.slice(0, max - 3) + "...";
}

/**
 * Extracts a concise summary of arguments without sensitive credentials.
 * @param {Record<string, any>} [args]
 * @returns {Record<string, any>}
 */
function sanitizeArgs(args) {
  if (!args || typeof args !== "object") return {};
  const summary = {};
  for (const [k, v] of Object.entries(args)) {
    if (k.toLowerCase().includes("token") || k.toLowerCase().includes("secret") || k.toLowerCase().includes("password")) {
      summary[k] = "[REDACTED]";
    } else if (typeof v === "string") {
      summary[k] = v.length > 80 ? v.slice(0, 77) + "..." : v;
    } else if (typeof v === "number" || typeof v === "boolean") {
      summary[k] = v;
    } else if (Array.isArray(v)) {
      summary[k] = `Array(${v.length})`;
    } else if (typeof v === "object" && v !== null) {
      summary[k] = `Object(${Object.keys(v).length})`;
    }
  }
  return summary;
}

/**
 * Builds an evidence dossier object for an execution (#64).
 *
 * @param {Object} params
 * @param {Record<string, any>} [params.execution]
 * @param {Record<string, any>} [params.decision]
 * @param {Record<string, any>} [params.context]
 * @param {string} [params.toolName]
 * @param {string} [params.command]
 * @param {Record<string, any>} [params.args]
 * @param {string} [params.userPrompt]
 * @param {string} [params.diffSnippet]
 * @param {string} [params.terminalOutput]
 * @param {string} [params.track]
 * @param {string} [params.riskBucket]
 * @returns {{
 *   toolName: string,
 *   command: string,
 *   argsSummary: Record<string, any>,
 *   userPrompt: string,
 *   diffSnippet: string,
 *   terminalOutput: string,
 *   track: string,
 *   riskBucket: string,
 *   timestamp: number
 * }}
 */
export function buildEvidenceDossier({
  execution = {},
  decision = {},
  context = {},
  toolName,
  command,
  args,
  userPrompt,
  diffSnippet,
  terminalOutput,
  track,
  riskBucket,
} = {}) {
  const tool = String(toolName || execution?.name || execution?.toolName || "").trim();
  const cmd = String(command || execution?.arguments?.command || execution?.command || "").trim();
  const rawArgs = args || execution?.arguments || {};
  const prompt = userPrompt || context?.userPrompt || context?.prompt || context?.goal || "";
  const diff = diffSnippet || context?.diffSnippet || context?.diff || rawArgs?.diff || "";
  const output = terminalOutput || context?.terminalOutput || context?.output || "";
  const assignedTrack = track || decision?.track || context?.track || "external";
  const assignedRisk = riskBucket || decision?.riskBucket || context?.riskBucket || "medium";

  return {
    toolName: tool,
    command: cmd,
    argsSummary: sanitizeArgs(rawArgs),
    userPrompt: truncate(prompt, MAX_PROMPT_CHARS),
    diffSnippet: truncate(diff, MAX_DIFF_CHARS),
    terminalOutput: truncate(output, MAX_OUTPUT_CHARS),
    track: assignedTrack,
    riskBucket: assignedRisk,
    timestamp: Date.now(),
  };
}

/**
 * Formats a single-line summary of an evidence dossier.
 * @param {ReturnType<typeof buildEvidenceDossier>} dossier
 * @returns {string}
 */
export function formatDossierSummary(dossier) {
  if (!dossier) return "[Dossier: empty]";
  const parts = [];
  if (dossier.toolName) parts.push(`tool=${dossier.toolName}`);
  if (dossier.track) parts.push(`track=${dossier.track}`);
  if (dossier.riskBucket) parts.push(`risk=${dossier.riskBucket}`);
  if (dossier.userPrompt) parts.push(`prompt="${dossier.userPrompt.slice(0, 30)}"`);
  if (dossier.diffSnippet) parts.push(`diff="${dossier.diffSnippet.slice(0, 30)}"`);
  return `[Dossier: ${parts.join(" ")}]`;
}
