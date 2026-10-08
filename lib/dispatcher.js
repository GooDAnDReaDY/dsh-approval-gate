// lib/dispatcher.js
// Command Dispatcher: architectural isolation of command parsing and syntactic dispatch
// from the safety evaluation engine.
// Resolves: #133, #65

import { tokenize, splitSubcommands } from "./tokenizer.js";
import { parseGitArgv, classifyGitOperation } from "./parsers/git.js";
import { extractRedirects, inspectRedirectSecurity, inspectSilentErrors, inspectPipelines } from "./parsers/shell-cmds.js";
import { isLoopbackCommand, isLoopbackUrl } from "./loopback.js";
import { resolveSafePath, isPathTraversal, isProtectedConfigPath } from "./paths.js";

export const TOOL_KIND_SHELL = "shell";
export const TOOL_KIND_FILE_WRITE = "file_write";
export const TOOL_KIND_FILE_READ = "file_read";
export const TOOL_KIND_NETWORK = "network";
export const TOOL_KIND_GENERIC = "generic";

export const DEFAULT_BASH_TOOL = "bash";
export const DEFAULT_FILE_WRITE_TOOLS = Object.freeze([
  "write",
  "edit",
  "Write",
  "Edit",
  "str_replace_editor",
  "str_replace",
  "apply_patch",
]);

export const DEFAULT_READ_ONLY_TOOLS = Object.freeze([
  "read_file",
  "view_file",
  "read_url_content",
  "search_web",
  "list_dir",
  "glob",
  "grep",
]);

export const DEFAULT_NETWORK_TOOLS = Object.freeze([
  "fetch",
  "web_fetch",
  "http_request",
  "read_url_content",
]);

/**
 * Extracts target file path from various tool argument schemas.
 *
 * @param {any} args
 * @returns {string | null}
 */
export function extractFilePath(args) {
  if (typeof args === "string") return args;
  if (!args || typeof args !== "object") return null;
  const keys = [
    "path",
    "file_path",
    "filePath",
    "file",
    "filename",
    "target",
    "to",
    "TargetFile",
    "AbsolutePath",
  ];
  for (const k of keys) {
    if (typeof args[k] === "string" && args[k].trim()) {
      return args[k].trim();
    }
  }
  return null;
}

/**
 * Checks whether an execution originates from a designated read-only reviewer agent.
 * Resolves: #65 (strict read-only reviewer subagent isolation).
 *
 * @param {any} execution
 * @param {any} [options]
 * @returns {boolean}
 */
export function isReviewerAgent(execution, options = {}) {
  if (options && options.reviewerMode === true) return true;
  const agent = execution && execution.agent;
  if (!agent) return false;

  const role = typeof agent.role === "string" ? agent.role.toLowerCase() : "";
  const name = typeof agent.name === "string" ? agent.name.toLowerCase() : "";
  const type = typeof agent.type === "string" ? agent.type.toLowerCase() : "";

  return role.includes("review") || name.includes("review") || type.includes("review");
}

export class CommandDispatcher {
  /**
   * @param {{
   *   toolName?: string,
   *   fileWriteTools?: string[] | Set<string>,
   *   readOnlyTools?: string[] | Set<string>,
   *   networkTools?: string[] | Set<string>,
   *   workspaceDir?: string
   * }} [options]
   */
  constructor(options = {}) {
    this.toolName = options.toolName || DEFAULT_BASH_TOOL;
    this.fileWriteTools = new Set(options.fileWriteTools || DEFAULT_FILE_WRITE_TOOLS);
    this.readOnlyTools = new Set(options.readOnlyTools || DEFAULT_READ_ONLY_TOOLS);
    this.networkTools = new Set(options.networkTools || DEFAULT_NETWORK_TOOLS);
    this.workspaceDir = options.workspaceDir || process.cwd();
  }

  /**
   * Categorizes the tool name into functional kind.
   *
   * @param {string} name
   * @returns {"shell" | "file_write" | "file_read" | "network" | "generic"}
   */
  classifyTool(name) {
    if (!name) return TOOL_KIND_GENERIC;
    if (name === this.toolName) return TOOL_KIND_SHELL;
    if (this.fileWriteTools.has(name)) return TOOL_KIND_FILE_WRITE;
    if (this.readOnlyTools.has(name)) return TOOL_KIND_FILE_READ;
    if (this.networkTools.has(name)) return TOOL_KIND_NETWORK;
    return TOOL_KIND_GENERIC;
  }

  /**
   * Dispatches and normalizes a tool execution request into a structured descriptor.
   *
   * @param {any} execution - The tool execution event carrying name, arguments, agent, session
   * @param {any} [options] - Dynamic context overrides
   * @returns {{
   *   tool: string,
   *   kind: "shell" | "file_write" | "file_read" | "network" | "generic",
   *   isMutating: boolean,
   *   reviewerViolation: boolean,
   *   command?: string,
   *   tokens?: any[],
   *   subcommands?: string[],
   *   git?: any,
   *   silentError?: any,
   *   loopback?: any,
   *   filePath?: string,
   *   pathSafety?: any
   * }}
   */
  dispatch(execution, options = {}) {
    const name = execution && execution.name ? String(execution.name).trim() : "";
    const args = execution ? execution.arguments : undefined;
    const kind = this.classifyTool(name);
    const isReviewer = isReviewerAgent(execution, options);

    const isMutating = kind === TOOL_KIND_SHELL || kind === TOOL_KIND_FILE_WRITE;
    const reviewerViolation = isReviewer && isMutating;

    const descriptor = {
      tool: name,
      kind,
      isMutating,
      reviewerViolation,
    };

    if (kind === TOOL_KIND_SHELL) {
      const rawCommand = args && typeof args === "object" ? args.command : (typeof args === "string" ? args : "");
      descriptor.command = typeof rawCommand === "string" ? rawCommand : "";

      if (descriptor.command) {
        const tokenized = tokenize(descriptor.command);
        descriptor.tokens = tokenized.tokens || [];
        descriptor.tokenizerOk = tokenized.ok;
        descriptor.tokenizerReason = tokenized.reason;

        // Subcommands breakdown
        descriptor.subcommands = splitSubcommands(descriptor.command);

        // Silent errors inspection (#90)
        descriptor.silentError = inspectSilentErrors(descriptor.command);

        // Git inspection (#125, #103)
        if (/\bgit\b/.test(descriptor.command)) {
          const firstWords = descriptor.command.trim().split(/\s+/);
          descriptor.git = parseGitArgv(firstWords);
          descriptor.gitClassification = classifyGitOperation(descriptor.git.verb, descriptor.git.args);
        }

        // Loopback detection (#40)
        descriptor.loopback = isLoopbackCommand(descriptor.command.trim().split(/\s+/));
      }
    } else if (kind === TOOL_KIND_FILE_WRITE) {
      const filePath = extractFilePath(args);
      descriptor.filePath = filePath;
      if (filePath) {
        const ws = options.workspaceDir || this.workspaceDir;
        descriptor.pathSafety = resolveSafePath(filePath, ws);
        descriptor.isProtected = isProtectedConfigPath(descriptor.pathSafety.canonical || filePath);
        descriptor.isTraversal = !descriptor.pathSafety.safe;
      }
    } else if (kind === TOOL_KIND_NETWORK) {
      const url = args && typeof args === "object" ? (args.url || args.Url || args.uri || args.Uri) : "";
      descriptor.url = typeof url === "string" ? url : "";
      if (descriptor.url) {
        descriptor.isLoopback = isLoopbackUrl(descriptor.url);
      }
    }

    return descriptor;
  }
}