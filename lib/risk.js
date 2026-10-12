// lib/risk.js
// Structured risk bucket classification and operational risk tagging.
// Resolves: #58 (Risk Buckets) and #70 (Risk Tags)

import {
  DEFAULT_BASH_TOOL,
  DEFAULT_FILE_WRITE_TOOLS,
  DEFAULT_READ_ONLY_TOOLS,
  DEFAULT_NETWORK_TOOLS,
  extractFilePath,
} from "./dispatcher.js";
import { isProtectedConfigPath } from "./paths.js";
import { isLoopbackHost, isLoopbackUrl } from "./loopback.js";

export const RISK_BUCKETS = Object.freeze({
  READ_ONLY: "READ_ONLY",
  WORKSPACE: "WORKSPACE",
  EGRESS: "EGRESS",
  SYSTEM: "SYSTEM",
  SECRETS: "SECRETS",
});

export const RISK_TAGS = Object.freeze({
  READ_ONLY: "read-only",
  FILE_MUTATION: "file-mutation",
  NETWORK: "network",
  GIT: "git",
  CREDENTIALS: "credentials",
  PACKAGE_MANAGER: "package-manager",
  SYSTEM_MUTATION: "system-mutation",
  PRIVILEGE_ESCALATION: "privilege-escalation",
  DESTRUCTIVE: "destructive",
});

const READ_ONLY_CMDS = new Set([
  "ls", "cat", "head", "tail", "grep", "find", "pwd", "which", "whereis",
  "file", "stat", "echo", "printf", "diff", "wc", "sort", "uniq", "date",
  "uname", "uptime", "hostname", "whoami", "id", "node -v", "npm -v", "git status",
  "git log", "git diff", "git show", "git rev-parse", "git branch",
]);

const SYSTEM_PKG_MANAGERS = new Set([
  "apt", "apt-get", "dpkg", "yum", "dnf", "pacman", "zypper", "brew", "snap", "flatpak", "apk",
]);

const DEV_PKG_MANAGERS = new Set(["npm", "pnpm", "yarn", "pip", "pip3", "cargo", "gem", "go", "composer"]);

const SYSTEM_SERVICES = new Set(["systemctl", "service", "init", "reboot", "shutdown", "poweroff", "journalctl"]);

const NETWORK_CMDS = new Set(["curl", "wget", "fetch", "nc", "netcat", "ncat", "ssh", "scp", "rsync", "ping", "telnet"]);

const SECRET_PATTERNS = [
  /(\.env|\.env\.[a-z0-9_.-]+)$/i,
  /id_rsa|id_ed25519|authorized_keys|known_hosts/i,
  /\/etc\/(shadow|sudoers|master\.passwd)/i,
  /\.git-credentials|\.netrc|\.dockercfg|\.npmrc/i,
];

/**
 * Categorizes an execution into one of the 5 standardized risk buckets (#58).
 * Priority waterfall: SECRETS -> SYSTEM -> EGRESS -> WORKSPACE -> READ_ONLY
 *
 * @param {any} execution
 * @param {any} [context]
 * @returns {string} Bucket name from RISK_BUCKETS
 */
export function categorizeRiskBucket(execution, context = {}) {
  const toolName = execution && execution.name;
  const args = execution && execution.arguments;
  const command = (args && typeof args === "object" && typeof args.command === "string")
    ? args.command.trim()
    : (typeof args === "string" ? args.trim() : "");
  const targetPath = extractFilePath(args);

  // 1. SECRETS check
  if (targetPath) {
    if (isProtectedConfigPath(targetPath) || SECRET_PATTERNS.some((p) => p.test(targetPath))) {
      return RISK_BUCKETS.SECRETS;
    }
  }
  if (command) {
    if (/\b(?:printenv|export|env)\b(?!\s*=[a-zA-Z0-9_.-]+)/i.test(command) && !/\b(?:npm|node|git|test|cargo)\b/i.test(command)) {
      return RISK_BUCKETS.SECRETS;
    }
    if (SECRET_PATTERNS.some((p) => p.test(command))) {
      return RISK_BUCKETS.SECRETS;
    }
  }

  // 2. SYSTEM check
  if (command) {
    const firstWord = command.split(/\s+/)[0].replace(/^sudo\s+/, "");
    if (/^(sudo|su|doas)\b/i.test(command)) return RISK_BUCKETS.SYSTEM;
    if (SYSTEM_PKG_MANAGERS.has(firstWord) || SYSTEM_SERVICES.has(firstWord)) return RISK_BUCKETS.SYSTEM;
    if (/\b(chmod|chown)\s+(-[a-zA-Z]*\s+)?[0-7]{3,4}\b/i.test(command)) return RISK_BUCKETS.SYSTEM;
    if (/\b(mkfs|fdisk|parted|mount|umount)\b/i.test(command)) return RISK_BUCKETS.SYSTEM;
    if (/\/(etc|usr|var|boot|sys|proc)\//i.test(command) && /[><]/.test(command)) return RISK_BUCKETS.SYSTEM;
  }
  if (targetPath && /(\/etc\/|\/boot\/|\/sys\/|\/proc\/)/i.test(targetPath)) {
    return RISK_BUCKETS.SYSTEM;
  }

  // 3. EGRESS check
  const netTools = new Set(DEFAULT_NETWORK_TOOLS);
  if (netTools.has(toolName)) {
    const url = (args && (args.url || args.Url || args.uri)) || "";
    if (url && (isLoopbackHost(url) || isLoopbackUrl(url))) {
      return RISK_BUCKETS.WORKSPACE;
    }
    return RISK_BUCKETS.EGRESS;
  }
  if (command) {
    if (/git\s+push\b/i.test(command)) return RISK_BUCKETS.EGRESS;
    const firstWord = command.split(/\s+/)[0];
    if (NETWORK_CMDS.has(firstWord)) {
      if (/\b(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)\b/i.test(command)) {
        return RISK_BUCKETS.WORKSPACE;
      }
      return RISK_BUCKETS.EGRESS;
    }
  }

  // 4. READ_ONLY check
  const readTools = new Set(DEFAULT_READ_ONLY_TOOLS);
  if (readTools.has(toolName)) {
    return RISK_BUCKETS.READ_ONLY;
  }
  if (command) {
    const normalizedCmd = command.split(/\s+/).slice(0, 2).join(" ");
    const singleCmd = command.split(/\s+/)[0];
    if (READ_ONLY_CMDS.has(normalizedCmd) || READ_ONLY_CMDS.has(singleCmd)) {
      if (!/[><|&;]/.test(command)) {
        return RISK_BUCKETS.READ_ONLY;
      }
    }
  }

  // 5. WORKSPACE (default for dev tasks)
  return RISK_BUCKETS.WORKSPACE;
}

/**
 * Extracts multidimensional risk tags for an execution (#70).
 *
 * @param {any} execution
 * @param {any} [context]
 * @returns {string[]} Sorted array of unique tag strings
 */
export function extractRiskTags(execution, context = {}) {
  const tags = new Set();
  const toolName = String((execution && execution.name) || "").trim();
  const args = execution && execution.arguments;
  const command = (args && typeof args === "object" && typeof args.command === "string")
    ? args.command.trim()
    : (typeof args === "string" ? args.trim() : "");
  const targetPath = extractFilePath(args);

  // File mutation
  const writeTools = new Set(DEFAULT_FILE_WRITE_TOOLS);
  if (
    writeTools.has(toolName) ||
    toolName === "write_file" ||
    toolName === "replace_file_content" ||
    /\b(write|edit)\b/i.test(toolName) ||
    /[><]/.test(command) ||
    /\b(rm|mv|cp|touch|mkdir|rmdir)\b/i.test(command)
  ) {
    tags.add(RISK_TAGS.FILE_MUTATION);
  }

  // Network
  const netTools = new Set(DEFAULT_NETWORK_TOOLS);
  if (netTools.has(toolName) || /git\s+push\b/i.test(command) || /\b(curl|wget|fetch|nc|ssh|ping)\b/i.test(command)) {
    tags.add(RISK_TAGS.NETWORK);
  }

  // Git
  if (/^git\b/i.test(command) || toolName.includes("git")) {
    tags.add(RISK_TAGS.GIT);
  }

  // Credentials / Secrets
  if (
    (targetPath && (isProtectedConfigPath(targetPath) || SECRET_PATTERNS.some((p) => p.test(targetPath)))) ||
    /\b(printenv|export|env)\b(?!\s*=[a-zA-Z0-9_.-]+)/i.test(command) ||
    SECRET_PATTERNS.some((p) => p.test(command)) ||
    /\b(Bearer|token|secret|password|api[_-]?key)\b/i.test(command)
  ) {
    tags.add(RISK_TAGS.CREDENTIALS);
  }

  // Package manager
  if (command) {
    const firstWord = command.split(/\s+/)[0].replace(/^sudo\s+/, "");
    if (SYSTEM_PKG_MANAGERS.has(firstWord) || DEV_PKG_MANAGERS.has(firstWord)) {
      tags.add(RISK_TAGS.PACKAGE_MANAGER);
    }
  }

  // Privilege escalation / System mutation
  if (command) {
    if (/^(sudo|su|doas)\b/i.test(command) || /\bchmod\s+(-[a-zA-Z]*\s+)?777\b/i.test(command)) {
      tags.add(RISK_TAGS.PRIVILEGE_ESCALATION);
    }
    const firstWord = command.split(/\s+/)[0].replace(/^sudo\s+/, "");
    if (SYSTEM_PKG_MANAGERS.has(firstWord) || SYSTEM_SERVICES.has(firstWord) || /\b(systemctl|service|reboot|shutdown)\b/i.test(command)) {
      tags.add(RISK_TAGS.SYSTEM_MUTATION);
    }
    if (/\b(rm\s+-[a-zA-Z]*[rf]|mkfs|shred|wipefs|git\s+clean\s+-[a-zA-Z]*f|git\s+reset\s+--hard)\b/i.test(command)) {
      tags.add(RISK_TAGS.DESTRUCTIVE);
    }
  }

  // Read only
  const readTools = new Set(DEFAULT_READ_ONLY_TOOLS);
  if (readTools.has(toolName) || (command && !tags.has(RISK_TAGS.FILE_MUTATION) && !tags.has(RISK_TAGS.DESTRUCTIVE) && !/[><|&;]/.test(command))) {
    const singleCmd = command ? command.split(/\s+/)[0] : "";
    if (READ_ONLY_CMDS.has(singleCmd) || readTools.has(toolName)) {
      tags.add(RISK_TAGS.READ_ONLY);
    }
  }

  return Array.from(tags).sort();
}
