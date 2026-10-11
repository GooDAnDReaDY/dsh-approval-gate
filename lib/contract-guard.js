// lib/contract-guard.js
// Enforces task contract boundaries and blocks out-of-scope system mutations (#87).

const SYSTEM_PACKAGE_MANAGERS = new Set([
  "apt",
  "apt-get",
  "dpkg",
  "yum",
  "dnf",
  "pacman",
  "zypper",
  "brew",
  "snap",
  "flatpak",
  "apk",
]);

const SYSTEM_SERVICE_COMMANDS = new Set([
  "systemctl",
  "service",
  "init",
  "reboot",
  "shutdown",
  "poweroff",
]);

const SYSTEM_NETWORKING_COMMANDS = new Set([
  "iptables",
  "ufw",
  "firewalld",
  "ifconfig",
  "netplan",
]);

const SYSTEM_CONFIG_TARGETS = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/sudoers",
  "/etc/fstab",
  "/etc/hosts",
  "/etc/pam.d",
  "/etc/profile",
  "/etc/bash.bashrc",
];

/**
 * Validates whether a command or tool execution stays within task contract boundaries (#87).
 */
export class ContractGuard {
  /**
   * @param {{
   *   allowSystemMutations?: boolean,
   *   allowedTools?: string[],
   *   allowedCommands?: string[],
   *   forbiddenCommands?: string[]
   * }} [contract]
   */
  constructor(contract = {}) {
    this.allowSystemMutations = contract.allowSystemMutations === true;
    this.allowedTools = Array.isArray(contract.allowedTools) ? new Set(contract.allowedTools) : null;
    this.allowedCommands = Array.isArray(contract.allowedCommands) ? new Set(contract.allowedCommands) : null;
    this.forbiddenCommands = Array.isArray(contract.forbiddenCommands) ? new Set(contract.forbiddenCommands) : null;
  }

  /**
   * Checks if an execution violates the task contract boundaries.
   *
   * @param {string} toolName
   * @param {string} [command]
   * @param {any} [execution]
   * @returns {{ allowed: boolean, reason?: string, detail?: string, snippet?: string }}
   */
  check(toolName, command, execution) {
    // 1. Tool-level restriction
    if (this.allowedTools && toolName && !this.allowedTools.has(toolName)) {
      return {
        allowed: false,
        reason: "contract-violation",
        detail: `Tool '${toolName}' is not permitted by task contract`,
        snippet: toolName,
      };
    }

    if (!command || typeof command !== "string") {
      return { allowed: true };
    }

    const trimmed = command.trim();
    if (!trimmed) return { allowed: true };

    const firstWord = trimmed.split(/\s+/)[0].replace(/^sudo\s+/, "");

    // 2. Explicit forbidden command list
    if (this.forbiddenCommands && this.forbiddenCommands.has(firstWord)) {
      return {
        allowed: false,
        reason: "contract-violation",
        detail: `Command '${firstWord}' is explicitly forbidden by task contract`,
        snippet: firstWord,
      };
    }

    // 3. System mutations guard when allowSystemMutations is false
    if (!this.allowSystemMutations) {
      if (SYSTEM_PACKAGE_MANAGERS.has(firstWord)) {
        return {
          allowed: false,
          reason: "contract-violation",
          detail: `Out-of-scope system package manager invocation: ${firstWord}`,
          snippet: trimmed,
        };
      }

      if (SYSTEM_SERVICE_COMMANDS.has(firstWord)) {
        return {
          allowed: false,
          reason: "contract-violation",
          detail: `Out-of-scope system service or reboot control: ${firstWord}`,
          snippet: trimmed,
        };
      }

      if (SYSTEM_NETWORKING_COMMANDS.has(firstWord)) {
        return {
          allowed: false,
          reason: "contract-violation",
          detail: `Out-of-scope network configuration command: ${firstWord}`,
          snippet: trimmed,
        };
      }

      // Check system configuration mutation redirects
      for (const target of SYSTEM_CONFIG_TARGETS) {
        if (trimmed.includes(target) && /[><]/.test(trimmed)) {
          return {
            allowed: false,
            reason: "contract-violation",
            detail: `Out-of-scope system configuration file write: ${target}`,
            snippet: trimmed,
          };
        }
      }
    }

    return { allowed: true };
  }
}
