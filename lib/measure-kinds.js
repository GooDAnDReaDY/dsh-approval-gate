// lib/measure-kinds.js
// Multi-level operational impact scale categorization (#97).
// Classifies execution into:
// - 'local-single': operation affects exactly one file or inspects local state
// - 'workspace-wide': operation affects the entire workspace/repository or multiple files
// - 'system-level': operation accesses or mutates OS-level, network, or environment state

export const MEASURE_KINDS = Object.freeze({
  LOCAL_SINGLE: "local-single",
  WORKSPACE_WIDE: "workspace-wide",
  SYSTEM_LEVEL: "system-level",
});

const SYSTEM_BINARIES = new Set([
  "sudo", "su", "doas",
  "systemctl", "service", "journalctl", "init",
  "apt", "apt-get", "dpkg", "apk", "dnf", "yum", "pacman", "zypper",
  "curl", "wget", "nc", "netcat", "ncat", "telnet", "ssh", "scp", "sftp", "rsync",
  "iptables", "nftables", "ufw", "firewall-cmd",
  "crontab", "at",
  "reboot", "shutdown", "poweroff", "halt",
  "mount", "umount", "fdisk", "parted", "mkfs", "dd",
  "insmod", "rmmod", "modprobe",
  "docker", "podman", "containerd", "runc", "crictl", "kubectl",
  "passwd", "useradd", "userdel", "usermod", "groupadd",
  "kill", "killall", "pkill", "xkill",
]);

const SYSTEM_PATH_REGEX = /((\/|\b)(etc|boot|sys|proc|dev|usr|var\/log|root)(\/|\b)|~?\/\.(ssh|gnupg|bashrc|zshrc|profile)(\/|\b))/i;

const WORKSPACE_COMMAND_PATTERNS = [
  /^(npm|pnpm|yarn|bun)\s+(install|add|remove|uninstall|update|upgrade|ci|build|pack|publish|run)/i,
  /^(cargo|go|dotnet|mvn|gradle)\s+(build|test|clean|install|run)/i,
  /^git\s+(checkout|switch|merge|rebase|pull|push|reset|clean|branch|tag|stash|restore|clone)/i,
  /^(find|grep|ripgrep|rg|ack|ag)\s+/i,
  /\b(make|ninja|cmake|meson)\b/i,
];

const SINGLE_FILE_TOOLS = new Set([
  "view_file", "read_file", "view",
  "write_to_file", "create_file", "write",
  "replace_file_content", "edit_file", "patch_file",
  "inspect_file",
]);

const SYSTEM_LEVEL_TOOLS = new Set([
  "read_url_content", "search_web", "web_search",
  "browse", "http_request", "network_fetch",
]);

/**
 * Classifies the operational impact scale for a tool call execution.
 * @param {Record<string, any>} execution
 * @param {Record<string, any>} [context]
 * @returns {'local-single' | 'workspace-wide' | 'system-level'}
 */
export function classifyMeasureKind(execution, context = {}) {
  if (!execution) return MEASURE_KINDS.LOCAL_SINGLE;
  if (typeof execution === "string") {
    execution = { name: "bash", arguments: { command: execution } };
  }

  const toolName = execution.name || execution.tool || "";
  const args = execution.arguments || {};

  // 1. Tool-level system categorization
  if (SYSTEM_LEVEL_TOOLS.has(toolName)) {
    return MEASURE_KINDS.SYSTEM_LEVEL;
  }

  // 2. Tool-level single-file mutations / reads
  if (SINGLE_FILE_TOOLS.has(toolName)) {
    const target = args.TargetFile || args.targetPath || args.path || args.file || "";
    if (typeof target === "string" && SYSTEM_PATH_REGEX.test(target)) {
      return MEASURE_KINDS.SYSTEM_LEVEL;
    }
    return MEASURE_KINDS.LOCAL_SINGLE;
  }

  // 3. Shell / command inspection
  const command = typeof args.command === "string" ? args.command.trim() : "";
  if (!command) {
    return MEASURE_KINDS.LOCAL_SINGLE;
  }

  // Fast check: first word
  const firstWord = command.split(/\s+/)[0]?.toLowerCase();
  if (SYSTEM_BINARIES.has(firstWord)) {
    return MEASURE_KINDS.SYSTEM_LEVEL;
  }
  if ((command.includes("/") || command.includes(".")) && SYSTEM_PATH_REGEX.test(command)) {
    return MEASURE_KINDS.SYSTEM_LEVEL;
  }

  // Check subcommands or pipes for system binaries only if operators present
  if (/[|;&]/.test(command)) {
    const tokens = command.split(/[\s|;&]+/);
    for (const token of tokens) {
      if (SYSTEM_BINARIES.has(token.toLowerCase())) {
        return MEASURE_KINDS.SYSTEM_LEVEL;
      }
    }
  }

  // Check workspace-wide patterns
  for (const pattern of WORKSPACE_COMMAND_PATTERNS) {
    if (pattern.test(command)) {
      return MEASURE_KINDS.WORKSPACE_WIDE;
    }
  }

  // Multi-target rm or recursive rm
  if (/^rm\s+/i.test(command)) {
    if (/\s-[a-zA-Z]*r/i.test(command) || command.includes("*") || command.split(/\s+/).length > 3) {
      return MEASURE_KINDS.WORKSPACE_WIDE;
    }
    return MEASURE_KINDS.LOCAL_SINGLE;
  }

  // Simple single-target commands
  if (/^(cat|head|tail|sed|awk|echo|touch|ls|stat|file)\b/i.test(command)) {
    if (command.includes("*") || command.includes(";")) {
      return MEASURE_KINDS.WORKSPACE_WIDE;
    }
    return MEASURE_KINDS.LOCAL_SINGLE;
  }

  // Default fallback for unrecognized operations
  return MEASURE_KINDS.LOCAL_SINGLE;
}

export function isSystemLevelExecution(execution, context) {
  return classifyMeasureKind(execution, context) === MEASURE_KINDS.SYSTEM_LEVEL;
}

export function isWorkspaceWideExecution(execution, context) {
  return classifyMeasureKind(execution, context) === MEASURE_KINDS.WORKSPACE_WIDE;
}
