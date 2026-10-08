// lib/parsers/git.js
// Specialized Git AST and semantics parser with classification of read, local mutation,
// remote operations, and destructive commands.
// Resolves: #125, #103

export const GIT_CATEGORY_READ = "read";
export const GIT_CATEGORY_MUTATE_LOCAL = "mutate_local";
export const GIT_CATEGORY_REMOTE = "remote";
export const GIT_CATEGORY_DESTRUCTIVE = "destructive";

const GLOBAL_FLAGS_WITH_VALUE = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--exec-path",
  "--super-prefix",
  "--config-env",
]);

const READ_ONLY_VERBS = new Set([
  "status",
  "log",
  "diff",
  "show",
  "rev-parse",
  "describe",
  "cat-file",
  "ls-files",
  "ls-tree",
  "shortlog",
  "blame",
  "check-ignore",
  "check-ref-format",
  "var",
  "version",
  "help",
  "symbolic-ref",
  "name-rev",
  "merge-base",
  "count-objects",
  "diff-index",
  "diff-tree",
  "for-each-ref",
  "rev-list",
]);

const LOCAL_MUTATE_VERBS = new Set([
  "add",
  "commit",
  "checkout",
  "switch",
  "branch",
  "tag",
  "stash",
  "merge",
  "rebase",
  "cherry-pick",
  "revert",
  "mv",
  "rm",
  "init",
  "apply",
  "am",
]);

const REMOTE_VERBS = new Set([
  "push",
  "pull",
  "fetch",
  "clone",
  "remote",
  "submodule",
]);

/**
 * Extracts global git options and isolates the git subcommand verb and its arguments.
 *
 * @param {string[]} argv - Array of tokens starting with 'git' or the first flag/verb.
 * @returns {{ verb: string, args: string[], globalOptions: Record<string, string>, rawArgv: string[] }}
 */
export function parseGitArgv(argv) {
  if (!Array.isArray(argv) || argv.length === 0) {
    return { verb: "", args: [], globalOptions: {}, rawArgv: [] };
  }

  const rawArgv = [...argv];
  let idx = rawArgv[0] === "git" ? 1 : 0;
  const globalOptions = {};

  while (idx < rawArgv.length && rawArgv[idx].startsWith("-")) {
    const flag = rawArgv[idx];
    if (flag === "--") {
      idx += 1;
      break;
    }
    if (GLOBAL_FLAGS_WITH_VALUE.has(flag)) {
      globalOptions[flag] = rawArgv[idx + 1] || "";
      idx += 2;
    } else if (flag.startsWith("--") && flag.includes("=")) {
      const eqIdx = flag.indexOf("=");
      globalOptions[flag.slice(0, eqIdx)] = flag.slice(eqIdx + 1);
      idx += 1;
    } else if (flag.length > 2 && flag[1] !== "-" && flag.startsWith("-C")) {
      globalOptions["-C"] = flag.slice(2);
      idx += 1;
    } else {
      globalOptions[flag] = "true";
      idx += 1;
    }
  }

  const verb = rawArgv[idx] || "";
  const args = rawArgv.slice(idx + 1);

  return { verb, args, globalOptions, rawArgv };
}

/**
 * Checks whether an argument contains a specific short flag (e.g. 'f' in '-fdx').
 *
 * @param {string[]} args
 * @param {string} flagChar
 * @returns {boolean}
 */
function hasShortFlag(args, flagChar) {
  for (const a of args) {
    if (a === "--") break;
    if (a.length > 1 && a[0] === "-" && a[1] !== "-" && a.includes(flagChar)) {
      return true;
    }
  }
  return false;
}

/**
 * Analyzes and classifies a git subcommand and its arguments.
 *
 * @param {string} verb
 * @param {string[]} args
 * @returns {{
 *   verb: string,
 *   category: "read" | "mutate_local" | "remote" | "destructive",
 *   isDestructive: boolean,
 *   isRemote: boolean,
 *   isForce: boolean,
 *   reason?: string,
 *   detail?: string
 * }}
 */
export function classifyGitOperation(verb, args = []) {
  if (!verb) {
    return {
      verb: "",
      category: GIT_CATEGORY_READ,
      isDestructive: false,
      isRemote: false,
      isForce: false,
    };
  }

  const subArgs = Array.isArray(args) ? args : [];

  // 1. Destructive operations check
  if (verb === "reset" && subArgs.includes("--hard")) {
    return {
      verb,
      category: GIT_CATEGORY_DESTRUCTIVE,
      isDestructive: true,
      isRemote: false,
      isForce: true,
      reason: "git-reset-hard",
      detail: "Destructive git reset --hard discards all uncommitted modifications",
    };
  }

  if (verb === "clean" && (subArgs.includes("-f") || subArgs.includes("--force") || hasShortFlag(subArgs, "f"))) {
    return {
      verb,
      category: GIT_CATEGORY_DESTRUCTIVE,
      isDestructive: true,
      isRemote: false,
      isForce: true,
      reason: "git-clean",
      detail: "Destructive git clean removes untracked files irreversibly",
    };
  }

  if (verb === "branch" && (subArgs.includes("-D") || (subArgs.includes("-d") && (subArgs.includes("-f") || subArgs.includes("--force"))))) {
    return {
      verb,
      category: GIT_CATEGORY_DESTRUCTIVE,
      isDestructive: true,
      isRemote: false,
      isForce: true,
      reason: "git-branch-force-delete",
      detail: "Forceful git branch deletion (-D) risks losing unmerged commits",
    };
  }

  // 2. Remote operations (#103: git push vs local git operations)
  if (verb === "push") {
    const isForce = subArgs.some((a) => (
      a === "--force" ||
      a === "-f" ||
      a.startsWith("--force-with-lease") ||
      a === "--delete" ||
      (a[0] === "+" && a.length > 1)
    )) || hasShortFlag(subArgs, "f");

    if (isForce) {
      return {
        verb,
        category: GIT_CATEGORY_DESTRUCTIVE,
        isDestructive: true,
        isRemote: true,
        isForce: true,
        reason: "git-force-push",
        detail: "Forceful git push overwrites remote repository commit history",
      };
    }

    return {
      verb,
      category: GIT_CATEGORY_REMOTE,
      isDestructive: false,
      isRemote: true,
      isForce: false,
      reason: "git-remote-push",
      detail: "Publishing commits to a remote repository via git push requires confirmation",
    };
  }

  if (verb === "checkout" && (subArgs.includes("-f") || subArgs.includes("--force") || (subArgs.includes("--") && subArgs.includes(".")))) {
    return {
      verb,
      category: GIT_CATEGORY_DESTRUCTIVE,
      isDestructive: true,
      isRemote: false,
      isForce: true,
      reason: "git-checkout-force",
      detail: "Forceful checkout discards local working tree changes",
    };
  }

  if (verb === "restore" && subArgs.includes("--worktree") && (subArgs.includes(".") || subArgs.includes("--staged"))) {
    return {
      verb,
      category: GIT_CATEGORY_DESTRUCTIVE,
      isDestructive: true,
      isRemote: false,
      isForce: true,
      reason: "git-restore-worktree",
      detail: "Restoring working tree files discards local changes",
    };
  }

  if (REMOTE_VERBS.has(verb)) {
    return {
      verb,
      category: GIT_CATEGORY_REMOTE,
      isDestructive: false,
      isRemote: true,
      isForce: false,
    };
  }

  if (LOCAL_MUTATE_VERBS.has(verb)) {
    return {
      verb,
      category: GIT_CATEGORY_MUTATE_LOCAL,
      isDestructive: false,
      isRemote: false,
      isForce: false,
    };
  }

  if (READ_ONLY_VERBS.has(verb)) {
    return {
      verb,
      category: GIT_CATEGORY_READ,
      isDestructive: false,
      isRemote: false,
      isForce: false,
    };
  }

  return {
    verb,
    category: GIT_CATEGORY_MUTATE_LOCAL,
    isDestructive: false,
    isRemote: false,
    isForce: false,
  };
}

/**
 * Full inspection of a git command invocation.
 *
 * @param {string[]} argv - Tokenized arguments
 * @returns {{
 *   verb: string,
 *   args: string[],
 *   category: "read" | "mutate_local" | "remote" | "destructive",
 *   isDestructive: boolean,
 *   isRemote: boolean,
 *   isForce: boolean,
 *   reason?: string,
 *   detail?: string
 * }}
 */
export function inspectGitCommand(argv) {
  const parsed = parseGitArgv(argv);
  const classification = classifyGitOperation(parsed.verb, parsed.args);
  return {
    ...classification,
    args: parsed.args,
    globalOptions: parsed.globalOptions,
  };
}