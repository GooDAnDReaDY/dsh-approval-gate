import test from "node:test";
import assert from "node:assert/strict";

import {
  parseGitArgv,
  classifyGitOperation,
  inspectGitCommand,
  GIT_CATEGORY_READ,
  GIT_CATEGORY_MUTATE_LOCAL,
  GIT_CATEGORY_REMOTE,
  GIT_CATEGORY_DESTRUCTIVE,
} from "../lib/parsers/git.js";

import {
  isDevicePath,
  extractRedirects,
  inspectRedirectSecurity,
  inspectSilentErrors,
  inspectPipelines,
} from "../lib/parsers/shell-cmds.js";

import {
  isLoopbackHost,
  isLoopbackUrl,
  isLoopbackCommand,
} from "../lib/loopback.js";

import {
  CommandDispatcher,
  isReviewerAgent,
  TOOL_KIND_SHELL,
  TOOL_KIND_FILE_WRITE,
  TOOL_KIND_FILE_READ,
} from "../lib/dispatcher.js";

import { inspectBashCommand, inspectExecution } from "../lib/inspect.js";

test("parsers/git: parses global flags and isolates subcommands (#125)", () => {
  const res1 = parseGitArgv(["git", "-C", "/path/to/repo", "status"]);
  assert.equal(res1.verb, "status");
  assert.deepEqual(res1.args, []);
  assert.equal(res1.globalOptions["-C"], "/path/to/repo");

  const res2 = parseGitArgv(["git", "--git-dir=/custom/.git", "log", "-n", "5"]);
  assert.equal(res2.verb, "log");
  assert.deepEqual(res2.args, ["-n", "5"]);
  assert.equal(res2.globalOptions["--git-dir"], "/custom/.git");
});

test("parsers/git: separates read-only operations (#125)", () => {
  const readVerbs = ["status", "log", "diff", "show", "rev-parse", "describe", "cat-file", "ls-files", "blame"];
  for (const v of readVerbs) {
    const res = classifyGitOperation(v, []);
    assert.equal(res.category, GIT_CATEGORY_READ, `verb ${v} should be read-only`);
    assert.equal(res.isDestructive, false);
    assert.equal(res.isRemote, false);
  }
});

test("parsers/git: permits local mutations while requiring confirmation for push (#125, #103)", () => {
  const commitOp = classifyGitOperation("commit", ["-m", "feat: new feature"]);
  assert.equal(commitOp.category, GIT_CATEGORY_MUTATE_LOCAL);
  assert.equal(commitOp.isDestructive, false);
  assert.equal(commitOp.isRemote, false);

  const checkoutOp = classifyGitOperation("checkout", ["-b", "feat/my-branch"]);
  assert.equal(checkoutOp.category, GIT_CATEGORY_MUTATE_LOCAL);

  const addOp = classifyGitOperation("add", ["."]);
  assert.equal(addOp.category, GIT_CATEGORY_MUTATE_LOCAL);

  // git push is categorized as remote (#103)
  const pushOp = classifyGitOperation("push", ["origin", "main"]);
  assert.equal(pushOp.category, GIT_CATEGORY_REMOTE);
  assert.equal(pushOp.isRemote, true);
  assert.equal(pushOp.reason, "git-remote-push");
});

test("parsers/git: detects and blocks destructive operations (#125)", () => {
  const hardReset = classifyGitOperation("reset", ["--hard"]);
  assert.equal(hardReset.isDestructive, true);
  assert.equal(hardReset.reason, "git-reset-hard");

  const forceClean = classifyGitOperation("clean", ["-fdx"]);
  assert.equal(forceClean.isDestructive, true);
  assert.equal(forceClean.reason, "git-clean");

  const forcePush1 = classifyGitOperation("push", ["--force", "origin", "main"]);
  assert.equal(forcePush1.isDestructive, true);
  assert.equal(forcePush1.reason, "git-force-push");

  const forcePush2 = classifyGitOperation("push", ["-f", "origin", "main"]);
  assert.equal(forcePush2.isDestructive, true);
  assert.equal(forcePush2.reason, "git-force-push");

  const branchForceDelete = classifyGitOperation("branch", ["-D", "feature-branch"]);
  assert.equal(branchForceDelete.isDestructive, true);
  assert.equal(branchForceDelete.reason, "git-branch-force-delete");

  const checkoutForce = classifyGitOperation("checkout", ["-f", "main"]);
  assert.equal(checkoutForce.isDestructive, true);
  assert.equal(checkoutForce.reason, "git-checkout-force");
});

test("parsers/shell-cmds: identifies physical devices and blocks redirects (#126)", () => {
  assert.equal(isDevicePath("/dev/sda"), true);
  assert.equal(isDevicePath("/dev/nvme0n1p1"), true);
  assert.equal(isDevicePath("/dev/loop0"), true);
  assert.equal(isDevicePath("/dev/null"), false);
  assert.equal(isDevicePath("/dev/stderr"), false);

  const devRedir = inspectRedirectSecurity([
    { operator: ">", path: "/dev/sda1", dynamic: false },
  ]);
  assert.ok(devRedir && devRedir.deny);
  assert.equal(devRedir.reason, "device-write");

  const secretRedir = inspectRedirectSecurity([
    { operator: ">", path: ".env", dynamic: false },
  ]);
  assert.ok(secretRedir && secretRedir.deny);
  assert.equal(secretRedir.reason, "secret-write");
});

test("parsers/shell-cmds: detects silent error masking patterns (#90)", () => {
  const r1 = inspectSilentErrors("rm -rf /tmp/test 2>/dev/null");
  assert.equal(r1.masked, true);
  assert.equal(r1.kind, "stderr-suppressed");

  const r2 = inspectSilentErrors("systemctl stop app || true");
  assert.equal(r2.masked, true);
  assert.equal(r2.kind, "exit-zero-forced");

  const r3 = inspectSilentErrors("set +e && ./deploy.sh");
  assert.equal(r3.masked, true);
  assert.equal(r3.kind, "errexit-disabled");

  const r4 = inspectSilentErrors("ls -la /tmp");
  assert.equal(r4.masked, false);
});

test("loopback: identifies localhost and loopback interfaces (#40)", () => {
  assert.equal(isLoopbackHost("localhost"), true);
  assert.equal(isLoopbackHost("sub.localhost"), true);
  assert.equal(isLoopbackHost("127.0.0.1"), true);
  assert.equal(isLoopbackHost("127.0.1.1"), true);
  assert.equal(isLoopbackHost("::1"), true);
  assert.equal(isLoopbackHost("0.0.0.0"), true);
  assert.equal(isLoopbackHost("google.com"), false);
  assert.equal(isLoopbackHost("192.168.1.1"), false);

  assert.equal(isLoopbackUrl("http://localhost:3000/api/health"), true);
  assert.equal(isLoopbackUrl("http://127.0.0.1:8080"), true);
  assert.equal(isLoopbackUrl("https://example.com/api"), false);

  const loopbackCmd = isLoopbackCommand(["curl", "http://localhost:5000/ready"]);
  assert.equal(loopbackCmd.isLoopback, true);

  const extCmd = isLoopbackCommand(["curl", "https://api.github.com/zen"]);
  assert.equal(extCmd.isLoopback, false);
});

test("dispatcher: isolates reviewer agents in read-only mode (#65)", () => {
  const dispatcher = new CommandDispatcher();

  const reviewerExec = {
    name: "bash",
    arguments: { command: "npm test" },
    agent: { role: "Code Reviewer", name: "reviewer-subagent" },
  };

  const desc = dispatcher.dispatch(reviewerExec);
  assert.equal(desc.kind, TOOL_KIND_SHELL);
  assert.equal(desc.isMutating, true);
  assert.equal(desc.reviewerViolation, true);

  const hit = inspectExecution(reviewerExec);
  assert.ok(hit.deny);
  assert.equal(hit.reason, "reviewer-read-only");

  // Read-only tools are allowed for reviewer
  const reviewerReadExec = {
    name: "read_file",
    arguments: { path: "package.json" },
    agent: { role: "Reviewer" },
  };
  const readDesc = dispatcher.dispatch(reviewerReadExec);
  assert.equal(readDesc.kind, TOOL_KIND_FILE_READ);
  assert.equal(readDesc.reviewerViolation, false);
});

test("inspect: blocks recursive chmod and chown (#65)", () => {
  const res1 = inspectBashCommand("chmod -R 777 /");
  assert.ok(res1.deny);

  const res2 = inspectBashCommand("chown -R root /etc");
  assert.ok(res2.deny);

  const res3 = inspectBashCommand("chmod --recursive 0755 /var");
  assert.ok(res3.deny);
});

test("inspect: detects remote git push and requires confirmation (#103)", () => {
  const hit1 = inspectBashCommand("git push origin main");
  assert.equal(hit1.ask, true);
  assert.equal(hit1.reason, "git-remote-push");

  // Local operations do not trigger git-remote-push
  const hit2 = inspectBashCommand("git commit -m 'feat: message'");
  assert.equal(hit2.ask, false);
  assert.equal(hit2.deny, false);

  const hit3 = inspectBashCommand("git checkout -b new-feat");
  assert.equal(hit3.ask, false);
  assert.equal(hit3.deny, false);
});

test("inspect: blocks destructive git force push (#125)", () => {
  const hit = inspectBashCommand("git push --force origin main");
  assert.ok(hit.deny);
  assert.equal(hit.reason, "git-force-push");
});

test("inspect: silent error guard asks on masked errors in sensitive commands (#90)", () => {
  const hit1 = inspectBashCommand("rm -rf /tmp/test 2>/dev/null");
  assert.equal(hit1.ask, true);
  assert.equal(hit1.reason, "silent-error-masked");

  const hit2 = inspectBashCommand("systemctl restart nginx || true");
  assert.ok(hit2.deny || hit2.ask);

  // Config flag enables silent error guard on all commands
  const hit3 = inspectBashCommand("npm run test 2>/dev/null", 0, { silentErrorGuard: true });
  assert.equal(hit3.ask, true);
  assert.equal(hit3.reason, "silent-error-masked");
});