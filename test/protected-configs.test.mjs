import test from "node:test";
import assert from "node:assert/strict";
import { isProtectedConfigPath } from "../lib/paths.js";
import { inspectExecution } from "../lib/inspect.js";

test("isProtectedConfigPath blocks .git tree and hooks", () => {
  assert.equal(isProtectedConfigPath(".git/config"), true);
  assert.equal(isProtectedConfigPath("/project/.git/hooks/post-checkout"), true);
  assert.equal(isProtectedConfigPath(".git"), true);
  assert.equal(isProtectedConfigPath(".gitignore"), false);
});

test("isProtectedConfigPath blocks .ssh keys and configuration", () => {
  assert.equal(isProtectedConfigPath("~/.ssh/id_rsa"), true);
  assert.equal(isProtectedConfigPath(".ssh/authorized_keys"), true);
  assert.equal(isProtectedConfigPath("~/.ssh/config"), true);
});

test("isProtectedConfigPath blocks shell startup persistence scripts", () => {
  assert.equal(isProtectedConfigPath("~/.bashrc"), true);
  assert.equal(isProtectedConfigPath(".zshrc"), true);
  assert.equal(isProtectedConfigPath("~/.profile"), true);
});

test("inspectExecution blocks tool write targeting .git and .ssh", () => {
  const hitGit = inspectExecution({
    name: "write",
    arguments: { path: ".git/hooks/pre-commit", content: "#!/bin/sh\nrm -rf /" },
  });
  assert.equal(hitGit.deny, true);
  assert.equal(hitGit.reason, "secret-write");

  const hitSsh = inspectExecution({
    name: "edit",
    arguments: { path: "~/.ssh/authorized_keys", content: "ssh-rsa AAAA..." },
  });
  assert.equal(hitSsh.deny, true);
  assert.equal(hitSsh.reason, "secret-write");
});

test("inspectExecution blocks shell redirect to .git or startup scripts", () => {
  const hit = inspectExecution({
    name: "bash",
    arguments: { command: "echo 'malicious' >> ~/.bashrc" },
  });
  assert.equal(hit.deny, true);
  assert.equal(hit.reason, "secret-write");
});

