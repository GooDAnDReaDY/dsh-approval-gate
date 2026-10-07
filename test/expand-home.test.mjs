import test from "node:test";
import assert from "node:assert/strict";
import { expandHome } from "../lib/paths.js";
import { isProtectedPath, inspectExecution } from "../lib/inspect.js";

test("expandHome expands tilde and env variables correctly", () => {
  const fakeEnv = { HOME: "/home/alice", USERPROFILE: "C:\\Users\\alice" };

  assert.equal(expandHome("~", fakeEnv), "/home/alice");
  assert.equal(expandHome("~/projects", fakeEnv), "/home/alice/projects");
  assert.equal(expandHome("~/.ssh/id_rsa", fakeEnv), "/home/alice/.ssh/id_rsa");
  assert.equal(expandHome("$HOME/.env", fakeEnv), "/home/alice/.env");
  assert.equal(expandHome("${HOME}/config/settings.yml", fakeEnv), "/home/alice/config/settings.yml");
  assert.equal(expandHome("/var/log", fakeEnv), "/var/log");
  assert.equal(expandHome("/opt/$HOME-backup", fakeEnv), "/opt/$HOME-backup");
  assert.equal(expandHome("/var/$HOME_data", fakeEnv), "/var/$HOME_data");
  assert.equal(expandHome("", fakeEnv), "");
  assert.equal(expandHome(null, fakeEnv), null);

  // Fallback when HOME empty but USERPROFILE present
  const winEnv = { HOME: "", USERPROFILE: "C:/Users/bob" };
  assert.equal(expandHome("~/.bashrc", winEnv), "C:/Users/bob/.bashrc");
  assert.equal(expandHome("%USERPROFILE%/data", winEnv), "C:/Users/bob/data");
});

test("isProtectedPath detects secrets in expanded home directories", () => {
  const fakeEnv = { HOME: "/home/charlie" };

  assert.equal(isProtectedPath("~/.ssh/id_rsa", fakeEnv), true);
  assert.equal(isProtectedPath("~/.ssh/authorized_keys", fakeEnv), true);
  assert.equal(isProtectedPath("$HOME/.env", fakeEnv), true);
  assert.equal(isProtectedPath("${HOME}/keys/prod.pem", fakeEnv), true);
  assert.equal(isProtectedPath("~/my-project/normal.js", fakeEnv), false);
});

test("inspectExecution blocks write tool targeting home secrets", () => {
  const hit1 = inspectExecution({
    name: "write",
    arguments: { path: "~/.ssh/id_rsa", content: "evil" }
  });
  assert.equal(hit1.deny, true);
  assert.equal(hit1.reason, "secret-write");

  const hit2 = inspectExecution({
    name: "edit",
    arguments: { file: "$HOME/.env", content: "KEY=1" }
  });
  assert.equal(hit2.deny, true);
  assert.equal(hit2.reason, "secret-write");
});

test("inspectExecution blocks shell redirect to expanded home secret", () => {
  const hit = inspectExecution({
    name: "bash",
    arguments: { command: "echo test > ~/.ssh/authorized_keys" }
  });
  assert.equal(hit.deny, true);
  assert.equal(hit.reason, "secret-write");
});
