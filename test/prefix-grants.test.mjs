import test from "node:test";
import assert from "node:assert/strict";
import { SessionGrantStore, matchGrantCriteria } from "../lib/grants.js";

test("matchGrantCriteria verifies commandPrefix accurately", () => {
  const grant = { commandPrefix: "git status" };

  assert.equal(matchGrantCriteria({ command: "git status" }, grant), true);
  assert.equal(matchGrantCriteria({ command: "git status --porcelain" }, grant), true);
  assert.equal(matchGrantCriteria({ command: "git push origin main" }, grant), false);
  assert.equal(matchGrantCriteria({ other: "value" }, grant), false);
});

test("matchGrantCriteria verifies pathPrefix accurately", () => {
  const grant = { pathPrefix: "/var/log/app" };

  assert.equal(matchGrantCriteria({ path: "/var/log/app/error.log" }, grant), true);
  assert.equal(matchGrantCriteria({ target: "/var/log/app/access.log" }, grant), true);
  assert.equal(matchGrantCriteria({ file: "/etc/passwd" }, grant), false);
});

test("matchGrantCriteria handles structured prefix object", () => {
  const grant = { prefix: { command: "npm test", cwd: "/home/app" } };

  assert.equal(matchGrantCriteria({ command: "npm test -- --watch", cwd: "/home/app/subproject" }, grant), true);
  assert.equal(matchGrantCriteria({ command: "npm test", cwd: "/var/other" }, grant), false);
  assert.equal(matchGrantCriteria({ command: "npm publish", cwd: "/home/app" }, grant), false);
});

test("matchGrantCriteria handles regex argsPattern", () => {
  const grant = { argsPattern: { command: /^git\s+(diff|status|log)/ } };

  assert.equal(matchGrantCriteria({ command: "git diff HEAD~1" }, grant), true);
  assert.equal(matchGrantCriteria({ command: "git status -s" }, grant), true);
  assert.equal(matchGrantCriteria({ command: "git reset --hard" }, grant), false);
});

test("SessionGrantStore authorizes commands via commandPrefix and limits usage", () => {
  const store = new SessionGrantStore();
  store.addGrant({
    tool: "bash",
    commandPrefix: "npm test",
    maxUses: 2,
    sessionId: "worker-1",
  });

  // Allowed prefix run 1
  assert.equal(store.decide("bash", { command: "npm test:unit" }, { sessionId: "worker-1" }), "allow");
  // Allowed prefix run 2
  assert.equal(store.decide("bash", { command: "npm test:integration" }, { sessionId: "worker-1" }), "allow");
  // Exhausted
  assert.equal(store.decide("bash", { command: "npm test:e2e" }, { sessionId: "worker-1" }), "no-match");

  // Non-matching command in same session is rejected immediately
  assert.equal(store.decide("bash", { command: "npm publish" }, { sessionId: "worker-1" }), "no-match");
});

