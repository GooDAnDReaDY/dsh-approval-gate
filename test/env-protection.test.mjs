import test from "node:test";
import assert from "node:assert/strict";
import { inspectExecution } from "../lib/inspect.js";

test("inspectExecution blocks bare env, printenv, export", () => {
  const hitEnv = inspectExecution({
    name: "bash",
    arguments: { command: "env" },
  });
  assert.equal(hitEnv.deny, true);
  assert.equal(hitEnv.reason, "env-dump-leak");

  const hitPrintenv = inspectExecution({
    name: "bash",
    arguments: { command: "printenv" },
  });
  assert.equal(hitPrintenv.deny, true);
  assert.equal(hitPrintenv.reason, "env-dump-leak");

  const hitExport = inspectExecution({
    name: "bash",
    arguments: { command: "export -p" },
  });
  assert.equal(hitExport.deny, true);
  assert.equal(hitExport.reason, "env-dump-leak");
});

test("inspectExecution blocks reading /proc/*/environ", () => {
  const hit = inspectExecution({
    name: "bash",
    arguments: { command: "cat /proc/self/environ | tr '\\0' '\\n'" },
  });
  assert.equal(hit.deny, true);
  assert.equal(hit.reason, "env-dump-leak");
});

test("inspectExecution blocks printenv targeting sensitive keys", () => {
  const hit = inspectExecution({
    name: "bash",
    arguments: { command: "printenv ANTHROPIC_API_KEY" },
  });
  assert.equal(hit.deny, true);
  assert.equal(hit.reason, "env-dump-leak");
});

test("inspectExecution allows legitimate env execution with subcommands and export assignments", () => {
  const hitCmd = inspectExecution({
    name: "bash",
    arguments: { command: "env NODE_ENV=production node app.js" },
  });
  assert.equal(hitCmd.deny, false);

  const hitExport = inspectExecution({
    name: "bash",
    arguments: { command: "export PORT=8080" },
  });
  assert.equal(hitExport.deny, false);

  const hitPath = inspectExecution({
    name: "bash",
    arguments: { command: "printenv PATH" },
  });
  assert.equal(hitPath.deny, false);
});

