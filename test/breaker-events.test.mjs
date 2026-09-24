import test from "node:test";
import assert from "node:assert/strict";
import {
  CircuitBreaker,
  CIRCUIT_STATE_ACTIVE,
  CIRCUIT_STATE_TRIPPED,
  CIRCUIT_STATE_RESUMED,
} from "../lib/breaker.js";

test("CircuitBreaker tracks state transitions and emits events on trip", () => {
  const events = [];
  const breaker = new CircuitBreaker({ maxConsecutive: 3 });

  const unsubscribe = breaker.onStateChange((ev) => {
    events.push(ev);
  });

  assert.equal(breaker.getState("test-sess"), CIRCUIT_STATE_ACTIVE);

  // Deny 1 & 2
  breaker.countDeny("test-sess");
  breaker.countDeny("test-sess");
  assert.equal(events.length, 0);

  // Deny 3 -> trips breaker
  const tripped = breaker.countDeny("test-sess");
  assert.equal(tripped, true);
  assert.equal(events.length, 1);
  assert.equal(events[0].sessionId, "test-sess");
  assert.equal(events[0].from, CIRCUIT_STATE_ACTIVE);
  assert.equal(events[0].to, CIRCUIT_STATE_TRIPPED);
  assert.ok(events[0].reason.includes("consecutive-threshold-exceeded"));
  assert.equal(breaker.getState("test-sess"), CIRCUIT_STATE_TRIPPED);

  const history = breaker.getHistory("test-sess");
  assert.equal(history.length, 1);
  assert.equal(history[0].to, CIRCUIT_STATE_TRIPPED);

  unsubscribe();
});

test("CircuitBreaker emits resume and active transition events on resume()", () => {
  const events = [];
  const breaker = new CircuitBreaker({ maxConsecutive: 2 });
  breaker.onStateChange((ev) => events.push(ev));

  breaker.countDeny("resume-sess");
  breaker.countDeny("resume-sess");
  assert.equal(breaker.isTripped("resume-sess"), true);
  assert.equal(events.length, 1);

  // Resume session
  breaker.resume("resume-sess", "user-approved-action");

  assert.equal(breaker.isTripped("resume-sess"), false);
  assert.equal(events.length, 3);
  assert.equal(events[1].from, CIRCUIT_STATE_TRIPPED);
  assert.equal(events[1].to, CIRCUIT_STATE_RESUMED);
  assert.equal(events[1].reason, "user-approved-action");
  assert.equal(events[2].from, CIRCUIT_STATE_RESUMED);
  assert.equal(events[2].to, CIRCUIT_STATE_ACTIVE);
  assert.equal(breaker.getState("resume-sess"), CIRCUIT_STATE_ACTIVE);

  const history = breaker.getHistory("resume-sess");
  assert.equal(history.length, 3);
});

test("CircuitBreaker calls logger warn/info when transitions happen", () => {
  const loggedWarns = [];
  const loggedInfos = [];
  const mockLogger = {
    warn: (msg) => loggedWarns.push(msg),
    info: (msg) => loggedInfos.push(msg),
  };

  const breaker = new CircuitBreaker({ maxConsecutive: 1, logger: mockLogger });
  breaker.countDeny("logged-sess");

  assert.equal(loggedWarns.length, 1);
  assert.ok(loggedWarns[0].includes("state=tripped"));

  breaker.resume("logged-sess");
  assert.ok(loggedInfos.length >= 2);
  assert.ok(loggedInfos[0].includes("state=resumed"));
});

