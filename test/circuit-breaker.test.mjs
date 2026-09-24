import test from "node:test";
import assert from "node:assert/strict";
import { CircuitBreaker } from "../lib/breaker.js";

test("CircuitBreaker initializes with defaults and clean state", () => {
  const breaker = new CircuitBreaker();
  assert.equal(breaker.isTripped("sess-1"), false);
  const snap = breaker.get("sess-1");
  assert.equal(snap.consecutive, 0);
  assert.equal(snap.total, 0);
  assert.equal(snap.tripped, false);
});

test("CircuitBreaker trips on 3 consecutive denies", () => {
  const breaker = new CircuitBreaker({ maxConsecutive: 3, maxTotal: 20 });
  assert.equal(breaker.countDeny("sess-1"), false); // 1
  assert.equal(breaker.isTripped("sess-1"), false);

  assert.equal(breaker.countDeny("sess-1"), false); // 2
  assert.equal(breaker.isTripped("sess-1"), false);

  assert.equal(breaker.countDeny("sess-1"), true); // 3 -> tripped!
  assert.equal(breaker.isTripped("sess-1"), true);

  // Subsequent countDeny keeps it tripped
  assert.equal(breaker.countDeny("sess-1"), false);
  assert.equal(breaker.isTripped("sess-1"), true);
});

test("CircuitBreaker resets consecutive count on allow", () => {
  const breaker = new CircuitBreaker({ maxConsecutive: 3, maxTotal: 20 });
  breaker.countDeny("sess-2");
  breaker.countDeny("sess-2");
  assert.equal(breaker.get("sess-2").consecutive, 2);

  breaker.resetConsecutive("sess-2");
  assert.equal(breaker.get("sess-2").consecutive, 0);
  assert.equal(breaker.get("sess-2").total, 2);
  assert.equal(breaker.isTripped("sess-2"), false);

  // Now needs 3 more consecutive to trip
  breaker.countDeny("sess-2");
  breaker.countDeny("sess-2");
  assert.equal(breaker.isTripped("sess-2"), false);
  breaker.countDeny("sess-2");
  assert.equal(breaker.isTripped("sess-2"), true);
});

test("CircuitBreaker trips on total denies even when interrupted", () => {
  const breaker = new CircuitBreaker({ maxConsecutive: 3, maxTotal: 5 });
  // Alternating deny and allow
  for (let i = 0; i < 4; i++) {
    breaker.countDeny("sess-3");
    breaker.resetConsecutive("sess-3");
  }
  assert.equal(breaker.isTripped("sess-3"), false);
  assert.equal(breaker.get("sess-3").total, 4);

  // 5th deny trips by maxTotal
  const justTripped = breaker.countDeny("sess-3");
  assert.equal(justTripped, true);
  assert.equal(breaker.isTripped("sess-3"), true);
});

test("CircuitBreaker resume fully resets state", () => {
  const breaker = new CircuitBreaker();
  breaker.countDeny("sess-4");
  breaker.countDeny("sess-4");
  breaker.countDeny("sess-4");
  assert.equal(breaker.isTripped("sess-4"), true);

  breaker.resume("sess-4");
  assert.equal(breaker.isTripped("sess-4"), false);
  assert.deepEqual(breaker.get("sess-4"), { consecutive: 0, total: 0, tripped: false });
});

test("CircuitBreaker isolates different sessions", () => {
  const breaker = new CircuitBreaker();
  breaker.countDeny("alice");
  breaker.countDeny("alice");
  breaker.countDeny("alice");
  assert.equal(breaker.isTripped("alice"), true);
  assert.equal(breaker.isTripped("bob"), false);
});
