import test from "node:test";
import assert from "node:assert/strict";
import { SessionGrantStore } from "../lib/grants.js";

test("prune removes expired and exhausted grants and cleans empty sessions", () => {
  const store = new SessionGrantStore();
  const baseNow = Date.now();

  // Session 1: 1 expired grant, 1 exhausted grant
  store.addGrant({ tool: "bash", ttlMs: 50, maxUses: 5, sessionId: "s1" });
  const gExhausted = store.addGrant({ tool: "bash", ttlMs: 10000, maxUses: 1, sessionId: "s1" });
  gExhausted.uses = 1;

  // Session 2: 1 active grant
  store.addGrant({ tool: "bash", ttlMs: 50000, maxUses: 10, sessionId: "s2" });

  assert.equal(store.sessions.size, 2);

  // Prune at baseNow + 100 ms (first grant expired, second exhausted, third still valid)
  const result = store.prune({ now: baseNow + 100 });

  assert.equal(result.removedCount, 2);
  assert.equal(result.remainingCount, 1);
  assert.equal(result.emptySessionsPruned, 1);

  // Session 1 was empty and thus pruned from map
  assert.equal(store.sessions.has("s1"), false);
  assert.equal(store.sessions.has("s2"), true);
  assert.equal(store.getGrants("s2").length, 1);
});

test("counter-based autoPrune automatically triggers prune after N operations", () => {
  const store = new SessionGrantStore({ autoPruneOps: 3 });

  // Add expired grant
  const g = store.addGrant({ tool: "bash", ttlMs: 10, maxUses: 1, sessionId: "s-auto" });

  // Advance time past expiration
  g.expiresAt = Date.now() - 1000;

  // Operation 1 (decide on other session)
  store.decide("bash", { command: "uptime" }, { sessionId: "other" });
  // Operation 2
  store.decide("bash", { command: "uptime" }, { sessionId: "other" });
  // Operation 3 -> triggers autoPrune
  store.decide("bash", { command: "uptime" }, { sessionId: "other" });

  // s-auto should now be pruned automatically
  assert.equal(store.sessions.has("s-auto"), false);
});

test("periodic prune timer starts and stops cleanly", () => {
  const store = new SessionGrantStore();
  store.startPeriodicPrune(100);
  assert.ok(store._pruneTimer !== null);

  store.stopPeriodicPrune();
  assert.equal(store._pruneTimer, null);
});

