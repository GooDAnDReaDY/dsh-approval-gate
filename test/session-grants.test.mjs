import test from "node:test";
import assert from "node:assert/strict";
import { SessionGrantStore } from "../lib/grants.js";
import { hashCall } from "../lib/canonical.js";

test("SessionGrantStore creates a grant with default TTL and maxUses", () => {
  const store = new SessionGrantStore({ defaultTtlMs: 60000, defaultMaxUses: 2 });
  const grant = store.addGrant({ tool: "bash", sessionId: "sess-1" });

  assert.equal(grant.tool, "bash");
  assert.equal(grant.sessionId, "sess-1");
  assert.equal(grant.maxUses, 2);
  assert.equal(grant.uses, 0);
  assert.ok(grant.expiresAt > Date.now());

  const active = store.getGrants("sess-1");
  assert.equal(active.length, 1);
  assert.equal(active[0].id, grant.id);
});

test("SessionGrantStore allows execution and consumes usages up to maxUses", () => {
  const store = new SessionGrantStore();
  store.addGrant({ tool: "bash", maxUses: 2, sessionId: "sess-1" });

  // First use -> allowed
  assert.equal(store.decide("bash", { command: "uptime" }, { sessionId: "sess-1" }), "allow");
  // Second use -> allowed
  assert.equal(store.decide("bash", { command: "uptime" }, { sessionId: "sess-1" }), "allow");
  // Third use -> no-match (exhausted)
  assert.equal(store.decide("bash", { command: "uptime" }, { sessionId: "sess-1" }), "no-match");
});

test("SessionGrantStore denies expired grants", () => {
  const store = new SessionGrantStore();
  const grant = store.addGrant({ tool: "bash", ttlMs: 100, maxUses: 10, sessionId: "sess-1" });

  const pastNow = grant.expiresAt + 10;
  assert.equal(store.decide("bash", { command: "uptime" }, { sessionId: "sess-1", now: pastNow }), "no-match");
  assert.equal(store.getGrants("sess-1", pastNow).length, 0);
});

test("SessionGrantStore matches specific callHash if provided", () => {
  const store = new SessionGrantStore();
  const targetCall = { name: "bash", arguments: { command: "git status" } };
  const h = hashCall(targetCall);

  store.addGrant({ tool: "bash", callHash: h, sessionId: "sess-1" });

  // Matching call allowed
  assert.equal(store.decide("bash", { command: "git status" }, { sessionId: "sess-1" }), "allow");
  // Different call no-match
  assert.equal(store.decide("bash", { command: "rm -rf /" }, { sessionId: "sess-1" }), "no-match");
});

test("SessionGrantStore supports revoking grants and session isolation", () => {
  const store = new SessionGrantStore();
  const g1 = store.addGrant({ tool: "bash", sessionId: "sess-1" });
  const g2 = store.addGrant({ tool: "bash", sessionId: "sess-2" });

  assert.equal(store.getGrants("sess-1").length, 1);
  assert.equal(store.getGrants("sess-2").length, 1);

  const revoked = store.revokeGrant(g1.id, "sess-1");
  assert.equal(revoked, true);
  assert.equal(store.getGrants("sess-1").length, 0);
  assert.equal(store.getGrants("sess-2").length, 1);
});

