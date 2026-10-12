// test/race-proxy-hmr.test.mjs
// Comprehensive test suite for Iteration 13 (#50, #51, #43, #41, #39).

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  // #50, #51
  raceHumanDecision,
  RaceHumanHandle,
  RACE_WINNERS,

  // #43
  RulesHmrWatcher,

  // #41
  NETWORK_POLICIES,
  resolveNetworkPolicy,
  checkNetworkAccess,

  // #39
  LocalEgressProxy,

  // Engine
  SecurityEngine,
} from "../lib/index.js";

// ============================================================================
// Issue #50: raceHumanDecision between Human and Host Timeout
// ============================================================================
test("#50 - human decision wins when resolved before timeout", async () => {
  const humanPromise = new Promise((resolve) => {
    setTimeout(() => resolve({ verdict: "allow" }), 20);
  });

  const result = await raceHumanDecision(humanPromise, { timeoutMs: 200, timeoutAction: "deny" });
  assert.equal(result.winner, RACE_WINNERS.HUMAN);
  assert.equal(result.verdict, "allow");
});

test("#50 - host timeout wins and executes timeoutAction when human is absent", async () => {
  const hangingPromise = new Promise(() => {}); // Never resolves

  const result = await raceHumanDecision(hangingPromise, { timeoutMs: 30, timeoutAction: "deny" });
  assert.equal(result.winner, RACE_WINNERS.TIMEOUT);
  assert.equal(result.verdict, "deny");
  assert.equal(result.reason, "host-timeout-expired");
});

test("#50 - lockedAsk enforces deny on timeout even if timeoutAction is allow", async () => {
  const hangingPromise = new Promise(() => {});

  const result = await raceHumanDecision(hangingPromise, {
    timeoutMs: 30,
    timeoutAction: "allow",
    lockedAsk: true,
  });
  assert.equal(result.winner, RACE_WINNERS.TIMEOUT);
  assert.equal(result.verdict, "deny");
});

// ============================================================================
// Issue #51: LLM Pre-emption Claim (RaceHumanHandle.claim)
// ============================================================================
test("#51 - fast pre-emption claim interrupts open decision", async () => {
  const handle = new RaceHumanHandle({ timeoutMs: 500, timeoutAction: "deny" });

  // Simulate LLM fast claim
  const claimRes = handle.claim("allow", "classifier-confident-safe");
  assert.equal(claimRes.claimed, true);

  const result = await handle.promise;
  assert.equal(result.winner, RACE_WINNERS.CLAIM);
  assert.equal(result.verdict, "allow");
  assert.equal(result.reason, "classifier-confident-safe");

  // Subsequent human resolve has no effect
  const lateResolve = handle.resolveHuman({ verdict: "deny" });
  assert.equal(lateResolve, false);
});

test("#51 - lockedAsk rejects auto-claiming allow", async () => {
  const handle = new RaceHumanHandle({ timeoutMs: 500, lockedAsk: true });
  const claimRes = handle.claim("allow", "fast-model");

  assert.equal(claimRes.claimed, false);
  assert.equal(claimRes.reason, "locked-ask-cannot-be-claimed-as-allow");
  handle.abort();
});

// ============================================================================
// Issue #43: Rules HMR Watcher without Daemon Restart
// ============================================================================
test("#43 - RulesHmrWatcher detects file changes and triggers atomic reload", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dsh-hmr-test-"));
  const rulesFile = path.join(tmpDir, "rules.yaml");
  fs.writeFileSync(rulesFile, "rules: []\n", "utf-8");

  let reloadsCount = 0;
  const mockEngine = {
    reload: () => {
      reloadsCount += 1;
    },
  };

  const watcher = new RulesHmrWatcher({ debounceMs: 50 });
  const watched = watcher.watch(mockEngine, [rulesFile]);
  assert.equal(watched, 1);

  // Trigger file update
  fs.writeFileSync(rulesFile, "rules:\n  - name: new-rule\n", "utf-8");

  // Wait for debounced reload
  await new Promise((r) => setTimeout(r, 150));
  assert.ok(reloadsCount >= 1);

  watcher.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ============================================================================
// Issue #41: Network Sandbox Mode Mapping
// ============================================================================
test("#41 - maps sandboxMode to network egress policy accurately", () => {
  assert.equal(resolveNetworkPolicy("read-only"), NETWORK_POLICIES.DENY_ALL);
  assert.equal(resolveNetworkPolicy("isolated"), NETWORK_POLICIES.DENY_ALL);
  assert.equal(resolveNetworkPolicy("workspace-write"), NETWORK_POLICIES.WHITELIST_ONLY);
  assert.equal(resolveNetworkPolicy("standard"), NETWORK_POLICIES.WHITELIST_ONLY);
  assert.equal(resolveNetworkPolicy("danger-full-access"), NETWORK_POLICIES.ALLOW_ALL);
});

test("#41 - checkNetworkAccess enforces egress restrictions per sandbox mode", () => {
  const whitelist = ["registry.npmjs.org", "*.github.com"];

  // 1. read-only mode blocks all outbound external traffic
  const ro = checkNetworkAccess("https://registry.npmjs.org", "read-only", { whitelist });
  assert.equal(ro.allowed, false);
  assert.equal(ro.reason, "sandbox-read-only-network-denied");

  // 2. workspace-write permits whitelisted domains
  const wwAllowed = checkNetworkAccess("api.github.com:443", "workspace-write", { whitelist });
  assert.equal(wwAllowed.allowed, true);
  assert.equal(wwAllowed.reason, "whitelist-allowed");

  // 3. workspace-write blocks unlisted domains
  const wwBlocked = checkNetworkAccess("evil-telemetry.example.com", "workspace-write", { whitelist });
  assert.equal(wwBlocked.allowed, false);
  assert.equal(wwBlocked.reason, "not-in-network-whitelist");

  // 4. danger-full-access permits all egress
  const full = checkNetworkAccess("evil-telemetry.example.com", "danger-full-access", { whitelist });
  assert.equal(full.allowed, true);
  assert.equal(full.reason, "danger-full-access-unrestricted");

  // 5. Loopback allowed by default
  const loopback = checkNetworkAccess("http://127.0.0.1:8080", "workspace-write");
  assert.equal(loopback.allowed, true);
  assert.equal(loopback.reason, "loopback-allowed");
});

// ============================================================================
// Issue #39: Local HTTP/CONNECT Forward Proxy
// ============================================================================
test("#39 - LocalEgressProxy binds to 127.0.0.1 and generates proxy environment", async () => {
  const proxy = new LocalEgressProxy({
    sandboxMode: "workspace-write",
    whitelist: ["api.github.com"],
  });

  const addr = await proxy.start();
  assert.equal(addr.host, "127.0.0.1");
  assert.ok(addr.port > 0);

  const env = proxy.getEnv();
  assert.equal(env.HTTP_PROXY, `http://127.0.0.1:${addr.port}`);
  assert.equal(env.ALL_PROXY, `http://127.0.0.1:${addr.port}`);
  assert.ok(env.NO_PROXY.includes("127.0.0.1"));

  // Check access policies
  assert.equal(proxy.checkAccess("api.github.com:443").allowed, true);
  assert.equal(proxy.checkAccess("unauthorized-site.com:80").allowed, false);

  await proxy.stop();
});

// ============================================================================
// SecurityEngine Integration for Iteration 13
// ============================================================================
test("Iteration 13 E2E - SecurityEngine exposes race, hmr, and network capabilities", () => {
  const engine = new SecurityEngine();

  // 1. Race handle helper
  const handle = engine.createRaceHandle({ timeoutMs: 100 });
  assert.ok(handle instanceof RaceHumanHandle);
  handle.abort();

  // 2. Network policy check helper
  const netCheck = engine.checkNetwork("api.github.com", "read-only");
  assert.equal(netCheck.allowed, false);
  assert.equal(netCheck.policy, NETWORK_POLICIES.DENY_ALL);

  // 3. Network policy resolution helper
  assert.equal(engine.resolveNetworkPolicy("danger-full-access"), NETWORK_POLICIES.ALLOW_ALL);
});
