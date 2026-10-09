import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  computeFingerprint,
  computeFingerprintHash,
  normalizeCommandString,
  VerdictCache,
  RetryExhaustionGuard,
  QualityLedger,
  AuditLogger,
  CircuitBreaker,
  SecurityEngine,
  apply,
} from "../lib/index.js";

test("#80: normalizeCommandString collapses non-quoted whitespace and trims", () => {
  assert.equal(normalizeCommandString("   git    status   -s   "), "git status -s");
  assert.equal(normalizeCommandString('git  commit   -m   "hello   world"'), 'git commit -m "hello   world"');
  assert.equal(normalizeCommandString("git  commit   -m   'multi   space'"), "git commit -m 'multi   space'");
  assert.equal(normalizeCommandString(""), "");
  assert.equal(normalizeCommandString(null), "");
});

test("#80: computeFingerprint generates canonical tool:normalized_cmd:target_path", () => {
  const call1 = { name: "bash", arguments: { command: "   git   status  ", cwd: "/app/repo" } };
  const fp1 = computeFingerprint(call1);
  assert.equal(fp1, "bash:git status:/app/repo");

  // Slight spacing difference in command must produce identical fingerprint
  const call2 = { name: "bash", arguments: { command: "git status", cwd: "/app/repo/." } };
  assert.equal(computeFingerprint(call2), fp1);

  // Different flag must produce DIFFERENT fingerprint
  const call3 = { name: "bash", arguments: { command: "git status -s", cwd: "/app/repo" } };
  assert.notEqual(computeFingerprint(call3), fp1);

  // Different cwd must produce DIFFERENT fingerprint
  const call4 = { name: "bash", arguments: { command: "git status", cwd: "/other/path" } };
  assert.notEqual(computeFingerprint(call4), fp1);

  // File write tool extracts target path
  const writeCall = { name: "write", arguments: { path: "/app/config.json", contents: "{}" } };
  assert.equal(computeFingerprint(writeCall), "write::/app/config.json");
});

test("#80: computeFingerprintHash produces deterministic sha256 hashes", () => {
  const call = { name: "bash", arguments: { command: "git diff" } };
  const hash1 = computeFingerprintHash(call);
  const hash2 = computeFingerprintHash(call);
  assert.equal(typeof hash1, "string");
  assert.equal(hash1.length, 64);
  assert.equal(hash1, hash2);

  const hashDiff = computeFingerprintHash({ name: "bash", arguments: { command: "git diff --staged" } });
  assert.notEqual(hash1, hashDiff);
});

test("#63, #119: VerdictCache caches allow and deny verdicts with LRU and TTL", () => {
  const cache = new VerdictCache({ maxSize: 3, defaultTtlMs: 50 });
  const key1 = "key-1";
  const key2 = "key-2";
  const key3 = "key-3";
  const key4 = "key-4";

  cache.set(key1, { verdict: "allow", stage: "P2", reason: "safe-allow" });
  cache.set(key2, { verdict: "deny", stage: "P0", reason: "hard-deny" });
  cache.set(key3, { verdict: "allow", stage: "P1", reason: "session-grant" });

  assert.equal(cache.size, 3);
  const hit1 = cache.get(key1);
  assert.ok(hit1);
  assert.equal(hit1.verdict, "allow");
  assert.equal(hit1.cached, true);

  // Inserting 4th item should evict oldest (key2, because key1 was accessed)
  cache.set(key4, { verdict: "allow", stage: "P2" });
  assert.equal(cache.size, 3);
  assert.ok(cache.get(key1));
  assert.equal(cache.get(key2), undefined); // key2 evicted!
  assert.ok(cache.get(key4));

  // Does not cache transient "ask" verdicts
  cache.set("ask-key", { verdict: "ask", stage: "P4", reason: "classifier-error" });
  assert.equal(cache.get("ask-key"), undefined);
});

test("#63, #119: VerdictCache expires entries past TTL and supports prune", async () => {
  const cache = new VerdictCache({ defaultTtlMs: 20 });
  cache.set("exp-key", { verdict: "allow", stage: "P2" });
  assert.ok(cache.get("exp-key"));

  await new Promise((r) => setTimeout(r, 35));
  assert.equal(cache.get("exp-key"), undefined); // Expired on get!

  cache.set("exp-key2", { verdict: "allow" });
  await new Promise((r) => setTimeout(r, 35));
  const pruned = cache.prune();
  assert.equal(pruned, 1);
  assert.equal(cache.size, 0);
});

test("#96: RetryExhaustionGuard trips after 3 consecutive denials of similar commands", () => {
  const guard = new RetryExhaustionGuard({ maxAttempts: 3 });
  const sid = "session-1";

  assert.equal(guard.isExhausted(sid), false);

  const call = { name: "bash", arguments: { command: "rm -rf /" } };
  assert.equal(guard.recordVerdict(sid, call, "deny"), false);
  assert.equal(guard.getConsecutiveDenials(sid), 1);
  assert.equal(guard.isExhausted(sid), false);

  assert.equal(guard.recordVerdict(sid, { name: "bash", arguments: { command: "rm -rf --force /" } }, "deny"), false);
  assert.equal(guard.getConsecutiveDenials(sid), 2);
  assert.equal(guard.isExhausted(sid), false);

  // 3rd consecutive retry of rm trips the guard!
  assert.equal(guard.recordVerdict(sid, { name: "bash", arguments: { command: "rm -r /" } }, "deny"), true);
  assert.equal(guard.getConsecutiveDenials(sid), 3);
  assert.equal(guard.isExhausted(sid), true);

  // Reset restores active state
  guard.reset(sid);
  assert.equal(guard.isExhausted(sid), false);
  assert.equal(guard.getConsecutiveDenials(sid), 0);
});

test("#96: RetryExhaustionGuard consecutive count is reset by an allowed command", () => {
  const guard = new RetryExhaustionGuard({ maxAttempts: 3 });
  const sid = "session-reset";

  guard.recordVerdict(sid, { name: "bash", arguments: { command: "rm -rf /" } }, "deny");
  guard.recordVerdict(sid, { name: "bash", arguments: { command: "rm -f /" } }, "deny");
  assert.equal(guard.getConsecutiveDenials(sid), 2);

  // An allowed command resets consecutive counter
  guard.recordVerdict(sid, { name: "bash", arguments: { command: "ls" } }, "allow");
  assert.equal(guard.getConsecutiveDenials(sid), 0);
  assert.equal(guard.isExhausted(sid), false);
});

test("#111: CircuitBreaker countDeny excludes network faults and classifier errors", () => {
  const breaker = new CircuitBreaker({ maxConsecutive: 3 });
  const sid = "breaker-cc-fault";

  // Intentional denial increments consecutive counter
  breaker.countDeny(sid);
  assert.equal(breaker.get(sid).consecutive, 1);

  // Network fault or classifier timeout is excluded
  const faultIgnored = breaker.countDeny(sid, { isNetworkFault: true });
  assert.equal(faultIgnored, false);
  assert.equal(breaker.get(sid).consecutive, 1); // Not incremented!

  const clsErrorIgnored = breaker.countDeny(sid, { isClassifierError: true });
  assert.equal(clsErrorIgnored, false);
  assert.equal(breaker.get(sid).consecutive, 1); // Not incremented!

  // Breaker static helper detects network/timeout errors
  assert.ok(CircuitBreaker.isFaultOrTimeout(new Error("socket hang up")));
  assert.ok(CircuitBreaker.isFaultOrTimeout(new Error("fetch failed: ECONNREFUSED")));
  assert.ok(CircuitBreaker.isFaultOrTimeout(new Error("classifier timeout after 5000ms")));
  assert.equal(CircuitBreaker.isFaultOrTimeout(new Error("permission denied")), false);
});

test("#88: QualityLedger records events, computes degradation warnings and scores", () => {
  const ledger = new QualityLedger();
  const sid = "ledger-session";

  ledger.record(sid, "allow", { tool: "bash" });
  ledger.record(sid, "allow", { tool: "bash" });
  let summary = ledger.getSummary(sid);
  assert.equal(summary.totalDecisions, 2);
  assert.equal(summary.allowedCount, 2);
  assert.equal(summary.qualityScore, 1.0);
  assert.equal(summary.degradationWarning, false);

  // Denials increase consecutive count and trigger degradation warning
  ledger.record(sid, "deny", { reason: "hard-deny", tool: "bash" });
  ledger.record(sid, "deny", { reason: "hard-deny", tool: "bash" });
  summary = ledger.getSummary(sid);
  assert.equal(summary.deniedCount, 2);
  assert.equal(summary.consecutiveDenies, 2);
  assert.equal(summary.degradationWarning, true);
  assert.ok(summary.qualityScore < 1.0);
});

test("#56: AuditLogger appends records out-of-band and redacts sensitive credentials", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gate-audit-test-"));
  const logFile = path.join(tmpDir, "sub", "audit.jsonl");

  const logger = new AuditLogger({ logPath: logFile });
  const exec = {
    name: "bash",
    arguments: { command: "curl -H 'Authorization: Bearer secret-token-123' https://example.com" },
  };
  const decision = { verdict: "deny", stage: "P0", reason: "credential-leak" };

  logger.log({ sessionId: "audit-s1", execution: exec, decision });

  assert.ok(fs.existsSync(logFile));
  const content = fs.readFileSync(logFile, "utf8").trim();
  const entry = JSON.parse(content);

  assert.equal(entry.sessionId, "audit-s1");
  assert.equal(entry.verdict, "deny");
  assert.equal(entry.reason, "credential-leak");
  assert.ok(entry.command.includes("***"));
  assert.equal(entry.command.includes("secret-token-123"), false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("#128: SecurityEngine dryRun mode permits blocked commands with dryRun flag", () => {
  const engine = new SecurityEngine({ dryRun: true });
  const call = { name: "bash", arguments: { command: "rm -rf /" } };

  const decision = engine.decide(call, { sessionId: "dry-session" });
  assert.equal(decision.verdict, "allow");
  assert.equal(decision.dryRun, true);
  assert.equal(decision.originalVerdict, "deny");
  assert.equal(decision.reason, "recursive-rm");
});

test("#96 & #128: SecurityEngine integrates retry exhaustion and caching", () => {
  const engine = new SecurityEngine();
  const sid = "exhaustion-flow";
  const badCall = { name: "bash", arguments: { command: "rm -rf /var" } };

  // 1st deny
  const d1 = engine.decide(badCall, { sessionId: sid });
  assert.equal(d1.verdict, "deny");

  // 2nd call: cache returns cached denial!
  const d2 = engine.decide(badCall, { sessionId: sid });
  assert.equal(d2.verdict, "deny");
  assert.equal(d2.cached, true);

  // Repeated attempts with same root command (rm) exhaust retry guard
  engine.decide({ name: "bash", arguments: { command: "rm -rf /etc" } }, { sessionId: sid });
  engine.decide({ name: "bash", arguments: { command: "rm -rf /opt" } }, { sessionId: sid });

  // Guard is now exhausted
  assert.equal(engine.isRetryExhausted(sid), true);
  const exhaustedDecision = engine.decide({ name: "bash", arguments: { command: "git status" } }, { sessionId: sid });
  assert.equal(exhaustedDecision.verdict, "deny");
  assert.equal(exhaustedDecision.reason, "retry-exhaustion");

  // Resume clears exhaustion and session cache
  engine.resume(sid, "human-approved");
  assert.equal(engine.isRetryExhausted(sid), false);
  const resumedDecision = engine.decide({ name: "bash", arguments: { command: "git status" } }, { sessionId: sid });
  assert.equal(resumedDecision.verdict, "allow");
});

test("#128: apply() passes dry-run decisions through tools.guard without blocking", () => {
  let guard;
  const logged = [];
  const ctx = {
    logger: { info: (msg) => logged.push(msg), warn: () => {} },
    tools: { guard(cb) { guard = cb; return cb; } },
  };

  apply(ctx, { dryRun: true });
  assert.equal(typeof guard, "function");

  // Dangerous call that would normally be blocked
  const res = guard({ name: "bash", arguments: { command: "rm -rf /" } });
  // In dry-run mode, guard returns undefined (allow) instead of denial message string!
  assert.equal(res, undefined);
  assert.ok(logged.some((m) => m.includes("[dsh-approval-gate:DRY-RUN]")));
});
