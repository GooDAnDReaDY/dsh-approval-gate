// test/learning-reviewer-eval.test.mjs
// Comprehensive test suite for Iteration 12 (#81, #79, #62, #69, #85).

import test from "node:test";
import assert from "node:assert/strict";

import {
  // #79, #81
  ConfirmationLearner,
  canLearnOperation,
  EXCLUSION_REASONS,
  normalizeLearningKey,

  // #85
  canonicalizeCommand,
  isSemanticallyEquivalent,
  findSemanticallyEquivalentRule,
  validateSemanticSimilarity,

  // #62
  assertSeparationOfDuties,
  IndependentReviewer,
  SAFETY_REVIEWER_SYSTEM_PROMPT,

  // #69
  runEvaluation,
  formatEvaluationReport,
  DEFAULT_EVAL_CORPUS,

  // Engine
  SecurityEngine,
} from "../lib/index.js";

// ============================================================================
// Issue #81: Hard Exclusion of Critical Categories from Learning
// ============================================================================
test("#81 - canLearnOperation strictly rejects critical, secret, and destructive operations", () => {
  // 1. Destructive operations
  assert.equal(canLearnOperation("bash", "rm -rf /tmp/data").canLearn, false);
  assert.equal(canLearnOperation("bash", "shred file.txt").canLearn, false);
  assert.equal(canLearnOperation("bash", "wipefs -a /dev/sda").canLearn, false);

  // 2. Privilege escalation & root
  assert.equal(canLearnOperation("bash", "sudo systemctl restart nginx").canLearn, false);
  assert.equal(canLearnOperation("bash", "chmod 777 /var/www").canLearn, false);
  assert.equal(canLearnOperation("bash", "chown root file").canLearn, false);

  // 3. Secrets & credentials
  assert.equal(canLearnOperation("bash", "cat .env").canLearn, false);
  assert.equal(canLearnOperation("bash", "cat ~/.ssh/id_rsa").canLearn, false);
  assert.equal(canLearnOperation("bash", "cat /etc/shadow").canLearn, false);
  assert.equal(canLearnOperation("view_file", "", { TargetFile: "/home/user/.aws/credentials" }).canLearn, false);

  // 4. Raw disks & filesystems
  assert.equal(canLearnOperation("bash", "mkfs.ext4 /dev/sdb").canLearn, false);
  assert.equal(canLearnOperation("bash", "dd if=/dev/zero of=/dev/sda").canLearn, false);

  // 5. Safe routine operations CAN be learned
  assert.equal(canLearnOperation("bash", "npm test").canLearn, true);
  assert.equal(canLearnOperation("bash", "pnpm test").canLearn, true);
  assert.equal(canLearnOperation("bash", "git status").canLearn, true);
  assert.equal(canLearnOperation("view_file", "", { TargetFile: "src/App.jsx" }).canLearn, true);
});

test("#81 - ConfirmationLearner never learns critical operations regardless of confirmation count", () => {
  const learner = new ConfirmationLearner({ minConfirmations: 2 });
  const criticalExec = { name: "bash", arguments: { command: "rm -rf /var/cache" } };

  for (let i = 0; i < 10; i++) {
    const res = learner.recordConfirmation("sess-test-81", criticalExec);
    assert.equal(res.learned, false);
    assert.equal(res.excluded, true);
  }

  const check = learner.isLearned("sess-test-81", criticalExec);
  assert.equal(check.learned, false);
  assert.equal(learner.getLearnedRules("sess-test-81").length, 0);
});

// ============================================================================
// Issue #79: Confirmation Learning after N-1 User Approvals
// ============================================================================
test("#79 - promotes safe routine operations after N-1 confirmations (default: 2)", () => {
  const learner = new ConfirmationLearner({ minConfirmations: 2 });
  const exec = { name: "bash", arguments: { command: "npm test" } };

  // Confirmation 1
  const first = learner.recordConfirmation("sess-79", exec);
  assert.equal(first.count, 1);
  assert.equal(first.learned, false);
  assert.equal(learner.isLearned("sess-79", exec).learned, false);

  // Confirmation 2 (reaches threshold)
  const second = learner.recordConfirmation("sess-79", exec);
  assert.equal(second.count, 2);
  assert.equal(second.learned, true);

  const check = learner.isLearned("sess-79", exec);
  assert.equal(check.learned, true);
  assert.equal(check.rule.command, "npm test");
});

test("#79 - SecurityEngine auto-allows learned operations at P1", () => {
  const engine = new SecurityEngine({ defaultVerdict: "ask" });
  const exec = { name: "bash", arguments: { command: "custom_routine_tool --check" } };

  // Initial verdict without learning: ask
  const initialDecision = engine.decide(exec, { sessionId: "sess-engine-79" });
  assert.equal(initialDecision.verdict, "ask");

  // Record 2 confirmations
  engine.recordConfirmation("sess-engine-79", exec);
  engine.recordConfirmation("sess-engine-79", exec);

  // Next evaluation: auto-allowed at P1!
  const learnedDecision = engine.decide(exec, { sessionId: "sess-engine-79" });
  assert.equal(learnedDecision.verdict, "allow");
  assert.equal(learnedDecision.stage, "P1");
  assert.equal(learnedDecision.reason, "learned-auto-allow");
});

// ============================================================================
// Issue #85: Semantic Command Similarity & Canonical Normalization
// ============================================================================
test("#85 - canonicalizeCommand normalizes package managers and dev flags", () => {
  assert.equal(canonicalizeCommand("pnpm test"), "npm test");
  assert.equal(canonicalizeCommand("yarn test"), "npm test");
  assert.equal(canonicalizeCommand("npm run test"), "npm test");
  assert.equal(canonicalizeCommand("bun test"), "npm test");
  assert.equal(canonicalizeCommand("pnpm run build"), "npm run build");
  assert.equal(canonicalizeCommand("yarn build"), "npm run build");
  assert.equal(canonicalizeCommand("python3 -m pytest"), "pytest");
  assert.equal(canonicalizeCommand("git status -s"), "git status");
  assert.equal(canonicalizeCommand("git status --short"), "git status");
  assert.equal(canonicalizeCommand("git diff HEAD"), "git diff");
});

test("#85 - isSemanticallyEquivalent identifies syntactic variants", () => {
  assert.equal(isSemanticallyEquivalent("npm test", "pnpm test").equivalent, true);
  assert.equal(isSemanticallyEquivalent("npm run test", "yarn test").equivalent, true);
  assert.equal(isSemanticallyEquivalent("git status", "git status -s").equivalent, true);
  assert.equal(isSemanticallyEquivalent("npm test", "npm run build").equivalent, false);
});

test("#85 - SecurityEngine auto-allows semantic variations of learned rules", () => {
  const engine = new SecurityEngine({ defaultVerdict: "ask" });

  // User confirms "npm test" twice
  engine.recordConfirmation("sess-sim-85", { name: "bash", arguments: { command: "npm test" } });
  engine.recordConfirmation("sess-sim-85", { name: "bash", arguments: { command: "npm test" } });

  // Agent executes "pnpm test" -> should be auto-allowed via semantic similarity!
  const decision = engine.decide(
    { name: "bash", arguments: { command: "pnpm test" } },
    { sessionId: "sess-sim-85" }
  );

  assert.equal(decision.verdict, "allow");
  assert.equal(decision.stage, "P1");
  assert.equal(decision.reason, "learned-semantic-allow");
});

test("#85 - validateSemanticSimilarity works with Flash model and fallback", async () => {
  // Deterministic fallback
  const res1 = await validateSemanticSimilarity("npm test", "pnpm test");
  assert.equal(res1.equivalent, true);
  assert.equal(res1.method, "canonical");

  // With mock Flash LLM
  const mockFlash = {
    classify: async () => ({ equivalent: true, confidence: 0.95 }),
  };
  const res2 = await validateSemanticSimilarity("jest --runInBand", "npm test", mockFlash);
  assert.equal(res2.equivalent, true);
  assert.equal(res2.method, "flash-model");
});

// ============================================================================
// Issue #62: Independent Reviewer Architecture & Separation of Duties
// ============================================================================
test("#62 - enforces separation of duties: primary agent cannot self-approve", async () => {
  // Direct predicate check
  assert.equal(assertSeparationOfDuties("agent-lead", "agent-lead").valid, false);
  assert.equal(assertSeparationOfDuties("agent-lead", "reviewer-model-2").valid, true);

  // IndependentReviewer review check
  const reviewer = new IndependentReviewer({ reviewerId: "agent-lead" });
  const result = await reviewer.review(
    { name: "bash", arguments: { command: "npm test" } },
    { agentId: "agent-lead" }
  );

  assert.equal(result.approved, false);
  assert.equal(result.verdict, "deny");
  assert.equal(result.separationOfDuties, false);
  assert.ok(result.reason.includes("self-approval-forbidden"));
});

test("#62 - IndependentReviewer calls external observer model safely", async () => {
  const mockReviewerClient = {
    classify: async (payload, meta) => {
      assert.ok(meta.systemPrompt.includes("independent security reviewer"));
      assert.equal(payload.tool, "bash");
      return { verdict: "allow", reason: "safe-read-only" };
    },
  };

  const reviewer = new IndependentReviewer({
    reviewerId: "reviewer-v2",
    reviewerClient: mockReviewerClient,
  });

  const result = await reviewer.review(
    { name: "bash", arguments: { command: "ls -la" } },
    { agentId: "agent-worker" }
  );

  assert.equal(result.approved, true);
  assert.equal(result.verdict, "allow");
  assert.equal(result.separationOfDuties, true);
});

// ============================================================================
// Issue #69: Autonomous Benchmark Evaluation Runner
// ============================================================================
test("#69 - runEvaluation calculates 0% FPR and 0% FNR across test corpus", () => {
  const engine = new SecurityEngine();
  const report = runEvaluation(engine, DEFAULT_EVAL_CORPUS);

  assert.ok(report.totalCases > 0);
  assert.equal(report.failedCases, 0);
  assert.equal(report.fpr, 0.0);
  assert.equal(report.fnr, 0.0);
  assert.equal(report.accuracy, 1.0);
  assert.ok(report.latency.avgMs >= 0);
});

test("#69 - formatEvaluationReport formats clean benchmark text", () => {
  const engine = new SecurityEngine();
  const metrics = runEvaluation(engine, DEFAULT_EVAL_CORPUS);
  const text = formatEvaluationReport(metrics);

  assert.ok(text.includes("Security Benchmark Report"));
  assert.ok(text.includes("FPR (False +) : 0.00%"));
  assert.ok(text.includes("FNR (False -) : 0.00%"));
  assert.ok(text.includes("ALL BENCHMARK VECTORS PASSED"));
});
