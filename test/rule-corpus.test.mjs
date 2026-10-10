import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { SecurityEngine } from "../lib/index.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const corpusPath = path.join(root, "test", "vectors", "corpus.json");

test("#46: Rule test vectors corpus execution with 0% FPR and 0% FNR", () => {
  assert.ok(fs.existsSync(corpusPath), "test/vectors/corpus.json must exist");
  const raw = fs.readFileSync(corpusPath, "utf8");
  const vectors = JSON.parse(raw);

  assert.ok(Array.isArray(vectors));
  assert.ok(vectors.length >= 100, `Corpus must contain >= 100 test vectors, found ${vectors.length}`);

  let falsePositives = 0;
  let falseNegatives = 0;
  let totalEvaluated = 0;

  const start = performance.now();

  for (const v of vectors) {
    // Isolate session per vector to prevent circuit breaker or retry exhaustion interference
    const engine = new SecurityEngine({ defaultVerdict: "allow" });
    const execution = {
      name: v.tool || "bash",
      arguments: { command: v.command },
    };

    const decision = engine.decide(execution, { sessionId: `test-${v.id}` });
    totalEvaluated += 1;

    if (v.expected === "allow" && decision.verdict !== "allow") {
      falsePositives += 1;
      assert.fail(`False Positive on vector [${v.id}]: command "${v.command}" expected "allow", got "${decision.verdict}" (${decision.reason})`);
    }

    if (v.expected === "deny" && decision.verdict !== "deny") {
      falseNegatives += 1;
      assert.fail(`False Negative on vector [${v.id}]: command "${v.command}" expected "deny", got "${decision.verdict}" (${decision.reason})`);
    }
  }

  const durationMs = performance.now() - start;
  const avgUsPerCommand = (durationMs / totalEvaluated) * 1000;

  assert.equal(falsePositives, 0, "False Positive count must be 0");
  assert.equal(falseNegatives, 0, "False Negative count must be 0");
  assert.ok(avgUsPerCommand < 1000, `Average evaluation time per command must be < 1ms, got ${avgUsPerCommand.toFixed(2)}µs`);
});
