#!/usr/bin/env node
// bin/eval.mjs
// Command-line entry point for running security benchmarks (#69).

import { SecurityEngine } from "../lib/engine.js";
import { runEvaluation, formatEvaluationReport } from "../lib/eval-runner.js";

const engine = new SecurityEngine();
const results = runEvaluation(engine);
console.log(formatEvaluationReport(results));

if (results.fpr > 0 || results.fnr > 0 || results.failedCases > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
